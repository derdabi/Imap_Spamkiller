import asyncio
import os
import tempfile
import unittest
from contextlib import ExitStack
from datetime import timedelta
from email.message import EmailMessage
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

# Tests never connect to the configured database or mailbox.
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["STATIC_DIR"] = str(Path(tempfile.gettempdir()) / "spamkiller-test-no-static")

from fastapi import HTTPException
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from spamkiller import main, scanner
from spamkiller.database import Base
from spamkiller.email_utils import extract_plain_text, parse_message
from spamkiller.models import LlmSettings, MailboxSettings, MessageRecord, now_utc
from spamkiller.rspamd import RspamdResult
from spamkiller.schemas import MailboxSettingsUpdate


class AttachmentPrivacyTests(unittest.TestCase):
    def test_attached_email_subtree_is_excluded(self):
        message = EmailMessage()
        message.set_content("Public body")
        attached = EmailMessage()
        attached.set_content("PRIVATE ATTACHED EMAIL")
        message.add_attachment(attached, filename="private.eml")
        self.assertEqual(extract_plain_text(parse_message(message.as_bytes()), 12000), "Public body")

    def test_multipart_attachment_subtree_is_excluded(self):
        message = EmailMessage()
        message.set_content("Public body")
        message.make_mixed()
        attached = EmailMessage()
        attached.set_content("PRIVATE TEXT")
        attached.add_alternative("<p>PRIVATE HTML</p>", subtype="html")
        attached["Content-Disposition"] = "attachment"
        message.attach(attached)
        self.assertEqual(extract_plain_text(message, 12000), "Public body")

    def test_top_level_text_attachment_is_excluded(self):
        message = EmailMessage()
        message.set_content("PRIVATE TEXT")
        message["Content-Disposition"] = 'attachment; filename="private.txt"'
        self.assertEqual(extract_plain_text(message, 12000), "")

    def test_body_alternatives_and_html_fallback_still_work(self):
        message = EmailMessage()
        message.set_content("Plain body")
        message.add_alternative("<p>HTML body</p>", subtype="html")
        self.assertEqual(extract_plain_text(message, 12000), "Plain body")
        html = EmailMessage()
        html.set_content('<p>HTML body</p><a href="https://example.com">Link</a>', subtype="html")
        self.assertIn("https://example.com", extract_plain_text(html, 12000))
        self.assertEqual(extract_plain_text(message, 5), "Plain")


class MailboxRegressionTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.session = Session(self.engine, expire_on_commit=False)
        self.mailbox = MailboxSettings(id=1, email="old@example.com", encrypted_password="saved", enabled=True)
        self.session.add_all([self.mailbox, LlmSettings(id=1)])
        self.session.commit()
        self.addCleanup(self.engine.dispose)
        self.addCleanup(self.session.close)

    def record(self, status="scanned", uid="1:1", **kwargs):
        record = MessageRecord(source_folder="INBOX", source_uid=uid, message_id="<one@example.com>", status=status, **kwargs)
        self.session.add(record)
        self.session.commit()
        return record

    def imap_patches(self, stack):
        stack.enter_context(patch.object(main.imap_client, "connect", return_value=object()))
        stack.enter_context(patch.object(main.imap_client, "list_folders", return_value=["INBOX"]))
        stack.enter_context(patch.object(main.imap_client, "logout_quietly"))

    def test_changed_identity_with_new_password_can_test_and_list_folders(self):
        payload = MailboxSettingsUpdate(email="new@example.com", password="new-password")
        with ExitStack() as stack:
            self.imap_patches(stack)
            stack.enter_context(patch.object(main, "encrypt_secret", return_value="encrypted-new"))
            self.assertTrue(main.test_mailbox_connection(payload, self.session).ok)
            self.assertEqual(main.list_mailbox_folders(payload, self.session), ["INBOX"])
            settings = main.imap_client.connect.call_args.args[0]
            self.assertEqual(settings.encrypted_password, "encrypted-new")
            self.assertEqual(settings.email, "new@example.com")

    def test_changed_identity_cannot_reuse_saved_password(self):
        with self.assertRaises(HTTPException) as error:
            main._saved_password_for_payload(self.mailbox, MailboxSettingsUpdate(email="new@example.com"))
        self.assertEqual(error.exception.status_code, 400)
        self.assertEqual(main._saved_password_for_payload(self.mailbox, MailboxSettingsUpdate(email="old@example.com")), "saved")

    def test_manual_spam_gets_retention_timestamp_and_expires(self):
        record = self.record()
        with ExitStack() as stack:
            self.imap_patches(stack)
            stack.enter_context(patch.object(main.imap_client, "move_by_message_id_anywhere", return_value=1))
            main.confirm_spam(record.id, self.session)
        self.assertEqual(record.status, "confirmed_spam")
        self.assertIsNotNone(record.quarantined_at)
        future = record.quarantined_at + timedelta(days=16)
        with patch.object(scanner, "now_utc", return_value=future), patch.object(scanner.imap_client, "delete_by_message_id_anywhere", return_value=1):
            self.assertEqual(scanner.delete_expired_quarantine(self.session, object(), self.mailbox), 1)
        self.assertEqual(record.status, "deleted")

    def test_confirming_quarantined_mail_preserves_retention_start(self):
        timestamp = now_utc() - timedelta(days=10)
        record = self.record(status="quarantined", quarantined_at=timestamp)
        main.confirm_spam(record.id, self.session)
        main.confirm_spam(record.id, self.session)
        self.assertEqual(record.quarantined_at, timestamp)

    def test_failed_move_does_not_start_retention(self):
        record = self.record()
        with ExitStack() as stack:
            self.imap_patches(stack)
            stack.enter_context(patch.object(main.imap_client, "move_by_message_id_anywhere", return_value=0))
            with self.assertRaises(HTTPException):
                main.confirm_spam(record.id, self.session)
        self.assertEqual(record.status, "scanned")
        self.assertIsNone(record.quarantined_at)

    def test_deleted_spam_replay_is_classified_again(self):
        self.record(status="deleted")
        with patch.object(scanner, "scan_with_rspamd", new_callable=AsyncMock, return_value=RspamdResult(10, "reject", {})) as scan:
            record = asyncio.run(scanner.scan_message(self.session, self.mailbox, b"Message-ID: <one@example.com>\r\n\r\nspam", "1:2"))
        scan.assert_awaited_once()
        self.assertEqual(record.status, "pending_quarantine")

    def test_explicit_restoration_still_suppresses_quarantine(self):
        self.record(status="restored")
        with patch.object(scanner, "scan_with_rspamd", new_callable=AsyncMock) as scan:
            record = asyncio.run(scanner.scan_message(self.session, self.mailbox, b"Message-ID: <one@example.com>\r\n\r\nbody", "1:2"))
        scan.assert_not_awaited()
        self.assertEqual(record.status, "removed_from_quarantine")

    def test_batches_drain_unprocessed_backlog(self):
        # The newest messages were already checked; older ones must still be scanned.
        self.record(uid="1:5")
        self.record(uid="1:6")
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            self.imap_patches(stack)
            stack.enter_context(patch.object(scanner, "get_settings", return_value=SimpleNamespace(data_dir=Path(directory), scan_batch_size=2)))
            stack.enter_context(patch.object(scanner.imap_client, "ensure_folder"))
            listing = stack.enter_context(patch.object(scanner.imap_client, "list_recent_uids", return_value=("1", [str(i) for i in range(1, 7)], 6)))
            fetch = stack.enter_context(patch.object(scanner.imap_client, "fetch_raw", side_effect=lambda _, uid: f"Message-ID: <{uid}@example.com>\r\n\r\nbody".encode()))
            scan = stack.enter_context(patch.object(scanner, "scan_with_rspamd", new_callable=AsyncMock, return_value=RspamdResult(0, "no action", {})))
            for expected in (2, 2, 0):
                result = asyncio.run(scanner.scan_once(self.session))
                self.assertEqual(result["scanned"], expected)
            self.assertEqual([call.args[1] for call in fetch.call_args_list], ["1", "2", "3", "4"])
            self.assertIsNone(listing.call_args.args[2])
            result = asyncio.run(scanner.scan_once(self.session, reevaluate_existing=True, scan_all=True))
            self.assertEqual(result["scanned"], 6)
            self.assertEqual(result["reevaluated"], 6)
            self.assertEqual(scan.await_count, 10)
        self.assertEqual(len(self.session.scalars(select(MessageRecord)).all()), 6)


if __name__ == "__main__":
    unittest.main()
