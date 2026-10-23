import asyncio
import sys
import tempfile
import threading
import unittest
from datetime import timedelta
from email.message import EmailMessage
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import patch

from fastapi import HTTPException
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from spamkiller import imap_client, main, scanner  # noqa: E402
from spamkiller import database  # noqa: E402
from spamkiller.database import Base  # noqa: E402
from spamkiller.llm import LlmVerdict  # noqa: E402
from spamkiller.models import AuditEvent, LlmSettings, MailboxSettings, MessageRecord, ScanResult  # noqa: E402
from spamkiller.rspamd import RspamdResult  # noqa: E402


class FakeImapClient:
    def __init__(self, folder_select_status: dict[str, str], search_results: dict[str, list[str]], uidvalidity: str | None = None):
        self.capabilities = ("IMAP4REV1", "UIDPLUS")
        self.folder_select_status = folder_select_status
        self.search_results = search_results
        self.uidvalidity = uidvalidity
        self.current_folder = None
        self.operations: list[tuple[str, str | None]] = []

    def select(self, folder: str, readonly: bool = False):
        folder_name = folder.strip('"')
        self.operations.append(("select", folder_name))
        self.current_folder = folder_name
        status = self.folder_select_status.get(folder_name, "OK")
        return status, [str(len(self.search_results.get(folder_name, []))).encode("ascii")]

    def uid(self, command: str, *args):
        self.operations.append((command, self.current_folder))
        if command == "SEARCH":
            uids = self.search_results.get(self.current_folder or "", [])
            return "OK", [" ".join(uids).encode("ascii") if uids else b""]
        if command == "EXPUNGE":
            return "OK", []
        return "OK", []

    def create(self, folder: str):
        self.operations.append(("create", folder.strip('"')))
        return "OK", []

    def response(self, code: str):
        return "OK", []

    def capability(self):
        return "OK", [b"IMAP4rev1 UIDPLUS"]

    def status(self, folder: str, items: str):
        self.operations.append(("status", folder.strip('"')))
        if self.uidvalidity:
            return "OK", [f'{folder} (UIDVALIDITY {self.uidvalidity})'.encode("ascii")]
        return "OK", []

    def expunge(self):
        self.operations.append(("expunge", self.current_folder))
        return "OK", []


class FailingStoreImapClient(FakeImapClient):
    def uid(self, command: str, *args):
        self.operations.append((command, self.current_folder))
        if command == "SEARCH":
            return "OK", [b"1"]
        if command == "STORE":
            return "NO", []
        return "OK", []


class NoUidPlusImapClient(FakeImapClient):
    def __init__(self, folder_select_status: dict[str, str], search_results: dict[str, list[str]]):
        super().__init__(folder_select_status, search_results)
        self.capabilities = ("IMAP4REV1",)

    def capability(self):
        return "OK", [b"IMAP4rev1"]


class ImapPathTests(unittest.TestCase):
    def test_list_recent_uids_raises_when_folder_cannot_be_selected(self) -> None:
        client = FakeImapClient({"INBOX": "NO"}, {})

        with self.assertRaisesRegex(RuntimeError, "Could not select folder INBOX"):
            imap_client.list_recent_uids(client, "INBOX", 10)

    def test_list_recent_uids_returns_selected_message_count(self) -> None:
        client = FakeImapClient({"INBOX": "OK"}, {"INBOX": ["1", "2", "3"]})

        uidvalidity, uids, message_count = imap_client.list_recent_uids(client, "INBOX", 2)

        self.assertEqual("unknown", uidvalidity)
        self.assertEqual(["2", "3"], uids)
        self.assertEqual(3, message_count)

    def test_list_recent_uids_falls_back_to_status_uidvalidity(self) -> None:
        client = FakeImapClient({"INBOX": "OK"}, {"INBOX": ["1", "2", "3"]}, uidvalidity="12345")

        uidvalidity, uids, message_count = imap_client.list_recent_uids(client, "INBOX", 2)

        self.assertEqual("12345", uidvalidity)
        self.assertEqual(["2", "3"], uids)
        self.assertEqual(3, message_count)
        self.assertIn(("status", "INBOX"), client.operations)

    def test_move_uid_raises_when_store_fails(self) -> None:
        client = FailingStoreImapClient({"INBOX": "OK"}, {"INBOX": ["42"]})

        with self.assertRaisesRegex(RuntimeError, "Could not delete UID 42"):
            imap_client.move_uid(client, "INBOX", "42", "SpamKiller/Quarantine")

    def test_move_uid_requires_uidplus_before_copying(self) -> None:
        client = NoUidPlusImapClient({"INBOX": "OK"}, {"INBOX": ["42"]})

        with self.assertRaisesRegex(RuntimeError, "UIDPLUS"):
            imap_client.move_uid(client, "INBOX", "42", "SpamKiller/Quarantine")

        self.assertNotIn(("COPY", "INBOX"), client.operations)

    def test_move_by_message_id_anywhere_skips_unavailable_folders(self) -> None:
        client = FakeImapClient(
            {"Broken/Quarantine": "NO", "SpamKiller/Quarantine": "OK"},
            {"SpamKiller/Quarantine": ["7"]},
        )

        moved = imap_client.move_by_message_id_anywhere(
            client,
            ["Broken/Quarantine", "SpamKiller/Quarantine"],
            "<message-id@example.com>",
            "INBOX",
        )

        self.assertEqual(1, moved)
        self.assertIn(("select", "SpamKiller/Quarantine"), client.operations)

    def test_delete_by_message_id_anywhere_skips_unavailable_folders(self) -> None:
        client = FakeImapClient(
            {"Broken/Quarantine": "NO", "SpamKiller/Quarantine": "OK"},
            {"SpamKiller/Quarantine": ["7"]},
        )

        removed = imap_client.delete_by_message_id_anywhere(client, ["Broken/Quarantine", "SpamKiller/Quarantine"], "<message-id@example.com>")

        self.assertEqual(1, removed)
        self.assertIn(("EXPUNGE", "SpamKiller/Quarantine"), client.operations)


class RestoreMessageTests(unittest.TestCase):
    def test_restore_message_refreshes_inbox_source_uid(self) -> None:
        engine = create_engine("sqlite:///:memory:", future=True)
        Base.metadata.create_all(engine)

        with Session(engine, expire_on_commit=False) as session:
            session.add(MailboxSettings(id=1, enabled=True, encrypted_password="saved", inbox_folder="INBOX", quarantine_folder="SpamKiller/Quarantine"))
            record = MessageRecord(
                source_folder="INBOX",
                source_uid="77:1",
                status="quarantined",
                message_id="<message-id@example.com>",
                quarantined_at=scanner.now_utc(),
            )
            session.add(record)
            session.commit()

            fake_client = FakeImapClient({"INBOX": "OK"}, {"INBOX": ["123"]}, uidvalidity="99")
            with patch.object(main.imap_client, "connect", return_value=fake_client), \
                patch.object(main.imap_client, "list_folders", return_value=["SpamKiller/Quarantine"]), \
                patch.object(main.imap_client, "move_by_message_id_anywhere", return_value=1), \
                patch.object(main.imap_client, "logout_quietly", return_value=None):

                result = main.restore_message(record.id, session=session)

            self.assertEqual({"restored": 1}, result)
            self.assertEqual("restored", record.status)
            self.assertEqual("INBOX", record.source_folder)
            self.assertEqual("99:123", record.source_uid)
            self.assertIsNone(record.quarantined_at)

    def test_restore_message_accepts_restore_failed_and_marks_retry(self) -> None:
        record = SimpleNamespace(id=1, status="restore_failed", message_id="<message-id@example.com>", updated_at=None)

        class FakeSession:
            def __init__(self):
                self.added = []
                self.commits = 0

            def get(self, model, message_id):
                return record if message_id == 1 else None

            def add(self, value):
                self.added.append(value)

            def commit(self):
                self.commits += 1

        session = cast(Session, FakeSession())
        fake_client = object()

        with patch.object(main, "get_or_create_mailbox_settings", return_value=SimpleNamespace(quarantine_folder="SpamKiller/Quarantine", inbox_folder="INBOX")), patch.object(main.imap_client, "connect", return_value=fake_client), patch.object(main.imap_client, "list_folders", return_value=["SpamKiller/Quarantine"]), patch.object(main.imap_client, "move_by_message_id_anywhere", return_value=0), patch.object(main.imap_client, "logout_quietly", return_value=None):
            result = main.restore_message(1, session=session)

        self.assertEqual({"restored": 0}, result)
        self.assertEqual("restore_failed", record.status)
        self.assertEqual(1, session.commits)


class MailboxSettingsSecurityTests(unittest.TestCase):
    def test_saved_password_cannot_be_reused_after_imap_identity_change(self) -> None:
        current = SimpleNamespace(
            encrypted_password="saved",
            email="user@example.com",
            imap_host="old.example.com",
            imap_port=993,
            imap_username="user@example.com",
        )
        payload = main.MailboxSettingsUpdate(
            email="user@example.com",
            imap_host="new.example.com",
            imap_port=993,
            imap_username="user@example.com",
        )

        with patch.object(main, "get_or_create_mailbox_settings", return_value=current):
            with self.assertRaisesRegex(HTTPException, "Enter the mailbox password"):
                main.update_mailbox_settings(payload, session=object())


class ConfirmSpamTests(unittest.TestCase):
    def test_confirm_quarantined_message_sets_confirmed_status(self) -> None:
        record = SimpleNamespace(id=1, status="quarantined", message_id="<message-id@example.com>", updated_at=None, quarantined_at=None)

        class FakeSession:
            def __init__(self):
                self.added = []
                self.commits = 0

            def get(self, model, message_id):
                return record if message_id == 1 else None

            def add(self, value):
                self.added.append(value)

            def commit(self):
                self.commits += 1

        session = cast(Session, FakeSession())

        result = main.confirm_spam(1, session=session)

        self.assertEqual({"ok": True}, result)
        self.assertEqual("confirmed_spam", record.status)
        self.assertIsNotNone(record.quarantined_at)
        self.assertEqual(1, session.commits)
        self.assertEqual("message_confirmed_spam", session.added[-1].event_type)

    def test_confirm_non_quarantined_message_moves_back_to_quarantine(self) -> None:
        record = SimpleNamespace(id=1, status="restore_failed", message_id="<message-id@example.com>", updated_at=None, quarantined_at=None)
        fake_client = object()

        class FakeSession:
            def __init__(self):
                self.added = []
                self.commits = 0

            def get(self, model, message_id):
                return record if message_id == 1 else None

            def add(self, value):
                self.added.append(value)

            def commit(self):
                self.commits += 1

        session = cast(Session, FakeSession())

        with patch.object(main, "get_or_create_mailbox_settings", return_value=SimpleNamespace(quarantine_folder="SpamKiller/Quarantine")), \
            patch.object(main.imap_client, "connect", return_value=fake_client) as connect, \
            patch.object(main.imap_client, "list_folders", return_value=["Inbox", "SpamKiller/Quarantine"]) as list_folders, \
            patch.object(main.imap_client, "move_by_message_id_anywhere", return_value=1) as move_by_message_id_anywhere, \
            patch.object(main.imap_client, "logout_quietly", return_value=None) as logout:

            result = main.confirm_spam(1, session=session)

        self.assertEqual({"ok": True}, result)
        self.assertEqual("confirmed_spam", record.status)
        # Confirming from outside quarantine must start the auto-delete clock.
        self.assertIsNotNone(record.quarantined_at)
        self.assertEqual(1, session.commits)
        connect.assert_called_once()
        list_folders.assert_called_once()
        move_by_message_id_anywhere.assert_called_once_with(
            fake_client,
            ["SpamKiller/Quarantine", "Inbox"],
            "<message-id@example.com>",
            "SpamKiller/Quarantine",
        )
        logout.assert_called_once()
        self.assertEqual("message_confirmed_spam", session.added[-1].event_type)

    def test_confirm_requires_message_id_when_not_quarantined(self) -> None:
        record = SimpleNamespace(id=1, status="restore_failed", message_id=None, updated_at=None)

        class FakeSession:
            def __init__(self):
                self.added = []
                self.commits = 0

            def get(self, model, message_id):
                return record if message_id == 1 else None

            def add(self, value):
                self.added.append(value)

            def commit(self):
                self.commits += 1

        session = cast(Session, FakeSession())

        with patch.object(main, "get_or_create_mailbox_settings", return_value=SimpleNamespace(quarantine_folder="SpamKiller/Quarantine")):
            with self.assertRaisesRegex(HTTPException, "Cannot confirm a message without Message-ID."):
                main.confirm_spam(1, session=session)

        self.assertEqual("restore_failed", record.status)
        self.assertEqual([], session.added)
        self.assertEqual(0, session.commits)


class InboxListingTests(unittest.TestCase):
    def test_inbox_returns_only_current_folder_messages_with_scan_info(self) -> None:
        engine = create_engine("sqlite:///:memory:", future=True)
        Base.metadata.create_all(engine)

        with Session(engine, expire_on_commit=False) as session:
            session.add(MailboxSettings(id=1, enabled=True, encrypted_password="saved", inbox_folder="INBOX"))
            clean = MessageRecord(source_folder="INBOX", source_uid="77:1", status="scanned", final_verdict="clean", subject="current clean")
            review = MessageRecord(source_folder="INBOX", source_uid="77:2", status="scanned", final_verdict="review", subject="current review")
            stale = MessageRecord(source_folder="INBOX", source_uid="77:3", status="scanned", final_verdict="review", subject="stale review")
            other_folder = MessageRecord(source_folder="Other", source_uid="77:2", status="scanned", final_verdict="review", subject="other folder")
            session.add_all([clean, review, stale, other_folder])
            session.flush()
            session.add_all([
                ScanResult(message_id=clean.id, rspamd_score=0.1, rspamd_action="no action", final_verdict="clean"),
                ScanResult(message_id=review.id, rspamd_score=4.2, rspamd_action="no action", final_verdict="review"),
                ScanResult(message_id=stale.id, rspamd_score=7.0, rspamd_action="add header", final_verdict="review"),
            ])
            session.commit()

            fake_client = FakeImapClient({"INBOX": "OK"}, {"INBOX": ["1", "2"]}, uidvalidity="77")
            with patch.object(main, "can_decrypt_secret", return_value=True), patch.object(main.imap_client, "connect", return_value=fake_client):
                rows = main.inbox(session=session)

        subjects = {row.subject for row in rows}
        self.assertEqual({"current clean", "current review"}, subjects)
        self.assertEqual({"clean", "review"}, {row.final_verdict for row in rows})
        self.assertTrue(all(row.analysis is not None for row in rows))

    def test_inbox_does_not_connect_before_mailbox_is_configured(self) -> None:
        engine = create_engine("sqlite:///:memory:", future=True)
        Base.metadata.create_all(engine)

        with Session(engine, expire_on_commit=False) as session:
            session.add(MailboxSettings(id=1, enabled=False, encrypted_password=None, inbox_folder="INBOX"))
            session.commit()

            with patch.object(main.imap_client, "connect") as connect:
                rows = main.inbox(session=session)

        self.assertEqual([], rows)
        connect.assert_not_called()

    def test_inbox_does_not_connect_when_saved_password_is_unreadable(self) -> None:
        engine = create_engine("sqlite:///:memory:", future=True)
        Base.metadata.create_all(engine)

        with Session(engine, expire_on_commit=False) as session:
            session.add(MailboxSettings(id=1, enabled=True, encrypted_password="unreadable", inbox_folder="INBOX"))
            session.commit()

            with patch.object(main, "can_decrypt_secret", return_value=False), patch.object(main.imap_client, "connect") as connect:
                rows = main.inbox(session=session)

        self.assertEqual([], rows)
        connect.assert_not_called()


class ScanLockTests(unittest.TestCase):
    def test_suspicious_low_score_symbols_trigger_llm(self) -> None:
        mailbox = cast(MailboxSettings, SimpleNamespace(uncertain_score_threshold=4.0, spam_score_threshold=8.0))
        rspamd = SimpleNamespace(
            score=3.1,
            symbols={
                "ARC_REJECT": {},
                "SUBJECT_NEEDS_ENCODING": {},
                "MV_CASE": {},
                "FORGED_SENDER": {},
                "MIME_HTML_ONLY": {},
            },
        )

        reason = scanner._llm_trigger_reason(mailbox, rspamd)

        self.assertIsNotNone(reason)
        self.assertIn("suspicious_signals:forged_sender", reason or "")

    def test_forged_sender_alone_does_not_trigger_review(self) -> None:
        # Envelope sender != From is normal for shop mail and newsletters sent via an ESP.
        mailbox = cast(MailboxSettings, SimpleNamespace(uncertain_score_threshold=4.0, spam_score_threshold=8.0))
        rspamd = SimpleNamespace(score=2.8, symbols={"FORGED_SENDER": {}, "FROM_NEQ_ENVFROM": {}, "MANY_INVISIBLE_PARTS": {}})

        reason = scanner._llm_trigger_reason(mailbox, rspamd, "Bestellt: Artikel", "Shop <order@shop.example>")

        self.assertIsNone(reason)

    def test_forged_sender_is_ignored_when_dmarc_passed(self) -> None:
        mailbox = cast(MailboxSettings, SimpleNamespace(uncertain_score_threshold=4.0, spam_score_threshold=8.0))
        rspamd = SimpleNamespace(score=2.5, symbols={"FORGED_SENDER": {}, "FROM_NEQ_ENVFROM": {}, "ARC_REJECT": {}, "DMARC_POLICY_ALLOW": {}})

        _trigger, signals, _score = scanner._collect_suspicious_signals(mailbox, rspamd)

        self.assertNotIn("forged_sender", signals)
        self.assertNotIn("multi_symbol_cluster", signals)

    def test_display_name_impersonation_with_hidden_controls_is_spam(self) -> None:
        sender = '"nor\u200feply@ba\u200fnk\ufeff.example" <random123@outlook.com>'
        rspamd = RspamdResult(3.3, "no action", {"FROM_NEQ_DISPLAY_NAME": {}})

        indicators = scanner.local_phishing_indicators(rspamd, subject="Re: Ben\u200fachrichtigung", sender=sender)
        reason = scanner.local_spam_reason(indicators)

        self.assertIn("sender_display_name_impersonates_domain", indicators)
        self.assertIsNotNone(reason)
        mailbox = cast(MailboxSettings, SimpleNamespace(uncertain_score_threshold=4.0, spam_score_threshold=8.0))
        skipped = LlmVerdict("skipped", 0.0, "", "off")
        self.assertEqual("spam", scanner.decide(mailbox, rspamd, skipped, local_spam_reason=reason).verdict)

    def test_matching_display_address_or_visible_text_is_not_impersonation(self) -> None:
        rspamd = RspamdResult(0.5, "no action", {})

        same_domain = scanner.local_phishing_indicators(rspamd, sender='"info@shop.example" <noreply@mail.shop.example>')
        hidden_only = scanner.local_phishing_indicators(rspamd, sender='"Dr.\u00adMuster" <muster@example.org>')

        self.assertNotIn("sender_display_name_impersonates_domain", same_domain)
        self.assertNotIn("sender_display_name_impersonates_domain", hidden_only)
        self.assertIsNone(scanner.local_spam_reason(hidden_only))

    def test_obfuscated_subject_triggers_llm_below_suspicious_threshold(self) -> None:
        mailbox = cast(MailboxSettings, SimpleNamespace(uncertain_score_threshold=4.0, spam_score_threshold=8.0))
        rspamd = SimpleNamespace(score=1.1, symbols={"MIME_HTML_ONLY": {}})

        reason = scanner._llm_trigger_reason(mailbox, rspamd, "Sehen S.ie selbst, warum")

        self.assertEqual("suspicious_signals:subject_obfuscation", reason)

    def test_hidden_unicode_subject_triggers_llm_below_suspicious_threshold(self) -> None:
        mailbox = cast(MailboxSettings, SimpleNamespace(uncertain_score_threshold=4.0, spam_score_threshold=8.0))
        rspamd = SimpleNamespace(score=1.1, symbols={})

        reason = scanner._llm_trigger_reason(mailbox, rspamd, "V\u200fR-Ba\u200fnk: Kennen Sie die neuen Nutzungsbedingungen?")

        self.assertEqual("suspicious_signals:subject_hidden_unicode_controls", reason)

    def test_hidden_unicode_sender_triggers_llm_below_suspicious_threshold(self) -> None:
        mailbox = cast(MailboxSettings, SimpleNamespace(uncertain_score_threshold=4.0, spam_score_threshold=8.0))
        rspamd = SimpleNamespace(score=1.1, symbols={})

        reason = scanner._llm_trigger_reason(mailbox, rspamd, "normal subject", "Comp\u200fliance <ua2n9droberw@gmx.com>")

        self.assertEqual("suspicious_signals:sender_hidden_unicode_controls", reason)

    def test_freemail_sender_claiming_bank_alone_stays_below_signal_threshold(self) -> None:
        mailbox = cast(MailboxSettings, SimpleNamespace(uncertain_score_threshold=4.0, spam_score_threshold=8.0))
        rspamd = SimpleNamespace(score=1.8, symbols={})

        indicators = scanner.local_phishing_indicators(
            rspamd,
            subject="VR-Bank: Kennen Sie die neuen Nutzungsbedingungen?",
            sender="Compliance <ua2n9droberw@gmx.com>",
        )
        reason = scanner._llm_trigger_reason(mailbox, rspamd, suspicious_indicators=indicators)

        self.assertIn("freemail_sender_with_institution_claim", indicators)
        self.assertIsNone(reason)

    def test_weak_message_id_symbol_alone_does_not_trigger_llm(self) -> None:
        mailbox = cast(MailboxSettings, SimpleNamespace(uncertain_score_threshold=4.0, spam_score_threshold=8.0))
        rspamd = SimpleNamespace(
            score=1.8,
            symbols={
                "FREEMAIL_ENVRCPT": {},
                "FROM_HAS_DN": {},
                "FROM_EQ_ENVFROM": {},
                "LOCAL_OUTBOUND": {},
                "TO_DN_NONE": {},
                "PREVIOUSLY_DELIVERED": {},
                "MID_RHS_NOT_FQDN": {},
                "TO_MATCH_ENVRCPT_ALL": {},
            },
        )

        indicators = scanner.local_phishing_indicators(rspamd, subject="Hello", sender="Friend <friend@example.com>")
        reason = scanner._llm_trigger_reason(mailbox, rspamd, "Hello", "Friend <friend@example.com>", indicators)

        self.assertEqual(["message_id_domain_not_fqdn"], indicators)
        self.assertIsNone(reason)

    def test_date_in_past_and_mime_html_only_alone_stays_below_signal_threshold(self) -> None:
        mailbox = cast(MailboxSettings, SimpleNamespace(uncertain_score_threshold=4.0, spam_score_threshold=8.0))
        rspamd = SimpleNamespace(score=1.1, symbols={"DATE_IN_PAST": {}, "MIME_HTML_ONLY": {}})

        reason = scanner._llm_trigger_reason(mailbox, rspamd)

        self.assertIsNone(reason)

    def test_from_neq_envfrom_and_invalid_msgid_alone_stays_below_signal_threshold(self) -> None:
        mailbox = cast(MailboxSettings, SimpleNamespace(uncertain_score_threshold=4.0, spam_score_threshold=8.0))
        rspamd = SimpleNamespace(score=1.1, symbols={"FROM_NEQ_ENVFROM": {}, "INVALID_MSGID": {}})

        reason = scanner._llm_trigger_reason(mailbox, rspamd)

        self.assertIsNone(reason)

    def test_scan_once_returns_busy_without_touching_session_when_lock_exists(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            Path(temp_dir, "scan.lock").mkdir()
            settings = SimpleNamespace(data_dir=Path(temp_dir), scan_batch_size=50)

            with patch.object(scanner, "get_settings", return_value=settings):
                result = asyncio.run(scanner.scan_once(session=object(), trigger="manual"))

        self.assertEqual("Scan already running.", result["message"])
        self.assertEqual(0, result["scanned"])

    def test_scan_lock_is_released_after_failure(self) -> None:
        class FakeSession:
            def add(self, _value):
                pass

            def commit(self):
                pass

            def rollback(self):
                pass

        mailbox = SimpleNamespace(enabled=True, inbox_folder="INBOX", quarantine_folder="SpamKiller/Quarantine")
        with tempfile.TemporaryDirectory() as temp_dir:
            settings = SimpleNamespace(data_dir=Path(temp_dir), scan_batch_size=50)

            with patch.object(scanner, "get_settings", return_value=settings), patch.object(scanner, "get_or_create_mailbox_settings", return_value=mailbox), patch.object(scanner.imap_client, "connect", side_effect=RuntimeError("boom")), patch.object(scanner.imap_client, "logout_quietly", return_value=None):
                with self.assertRaisesRegex(RuntimeError, "boom"):
                    asyncio.run(scanner.scan_once(cast(Session, FakeSession()), trigger="manual"))

        self.assertFalse(Path(temp_dir, "scan.lock").exists())

    def test_scan_runs_blocking_imap_calls_off_the_event_loop(self) -> None:
        class FakeSession:
            def add(self, _value):
                pass

            def commit(self):
                pass

            def rollback(self):
                pass

        loop_threads = []

        def fake_connect(_mailbox):
            loop_threads.append(threading.get_ident())
            raise RuntimeError("boom")

        mailbox = SimpleNamespace(enabled=True, inbox_folder="INBOX", quarantine_folder="SpamKiller/Quarantine")
        with tempfile.TemporaryDirectory() as temp_dir:
            settings = SimpleNamespace(data_dir=Path(temp_dir), scan_batch_size=50)

            with patch.object(scanner, "get_settings", return_value=settings), patch.object(scanner, "get_or_create_mailbox_settings", return_value=mailbox), patch.object(scanner.imap_client, "connect", side_effect=fake_connect), patch.object(scanner.imap_client, "logout_quietly", return_value=None):
                with self.assertRaisesRegex(RuntimeError, "boom"):
                    asyncio.run(scanner.scan_once(cast(Session, FakeSession()), trigger="manual"))

        self.assertEqual(1, len(loop_threads))
        self.assertNotEqual(threading.get_ident(), loop_threads[0])


class ScanMessagePrivacyTests(unittest.TestCase):
    def test_llm_body_excerpt_is_omitted_when_disabled(self) -> None:
        engine = create_engine("sqlite:///:memory:", future=True)
        Base.metadata.create_all(engine)

        message = EmailMessage()
        message["From"] = "Sender <sender@example.com>"
        message["Subject"] = "Suspicious"
        message["Message-ID"] = "<message@example.com>"
        message.set_content("Secret body text. Visit https://example.com/login")

        captured_features = {}

        async def fake_rspamd(_raw, *, rcpt=None):
            return RspamdResult(4.5, "no action", {})

        async def fake_classify(_settings, features):
            captured_features.update(features)
            return LlmVerdict("unsure", 0.2, "needs review", "openai")

        with Session(engine, expire_on_commit=False) as session:
            session.add(LlmSettings(id=1, provider="openai", enabled=True, send_body_excerpt=False, max_excerpt_chars=12000))
            session.commit()

            mailbox = MailboxSettings(
                id=1,
                email="user@example.com",
                imap_username="user@example.com",
                inbox_folder="INBOX",
                uncertain_score_threshold=4.0,
                spam_score_threshold=8.0,
            )
            with patch.object(scanner, "scan_with_rspamd", side_effect=fake_rspamd), patch.object(scanner, "classify_with_llm", side_effect=fake_classify):
                asyncio.run(scanner.scan_message(session, mailbox, message.as_bytes(), "77:1"))

        self.assertEqual("", captured_features["body_excerpt"])
        self.assertIn("example.com", captured_features["link_domains"])


class AutoDeleteTests(unittest.TestCase):
    def test_auto_delete_only_searches_configured_quarantine_folder(self) -> None:
        engine = create_engine("sqlite:///:memory:", future=True)
        Base.metadata.create_all(engine)

        with Session(engine, expire_on_commit=False) as session:
            mailbox = MailboxSettings(id=1, quarantine_folder="SpamKiller/Quarantine", auto_delete_enabled=True, auto_delete_after_days=15)
            record = MessageRecord(
                source_folder="INBOX",
                source_uid="77:1",
                status="quarantined",
                final_verdict="spam",
                message_id="<message@example.com>",
                quarantined_at=scanner.now_utc() - timedelta(days=30),
            )
            session.add_all([mailbox, record])
            session.commit()

            fake_client = object()
            with patch.object(scanner.imap_client, "list_folders") as list_folders, patch.object(scanner.imap_client, "delete_by_message_id_anywhere", return_value=1) as delete_anywhere:
                deleted = scanner.delete_expired_quarantine(session, fake_client, mailbox)

        self.assertEqual(1, deleted)
        list_folders.assert_not_called()
        delete_anywhere.assert_called_once_with(fake_client, ["SpamKiller/Quarantine"], "<message@example.com>")

    def test_auto_deleted_message_does_not_suppress_future_quarantine(self) -> None:
        engine = create_engine("sqlite:///:memory:", future=True)
        Base.metadata.create_all(engine)

        with Session(engine, expire_on_commit=False) as session:
            auto_deleted = MessageRecord(source_folder="INBOX", source_uid="77:1", status="deleted", final_verdict="spam", message_id="<spam@example.com>")
            restored = MessageRecord(source_folder="INBOX", source_uid="77:2", status="restored", final_verdict="spam", message_id="<ham@example.com>")
            session.add_all([auto_deleted, restored])
            session.commit()

            self.assertIsNone(scanner._quarantine_removal_history(session, "<spam@example.com>"))
            self.assertEqual(restored.id, scanner._quarantine_removal_history(session, "<ham@example.com>").id)


class AuditRetentionTests(unittest.TestCase):
    def test_prune_removes_only_old_scan_level_events(self) -> None:
        engine = create_engine("sqlite:///:memory:", future=True)
        Base.metadata.create_all(engine)

        with Session(engine, expire_on_commit=False) as session:
            record = MessageRecord(source_folder="INBOX", source_uid="77:1")
            session.add(record)
            session.flush()
            old = scanner.now_utc() - timedelta(days=scanner.SCAN_AUDIT_RETENTION_DAYS + 1)
            session.add_all(
                [
                    AuditEvent(event_type="scan_completed", details={}, created_at=old),
                    AuditEvent(event_type="scan_completed", details={}),
                    AuditEvent(message_id=record.id, event_type="message_quarantined", details={}, created_at=old),
                ]
            )
            session.commit()

            pruned = scanner.prune_scan_audit_events(session)
            remaining = sorted((row.event_type, row.message_id is None) for row in session.query(AuditEvent).all())

        self.assertEqual(1, pruned)
        self.assertEqual([("message_quarantined", False), ("scan_completed", True)], remaining)


class ImapQuotingTests(unittest.TestCase):
    def test_quote_and_list_parsing_round_trip_backslashes_and_quotes(self) -> None:
        name = 'Spam\Old "Archive"'
        line = '(\HasNoChildren) "/" ' + imap_client._quote(name)

        self.assertEqual(name, imap_client._parse_list_folder(line))


class FolderReconciliationTests(unittest.TestCase):
    def test_mark_missing_folder_records_hides_stale_review_records(self) -> None:
        engine = create_engine("sqlite:///:memory:", future=True)
        Base.metadata.create_all(engine)

        with Session(engine, expire_on_commit=False) as session:
            current = MessageRecord(source_folder="INBOX", source_uid="42:1", status="scanned", final_verdict="review")
            stale = MessageRecord(source_folder="INBOX", source_uid="42:2", status="scanned", final_verdict="review")
            clean = MessageRecord(source_folder="INBOX", source_uid="42:3", status="scanned", final_verdict="clean")
            other_folder = MessageRecord(source_folder="Other", source_uid="42:4", status="scanned", final_verdict="review")
            session.add_all([current, stale, clean, other_folder])
            session.commit()

            missing = scanner._mark_missing_folder_records(session, "INBOX", {"42:1"})
            session.commit()

            self.assertEqual(1, missing)
            self.assertEqual("scanned", current.status)
            self.assertEqual("missing_from_folder", stale.status)
            self.assertEqual("scanned", clean.status)
            self.assertEqual("scanned", other_folder.status)


class ExceptionMessageTests(unittest.TestCase):
    def test_exception_message_uses_exception_type_when_message_is_empty(self) -> None:
        self.assertEqual("TimeoutError", scanner.exception_message(TimeoutError()))


class SchemaMigrationTests(unittest.TestCase):
    def test_sqlite_migration_adds_missing_columns_and_scalar_defaults(self) -> None:
        engine = create_engine("sqlite:///:memory:", future=True)
        with engine.begin() as connection:
            connection.execute(text("CREATE TABLE mailbox_settings (id INTEGER PRIMARY KEY, email VARCHAR(320))"))
            connection.execute(text("INSERT INTO mailbox_settings (id, email) VALUES (1, 'user@example.com')"))

        Base.metadata.create_all(engine)
        database._migrate_sqlite_schema(engine)

        columns = {column["name"] for column in inspect(engine).get_columns("mailbox_settings")}
        self.assertIn("auto_delete_after_days", columns)
        self.assertIn("enabled", columns)
        with engine.connect() as connection:
            row = connection.execute(text("SELECT auto_delete_after_days, enabled FROM mailbox_settings WHERE id = 1")).one()

        self.assertEqual(15, row.auto_delete_after_days)
        self.assertEqual(0, row.enabled)


if __name__ == "__main__":
    unittest.main()
