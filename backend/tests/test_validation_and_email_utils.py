import sys
import unittest
from email.message import EmailMessage
from pathlib import Path
from tempfile import TemporaryDirectory


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pydantic import ValidationError  # noqa: E402

from spamkiller.config import Settings  # noqa: E402
from spamkiller.email_utils import extract_link_domains, extract_plain_text  # noqa: E402
from spamkiller.rspamd import extract_public_source_ip, extract_scan_metadata  # noqa: E402
from spamkiller.schemas import MailboxSettingsUpdate  # noqa: E402


class ValidationAndEmailUtilsTests(unittest.TestCase):
    def test_uncertain_threshold_cannot_exceed_spam_threshold(self) -> None:
        with self.assertRaises(ValidationError):
            MailboxSettingsUpdate(email="user@example.com", uncertain_score_threshold=9.0, spam_score_threshold=8.0)

    def test_html_only_email_extracts_text_and_links(self) -> None:
        message = EmailMessage()
        message.set_content('<html><body><p>Verify your account</p><a href="https://example.com/login">Open</a></body></html>', subtype="html")

        text = extract_plain_text(message, 1000)

        self.assertIn("Verify your account", text)
        self.assertIn("example.com", extract_link_domains(text))

    def test_link_domains_use_real_host_not_userinfo_or_port(self) -> None:
        domains = extract_link_domains("Login: https://www.bank.example@evil.example:8443/x and https://Shop.Example./a")

        self.assertEqual(["evil.example", "shop.example"], domains)

    def test_app_secret_is_generated_and_reused_when_unset(self) -> None:
        with TemporaryDirectory() as directory:
            settings = Settings(app_secret=None, data_dir=Path(directory))

            first = settings.encryption_secret
            second = Settings(app_secret="", data_dir=Path(directory)).encryption_secret

            self.assertTrue(first)
            self.assertEqual(first, second)
            self.assertEqual(first, (Path(directory) / "app_secret").read_text(encoding="utf-8").strip())

    def test_cors_origins_filter_wildcard(self) -> None:
        settings = Settings(cors_allow_origins="*, http://localhost:5173, https://app.example")

        self.assertEqual(["http://localhost:5173", "https://app.example"], settings.parsed_cors_allow_origins)

    def test_rspamd_source_ip_uses_first_public_received_hop(self) -> None:
        raw = (
            b"Received: from sender.example ([8.8.8.8]) by mx.example.net; Mon, 18 May 2026 15:15:31 +0000\r\n"
            b"Received: from forged.example ([1.1.1.1]) by sender.example; Mon, 18 May 2026 15:15:30 +0000\r\n"
            b"From: sender@example.com\r\n"
            b"To: user@example.com\r\n"
            b"Subject: Test\r\n"
            b"\r\n"
            b"Body"
        )

        self.assertEqual("8.8.8.8", extract_public_source_ip(raw))

    def test_rspamd_source_ip_skips_internal_provider_hops(self) -> None:
        # t-online style: internal 10.x relays on top, the MX hop below records the real client IP.
        raw = (
            b"Received: from internal.local ([10.223.144.65]) by store.example.net; Mon, 18 May 2026 15:15:32 +0000\r\n"
            b"Received: from mailin.example.net by internal.local with LMTP; Mon, 18 May 2026 15:15:31 +0000\r\n"
            b"Received: from sender.example ([8.8.8.8]) by mailin.example.net [194.25.134.8]; Mon, 18 May 2026 15:15:30 +0000\r\n"
            b"Received: from forged.example ([1.1.1.1]) by sender.example; Mon, 18 May 2026 15:15:29 +0000\r\n"
            b"From: sender@example.com\r\n"
            b"Subject: Test\r\n"
            b"\r\n"
            b"Body"
        )

        self.assertEqual("8.8.8.8", extract_public_source_ip(raw))

    def test_rspamd_source_ip_ignores_receiving_server_ip_and_private_only_chains(self) -> None:
        by_only = b"Received: from internal.local ([10.0.0.5]) by mx.example.net [194.25.134.8]\r\nSubject: x\r\n\r\nBody"
        private_only = b"Received: from a ([10.0.0.5]) by b\r\nReceived: from c ([192.168.1.2]) by a\r\nSubject: x\r\n\r\nBody"

        self.assertIsNone(extract_public_source_ip(by_only))
        self.assertIsNone(extract_public_source_ip(private_only))

    def test_rspamd_metadata_includes_sender_recipient_and_trusted_ip(self) -> None:
        raw = (
            b"Received: from sender.example ([8.8.8.8]) by mx.example.net; Mon, 18 May 2026 15:15:31 +0000\r\n"
            b"Return-Path: <bounce@example.com>\r\n"
            b"From: Display Name <sender@example.com>\r\n"
            b"To: user@example.com\r\n"
            b"Subject: Test\r\n"
            b"\r\n"
            b"Body"
        )

        metadata = extract_scan_metadata(raw, rcpt="user@example.com")

        self.assertEqual("8.8.8.8", metadata["IP"])
        self.assertEqual("bounce@example.com", metadata["From"])
        self.assertEqual("user@example.com", metadata["Rcpt"])


if __name__ == "__main__":
    unittest.main()
