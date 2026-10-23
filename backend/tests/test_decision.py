import sys
from types import SimpleNamespace
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from spamkiller.decision import decide  # noqa: E402
from spamkiller.scanner import _collect_suspicious_signals  # noqa: E402
from spamkiller.llm import LlmVerdict  # noqa: E402
from spamkiller.rspamd import RspamdResult  # noqa: E402


class DecisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.settings = SimpleNamespace(spam_score_threshold=6.0, uncertain_score_threshold=4.0)
        self.llm = LlmVerdict("skipped", 0.0, "LLM not needed.", "off")

    def test_rspamd_spam_action_overrides_low_score(self) -> None:
        decision = decide(self.settings, RspamdResult(1.0, "reject", {}), self.llm)

        self.assertEqual("spam", decision.verdict)
        self.assertIn("reject", decision.explanation)

    def test_rspamd_add_header_action_needs_review_without_auto_quarantine(self) -> None:
        decision = decide(self.settings, RspamdResult(1.0, "add header", {}), self.llm)

        self.assertEqual("review", decision.verdict)
        self.assertIn("add header", decision.explanation)

    def test_high_score_overrides_rspamd_review_action(self) -> None:
        decision = decide(self.settings, RspamdResult(10.0, "soft reject", {}), self.llm)

        self.assertEqual("spam", decision.verdict)

    def test_rspamd_review_action_overrides_uncertain_score(self) -> None:
        decision = decide(self.settings, RspamdResult(4.5, "soft reject", {}), self.llm)

        self.assertEqual("review", decision.verdict)
        self.assertIn("soft reject", decision.explanation)

    def test_score_threshold_is_fallback_when_action_is_no_action(self) -> None:
        decision = decide(self.settings, RspamdResult(6.0, "no action", {}), self.llm)

        self.assertEqual("spam", decision.verdict)

    def test_high_confidence_llm_spam_overrides_low_rspamd_score(self) -> None:
        llm = LlmVerdict("spam", 0.92, "forged sender and scam content", "anthropic")
        decision = decide(self.settings, RspamdResult(3.1, "no action", {}), llm)

        self.assertEqual("spam", decision.verdict)
        self.assertIn("anthropic", decision.explanation)

    def test_uncertain_score_still_goes_to_review(self) -> None:
        decision = decide(self.settings, RspamdResult(4.5, "no action", {}), self.llm)

        self.assertEqual("review", decision.verdict)

    def test_low_score_trigger_forces_review(self) -> None:
        decision = decide(
            self.settings,
            RspamdResult(1.2, "no action", {}),
            self.llm,
            llm_trigger="suspicious_symbols:DATE_IN_PAST,MIME_HTML_ONLY",
        )

        self.assertEqual("review", decision.verdict)
        self.assertIn("suspicious indicators", decision.explanation)

    def test_low_score_without_trigger_stays_clean(self) -> None:
        decision = decide(self.settings, RspamdResult(1.2, "no action", {}), self.llm)

        self.assertEqual("clean", decision.verdict)
        self.assertIn("below the suspicious threshold", decision.explanation)

    def test_low_score_subject_html_encoding_combo_triggers_review_reason(self) -> None:
        trigger, signals, score = _collect_suspicious_signals(
            self.settings,
            RspamdResult(2.3, "no action", {"ARC_REJECT": {}, "SUBJECT_NEEDS_ENCODING": {}, "MIME_HTML_ONLY": {}}),
            subject='Nur fuer kurze Zeit: Sichern Sie sich 20% Rabatt',
        )
        self.assertIsNotNone(trigger)
        self.assertTrue(trigger.startswith("suspicious_signals:"))
        self.assertIn("arc_reject_subject_encoding_mime_html", signals)
        self.assertGreaterEqual(score, 3.0)

        decision = decide(self.settings, RspamdResult(2.3, "no action", {"ARC_REJECT": {}, "SUBJECT_NEEDS_ENCODING": {}, "MIME_HTML_ONLY": {}}), self.llm, llm_trigger=trigger)
        self.assertEqual("review", decision.verdict)

    def test_single_weak_symbol_stays_clean(self) -> None:
        trigger, signals, score = _collect_suspicious_signals(self.settings, RspamdResult(1.2, "no action", {"MIME_HTML_ONLY": {}}))

        self.assertIsNone(trigger)
        self.assertEqual([], signals)
        self.assertEqual(0.0, score)


if __name__ == "__main__":
    unittest.main()
