from dataclasses import dataclass

from .llm import LlmVerdict
from .models import MailboxSettings
from .rspamd import RspamdResult


SPAM_ACTIONS = {"reject", "quarantine", "discard"}
REVIEW_ACTIONS = {"add header", "rewrite subject", "soft reject", "greylist"}


@dataclass
class Decision:
    verdict: str
    explanation: str


def decide(settings: MailboxSettings, rspamd: RspamdResult, llm: LlmVerdict, *, llm_trigger: str | None = None, local_spam_reason: str | None = None) -> Decision:
    action = rspamd.action.strip().lower()
    if action == "unavailable":
        return Decision("review", "Rspamd could not scan this message, so it was left in the inbox.")

    if local_spam_reason:
        return Decision("spam", f"Local phishing rule: {local_spam_reason}.")

    if llm.verdict == "spam" and llm.confidence >= 0.75:
        return Decision("spam", f"{llm.provider} marked suspicious message as spam: {llm.reason}")

    if action in SPAM_ACTIONS:
        return Decision("spam", f"Rspamd action '{rspamd.action}' recommends spam handling.")

    if rspamd.score >= settings.spam_score_threshold:
        return Decision("spam", f"Rspamd score {rspamd.score:.1f} is above the spam threshold.")

    if action in REVIEW_ACTIONS:
        return Decision("review", f"Rspamd action '{rspamd.action}' needs manual review.")

    if llm_trigger and rspamd.score < settings.uncertain_score_threshold and not (llm.verdict == "spam" and llm.confidence >= 0.75):
        return Decision("review", f"Rspamd score is low but suspicious indicators suggest review: {llm_trigger}")

    if rspamd.score >= settings.uncertain_score_threshold:
        if llm.verdict == "clean" and llm.confidence >= 0.75:
            return Decision("clean", f"Rspamd was uncertain but {llm.provider} marked it clean: {llm.reason}")
        return Decision("review", "Rspamd score is suspicious but not high enough for automatic quarantine.")

    return Decision("clean", f"Rspamd score {rspamd.score:.1f} is below the suspicious threshold.")
