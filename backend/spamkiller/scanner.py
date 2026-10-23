import asyncio
import logging
import math
import os
import re
import time
import unicodedata
from datetime import timedelta
from email.utils import getaddresses
from pathlib import Path

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import imap_client
from .config import get_settings
from .decision import decide
from .email_utils import extract_link_domains, extract_plain_text, header_text, message_received_at, parse_message
from .llm import LlmVerdict, classify_with_llm, detect_prompt_injection_markers
from .models import AuditEvent, LlmSettings, MailboxSettings, MessageRecord, ScanResult, now_utc
from .rspamd import scan_with_rspamd


SCAN_LOCK_STALE_SECONDS = 6 * 60 * 60
# Scan-level audit events (no message attached) are written on every poll; per-message history is kept.
SCAN_AUDIT_RETENTION_DAYS = 30
SUSPICIOUS_LLM_SYMBOLS = {
    "ARC_REJECT",
    "CTYPE_MIXED_BOGUS",
    "FORGED_SENDER",
    "FROM_NEQ_ENVFROM",
    "INVALID_MSGID",
    "MANY_INVISIBLE_PARTS",
    "MID_MISSING_BRACKETS",
    "MID_RHS_NOT_FQDN",
    "MISSING_MIME_VERSION",
    "MV_CASE",
    "SUBJ_EXCESS_BASE64",
    "SUBJECT_NEEDS_ENCODING",
    "ZERO_FONT",
}
DISPLAY_NAME_DOMAIN_RE = re.compile(r"[\w.+-]+@((?:[a-z0-9-]+\.)+[a-z]{2,24})\b", re.IGNORECASE)
# DMARC pass means the From domain is authenticated, so envelope/From differences are just a bulk-mail relay.
DMARC_PASS_SYMBOLS = {"DMARC_POLICY_ALLOW"}
OBFUSCATED_WORD_RE = re.compile(r"\b[A-Za-z]{1,3}\.[A-Za-z]{2,}\b")
FREEMAIL_DOMAINS = {
    "aol.com",
    "gmx.com",
    "gmx.de",
    "gmail.com",
    "googlemail.com",
    "hotmail.com",
    "icloud.com",
    "live.com",
    "mail.com",
    "outlook.com",
    "t-online.de",
    "web.de",
    "yahoo.com",
    "yahoo.de",
}
INSTITUTION_CLAIM_RE = re.compile(
    r"\b(bank|vr\s*-?\s*bank|volksbank|sparkasse|konto|account|compliance|security|secure|nutzungsbedingungen)\b",
    re.IGNORECASE,
)
MARKETING_PRESSURE_SUBJECT_RE = re.compile(
    r"\b(sofort|schnell|dringend|jetzt|nur noch|nur heute|nur heute nur|letzte chance|time|today|today only|act now|click|klicken|bestellen|sichern|sichern sie|sofort handeln)\b",
    re.IGNORECASE,
)
FINANCIAL_OFFER_SUBJECT_RE = re.compile(
    r"\b(rabatt|discount|angebot|angebote|sparen|preis|gebühren|konto|kontoauszug|zahlung|zahlungsmethode|gutschrift|telekom|vodafone|bank)\b",
    re.IGNORECASE,
)
CLICK_PRESSURE_SUBJECT_RE = re.compile(r"\b(klicken|click|link|bestätigen|verify|activate|anmeldung|aktualisieren|login|anmelden)\b", re.IGNORECASE)
PERCENT_OFF_RE = re.compile(r"\b\d{1,3}\s*%\b")
WEAK_PHISHING_INDICATORS = {"message_id_domain_not_fqdn"}
# Auto-deleted spam ("deleted") is not a user decision, so it must not suppress future quarantine.
REMOVED_FROM_QUARANTINE_STATUSES = {"restored", "removed_from_quarantine"}
SUSPICIOUS_SIGNAL_THRESHOLD = 3.0
SUSPICIOUS_INDICATOR_WEIGHTS = {
    "subject_hidden_unicode_controls": 3.2,
    "sender_hidden_unicode_controls": 3.2,
    "body_hidden_unicode_controls": 3.0,
    "subject_obfuscation": 3.0,
    "sender_obfuscation": 3.0,
    "subject_offer_pressure": 1.6,
    "sender_domain_suspicious": 1.8,
    "reply_to_domain_mismatch": 1.8,
    "freemail_sender_with_institution_claim": 1.8,
    "institution_claim_with_external_link_domain": 1.8,
    "sender_display_domain_mismatch": 2.2,
    "sender_display_name_impersonates_domain": 2.2,
    "subject_encoding_finance_offer": 2.2,
}
SUSPICIOUS_INDICATOR_DEFAULT_WEIGHT = 1.0

logger = logging.getLogger(__name__)


def _try_acquire_scan_lock() -> Path | None:
    lock_path = get_settings().data_dir / "scan.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        lock_path.mkdir()
        return lock_path
    except FileExistsError:
        if not _scan_lock_is_stale(lock_path):
            return None
        try:
            os.rmdir(lock_path)
            lock_path.mkdir()
            return lock_path
        except OSError:
            return None


def _scan_lock_is_stale(lock_path: Path) -> bool:
    try:
        return time.time() - lock_path.stat().st_mtime > SCAN_LOCK_STALE_SECONDS
    except FileNotFoundError:
        return True


def _release_scan_lock(lock_path: Path) -> None:
    try:
        os.rmdir(lock_path)
    except FileNotFoundError:
        pass


def exception_message(exc: BaseException) -> str:
    return str(exc).strip() or exc.__class__.__name__


def get_or_create_mailbox_settings(session: Session) -> MailboxSettings:
    settings = session.get(MailboxSettings, 1)
    if not settings:
        settings = MailboxSettings(id=1)
        session.add(settings)
        session.commit()
        session.refresh(settings)
    return settings


def get_or_create_llm_settings(session: Session) -> LlmSettings:
    settings = session.get(LlmSettings, 1)
    if not settings:
        settings = LlmSettings(id=1)
        session.add(settings)
        session.commit()
        session.refresh(settings)
    return settings


async def scan_once(session: Session, trigger: str = "scheduled", *, reevaluate_existing: bool = False, scan_all: bool = False) -> dict:
    scan_lock = _try_acquire_scan_lock()
    if scan_lock is None:
        return {"scanned": 0, "quarantined": 0, "deleted": 0, "message": "Scan already running."}

    settings = get_settings()
    started_at = time.monotonic()
    mailbox = get_or_create_mailbox_settings(session)
    scan_details = {
        "trigger": trigger,
        "folder": mailbox.inbox_folder,
        "quarantine_folder": mailbox.quarantine_folder,
        "batch_size": None if scan_all else settings.scan_batch_size,
        "mode": "reevaluate" if reevaluate_existing else "scan",
        "auto_delete_enabled": getattr(mailbox, "auto_delete_enabled", False),
        "auto_delete_after_days": getattr(mailbox, "auto_delete_after_days", None),
        "spam_score_threshold": getattr(mailbox, "spam_score_threshold", None),
        "uncertain_score_threshold": getattr(mailbox, "uncertain_score_threshold", None),
    }
    try:
        session.add(AuditEvent(event_type="scan_started", details=scan_details))
        session.commit()

        if not mailbox.enabled:
            result = {
                **scan_details,
                "scanned": 0,
                "clean": 0,
                "review": 0,
                "quarantined": 0,
                "deleted": 0,
                "failed": 0,
                "skipped_existing": 0,
                "reevaluated": 0,
                "duration_seconds": round(time.monotonic() - started_at, 2),
                "message": "Mailbox scanning is disabled.",
            }
            session.add(AuditEvent(event_type="scan_disabled", details={**scan_details, "duration_seconds": result["duration_seconds"], "reason": "Mailbox scanning is disabled."}))
            session.commit()
            return result

        client = None
        scanned = 0
        clean = 0
        review = 0
        quarantined = 0
        quarantine_suppressed = 0
        failed = 0
        skipped_existing = 0
        reevaluated = 0
        missing_from_folder = 0
        candidate_count = 0
        folder_message_count = None
        uidvalidity = "unknown"
        try:
            # imaplib is blocking; run it in a thread so manual scans don't stall the API event loop.
            client = await asyncio.to_thread(imap_client.connect, mailbox)
            await asyncio.to_thread(imap_client.ensure_folder, client, mailbox.quarantine_folder)
            uidvalidity, uids, folder_message_count = await asyncio.to_thread(imap_client.list_recent_uids, client, mailbox.inbox_folder, None)
            if not reevaluate_existing:
                processed_uids = set(session.scalars(
                    select(MessageRecord.source_uid).where(MessageRecord.source_folder == mailbox.inbox_folder)
                ))
                pending_uids = [uid for uid in uids if f"{uidvalidity}:{uid}" not in processed_uids]
                skipped_existing = len(uids) - len(pending_uids)
                if not scan_all:
                    # Process the oldest outstanding messages first so incoming mail
                    # cannot keep an existing backlog outside the batch forever.
                    pending_uids = pending_uids[:settings.scan_batch_size]
            else:
                pending_uids = uids if scan_all else uids[:settings.scan_batch_size]
            candidate_count = len(pending_uids)
            session.add(
                AuditEvent(
                    event_type="scan_mailbox_checked",
                    details={
                        **scan_details,
                        "folder": mailbox.inbox_folder,
                        "folder_message_count": folder_message_count,
                        "candidate_count": candidate_count,
                        "uidvalidity": uidvalidity,
                    },
                )
            )
            session.commit()
            if scan_all:
                missing_from_folder = _mark_missing_folder_records(session, mailbox.inbox_folder, {f"{uidvalidity}:{uid}" for uid in uids})
                session.commit()
            for uid in pending_uids:
                source_uid = f"{uidvalidity}:{uid}"
                exists = session.scalar(select(MessageRecord).where(MessageRecord.source_folder == mailbox.inbox_folder, MessageRecord.source_uid == source_uid))
                if exists and _was_removed_from_quarantine(exists):
                    skipped_existing += 1
                    continue
                if exists and not reevaluate_existing:
                    skipped_existing += 1
                    continue
                try:
                    raw = await asyncio.to_thread(imap_client.fetch_raw, client, uid)
                    result = await scan_message(session, mailbox, raw, source_uid, existing_record=exists)
                except IntegrityError:
                    session.rollback()
                    continue
                except Exception as exc:
                    session.rollback()
                    failed += 1
                    session.add(AuditEvent(event_type="scan_message_failed", details={"folder": mailbox.inbox_folder, "uid": uid, "error": exception_message(exc)}))
                    session.commit()
                    continue
                scanned += 1
                if exists:
                    reevaluated += 1
                if result.final_verdict == "spam":
                    if result.status == "removed_from_quarantine":
                        quarantine_suppressed += 1
                        session.commit()
                        continue
                    try:
                        await asyncio.to_thread(imap_client.move_uid, client, mailbox.inbox_folder, uid, mailbox.quarantine_folder)
                    except Exception as exc:
                        session.rollback()
                        failed += 1
                        session.add(
                            AuditEvent(
                                event_type="message_quarantine_failed",
                                details={"folder": mailbox.inbox_folder, "uid": uid, "error": exception_message(exc)},
                            )
                        )
                        session.commit()
                        continue
                    result.status = "quarantined"
                    result.quarantined_at = now_utc()
                    quarantined += 1
                    session.add(AuditEvent(message_id=result.id, event_type="message_quarantined", details={"uid": uid}))
                elif result.final_verdict == "review":
                    review += 1
                else:
                    clean += 1
                session.commit()
            # Runs on the loop thread: it shares the session, and only touches IMAP for expired records.
            deleted = delete_expired_quarantine(session, client, mailbox)
            result = {
                "folder": mailbox.inbox_folder,
                "trigger": trigger,
                "batch_size": None if scan_all else settings.scan_batch_size,
                "mode": scan_details["mode"],
                "scanned": scanned,
                "clean": clean,
                "review": review,
                "quarantined": quarantined,
                "quarantine_suppressed": quarantine_suppressed,
                "deleted": deleted,
                "failed": failed,
                "skipped_existing": skipped_existing,
                "reevaluated": reevaluated,
                "missing_from_folder": missing_from_folder,
                "candidate_count": candidate_count,
                "folder_message_count": folder_message_count,
                "uidvalidity": uidvalidity,
                "duration_seconds": round(time.monotonic() - started_at, 2),
                "message": "Scan completed.",
            }
            session.add(AuditEvent(event_type="scan_completed", details=result))
            session.commit()
            return result
        except Exception as exc:
            session.rollback()
            session.add(
                AuditEvent(
                    event_type="scan_failed",
                    details={**scan_details, "duration_seconds": round(time.monotonic() - started_at, 2), "error": exception_message(exc)},
                )
            )
            session.commit()
            raise
        finally:
            await asyncio.to_thread(imap_client.logout_quietly, client)
    finally:
        _release_scan_lock(scan_lock)


def _mark_missing_folder_records(session: Session, folder: str, current_source_uids: set[str]) -> int:
    records = session.scalars(
        select(MessageRecord).where(
            MessageRecord.source_folder == folder,
            MessageRecord.status.in_(["scanned", "pending_quarantine", "restore_failed"]),
            MessageRecord.final_verdict != "clean",
        )
    ).all()
    missing = 0
    for record in records:
        if record.source_uid in current_source_uids:
            continue
        record.status = "missing_from_folder"
        record.updated_at = now_utc()
        missing += 1
    return missing


async def scan_message(session: Session, mailbox: MailboxSettings, raw: bytes, uid: str, existing_record: MessageRecord | None = None) -> MessageRecord:
    llm_settings = get_or_create_llm_settings(session)
    parsed = parse_message(raw)
    message_id = header_text(parsed, "Message-ID") or None
    plain_text = extract_plain_text(parsed, llm_settings.max_excerpt_chars)
    llm_body_excerpt = plain_text if llm_settings.send_body_excerpt else ""
    restored_record = _quarantine_removal_history(session, message_id, existing_record)
    if restored_record:
        record = existing_record or MessageRecord(source_folder=mailbox.inbox_folder, source_uid=uid)
        record.message_id = message_id
        record.sender = header_text(parsed, "From")
        record.subject = header_text(parsed, "Subject")
        record.received_at = message_received_at(parsed)
        record.status = "removed_from_quarantine"
        record.final_verdict = "spam"
        record.explanation = "Automatic quarantine suppressed because this message was previously removed from quarantine."
        record.quarantined_at = None
        record.deleted_at = None
        record.updated_at = now_utc()
        session.add(record)
        session.flush()
        session.add(
            AuditEvent(
                message_id=record.id,
                event_type="message_quarantine_suppressed",
                details={
                    "reason": "previously_removed_from_quarantine",
                    "matched_message_id": message_id,
                    "history_record_id": restored_record.id,
                    "history_status": restored_record.status,
                },
            )
        )
        return record

    rspamd = await scan_with_rspamd(raw, rcpt=mailbox.email or mailbox.imap_username or None)
    record = existing_record or MessageRecord(source_folder=mailbox.inbox_folder, source_uid=uid)
    record.message_id = message_id
    record.sender = header_text(parsed, "From")
    record.subject = header_text(parsed, "Subject")
    record.received_at = message_received_at(parsed)
    reply_to = header_text(parsed, "Reply-To")
    link_domains = extract_link_domains(plain_text)
    suspicious_indicators = local_phishing_indicators(
        rspamd,
        subject=record.subject,
        sender=record.sender,
        reply_to=reply_to,
        link_domains=link_domains,
        body_excerpt=plain_text,
    )
    session.add(record)
    session.flush()

    llm_provider = llm_settings.provider if llm_settings.enabled else "off"
    llm = LlmVerdict("skipped", 0.0, "Rspamd score is below the suspicious threshold and no suspicious symbol trigger matched.", llm_provider)
    prompt_injection_markers: list[str] = []
    suspicious_signals: list[str] = []
    suspicious_signal_score = 0.0
    llm_trigger, suspicious_signals, suspicious_signal_score = _collect_suspicious_signals(
        mailbox,
        rspamd,
        subject=record.subject,
        sender=record.sender,
        suspicious_indicators=suspicious_indicators,
    )
    spam_reason = local_spam_reason(suspicious_indicators)
    if llm_trigger and not spam_reason:
        features = {
            "subject": record.subject,
            "from": record.sender,
            "reply_to": reply_to,
            "sender_domain": _address_domain(record.sender),
            "reply_to_domain": _address_domain(reply_to),
            "link_domains": link_domains,
            "body_excerpt": llm_body_excerpt,
            "rspamd_score": rspamd.score,
            "rspamd_action": rspamd.action,
            "rspamd_symbols": list(rspamd.symbols.keys())[:30],
            "suspicious_indicators": suspicious_indicators,
        }
        prompt_injection_markers = detect_prompt_injection_markers(features)
        features["prompt_injection_markers"] = prompt_injection_markers
        try:
            llm = await classify_with_llm(llm_settings, features)
        except Exception as exc:
            llm = LlmVerdict("skipped", 0.0, f"LLM classification failed: {exc}", llm_settings.provider)

    decision = decide(mailbox, rspamd, llm, llm_trigger=llm_trigger, local_spam_reason=spam_reason)
    record.final_verdict = decision.verdict
    record.explanation = decision.explanation
    record.status = "scanned" if decision.verdict != "spam" else "pending_quarantine"
    record.quarantined_at = None
    record.deleted_at = None
    record.updated_at = now_utc()
    session.add(
        ScanResult(
            message_id=record.id,
            rspamd_score=rspamd.score,
            rspamd_action=rspamd.action,
            rspamd_symbols=rspamd.symbols,
            llm_provider=llm.provider,
            llm_verdict=llm.verdict,
            llm_confidence=llm.confidence,
            final_verdict=decision.verdict,
            explanation=decision.explanation,
        )
    )
    audit_details = {
        "verdict": decision.verdict,
        "score": rspamd.score,
        "action": rspamd.action,
        "subject": record.subject,
        "sender": record.sender,
        "explanation": decision.explanation,
        "uncertain_score_threshold": mailbox.uncertain_score_threshold,
        "spam_score_threshold": mailbox.spam_score_threshold,
        "rspamd_symbols": _top_rspamd_symbols(rspamd.symbols),
        "rspamd_source_ip": rspamd.source_ip or "none",
        "llm_provider": llm.provider,
        "llm_verdict": llm.verdict,
        "llm_confidence": llm.confidence,
        "llm_reason": llm.reason,
        "llm_trigger": llm_trigger or "none",
        "suspicious_signals": suspicious_signals,
        "suspicious_signal_score": suspicious_signal_score,
        "suspicious_indicators": suspicious_indicators,
    }
    if prompt_injection_markers:
        audit_details["prompt_injection_markers"] = prompt_injection_markers
    session.add(AuditEvent(message_id=record.id, event_type="message_scanned", details=audit_details))
    return record


def _was_removed_from_quarantine(record: MessageRecord) -> bool:
    return record.status in REMOVED_FROM_QUARANTINE_STATUSES


def _quarantine_removal_history(session: Session, message_id: str | None, existing_record: MessageRecord | None = None) -> MessageRecord | None:
    if existing_record and _was_removed_from_quarantine(existing_record):
        return existing_record
    if not message_id:
        return None
    return session.scalar(
        select(MessageRecord)
        .where(
            MessageRecord.message_id == message_id,
            MessageRecord.status.in_(REMOVED_FROM_QUARANTINE_STATUSES),
        )
        .order_by(MessageRecord.updated_at.desc())
    )


def _llm_trigger_reason(mailbox: MailboxSettings, rspamd, subject: str = "", sender: str = "", suspicious_indicators: list[str] | None = None) -> str | None:
    trigger, _signals, _score = _collect_suspicious_signals(mailbox, rspamd, subject=subject, sender=sender, suspicious_indicators=suspicious_indicators)
    return trigger


def _collect_suspicious_signals(
    mailbox: MailboxSettings,
    rspamd,
    *,
    subject: str = "",
    sender: str = "",
    suspicious_indicators: list[str] | None = None,
) -> tuple[str | None, list[str], float]:
    if rspamd.score >= mailbox.spam_score_threshold:
        return None, [], 0.0
    if rspamd.score >= mailbox.uncertain_score_threshold:
        return "score_in_uncertain_range", ["score_in_uncertain_range"], 0.0

    symbols = set(rspamd.symbols)
    indicators = suspicious_indicators or local_phishing_indicators(rspamd, subject=subject, sender=sender)

    suspicious_signals: list[str] = []
    signal_score = 0.0

    dmarc_passed = bool(DMARC_PASS_SYMBOLS & symbols)

    # FORGED_SENDER only means envelope sender != From, which is normal for newsletters and shop mail
    # sent through an ESP, so it needs other evidence before it triggers review.
    if "FORGED_SENDER" in symbols and not dmarc_passed:
        suspicious_signals.append("forged_sender")
        signal_score += 2.0

    if {"DATE_IN_PAST", "MIME_HTML_ONLY"}.issubset(symbols) and rspamd.score >= 1.0:
        suspicious_signals.append("date_in_past_mime_html_only")
        signal_score += 2.0

    if {"FROM_NEQ_ENVFROM", "INVALID_MSGID"}.issubset(symbols) and rspamd.score >= 1.0:
        suspicious_signals.append("from_neq_envfrom_invalid_msgid")
        signal_score += 2.0

    if {"ARC_REJECT", "SUBJECT_NEEDS_ENCODING", "MIME_HTML_ONLY"}.issubset(symbols):
        suspicious_signals.append("arc_reject_subject_encoding_mime_html")
        signal_score += 3.3

    if {"ARC_REJECT", "RCVD_NO_TLS_LAST"}.issubset(symbols):
        suspicious_signals.append("arc_reject_no_tls")
        signal_score += 2.3

    if {"SUBJECT_NEEDS_ENCODING", "MIME_HTML_ONLY"}.issubset(symbols) and rspamd.score >= 1.0:
        suspicious_signals.append("subject_encoding_mime_html")
        signal_score += 1.8

    if {"MIME_HTML_ONLY", "MANY_INVISIBLE_PARTS", "ZERO_FONT"}.issubset(symbols):
        suspicious_signals.append("mime_html_invisible_zero_font")
        signal_score += 2.1

    if {"MID_RHS_NOT_FQDN", "MISSING_MIME_VERSION"}.issubset(symbols) and rspamd.score >= 2.5:
        suspicious_signals.append("mid_rhs_not_fqdn_missing_mime_version")
        signal_score += 1.8

    if rspamd.score >= 2.0 and not dmarc_passed and "ARC_REJECT" in symbols and {"FORGED_SENDER", "FROM_NEQ_ENVFROM"} & symbols:
        suspicious_signals.append("multi_symbol_cluster")
        signal_score += 2.1

    for indicator in indicators:
        if indicator in suspicious_signals:
            continue
        weight = SUSPICIOUS_INDICATOR_WEIGHTS.get(indicator, SUSPICIOUS_INDICATOR_DEFAULT_WEIGHT)
        if weight <= 0:
            continue
        suspicious_signals.append(indicator)
        signal_score += weight

    if "subject_offer_pressure" in suspicious_signals and "subject_encoding_finance_offer" in suspicious_signals:
        signal_score += 0.8
    if "sender_display_domain_mismatch" in suspicious_signals and "MANY_INVISIBLE_PARTS" in symbols:
        suspicious_signals.append("sender_display_mismatch_invisible_content")
        signal_score += 1.0

    suspicious_signals = [signal for signal in suspicious_signals if signal]
    if not suspicious_signals:
        return None, [], 0.0

    if signal_score >= SUSPICIOUS_SIGNAL_THRESHOLD:
        if len(suspicious_signals) > 4:
            suspicious_signals = suspicious_signals[:4]
        return "suspicious_signals:" + "+".join(suspicious_signals), suspicious_signals, round(signal_score, 2)

    return None, [], 0.0


def local_phishing_indicators(rspamd, *, subject: str = "", sender: str = "", reply_to: str = "", link_domains: list[str] | None = None, body_excerpt: str = "") -> list[str]:
    indicators: list[str] = []
    symbols = set(rspamd.symbols)
    sender_name, _sender_address = _first_mailbox(sender)
    sender_domain = _address_domain(sender)
    reply_to_domain = _address_domain(reply_to)
    claim_text = " ".join([subject or "", sender_name or ""])
    has_institution_claim = bool(INSTITUTION_CLAIM_RE.search(claim_text))

    if _has_hidden_unicode_controls(subject):
        indicators.append("subject_hidden_unicode_controls")
    if _has_hidden_unicode_controls(sender):
        indicators.append("sender_hidden_unicode_controls")
    if _has_hidden_unicode_controls(body_excerpt):
        indicators.append("body_hidden_unicode_controls")
    if _has_obfuscated_subject_word(subject):
        indicators.append("subject_obfuscation")
    if _has_obfuscated_subject_word(sender_name):
        indicators.append("sender_obfuscation")
    if sender_domain in FREEMAIL_DOMAINS and has_institution_claim:
        indicators.append("freemail_sender_with_institution_claim")
    if sender_domain and reply_to_domain and not _domains_match(sender_domain, reply_to_domain) and rspamd.score >= 2.0:
        indicators.append("reply_to_domain_mismatch")
    if _subject_has_marketing_pressure(subject):
        indicators.append("subject_offer_pressure")
    if sender_domain and _sender_domain_looks_suspicious(sender_domain):
        indicators.append("sender_domain_suspicious")
    if _sender_display_name_mismatches_domain(sender_name, sender_domain):
        indicators.append("sender_display_domain_mismatch")
    if _display_name_impersonates_domain(sender_name, sender_domain):
        indicators.append("sender_display_name_impersonates_domain")
    if _subject_has_financial_offer(subject) and "SUBJECT_NEEDS_ENCODING" in symbols and "subject_encoding_finance_offer" not in indicators:
        indicators.append("subject_encoding_finance_offer")
    if has_institution_claim and sender_domain and link_domains:
        external_link_domains = [domain for domain in link_domains if not _domains_match(sender_domain, domain)]
        if external_link_domains:
            indicators.append("institution_claim_with_external_link_domain")
    if "MID_RHS_NOT_FQDN" in symbols:
        indicators.append("message_id_domain_not_fqdn")

    return list(dict.fromkeys(indicators))


def local_spam_reason(suspicious_indicators: list[str]) -> str | None:
    # A display name that names a different domain *and* hides invisible control characters
    # (e.g. "nor\u200feply@ba\u200fnk.example" <x@outlook.com>) is impersonation; legitimate senders do neither.
    if "sender_display_name_impersonates_domain" in suspicious_indicators and "sender_hidden_unicode_controls" in suspicious_indicators:
        return "sender display name impersonates another domain using hidden control characters"
    return None


def _display_name_impersonates_domain(sender_name: str, sender_domain: str) -> bool:
    if not sender_name or not sender_domain:
        return False
    visible_name = "".join(char for char in sender_name if unicodedata.category(char) != "Cf")
    claimed = [match.group(1).lower() for match in DISPLAY_NAME_DOMAIN_RE.finditer(visible_name)]
    return any(not _domains_match(domain, sender_domain) for domain in claimed)


def _subject_has_marketing_pressure(subject: str) -> bool:
    if not subject:
        return False
    return bool(
        MARKETING_PRESSURE_SUBJECT_RE.search(subject)
        and (CLICK_PRESSURE_SUBJECT_RE.search(subject) or PERCENT_OFF_RE.search(subject))
    )


def _subject_has_financial_offer(subject: str) -> bool:
    return bool(
        FINANCIAL_OFFER_SUBJECT_RE.search(subject)
        or (MARKETING_PRESSURE_SUBJECT_RE.search(subject) and PERCENT_OFF_RE.search(subject))
    )


def _sender_display_name_mismatches_domain(sender_name: str, sender_domain: str) -> bool:
    if not sender_name or not sender_domain:
        return False
    display_tokens = [token for token in re.findall(r"[a-zA-Z0-9]{4,}", sender_name.lower()) if not token.isdigit()]
    if len(display_tokens) < 2 and not re.search(r"[A-Za-z]{3,}\s*[-_]\s*[A-Za-z]{3,}", sender_name):
        return False
    domain_tokens = [token for token in re.findall(r"[a-zA-Z0-9]{4,}", sender_domain.lower()) if not token.isdigit()]
    if not domain_tokens:
        return False
    return not any(display in domain or domain in display for display in display_tokens for domain in domain_tokens)


def _sender_domain_looks_suspicious(domain: str) -> bool:
    labels = [token.strip("[]<>[]\"'") for token in domain.split(".") if token]
    if not labels:
        return False
    if len(labels) >= 2 and labels[-1].lower() in FREEMAIL_DOMAINS:
        return False

    for label in labels[:-1]:
        if _is_suspicious_label_token(label):
            return True
    return False


def _is_suspicious_label_token(label: str) -> bool:
    token = re.sub(r"[^a-zA-Z0-9]", "", label.lower())
    if len(token) <= 3:
        return False
    if not token:
        return False

    if token.isdigit():
        return True

    digit_count = sum(1 for char in token if char.isdigit())
    digit_ratio = digit_count / len(token)
    if digit_ratio >= 0.45 and len(token) >= 8:
        return True
    if 6 <= len(token) <= 8 and digit_count >= 1 and digit_ratio >= 0.15:
        return True
    if re.search(r"^[a-z]{1,2}\d{3,}$", token):
        return True
    if re.search(r"^\d{3,}[a-z]{1,2}$", token):
        return True
    if len(token) <= 5 and any(char.isdigit() for char in token):
        return True
    entropy = _token_entropy(token)
    return entropy >= 3.45 and len(token) >= 9


def _token_entropy(token: str) -> float:
    if not token:
        return 0.0
    total = len(token)
    freq: dict[str, int] = {}
    for char in token:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    for count in freq.values():
        ratio = count / total
        entropy += -(ratio * (math.log2(ratio)))
    return entropy


def _has_obfuscated_subject_word(subject: str) -> bool:
    return bool(OBFUSCATED_WORD_RE.search(subject or ""))


def _has_hidden_unicode_controls(value: str) -> bool:
    return any(unicodedata.category(char) == "Cf" for char in value or "")


def _first_mailbox(value: str) -> tuple[str, str]:
    for name, address in getaddresses([value or ""]):
        if name or address:
            return str(name or ""), str(address or "")
    return "", ""


def _address_domain(value: str) -> str:
    _name, address = _first_mailbox(value)
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].strip().strip(">.").lower()


def _domains_match(left: str, right: str) -> bool:
    left = left.lower().removeprefix("www.")
    right = right.lower().removeprefix("www.")
    return left == right or left.endswith(f".{right}") or right.endswith(f".{left}")


def _top_rspamd_symbols(symbols: dict, limit: int = 8) -> list[dict]:
    rows = []
    for name, value in symbols.items():
        score = 0.0
        description = ""
        options = []
        if isinstance(value, dict):
            try:
                score = float(value.get("score", 0.0) or 0.0)
            except (TypeError, ValueError):
                score = 0.0
            description = str(value.get("description", "") or "")
            raw_options = value.get("options", []) or []
            if isinstance(raw_options, list):
                options = [str(option) for option in raw_options[:4]]
        rows.append({"name": str(name), "score": score, "description": description, "options": options})
    return sorted(rows, key=lambda row: abs(row["score"]), reverse=True)[:limit]


def delete_expired_quarantine(session: Session, client, mailbox: MailboxSettings) -> int:
    if not mailbox.auto_delete_enabled:
        return 0
    cutoff = now_utc() - timedelta(days=mailbox.auto_delete_after_days)
    folders = [mailbox.quarantine_folder]
    records = session.scalars(
        select(MessageRecord).where(
            MessageRecord.status.in_(["quarantined", "confirmed_spam"]),
            MessageRecord.quarantined_at.is_not(None),
            MessageRecord.quarantined_at < cutoff,
            MessageRecord.deleted_at.is_(None),
        )
    ).all()
    deleted = 0
    for record in records:
        if not record.message_id:
            continue
        removed = imap_client.delete_by_message_id_anywhere(client, folders, record.message_id)
        if removed:
            record.status = "deleted"
            record.deleted_at = now_utc()
            record.updated_at = now_utc()
            session.add(AuditEvent(message_id=record.id, event_type="message_auto_deleted", details={"removed": removed}))
            deleted += removed
    session.commit()
    return deleted


def prune_scan_audit_events(session: Session) -> int:
    cutoff = now_utc() - timedelta(days=SCAN_AUDIT_RETENTION_DAYS)
    result = session.execute(delete(AuditEvent).where(AuditEvent.message_id.is_(None), AuditEvent.created_at < cutoff))
    session.commit()
    return result.rowcount or 0


async def worker_loop(session_factory) -> None:
    while True:
        with session_factory() as session:
            mailbox = get_or_create_mailbox_settings(session)
            try:
                await scan_once(session)
            except Exception:
                session.rollback()
                logger.exception("Scheduled scan failed.")
            try:
                prune_scan_audit_events(session)
            except Exception:
                session.rollback()
                logger.exception("Pruning old audit events failed.")
            sleep_for = max(60, mailbox.poll_interval_seconds)
        await asyncio.sleep(sleep_for)
