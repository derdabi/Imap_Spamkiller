from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import desc, select
from sqlalchemy.orm import Session, selectinload

from . import imap_client
from .config import get_settings
from .crypto import can_decrypt_secret, encrypt_secret
from .database import get_session, init_db
from .llm import list_llm_models as fetch_llm_models, test_llm_connection
from .models import AuditEvent, LlmSettings, MailboxSettings, MessageRecord, now_utc
from .scanner import exception_message, get_or_create_llm_settings, get_or_create_mailbox_settings, local_phishing_indicators, scan_once
from .rspamd import RspamdResult
from .schemas import (
    AuditEventRead,
    ConnectionTestResult,
    MessageInboxRead,
    MessageScanResultRead,
    LlmModelsResult,
    LlmSettingsRead,
    LlmTestResult,
    LlmSettingsUpdate,
    MailboxSettingsRead,
    MailboxSettingsUpdate,
    MessageRead,
)


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(title="IMAP SpamKiller", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().parsed_cors_allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.get("/api/health")
def health() -> dict:
    return {"ok": True}


@app.get("/api/settings/mailbox", response_model=MailboxSettingsRead)
def read_mailbox_settings(session: Session = Depends(get_session)) -> MailboxSettingsRead:
    settings = get_or_create_mailbox_settings(session)
    return _mailbox_read(settings)


@app.put("/api/settings/mailbox", response_model=MailboxSettingsRead)
def update_mailbox_settings(payload: MailboxSettingsUpdate, session: Session = Depends(get_session)) -> MailboxSettingsRead:
    settings = get_or_create_mailbox_settings(session)
    if settings.encrypted_password and not payload.password and _imap_identity_changed(settings, payload):
        raise HTTPException(status_code=400, detail="Enter the mailbox password when changing IMAP host, port, username, or email.")
    settings.provider = payload.provider
    settings.email = str(payload.email)
    settings.imap_host = payload.imap_host
    settings.imap_port = payload.imap_port
    settings.imap_username = payload.imap_username or str(payload.email)
    if payload.password:
        settings.encrypted_password = encrypt_secret(payload.password)
    settings.inbox_folder = payload.inbox_folder
    settings.quarantine_folder = payload.quarantine_folder
    settings.poll_interval_seconds = payload.poll_interval_seconds
    settings.auto_delete_enabled = payload.auto_delete_enabled
    settings.auto_delete_after_days = payload.auto_delete_after_days
    settings.spam_score_threshold = payload.spam_score_threshold
    settings.uncertain_score_threshold = payload.uncertain_score_threshold
    settings.enabled = payload.enabled
    settings.updated_at = now_utc()
    session.commit()
    session.refresh(settings)
    return _mailbox_read(settings)


@app.post("/api/settings/mailbox/test", response_model=ConnectionTestResult)
def test_mailbox_connection(payload: MailboxSettingsUpdate, session: Session = Depends(get_session)) -> ConnectionTestResult:
    current = get_or_create_mailbox_settings(session)
    saved_password = _saved_password_for_payload(current, payload)
    settings = MailboxSettings(
        email=str(payload.email),
        imap_host=payload.imap_host,
        imap_port=payload.imap_port,
        imap_username=payload.imap_username or str(payload.email),
        encrypted_password=encrypt_secret(payload.password) if payload.password else saved_password,
    )
    client = None
    try:
        client = imap_client.connect(settings)
        return ConnectionTestResult(ok=True, message="Connection succeeded.")
    except Exception as exc:
        return ConnectionTestResult(ok=False, message=str(exc))
    finally:
        imap_client.logout_quietly(client)


@app.post("/api/settings/mailbox/folders", response_model=list[str])
def list_mailbox_folders(payload: MailboxSettingsUpdate, session: Session = Depends(get_session)) -> list[str]:
    current = get_or_create_mailbox_settings(session)
    saved_password = _saved_password_for_payload(current, payload)
    settings = MailboxSettings(
        email=str(payload.email),
        imap_host=payload.imap_host,
        imap_port=payload.imap_port,
        imap_username=payload.imap_username or str(payload.email),
        encrypted_password=encrypt_secret(payload.password) if payload.password else saved_password,
    )
    client = None
    try:
        client = imap_client.connect(settings)
        return imap_client.list_folders(client)
    finally:
        imap_client.logout_quietly(client)


@app.get("/api/settings/llm", response_model=LlmSettingsRead)
def read_llm_settings(session: Session = Depends(get_session)) -> LlmSettingsRead:
    settings = get_or_create_llm_settings(session)
    return _llm_read(settings)


@app.put("/api/settings/llm", response_model=LlmSettingsRead)
def update_llm_settings(payload: LlmSettingsUpdate, session: Session = Depends(get_session)) -> LlmSettingsRead:
    settings = get_or_create_llm_settings(session)
    settings.provider = payload.provider
    settings.model = payload.model
    settings.enabled = payload.provider != "off"
    settings.send_body_excerpt = payload.send_body_excerpt
    settings.max_excerpt_chars = payload.max_excerpt_chars
    if payload.api_key:
        settings.encrypted_api_key = encrypt_secret(payload.api_key)
    settings.updated_at = now_utc()
    session.commit()
    session.refresh(settings)
    return _llm_read(settings)


@app.post("/api/settings/credentials/reset")
def reset_saved_credentials(session: Session = Depends(get_session)) -> dict:
    mailbox = get_or_create_mailbox_settings(session)
    llm = get_or_create_llm_settings(session)
    mailbox.encrypted_password = None
    mailbox.enabled = False
    mailbox.updated_at = now_utc()
    llm.encrypted_api_key = None
    llm.enabled = False
    llm.updated_at = now_utc()
    session.commit()
    return {"ok": True, "message": "Saved credentials cleared. Re-enter your mailbox password and API key if needed."}


@app.post("/api/settings/llm/test", response_model=LlmTestResult)
async def test_llm(payload: LlmSettingsUpdate, session: Session = Depends(get_session)) -> LlmTestResult:
    current = get_or_create_llm_settings(session)
    settings = LlmSettings(
        provider=payload.provider,
        model=payload.model,
        enabled=payload.enabled and payload.provider != "off",
        encrypted_api_key=encrypt_secret(payload.api_key) if payload.api_key else current.encrypted_api_key,
    )
    try:
        await test_llm_connection(settings)
        return LlmTestResult(ok=True, message="LLM connection succeeded.")
    except Exception as exc:
        return LlmTestResult(ok=False, message=str(exc))


@app.post("/api/settings/llm/models", response_model=LlmModelsResult)
async def list_llm_models(payload: LlmSettingsUpdate, session: Session = Depends(get_session)) -> LlmModelsResult:
    current = get_or_create_llm_settings(session)
    settings = LlmSettings(
        provider=payload.provider,
        model=payload.model,
        enabled=payload.enabled and payload.provider != "off",
        encrypted_api_key=encrypt_secret(payload.api_key) if payload.api_key else current.encrypted_api_key,
    )
    try:
        models = await fetch_llm_models(settings)
        return LlmModelsResult(ok=True, models=models, message=f"Loaded {len(models)} models.")
    except Exception as exc:
        return LlmModelsResult(ok=False, models=[], message=str(exc))


@app.post("/api/scan/run")
async def run_scan(session: Session = Depends(get_session)) -> dict:
    try:
        return await scan_once(session, trigger="manual")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=exception_message(exc)) from exc


@app.post("/api/scan/reevaluate")
async def reevaluate_scan(session: Session = Depends(get_session)) -> dict:
    try:
        return await scan_once(session, trigger="reevaluate", reevaluate_existing=True, scan_all=True)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=exception_message(exc)) from exc


@app.get("/api/messages/quarantine", response_model=list[MessageRead])
def quarantine(session: Session = Depends(get_session)) -> list[MessageRead]:
    rows = session.scalars(
        select(MessageRecord)
        .where(MessageRecord.status.in_(["quarantined", "restore_failed"]))
        .order_by(desc(MessageRecord.quarantined_at))
    ).all()
    return [_message_read(row) for row in rows]


@app.get("/api/messages/inbox", response_model=list[MessageInboxRead])
def inbox(session: Session = Depends(get_session)) -> list[MessageInboxRead]:
    mailbox = get_or_create_mailbox_settings(session)
    if not mailbox.enabled or not mailbox.encrypted_password or not can_decrypt_secret(mailbox.encrypted_password):
        return []

    client = None
    try:
        client = imap_client.connect(mailbox)
        uidvalidity, uids, _message_count = imap_client.list_recent_uids(client, mailbox.inbox_folder, None)
    finally:
        imap_client.logout_quietly(client)

    current_source_uids = [f"{uidvalidity}:{uid}" for uid in uids]
    if not current_source_uids:
        return []

    rows = (
        session.scalars(
            select(MessageRecord)
            .options(selectinload(MessageRecord.scan_results))
            .where(
                MessageRecord.source_folder == mailbox.inbox_folder,
                MessageRecord.source_uid.in_(current_source_uids),
            )
            .order_by(desc(MessageRecord.updated_at))
            .limit(200)
        )
        .all()
    )
    return [_message_inbox_read(row) for row in rows]


@app.post("/api/messages/{message_id}/restore")
def restore_message(message_id: int, session: Session = Depends(get_session)) -> dict:
    mailbox = get_or_create_mailbox_settings(session)
    record = session.get(MessageRecord, message_id)
    if not record or record.status not in {"quarantined", "restore_failed"}:
        raise HTTPException(status_code=404, detail="Quarantined message not found.")
    if not record.message_id:
        raise HTTPException(status_code=409, detail="Cannot restore a message without Message-ID.")
    client = None
    try:
        client = imap_client.connect(mailbox)
        folders = [mailbox.quarantine_folder]
        try:
            folders.extend(folder for folder in imap_client.list_folders(client) if folder not in folders)
        except Exception:
            pass
        moved = imap_client.move_by_message_id_anywhere(client, folders, record.message_id, mailbox.inbox_folder)
        if moved:
            _refresh_restored_message_source(session, client, mailbox, record)
    finally:
        imap_client.logout_quietly(client)
    record.status = "restored" if moved else "restore_failed"
    record.updated_at = now_utc()
    session.add(AuditEvent(message_id=record.id, event_type="message_restored", details={"moved": moved}))
    session.commit()
    return {"restored": moved}


@app.post("/api/messages/{message_id}/confirm-spam")
def confirm_spam(message_id: int, session: Session = Depends(get_session)) -> dict:
    record = session.get(MessageRecord, message_id)
    if not record:
        raise HTTPException(status_code=404, detail="Message not found.")

    previous_status = record.status

    if record.status == "confirmed_spam":
        return {"ok": True}

    if record.status != "quarantined":
        if not record.message_id:
            raise HTTPException(status_code=409, detail="Cannot confirm a message without Message-ID.")

        mailbox = get_or_create_mailbox_settings(session)
        client = None
        folders = [mailbox.quarantine_folder]

        try:
            client = imap_client.connect(mailbox)
            try:
                folders.extend(folder for folder in imap_client.list_folders(client) if folder not in folders)
            except Exception:
                pass
            moved = imap_client.move_by_message_id_anywhere(client, folders, record.message_id, mailbox.quarantine_folder)
        finally:
            imap_client.logout_quietly(client)

        if not moved:
            raise HTTPException(status_code=409, detail="Could not move message to quarantine.")

    record.status = "confirmed_spam"
    record.updated_at = now_utc()
    if previous_status != "quarantined" or record.quarantined_at is None:
        record.quarantined_at = record.updated_at
    record.deleted_at = None

    session.add(AuditEvent(message_id=record.id, event_type="message_confirmed_spam", details={"previous_status": previous_status}))
    session.commit()
    return {"ok": True}


def _refresh_restored_message_source(session: Session, client, mailbox: MailboxSettings, record: MessageRecord) -> None:
    if not record.message_id:
        return

    try:
        uidvalidity, uids = imap_client.locate_message_id_in_folder(client, mailbox.inbox_folder, record.message_id)
    except Exception:
        return
    if not uids:
        return

    source_uid = f"{uidvalidity}:{uids[-1]}"
    existing = session.scalar(
        select(MessageRecord).where(
            MessageRecord.source_folder == mailbox.inbox_folder,
            MessageRecord.source_uid == source_uid,
            MessageRecord.id != record.id,
        )
    )
    if existing:
        return

    record.source_folder = mailbox.inbox_folder
    record.source_uid = source_uid
    record.quarantined_at = None


@app.get("/api/audit", response_model=list[AuditEventRead])
def audit_events(session: Session = Depends(get_session)) -> list[AuditEventRead]:
    rows = session.scalars(select(AuditEvent).order_by(desc(AuditEvent.created_at)).limit(100)).all()
    return [AuditEventRead(id=row.id, event_type=row.event_type, details=row.details, created_at=_utc_datetime(row.created_at)) for row in rows]


def _mailbox_read(settings: MailboxSettings) -> MailboxSettingsRead:
    password_unreadable = bool(settings.encrypted_password) and not can_decrypt_secret(settings.encrypted_password)
    return MailboxSettingsRead(
        provider=settings.provider,
        email=settings.email,
        imap_host=settings.imap_host,
        imap_port=settings.imap_port,
        imap_username=settings.imap_username,
        inbox_folder=settings.inbox_folder,
        quarantine_folder=settings.quarantine_folder,
        poll_interval_seconds=settings.poll_interval_seconds,
        auto_delete_enabled=settings.auto_delete_enabled,
        auto_delete_after_days=settings.auto_delete_after_days,
        spam_score_threshold=settings.spam_score_threshold,
        uncertain_score_threshold=settings.uncertain_score_threshold,
        enabled=settings.enabled,
        has_password=bool(settings.encrypted_password),
        password_unreadable=password_unreadable,
    )


def _llm_read(settings: LlmSettings) -> LlmSettingsRead:
    api_key_unreadable = bool(settings.encrypted_api_key) and not can_decrypt_secret(settings.encrypted_api_key)
    return LlmSettingsRead(
        provider=settings.provider,
        model=settings.model,
        enabled=settings.enabled,
        send_body_excerpt=settings.send_body_excerpt,
        max_excerpt_chars=settings.max_excerpt_chars,
        has_api_key=bool(settings.encrypted_api_key),
        api_key_unreadable=api_key_unreadable,
    )


def _saved_password_for_payload(current: MailboxSettings, payload: MailboxSettingsUpdate) -> str | None:
    if payload.password:
        return None
    if current.encrypted_password and _imap_identity_changed(current, payload):
        raise HTTPException(status_code=400, detail="Enter the mailbox password when changing IMAP host, port, username, or email.")
    return current.encrypted_password


def _imap_identity_changed(current: MailboxSettings, payload: MailboxSettingsUpdate) -> bool:
    return (
        current.email != str(payload.email)
        or current.imap_host != payload.imap_host
        or current.imap_port != payload.imap_port
        or _effective_imap_username(current) != (payload.imap_username or str(payload.email))
    )


def _effective_imap_username(settings: MailboxSettings) -> str:
    return settings.imap_username or settings.email


def _message_read(row: MessageRecord) -> MessageRead:
    return MessageRead(
        id=row.id,
        sender=row.sender,
        subject=row.subject,
        received_at=_utc_datetime(row.received_at),
        final_verdict=row.final_verdict,
        explanation=row.explanation,
        quarantined_at=_utc_datetime(row.quarantined_at),
    )


def _message_inbox_read(row: MessageRecord) -> MessageInboxRead:
    return MessageInboxRead(
        id=row.id,
        sender=row.sender,
        subject=row.subject,
        received_at=_utc_datetime(row.received_at),
        source_folder=row.source_folder,
        status=row.status,
        final_verdict=row.final_verdict,
        explanation=row.explanation,
        analysis=_message_scan_result(row),
    )


def _message_scan_result(row: MessageRecord) -> MessageScanResultRead | None:
    if not row.scan_results:
        return None

    latest = max(row.scan_results, key=lambda result: result.created_at)
    return MessageScanResultRead(
        rspamd_score=latest.rspamd_score,
        rspamd_action=latest.rspamd_action,
        rspamd_symbols=_scan_symbol_names(latest.rspamd_symbols),
        suspicious_indicators=local_phishing_indicators(
            RspamdResult(latest.rspamd_score, latest.rspamd_action, latest.rspamd_symbols or {}),
            subject=row.subject,
            sender=row.sender,
        ),
        llm_provider=latest.llm_provider,
        llm_verdict=latest.llm_verdict,
        llm_confidence=latest.llm_confidence,
    )


def _scan_symbol_names(value: object) -> list[str]:
    if isinstance(value, dict):
        return [str(symbol) for symbol in list(value.keys())[:8]]
    if isinstance(value, list):
        return [str(symbol) for symbol in value[:8]]
    return []


def _utc_datetime(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


static_dir = get_settings().static_dir
if static_dir.exists():
    app.mount("/assets", StaticFiles(directory=static_dir / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def frontend(path: str = ""):
        return FileResponse(static_dir / "index.html", headers={"Cache-Control": "no-store"})
