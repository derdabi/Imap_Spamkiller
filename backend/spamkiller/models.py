from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


class MailboxSettings(Base):
    __tablename__ = "mailbox_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    provider: Mapped[str] = mapped_column(String(80), default="t-online")
    email: Mapped[str] = mapped_column(String(320), default="")
    imap_host: Mapped[str] = mapped_column(String(255), default="secureimap.t-online.de")
    imap_port: Mapped[int] = mapped_column(Integer, default=993)
    imap_username: Mapped[str] = mapped_column(String(320), default="")
    encrypted_password: Mapped[str | None] = mapped_column(Text, nullable=True)
    inbox_folder: Mapped[str] = mapped_column(String(255), default="INBOX")
    quarantine_folder: Mapped[str] = mapped_column(String(255), default="SpamKiller/Quarantine")
    poll_interval_seconds: Mapped[int] = mapped_column(Integer, default=300)
    auto_delete_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    auto_delete_after_days: Mapped[int] = mapped_column(Integer, default=15)
    spam_score_threshold: Mapped[float] = mapped_column(Float, default=6.0)
    uncertain_score_threshold: Mapped[float] = mapped_column(Float, default=4.0)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class LlmSettings(Base):
    __tablename__ = "llm_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    provider: Mapped[str] = mapped_column(String(40), default="off")
    model: Mapped[str] = mapped_column(String(120), default="")
    encrypted_api_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    send_body_excerpt: Mapped[bool] = mapped_column(Boolean, default=True)
    max_excerpt_chars: Mapped[int] = mapped_column(Integer, default=12000)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class MessageRecord(Base):
    __tablename__ = "messages"
    __table_args__ = (UniqueConstraint("source_folder", "source_uid", name="uq_source_message"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_folder: Mapped[str] = mapped_column(String(255))
    source_uid: Mapped[str] = mapped_column(String(80))
    message_id: Mapped[str | None] = mapped_column(String(998), nullable=True, index=True)
    sender: Mapped[str] = mapped_column(String(998), default="")
    subject: Mapped[str] = mapped_column(String(998), default="")
    received_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(40), default="scanned")
    final_verdict: Mapped[str] = mapped_column(String(40), default="clean")
    explanation: Mapped[str] = mapped_column(Text, default="")
    quarantined_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)

    scan_results: Mapped[list["ScanResult"]] = relationship(back_populates="message")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    message_id: Mapped[int] = mapped_column(ForeignKey("messages.id"))
    rspamd_score: Mapped[float] = mapped_column(Float, default=0.0)
    rspamd_action: Mapped[str] = mapped_column(String(80), default="no action")
    rspamd_symbols: Mapped[dict] = mapped_column(JSON, default=dict)
    llm_provider: Mapped[str] = mapped_column(String(40), default="off")
    llm_verdict: Mapped[str] = mapped_column(String(40), default="skipped")
    llm_confidence: Mapped[float] = mapped_column(Float, default=0.0)
    final_verdict: Mapped[str] = mapped_column(String(40), default="clean")
    explanation: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)

    message: Mapped[MessageRecord] = relationship(back_populates="scan_results")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    message_id: Mapped[int | None] = mapped_column(ForeignKey("messages.id"), nullable=True)
    event_type: Mapped[str] = mapped_column(String(80))
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
