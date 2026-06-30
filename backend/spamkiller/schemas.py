from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, model_validator


class MailboxSettingsRead(BaseModel):
    provider: str
    email: str
    imap_host: str
    imap_port: int
    imap_username: str
    inbox_folder: str
    quarantine_folder: str
    poll_interval_seconds: int
    auto_delete_enabled: bool
    auto_delete_after_days: int
    spam_score_threshold: float
    uncertain_score_threshold: float
    enabled: bool
    has_password: bool
    password_unreadable: bool = False


class MailboxSettingsUpdate(BaseModel):
    provider: str = "t-online"
    email: EmailStr | str = ""
    imap_host: str = "secureimap.t-online.de"
    imap_port: int = Field(default=993, ge=1, le=65535)
    imap_username: str = ""
    password: str | None = None
    inbox_folder: str = "INBOX"
    quarantine_folder: str = "SpamKiller/Quarantine"
    poll_interval_seconds: int = Field(default=300, ge=60, le=86400)
    auto_delete_enabled: bool = True
    auto_delete_after_days: int = Field(default=15, ge=1, le=365)
    spam_score_threshold: float = Field(default=6.0, ge=1.0, le=30.0)
    uncertain_score_threshold: float = Field(default=4.0, ge=0.0, le=30.0)
    enabled: bool = False

    @model_validator(mode="after")
    def validate_threshold_order(self) -> "MailboxSettingsUpdate":
        if self.uncertain_score_threshold > self.spam_score_threshold:
            raise ValueError("uncertain_score_threshold must be less than or equal to spam_score_threshold")
        return self


class LlmSettingsRead(BaseModel):
    provider: str
    model: str
    enabled: bool
    send_body_excerpt: bool
    max_excerpt_chars: int
    has_api_key: bool
    api_key_unreadable: bool = False


class LlmSettingsUpdate(BaseModel):
    provider: str = Field(default="off", pattern="^(off|openai|anthropic)$")
    model: str = ""
    api_key: str | None = None
    enabled: bool = False
    send_body_excerpt: bool = True
    max_excerpt_chars: int = Field(default=12000, ge=200, le=12000)


class ConnectionTestResult(BaseModel):
    ok: bool
    message: str


class LlmTestResult(BaseModel):
    ok: bool
    message: str


class LlmModelsResult(BaseModel):
    ok: bool
    models: list[str]
    message: str


class MessageRead(BaseModel):
    id: int
    sender: str
    subject: str
    received_at: datetime | None
    final_verdict: str
    explanation: str
    quarantined_at: datetime | None


class MessageScanResultRead(BaseModel):
    rspamd_score: float
    rspamd_action: str
    rspamd_symbols: list[str] = Field(default_factory=list)
    suspicious_indicators: list[str] = Field(default_factory=list)
    llm_provider: str
    llm_verdict: str
    llm_confidence: float


class MessageInboxRead(BaseModel):
    id: int
    sender: str
    subject: str
    received_at: datetime | None
    source_folder: str
    status: str
    final_verdict: str
    explanation: str
    analysis: MessageScanResultRead | None = None


class AuditEventRead(BaseModel):
    id: int
    event_type: str
    details: dict
    created_at: datetime
