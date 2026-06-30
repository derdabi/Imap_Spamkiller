import secrets
from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_secret: str | None = None
    data_dir: Path = Path("/data")
    database_url: str | None = None
    rspamd_url: str = "http://rspamd:11333"
    rspamd_settings_id: str | None = None
    static_dir: Path = Path("/app/static")
    scan_batch_size: int = 50
    cors_allow_origins: str = "http://127.0.0.1:5173,http://localhost:5173"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    @field_validator("app_secret", mode="before")
    @classmethod
    def blank_secret_is_unset(cls, value: str | None) -> str | None:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("rspamd_settings_id", mode="before")
    @classmethod
    def blank_rspamd_settings_id_is_unset(cls, value: str | None) -> str | None:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @property
    def resolved_database_url(self) -> str:
        if self.database_url:
            return self.database_url
        return f"sqlite:///{self.data_dir / 'spamkiller.db'}"

    @property
    def encryption_secret(self) -> str:
        if self.app_secret:
            return self.app_secret
        return _read_or_create_secret(self.data_dir / "app_secret")

    @property
    def parsed_cors_allow_origins(self) -> list[str]:
        return [origin for origin in (item.strip() for item in self.cors_allow_origins.split(",")) if origin and origin != "*"]


def _read_or_create_secret(path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        secret = path.read_text(encoding="utf-8").strip()
        if secret:
            return secret
    except FileNotFoundError:
        pass

    generated = secrets.token_urlsafe(48)
    try:
        with path.open("x", encoding="utf-8") as file:
            file.write(generated + "\n")
        try:
            path.chmod(0o600)
        except OSError:
            pass
        return generated
    except FileExistsError:
        return path.read_text(encoding="utf-8").strip()


@lru_cache
def get_settings() -> Settings:
    return Settings()
