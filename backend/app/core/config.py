from __future__ import annotations

from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})

_MAX_SESSION_LIFETIME_SECONDS = 14 * 24 * 60 * 60


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "LoonInspect"
    debug: bool = False

    database_url: str = "sqlite+aiosqlite:///./looninspect.db"

    cors_origins: list[str] = ["http://localhost:5173"]

    encryption_key: str | None = None

    siem_webhook_url: str | None = None

    user_agent_product_name: str = "LoonSecIO"

    scheduler_enabled: bool = True
    sync_hour: int = 1
    sync_minute: int = 0
    sync_timezone: str = "America/Chicago"

    log_level: str = "INFO"
    # "auto" resolves to console locally and JSON in a container — see
    # resolved_log_format. Set explicitly to override either way.
    log_format: Literal["auto", "json", "console"] = "auto"

    # Sliding idle timeout: refreshed on each authenticated request, so this is time
    # since last activity rather than time since login. 0 disables idle expiry
    # entirely; any other value must be between 60s and 14 days.
    session_lifetime_seconds: int = 3600

    # Optional non-interactive bootstrap for automated deployments. When both are set,
    # the first-run claim flow is skipped and this admin is created at startup.
    initial_admin_email: str | None = None
    initial_admin_password: str | None = None

    # Relative on purpose. The container's WORKDIR is /app and the data volume mounts
    # at /app/data, so this resolves onto the volume with no env var needed — which
    # matters, because audit written anywhere else is destroyed on the next
    # `docker compose up --build`.
    audit_log_path: str = "./data/audit/audit.jsonl"
    audit_retention_days: int = 30

    @field_validator("log_level")
    @classmethod
    def _normalize_log_level(cls, value: str) -> str:
        normalized = value.strip().upper()
        if normalized not in _LOG_LEVELS:
            raise ValueError(f"log_level must be one of {sorted(_LOG_LEVELS)}, got {value!r}")
        return normalized

    @field_validator("audit_retention_days")
    @classmethod
    def _validate_audit_retention(cls, value: int) -> int:
        if 1 <= value <= 3650:
            return value
        raise ValueError("audit_retention_days must be between 1 and 3650")

    @field_validator("session_lifetime_seconds")
    @classmethod
    def _validate_session_lifetime(cls, value: int) -> int:
        if value == 0 or 60 <= value <= _MAX_SESSION_LIFETIME_SECONDS:
            return value
        raise ValueError(
            "session_lifetime_seconds must be 0 (never idle out) or between 60 and "
            f"{_MAX_SESSION_LIFETIME_SECONDS} (14 days)"
        )

    @property
    def secure_cookies(self) -> bool:
        return not self.debug

    @property
    def resolved_log_format(self) -> str:
        if self.log_format != "auto":
            return self.log_format
        return "console" if self.debug else "json"


settings = Settings()
