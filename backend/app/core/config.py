from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


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


settings = Settings()
