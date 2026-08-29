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

    # Postgres only. The default targets a locally-run database on the conventional
    # port so `alembic` and a bare `uvicorn` work without env plumbing; docker compose
    # supplies the real one. There is no embedded file database to fall back to any
    # more — row-level security, the run mutex, and a queryable run log are all things
    # SQLite cannot express, which is why it was retired rather than kept as an option.
    database_url: str = "postgresql+asyncpg://looninspect_app@localhost:5432/looninspect"

    # bundled   the Postgres service shipped alongside the app in docker-compose.yml.
    # external  an operator-run database. Stubbed deliberately: the seam is named here
    #           so the choice is explicit in configuration rather than inferred from
    #           whatever DATABASE_URL happens to point at, but v0 ships the bundled
    #           service only and startup refuses the other value rather than half
    #           supporting it. See #29.
    database_mode: Literal["bundled", "external"] = "bundled"

    cors_origins: list[str] = ["http://localhost:5173"]

    encryption_key: str | None = None

    # Legacy, single-destination path. Read once at first boot to auto-create an
    # equivalent Destination row if none exist yet (see bootstrap.migrate_legacy_siem_
    # webhook) — the `destinations` table is the source of truth for everything after
    # that, including this one. Kept as a setting rather than removed so that
    # migration path keeps working for anyone upgrading with it already set.
    siem_webhook_url: str | None = None

    event_outbox_retention_days: int = 7

    # How long a run may go without a heartbeat before the next acquirer reclaims it as
    # dead. The floor is a device that takes longer than this to process: the sweep beats
    # every 15s between devices, so five minutes is twenty missed beats, not a slow one.
    # Too low steals the lock from a healthy run; too high is how long a connection stays
    # unsyncable after a hard kill.
    run_stale_after_seconds: int = 300

    # Follows audit (30) rather than the outbox (7): the run log is what someone opens to
    # answer "did this run last month", and it is one row per run plus engine lines, not
    # a row per event per destination. See app.core.runs.purge_runs.
    run_retention_days: int = 30

    # How many device failures one sweep may absorb before the whole run is failed:
    # the larger of the absolute floor and this percentage of the devices attempted so
    # far (app.mdm.service.sweep_failures_allowed, #92). The floor keeps a small fleet
    # from failing over a handful of bad devices — 1% of 200 devices is 2 — and the
    # percentage keeps 25 from reading as an outage threshold on 40,000. Settings
    # rather than constants on least-regret grounds: if either default turns out wrong
    # for a fleet, the operator corrects it with one env var instead of waiting for a
    # release.
    sweep_failure_max_absolute: int = 25
    sweep_failure_max_percent: float = 1.0

    user_agent_product_name: str = "LoonSecIO"

    # Where the daily exchange posts. The default is the production collector; tests
    # and the future api.loonsec.io consolidation point it elsewhere.
    sharing_endpoint: str = "https://api.loonsec.io/v1/exchange"

    # Hard kill switch for community data sharing (docs/data-sharing.md), for fleet
    # and air-gapped deployments: false wins over any tier stored in the database,
    # and the UI shows the override as the reason the control is locked.
    community_sharing: bool = True

    # Daily check against main's HEAD so the UI can say a newer build exists.
    # UPDATE_CHECK=false turns the outbound call off entirely (see issue #43).
    update_check: bool = True
    # Where that check asks. Empty means the default provider (GitHub's commits API);
    # the api.loonsec.io flip (#43) and tests point this elsewhere. The response just
    # needs a JSON body with a "sha" key.
    update_check_url: str = ""

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

    # A template, not a literal path: the tenant is inserted as a directory above the
    # filename, so this becomes ./data/audit/<tenant-id>/audit.jsonl, with a `system`
    # directory for records belonging to no tenant. See app.core.audit.audit_path_for.
    #
    # Relative on purpose. The container's WORKDIR is /app and the data volume mounts
    # at /app/data, so this resolves onto the volume with no env var needed — which
    # matters, because audit written anywhere else is destroyed on the next
    # `docker compose up --build`.
    audit_log_path: str = "./data/audit/audit.jsonl"
    audit_retention_days: int = 30

    host: str = "0.0.0.0"
    port: int = 8001

    # off          plain HTTP (default — unchanged behaviour)
    # self-signed  generate a certificate on first boot and persist it
    # provided     serve from a mounted certificate and key
    tls_mode: Literal["off", "self-signed", "provided"] = "off"
    tls_cert_path: str = "./data/certs/server.crt"
    tls_key_path: str = "./data/certs/server.key"
    tls_hostname: str = "localhost"

    # Which peer addresses may set X-Forwarded-For/-Proto. Defaults to uvicorn's own
    # default of localhost only: trusting an arbitrary peer's forwarded headers lets
    # anyone who can reach the port forge the client IP recorded in the audit log.
    # Behind a reverse proxy, set this to the proxy's address.
    forwarded_allow_ips: str = "127.0.0.1"

    # Marks the session cookie Secure. On by default because the alternative fails
    # silently in the dangerous direction. Browsers refuse Secure cookies over plain
    # HTTP everywhere except localhost, so turn this off *only* for a deliberate
    # plain-HTTP deployment — see the startup warning in app.serve.
    secure_cookies: bool = True

    @field_validator("database_url")
    @classmethod
    def _require_asyncpg(cls, value: str) -> str:
        if value.startswith("postgresql+asyncpg://"):
            return value
        raise ValueError(
            "database_url must be a postgresql+asyncpg:// URL. SQLite is no longer "
            f"supported (see #29); got {value.split('://', 1)[0]!r}"
        )

    @field_validator("database_mode")
    @classmethod
    def _reject_external_database(cls, value: str) -> str:
        if value == "bundled":
            return value
        raise ValueError(
            "database_mode='external' is not supported in v0 — only the Postgres "
            "service bundled in docker-compose.yml is shipped. Leave this at 'bundled'."
        )

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

    @field_validator("event_outbox_retention_days")
    @classmethod
    def _validate_outbox_retention(cls, value: int) -> int:
        if 1 <= value <= 3650:
            return value
        raise ValueError("event_outbox_retention_days must be between 1 and 3650")

    @field_validator("run_retention_days")
    @classmethod
    def _validate_run_retention(cls, value: int) -> int:
        if 1 <= value <= 3650:
            return value
        raise ValueError("run_retention_days must be between 1 and 3650")

    @field_validator("run_stale_after_seconds")
    @classmethod
    def _validate_run_stale_after(cls, value: int) -> int:
        if 60 <= value <= 86400:
            return value
        raise ValueError("run_stale_after_seconds must be between 60 and 86400")

    @field_validator("sweep_failure_max_absolute")
    @classmethod
    def _validate_sweep_failure_max_absolute(cls, value: int) -> int:
        # 0 is legal and means "no absolute allowance — the percentage alone decides".
        if 0 <= value <= 1_000_000:
            return value
        raise ValueError("sweep_failure_max_absolute must be between 0 and 1000000")

    @field_validator("sweep_failure_max_percent")
    @classmethod
    def _validate_sweep_failure_max_percent(cls, value: float) -> float:
        if 0.0 <= value <= 100.0:
            return value
        raise ValueError("sweep_failure_max_percent must be between 0.0 and 100.0")

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
    def resolved_log_format(self) -> str:
        if self.log_format != "auto":
            return self.log_format
        return "console" if self.debug else "json"


settings = Settings()
