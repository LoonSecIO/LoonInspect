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
    # How long a dead-lettered delivery keeps its event after the ordinary window above
    # (#91). A delivery that spent its ten attempts is evidence of a gap in the trail,
    # and it is what a redrive re-sends; purged with its event at seven days, the gap was
    # permanent and invisible. Thirty days is the audit and run-log precedent.
    dead_letter_retention_days: int = 30

    # The ceiling on one Splunk HEC request body, in bytes. A `device.inventory` snapshot
    # is expanded at delivery into one HEC event per section item (app.core.hec_fanout)
    # and sent as ONE request of N concatenated events — ~90 KB for a Mac with 83 apps.
    # A device whose expansion exceeds this ceiling is sent as consecutive requests of at
    # most this many bytes, whole events only, in order (app.core.outbox); the delivery
    # succeeds only when every request does.
    #
    # The number is set against the tightest ceiling Splunk documents, with headroom:
    # Splunk Cloud Platform's service description states HEC is enabled "with a 1 MB size
    # limit on the maximum content length", and 1,000,000 bytes was Splunk Enterprise's
    # own `[http_input] max_content_length` default before it was raised to 838,860,800
    # (the value shipped in a 10.4 `limits.conf`). A request over the ceiling is refused
    # whole with HTTP 413 and would be retried ten times and dead-lettered — so the
    # default sits 10% under that 1,000,000, and the upper bound below is Enterprise's
    # shipped default. An operator on Enterprise with a large fleet of large devices may
    # raise it; nothing else about delivery changes.
    splunk_hec_max_request_bytes: int = 900_000

    # The same ceiling for the record fan-out (#306), on `runreveal`, `generic_webhook`
    # and `elastic`. A separate knob rather than a reuse of the Splunk one: an operator
    # tuning a RunReveal ingest limit should not have to set a setting named for a
    # product they do not run, and the two receivers' limits are genuinely unrelated —
    # HEC's is Splunk's `max_content_length`, a webhook's is whatever the receiver or the
    # proxy in front of it enforces. Same default, because 900 KB is a conservative body
    # size anywhere, and the same whole-records-only splitting either side of it.
    record_fanout_max_request_bytes: int = 900_000

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

    # Where the Jamf patch catalog is pulled from (app.mdm.patch.jamf_catalog). The
    # default is Jamf's public patch server, unchanged from the module constant this
    # replaced (#382). A setting rather than a constant for the same reason
    # sharing_endpoint is one: the address of something this container dials is
    # configuration, and the catalog may one day arrive by the vulnerability epoch's
    # reserved `catalog` section instead of being pulled at all (LoonVD-Internal's
    # sharedAssets/contract/epoch.md, the published format docs/vulnerabilities.md
    # points at). Deliberately not plumbed through docker-compose.yml: nothing about
    # the shipped stack wants it moved, and a second source will be chosen by which
    # CatalogSource is in use, not by editing this URL. A value that is not an address
    # is refused with a sentence that names this variable, not a traceback
    # (app/mdm/patch/jamf_catalog.py, docs/troubleshooting.md section 6).
    jamf_patch_base_url: str = "https://jamf-patch.jamfcloud.com/v1"

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
    # since last activity rather than time since login. The browser's cookies slide
    # with it — activity re-issues both auth cookies with a fresh Max-Age (see
    # app.core.auth._authenticate_session), so the browser keeps presenting the
    # session for as long as the server would accept it. 0 disables idle expiry
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

    # How long an idle connection is held open for the client's next request, in seconds
    # (uvicorn's `timeout_keep_alive`; the default is uvicorn's own). Behind a reverse
    # proxy or load balancer, set it above the proxy's idle timeout (#399): the proxy
    # holds its connections to the app open that long and reuses them, and a request it
    # sends down one the app has already closed never arrives — the client gets a blank
    # 502 from a healthy app, with no line in the app's log. An AWS ALB idles 60 s by
    # default; pods-ingress runs 130 s (#401), so a pod sets 135.
    keep_alive_timeout_seconds: int = 5

    # Lets an MDM connection's base_url be plain http. Off by default: the Jamf
    # client-credentials POST carries the client secret in its body, so http hands it
    # to anyone on the path. On rather than absent because a lab Jamf Pro on an
    # operator's own network is a real thing to point this at — but it has to be a
    # decision someone made, not a URL that happened to save (#131). See
    # app.core.egress.
    allow_insecure_mdm_base_url: bool = False

    # The same opt-in for a destination URL (#131): every delivery carries that
    # destination's own credential, so plain http is refused unless an operator says a
    # lab SIEM without TLS is what they have (docs/splunk-setup.md). Loopback, link-local
    # and the rest of app.core.egress's refused space stay refused either way.
    allow_insecure_destination_url: bool = False

    # Marks the session cookie Secure. On by default because the alternative fails
    # silently in the dangerous direction. Browsers refuse Secure cookies over plain
    # HTTP everywhere except localhost, so turn this off *only* for a deliberate
    # plain-HTTP deployment — see the startup warning in app.serve.
    secure_cookies: bool = True

    # The one knob (#186, ruling 3 on #133): off suppresses all five headers
    # SecurityHeadersMiddleware stamps, HSTS included, or it is not one knob. On by
    # default — none of X-Content-Type-Options, X-Frame-Options, Referrer-Policy or
    # Permissions-Policy can break a same-origin SPA with zero embeds, and CSP (the one
    # header here that could) is deliberately not in this cut (see #187).
    security_headers: bool = True

    # Content-Security-Policy (#187): a value, not a second knob. Empty — the default,
    # and what docker-compose passes when the variable is unset — emits the app's own
    # two policies (SecurityHeadersMiddleware). `off` emits no CSP and keeps the other
    # headers, for the operator whose deployment it broke. Anything else is emitted
    # verbatim on every response: it *replaces* the policy rather than extending it,
    # which is the escape hatch for the one fact the backend cannot know — a frontend
    # rebuilt with VITE_API_BASE_URL pointing off-origin needs a wider connect-src.
    content_security_policy: str = ""

    # The HSTS relay's argument, not a second knob (#186, ruling 4 on #133): the app
    # cannot know whether this hostname will still terminate valid HTTPS in six months,
    # only the operator can, so unlike the other four headers this one is never on by
    # default. 0 means never emit — the repo's existing sentinel idiom, see
    # session_lifetime_seconds above. Any positive value is copied verbatim into
    # `Strict-Transport-Security: max-age=<n>`; includeSubDomains and preload are never
    # emitted and are not configurable — no code path here can produce either.
    hsts_max_age: int = 0

    @field_validator("hsts_max_age")
    @classmethod
    def _validate_hsts_max_age(cls, value: int) -> int:
        if value < 0:
            raise ValueError("hsts_max_age must be >= 0 (0 disables HSTS entirely)")
        return value

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

    @field_validator("dead_letter_retention_days")
    @classmethod
    def _validate_dead_letter_retention(cls, value: int) -> int:
        if 1 <= value <= 3650:
            return value
        raise ValueError("dead_letter_retention_days must be between 1 and 3650")

    @field_validator("run_retention_days")
    @classmethod
    def _validate_run_retention(cls, value: int) -> int:
        if 1 <= value <= 3650:
            return value
        raise ValueError("run_retention_days must be between 1 and 3650")

    @field_validator("splunk_hec_max_request_bytes")
    @classmethod
    def _validate_splunk_hec_max_request_bytes(cls, value: int) -> int:
        # The floor is one sub-event with room to spare (a sub-event is ~1 KB); the ceiling
        # is Splunk Enterprise's shipped `max_content_length`. A single event larger than
        # the ceiling is still sent, alone — the setting bounds requests, not events.
        if 4_096 <= value <= 838_860_800:
            return value
        raise ValueError("splunk_hec_max_request_bytes must be between 4096 and 838860800")

    @field_validator("record_fanout_max_request_bytes")
    @classmethod
    def _validate_record_fanout_max_request_bytes(cls, value: int) -> int:
        # Same bounds and the same reasoning as the HEC ceiling above: the floor is one
        # record with room to spare, and a single record larger than the ceiling is still
        # sent, alone — the setting bounds requests, not records.
        if 4_096 <= value <= 838_860_800:
            return value
        raise ValueError("record_fanout_max_request_bytes must be between 4096 and 838860800")

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
            f"session_lifetime_seconds must be 0 (never idle out) or between 60 and {_MAX_SESSION_LIFETIME_SECONDS} (14 days)"
        )

    @field_validator("keep_alive_timeout_seconds")
    @classmethod
    def _validate_keep_alive_timeout(cls, value: int) -> int:
        if 1 <= value <= 600:
            return value
        raise ValueError(
            "KEEP_ALIVE_TIMEOUT_SECONDS must be between 1 and 600 seconds. Behind a reverse proxy "
            "or load balancer, set it above the proxy's idle timeout — a proxy's idle timeout "
            "must be shorter than the app's keep-alive, or the proxy reuses a connection the "
            "app already closed and answers 502."
        )

    @property
    def resolved_log_format(self) -> str:
        if self.log_format != "auto":
            return self.log_format
        return "console" if self.debug else "json"


settings = Settings()
