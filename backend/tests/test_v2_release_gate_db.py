"""Evidence for the v2 release gate (#624), runnable on the database lane (#657).

Each test's docstring names the #624 or #622 bullet it evidences; bullets existing tests
cover are cited in the pull request body. Nothing here changes behaviour. The walk runs the
real migration scripts inside a scratch schema, in one transaction the test rolls back.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from alembic.config import Config
from alembic.runtime.environment import EnvironmentContext
from alembic.script import ScriptDirectory
from sqlalchemy import delete, text

from app.core import intelligence, participation, sharing
from app.core.config import settings
from app.core.database import Base
from app.core.sharing import get_or_create_settings, run_exchange
from app.core.vuln import NO_CORPUS
from app.core.vuln_library import earned_corpus
from app.core.vuln_selection import selected_signature
from app.models.schema import MdmConnection, ShareLog, VulnCorpusAcquisition, VulnCorpusSelection
from tests.test_intelligence import ACT, KEY, answer
from tests.test_vuln_library import BUNDLE, CORPUS_URL, SIGNATURE
from tests.test_vuln_library_db import acting_tenant, empty  # noqa: F401 — fixtures
from tests.test_vuln_retention_db import retained  # noqa: F401 — fixture

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

BACKEND = Path(__file__).resolve().parents[1]
V1_HEAD = "f526e8b3d901"  # v1.0.0's Alembic head (git show v1.0.0:backend/migrations/versions)
INDEX_REWRITE = "e621c4a8b903"  # #637: the installed_apps index rewrite that needs a window
SCHEMA = f"v2_release_walk_{os.getpid()}"  # per process, so two runs on one database do not collide
EPOCH_SIGNATURE = "5" * 64
BUILD_KEY = "v1:" + "6" * 64
TITLE_KEY = "v1:" + "7" * 64
DORMANT_LICENCE = "dormant-licence-ciphertext-as-v1-stored-it"
OFF_TENANT = uuid.UUID(int=65700)
KEYS_TENANT = uuid.UUID(int=65701)


def _upgrade(connection, config: Config, script: ScriptDirectory, target: str) -> None:
    """What `alembic upgrade <target>` does, on this connection instead of env.py's engine."""

    def upgrade(rev, _context):
        return script._upgrade_revs(target, rev)

    with EnvironmentContext(config, script, fn=upgrade, destination_rev=target) as env:
        env.configure(connection=connection, target_metadata=Base.metadata)
        with env.begin_transaction():
            env.run_migrations()


def _act(connection, tenant: uuid.UUID) -> None:
    connection.execute(text("SELECT set_config('looninspect.tenant_id', :tenant, true)"), {"tenant": str(tenant)})


def _seed_v1(connection) -> None:
    """Two v1 tenants: tier off with a dormant licence key, and keys; both hold the corpus."""
    now = datetime(2026, 9, 20, 16, tzinfo=UTC)
    for tenant, tier in ((OFF_TENANT, "off"), (KEYS_TENANT, "keys")):
        connection.execute(
            text(
                "INSERT INTO tenants (id, slug, name, kind, created_at, updated_at) "
                "VALUES (:id, :slug, 'release-gate walk', 'operational', :now, :now)"
            ),
            {"id": str(tenant), "slug": f"walk-{tier}", "now": now},
        )
        _act(connection, tenant)
        connection.execute(
            text(
                "INSERT INTO data_sharing_settings (tenant_id, tier, submission_uuid, exclude_globs, updated_at, "
                "pending_reveal_keys, ai_inference) VALUES (:tenant, :tier, :submission, '[]', NULL, '[]', false)"
            ),
            {"tenant": str(tenant), "tier": tier, "submission": str(uuid.uuid4())},
        )
        connection_id = connection.scalar(
            text(
                "INSERT INTO mdm_connections (tenant_id, name, provider, base_url, is_active, credentials_encrypted, "
                "webhook_secret_encrypted, patch_management_provider, loonsecio_license_key_encrypted, "
                "loonsecio_data_sharing_enabled, user_agent_override, sweep_page_size, token_cache_mode, "
                "capability_devices, capability_users, capability_webhooks, capability_jamf_pro, "
                "last_successful_auth_at, credentials_rotated_at, credentials_fingerprint, created_at, updated_at) "
                "VALUES (:tenant, 'Jamf Pro', 'jamf', 'https://jamf.example', true, NULL, NULL, 'none', :licence, false, "
                "NULL, NULL, 'cache_and_hold', true, false, false, false, NULL, NULL, NULL, :now, :now) RETURNING id"
            ),
            {"tenant": str(tenant), "licence": DORMANT_LICENCE if tier == "off" else None, "now": now},
        )
        for n in range(3):
            device_id = connection.scalar(
                text(
                    "INSERT INTO devices (tenant_id, mdm_connection_id, mdm_provider, external_id, platform, "
                    "serial_number, hostname) VALUES (:tenant, :connection, 'jamf', :external, 'macos', :serial, :host) "
                    "RETURNING id"
                ),
                {
                    "tenant": str(tenant),
                    "connection": connection_id,
                    "external": str(n),
                    "serial": f"C02{tier}{n}",
                    "host": f"mac-{n}",
                },
            )
            connection.execute(
                text(
                    "INSERT INTO installed_apps (tenant_id, device_id, name, bundle_id, version, app_hash, version_hash, "
                    "key_title, key_full, vuln_assessment, vuln_counts, vuln_ids, vuln_ids_truncated, vuln_signature) "
                    "VALUES (:tenant, :device, 'Wireshark', 'org.wireshark.Wireshark', '4.2.0', :app_hash, :version_hash, "
                    ":key_title, :key_full, 'covered', :counts, :ids, false, :signature)"
                ),
                {
                    "tenant": str(tenant),
                    "device": device_id,
                    "app_hash": "a" * 32,
                    "version_hash": "b" * 32,
                    "key_title": TITLE_KEY,
                    "key_full": BUILD_KEY,
                    "counts": json.dumps({"total": 17, "kev": 0, "critical": 1, "high": 6, "medium": 8, "low": 2}),
                    "ids": json.dumps(["CVE-2024-0001"]),
                    "signature": EPOCH_SIGNATURE,
                },
            )
    connection.execute(
        text(
            "INSERT INTO vuln_library_epoch (id, epoch_id, signature, asof, loaded_at, row_count, title_count) "
            "VALUES (1, '0008', :signature, :now, :now, 1, 1)"
        ),
        {"signature": EPOCH_SIGNATURE, "now": now},
    )
    connection.execute(
        text(
            "INSERT INTO vuln_library_rows (key_full, ids, truncated, counts, oldest_published) "
            "VALUES (:key, :ids, false, :counts, '{}')"
        ),
        {"key": BUILD_KEY, "ids": json.dumps(["CVE-2024-0001"]), "counts": json.dumps({"total": 17})},
    )
    connection.execute(
        text(
            "INSERT INTO vuln_library_titles (title_id, key_title, catalog_last_modified, versions_compiled) "
            "VALUES ('wireshark', :key, '2026-09-01T00:00:00Z', 1)"
        ),
        {"key": TITLE_KEY},
    )


async def test_the_v1_0_0_to_head_walk_enables_nothing_and_keeps_every_answer(db, capsys):
    """#624: "Upgrade never enables uploads or transmits dormant licence keys; never-qualified
    tenants acquire no neighboring corpus"; #621: "no zero-priming or loss of recorded history".
    The real migration scripts from v1.0.0's head to today's, over a seeded v1 instance."""
    config = Config(str(BACKEND / "alembic.ini"))
    config.attributes["configure_logger"] = False
    script = ScriptDirectory.from_config(config)
    head = script.get_current_head()
    before_rewrite = script.get_revision(INDEX_REWRITE).down_revision
    timings: dict[str, float] = {}

    def exercise(connection):
        connection.execute(text(f"CREATE SCHEMA {SCHEMA}"))
        connection.execute(text(f"SET LOCAL search_path TO {SCHEMA}"))
        started = time.perf_counter()
        _upgrade(connection, config, script, V1_HEAD)
        timings["to_v1"] = time.perf_counter() - started
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == V1_HEAD
        _seed_v1(connection)
        started = time.perf_counter()
        _upgrade(connection, config, script, before_rewrite)
        timings["v1_to_before_rewrite"] = time.perf_counter() - started
        started = time.perf_counter()
        _upgrade(connection, config, script, INDEX_REWRITE)
        timings["index_rewrite"] = time.perf_counter() - started
        started = time.perf_counter()
        _upgrade(connection, config, script, head)
        timings["rewrite_to_head"] = time.perf_counter() - started
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == head

        for tenant, tier in ((OFF_TENANT, "off"), (KEYS_TENANT, "keys")):
            _act(connection, tenant)
            # Consent is untouched, and the v2 columns arrive empty: no upload, no credential, no receipt.
            row = connection.execute(
                text("SELECT tier, intelligence_credential, participation_receipt FROM data_sharing_settings")
            ).one()
            assert row == (tier, None, None)
            assert connection.scalar(text("SELECT count(*) FROM share_log")) == 0
            # The dormant licence key is stored exactly as v1 stored it, and read by nothing.
            assert connection.scalar(text("SELECT loonsecio_license_key_encrypted FROM mdm_connections")) == (
                DORMANT_LICENCE if tier == "off" else None
            )
            # Only the consenting tenant acquires the installed release; nobody is selected yet.
            grants = connection.execute(text("SELECT signature, basis FROM vuln_corpus_acquisitions")).all()
            assert grants == ([(EPOCH_SIGNATURE, "legacy_consent")] if tier == "keys" else [])
            assert connection.scalar(text("SELECT count(*) FROM vuln_corpus_selections")) == 0
            # Every stored answer survives byte for byte: nothing was primed, resolved or re-dated.
            answers = connection.execute(
                text(
                    "SELECT vuln_assessment, vuln_counts::text, vuln_ids::text, vuln_ids_truncated, vuln_signature "
                    "FROM installed_apps"
                )
            ).all()
            assert len(answers) == 3
            counts = {"total": 17, "kev": 0, "critical": 1, "high": 6, "medium": 8, "low": 2}
            expected = ("covered", counts, ["CVE-2024-0001"], False, EPOCH_SIGNATURE)
            assert all((a[0], json.loads(a[1]), json.loads(a[2]), a[3], a[4]) == expected for a in answers)
        # The installed projection was retained as a release, without inventing a manifest, and stays the active library.
        assert connection.execute(text("SELECT signature, manifest FROM vuln_corpus_releases")).all() == [(EPOCH_SIGNATURE, None)]
        assert connection.scalar(text("SELECT signature FROM vuln_library_epoch")) == EPOCH_SIGNATURE
        indexes = set(
            connection.scalars(
                text("SELECT indexname FROM pg_indexes WHERE schemaname = :schema AND tablename = 'installed_apps'"),
                {"schema": SCHEMA},
            )
        )
        assert "ix_installed_apps_tenant_device" in indexes and "ix_installed_apps_tenant_id" not in indexes

    connection = await db.connection()
    try:
        await connection.run_sync(exercise)
    finally:
        await db.rollback()
    with capsys.disabled():
        print(
            f"\nv1.0.0 -> {head} walk: baseline->v1 {timings['to_v1']:.2f}s, v1->{before_rewrite} "
            f"{timings['v1_to_before_rewrite']:.2f}s, {INDEX_REWRITE} (#637 index rewrite, 6 installed_apps rows) "
            f"{timings['index_rewrite'] * 1000:.0f} ms, ->head {timings['rewrite_to_head']:.2f}s"
        )


ORIGIN = "https://service.example"
RECEIPT = "loon_rcpt_" + "r" * 43
ACCEPTED = "2026-09-23T03:00:00Z"
UNTIL = "2999-10-23T03:00:00Z"
FLAGS = ("intelligence_access", "contribution_receipts", "vuln_tenant_selection", "vuln_release_retention", "community_sharing")
LIVE_LICENCE = "LIC-DORMANT-CONNECTION-KEY-NEVER-SENT"


class BothRoutes:
    """Every Support route one tenant can use, recording each call so the test reads what left."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict, str | None]] = []
        self.paid: tuple[int, str] = (200, "paid")

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            assert str(request.url) == CORPUS_URL and "authorization" not in request.headers
            return httpx.Response(200, content=BUNDLE)
        body = json.loads(request.content)
        self.calls.append((request.url.path, body, request.headers.get("authorization")))
        corpus = {"url": CORPUS_URL, "signature": SIGNATURE, "asof": "2026-09-10T20:00:00Z"}
        if request.url.path == "/v1/exchange":
            reply: dict = {"contract": "v1", "corpus": corpus}
            if body.get("participation_receipt") is True:
                reply["participation"] = {"receipt": RECEIPT, "accepted_at": ACCEPTED, "updates_until": UNTIL}
            return httpx.Response(200, json=reply)
        if request.url.path == "/v2/activate":
            return httpx.Response(200, json=answer(credential=KEY))
        if request.url.path == "/v2/intelligence":
            code, state = self.paid
            if code != 200:
                return httpx.Response(code, json={"state": state, "error": "no"})
            return httpx.Response(200, json=answer(corpus=corpus))
        if request.url.path == "/v2/contribution/intelligence":
            block = {"contract": "v2", "state": "contributing", "accepted_at": ACCEPTED, "updates_until": UNTIL}
            return httpx.Response(200, json={**block, "corpus": corpus})
        if request.url.path == "/v2/contribution/withdraw":
            return httpx.Response(200, json={"contract": "v2", "state": "withdrawn"})
        raise AssertionError(f"unexpected call to {request.url}")

    def to(self, path: str) -> list[tuple[dict, str | None]]:
        return [(body, bearer) for called, body, bearer in self.calls if called == path]


@pytest_asyncio.fixture(loop_scope="session")
async def both_routes(db, retained, monkeypatch):  # noqa: F811 — fixture
    """A consenting tenant, both previews on, a licence key nothing may read, every route at ORIGIN."""
    for flag in FLAGS:
        monkeypatch.setattr(settings, flag, True)
    monkeypatch.setattr(settings, "sharing_endpoint", ORIGIN + "/v1/exchange")
    monkeypatch.setattr(settings, "intelligence_endpoint", ORIGIN)
    monkeypatch.setattr(sharing, "_RETRY_DELAYS", (0, 0, 0))

    async def reset(tier: str) -> None:
        await db.rollback()
        await db.execute(delete(ShareLog).where(ShareLog.tier != "ai"))
        await db.execute(delete(VulnCorpusSelection))
        await db.execute(delete(VulnCorpusAcquisition))
        await db.execute(delete(MdmConnection).where(MdmConnection.name == "release-gate coexistence"))
        row = await get_or_create_settings(db)
        row.tier = tier
        row.pending_reveal_keys = []
        row.intelligence_credential = None
        row.intelligence_status = {}
        row.participation_receipt = None
        row.participation_status = {}
        await db.commit()

    original = (await get_or_create_settings(db)).tier
    await reset("keys")
    db.add(
        MdmConnection(
            name="release-gate coexistence",
            provider="jamf",
            base_url="https://jamf.example",
            loonsecio_license_key_encrypted=LIVE_LICENCE,
        )
    )
    await db.commit()
    yield
    await reset(original)


async def test_paid_and_contribution_routes_coexist_without_linking_or_leaking(db, both_routes):
    """#622: "If paid and contribution routes coexist, either can maintain update eligibility
    without silently linking the two request identities"; #624: "never transmits dormant
    licence keys". One tenant, both credentials, every request read back."""
    service = BothRoutes()
    transport = httpx.MockTransport(service)

    # The consenting exchange earns a receipt and delivers the corpus; the selection is this tenant's.
    log = await run_exchange(db, transport=transport)
    assert log.outcome == "sent"
    await db.rollback()
    row = await get_or_create_settings(db)
    submission = str(row.submission_uuid)
    assert row.participation_receipt == RECEIPT and await selected_signature(db) == SIGNATURE

    # Paid activation and refresh beside it: the credential is stored, the selection stays the same release.
    activated = await intelligence.activate(db, ACT, transport=transport)
    assert activated["credentialPresent"] and activated["sharingTier"] == "keys"
    refreshed = await intelligence.refresh(db, transport=transport)
    assert refreshed["state"] == "paid" and refreshed["selectedCorpus"] == SIGNATURE

    # A day whose corpus did not arrive is fetched with the receipt alone, paid credential or not.
    await participation.after_delivery(db, "upload_failed")
    assert await participation.redemption_due(db)
    pointer = await participation.redeem(db, transport=transport)
    assert pointer is not None and pointer.signature == SIGNATURE

    ((upload, upload_bearer),) = service.to("/v1/exchange")
    ((activation, activation_bearer),) = service.to("/v2/activate")
    ((paid, paid_bearer),) = service.to("/v2/intelligence")
    ((redemption, redemption_bearer),) = service.to("/v2/contribution/intelligence")
    # The anonymous exchange carries the submission UUID and no credential of either kind.
    assert upload_bearer is None and upload["submission"] == submission
    assert activation_bearer is None and set(activation) == {"contract", "client_version", "activation_secret"}
    # The paid request carries the paid credential and the documented fields, never the receipt or the UUID.
    assert paid_bearer == f"Bearer {KEY}" and set(paid) == {"contract", "client_version", "channel"}
    assert redemption_bearer == f"Bearer {RECEIPT}" and set(redemption) == {"contract", "client_version"}
    for path, body, bearer in service.calls:
        recorded = json.dumps(body) + (bearer or "")
        assert LIVE_LICENCE not in recorded, path
        if path != "/v1/exchange":
            assert submission not in recorded, path
        if path != "/v2/intelligence":
            assert KEY not in recorded, path
        if path != "/v2/contribution/intelligence":
            assert RECEIPT not in recorded, path

    # Revoking the paid credential ends that route only: the receipt still maintains eligibility,
    # and the held selection answers throughout.
    service.paid = (403, "revoked")
    revoked = await intelligence.refresh(db, transport=transport)
    assert revoked["state"] == "revoked" and revoked["selectedCorpus"] == SIGNATURE
    assert (await earned_corpus(db)) is not NO_CORPUS
    await db.rollback()
    row = await get_or_create_settings(db)
    assert row.participation_receipt == RECEIPT and row.participation_status["state"] == "contributing"
    await participation.after_delivery(db, "upload_failed")
    assert await participation.redemption_due(db)
    again = await participation.redeem(db, transport=transport)
    assert again is not None and again.signature == SIGNATURE
    assert len(service.to("/v2/contribution/intelligence")) == 2

    # And the other way: sharing turned off withdraws the receipt, while paid access keeps refreshing.
    service.paid = (200, "paid")
    row = await participation.locked_row(db)
    row.tier = "off"
    participation.mark_withdrawal(row)
    await db.commit()
    assert await participation.withdraw(db, transport=transport)
    ((withdrawal, withdrawal_bearer),) = service.to("/v2/contribution/withdraw")
    assert withdrawal_bearer == f"Bearer {RECEIPT}" and set(withdrawal) == {"contract", "client_version"}
    assert KEY not in json.dumps(withdrawal)
    row = await get_or_create_settings(db)
    assert row.participation_receipt is None and row.tier == "off"
    paid_again = await intelligence.refresh(db, transport=transport)
    assert paid_again["state"] == "paid" and paid_again["selectedCorpus"] == SIGNATURE
    assert service.to("/v2/intelligence")[-1][1] == f"Bearer {KEY}"
