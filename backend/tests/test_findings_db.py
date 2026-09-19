"""The finding ledger: the seven facts #590 asks for (ruled in #589).

Driven through `reconcile_device_findings` over hand-written stored answers rather than a
sweep, because those columns are exactly what the ledger reads — the ones
`record_device_apps` makes current (#381) — so an epoch, a corpus and a Jamf fake would slow
the suite without moving an assertion. The app rows are transient: the diff reads their
attributes, never their identity. Gated on RUN_DB_TESTS like every DB suite."""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from sqlalchemy import select

from app.core.content_keys import app_full_key, app_title_key
from app.core.findings import BASIS_BACKFILL, BASIS_OBSERVED, RESOLVED_BUILD_CHANGED, RESOLVED_CORPUS_WITHDRAWN
from app.core.findings import reconcile_device_findings as reconcile
from app.core.hashing import compute_app_hash, compute_version_hash
from app.models.schema import Device, DeviceChange, DeviceFinding, InstalledApp
from tests.test_sweep_costs_db import connection, statements  # noqa: F401 — the fixture and the instrument

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

DAY1, DAY2 = datetime(2026, 9, 1, 12, tzinfo=UTC), datetime(2026, 9, 8, 12, tzinfo=UTC)
DAY3 = datetime(2026, 9, 15, 12, tzinfo=UTC)
CVE, OTHER = "CVE-2026-1001", "CVE-2026-2002"
WIRESHARK, SAFARI = ("Wireshark.app", "org.wireshark.Wireshark"), ("Safari.app", "com.apple.Safari")
JAMF_ID = "4242"


@pytest_asyncio.fixture(loop_scope="session")
async def mac(db, connection):  # noqa: F811 — pytest reads the imported fixture by name
    """One Mac under `test_sweep_costs_db`'s connection fixture, which deletes the fleet — and
    with it, by CASCADE, this Mac's ledger rows and this connection's change log."""
    mine = {"mdm_connection_id": connection.id, "mdm_provider": "jamf", "external_id": JAMF_ID, "hostname": "ledger.host"}
    db.add(device := Device(serial_number="C02LEDGER01", **mine))
    await db.commit()
    return device


def _app(identity: tuple[str, str], version: str, ids: list[str], *, truncated: bool = False) -> InstalledApp:
    # One app row with a stored answer, keyed through `content_keys` rather than by literal.
    name, bundle = identity
    hashes = {"app_hash": compute_app_hash(name, bundle), "version_hash": compute_version_hash(name, bundle, version, None)}
    keys = {"key_title": app_title_key(name, bundle), "key_full": app_full_key(name, bundle, version, None)}
    answer = {"vuln_assessment": "covered", "vuln_ids": list(ids), "vuln_ids_truncated": truncated}
    return InstalledApp(name=name, bundle_id=bundle, version=version, **hashes, **keys, **answer)


async def _sync(db, device: Device, apps: list[InstalledApp], at: datetime, *, new: bool = False) -> None:
    await reconcile(db, device=device, rows=apps, observed_at=at, device_is_new=new)
    await db.commit()


async def _ledger(db, device: Device) -> dict[tuple[str, str], DeviceFinding]:
    # This Mac's rows by (carrier, id). `populate_existing` because the upsert is Core: a
    # cached instance would otherwise still carry the attributes it had before a reopen.
    mine = select(DeviceFinding).where(DeviceFinding.device_id == device.id).execution_options(populate_existing=True)
    return {(row.carrier_key, row.finding_id): row for row in (await db.execute(mine)).scalars().all()}


def _arrival(device: Device, identity: tuple[str, str], version: str, *, at: datetime) -> DeviceChange:
    # The change-log row that put this build on this Mac, in `app.changes.derive`'s shape.
    name, bundle = identity
    subject = {"mdm_connection_id": device.mdm_connection_id, "subject_kind": "computer", "subject_id": JAMF_ID}
    entry = {"section": "applications", "entry_kind": "application", "change": "added", "new_value": {"version": version}}
    entry["entry_identity"] = {"name": name, "bundleId": bundle, "path": f"/Applications/{name}"}
    return DeviceChange(observed_at=at, collected_at=at, trigger="sweep", level="normal", policy_version="v1", **subject, **entry)


async def test_a_build_bump_still_carrying_the_id_keeps_the_row_and_its_clock(db, mac) -> None:
    await _sync(db, mac, [_app(WIRESHARK, "4.2.0", [CVE])], DAY1, new=True)  # nothing to backfill
    await _sync(db, mac, [_app(WIRESHARK, "4.6.0", [CVE])], DAY2)
    (row,) = (await _ledger(db, mac)).values()
    assert (row.first_observed_at, row.resolved_at, row.first_seen_basis) == (DAY1, None, BASIS_OBSERVED)
    assert row.build_key_full == app_full_key(*WIRESHARK, "4.6.0", None), "the build is an attribute, and it moved"


async def test_a_bump_without_the_id_closes_build_changed_and_a_regression_reopens_that_row(db, mac) -> None:
    await _sync(db, mac, [_app(WIRESHARK, "4.2.0", [CVE])], DAY1)
    await _sync(db, mac, [_app(WIRESHARK, "4.6.0", [])], DAY2)
    (row,) = (await _ledger(db, mac)).values()
    assert (row.resolved_at, row.resolved_reason, row.last_observed_at) == (DAY2, RESOLVED_BUILD_CHANGED, DAY2)
    was = row.id
    await _sync(db, mac, [_app(WIRESHARK, "4.2.0", [CVE])], DAY3)
    (row,) = (await _ledger(db, mac)).values()
    assert (row.id, row.resolved_at, row.first_observed_at) == (was, None, DAY1), "the same row, back on its own clock"


async def test_one_finding_on_two_carriers_is_two_rows(db, mac) -> None:
    # #589's pair is Safari and macOS; the OS is not a carrier here yet, so two app carriers.
    await _sync(db, mac, [_app(SAFARI, "18.0", [CVE]), _app(WIRESHARK, "4.2.0", [CVE])], DAY1)
    rows = await _ledger(db, mac)
    assert sorted(rows) == sorted([(app_title_key(*SAFARI), CVE), (app_title_key(*WIRESHARK), CVE)])


async def test_a_capped_build_never_closes_a_row_by_absence(db, mac) -> None:
    await _sync(db, mac, [_app(WIRESHARK, "4.2.0", [CVE], truncated=True)], DAY1)
    # The same truncated build, its 50 now showing a different id: absence proves nothing.
    await _sync(db, mac, [_app(WIRESHARK, "4.2.0", [OTHER], truncated=True)], DAY2)
    row = (await _ledger(db, mac))[(app_title_key(*WIRESHARK), CVE)]
    assert row.resolved_at is None and row.capped
    # It closes when the BUILD moves — a fact about the Mac, not about the list.
    await _sync(db, mac, [_app(WIRESHARK, "4.6.0", [OTHER])], DAY3)
    assert (await _ledger(db, mac))[(app_title_key(*WIRESHARK), CVE)].resolved_reason == RESOLVED_BUILD_CHANGED


async def test_an_epoch_withdrawal_closes_corpus_withdrawn_not_build_changed(db, mac) -> None:
    await _sync(db, mac, [_app(WIRESHARK, "4.2.0", [CVE, OTHER])], DAY1)
    # The same build, re-judged under an epoch that no longer lists one of the two.
    await _sync(db, mac, [_app(WIRESHARK, "4.2.0", [OTHER])], DAY2)
    rows = await _ledger(db, mac)
    assert rows[(app_title_key(*WIRESHARK), CVE)].resolved_reason == RESOLVED_CORPUS_WITHDRAWN
    assert rows[(app_title_key(*WIRESHARK), OTHER)].resolved_at is None


async def test_a_sweep_in_which_nothing_moved_issues_no_ledger_statement(db, mac) -> None:
    apps = [_app(WIRESHARK, "4.2.0", [CVE, OTHER]), _app(SAFARI, "18.0", [CVE])]
    await _sync(db, mac, apps, DAY1)
    with statements() as seen:
        await _sync(db, mac, apps, DAY2)
    writes = [s for s in seen if "device_findings" in s and not s.lstrip().upper().startswith("SELECT")]
    assert writes == [], writes


async def test_a_backfill_takes_the_change_log_arrival_then_the_first_observation(db, mac) -> None:
    db.add(_arrival(mac, WIRESHARK, "4.2.0", at=DAY1))
    await db.commit()
    await _sync(db, mac, [_app(WIRESHARK, "4.2.0", [CVE]), _app(SAFARI, "18.0", [OTHER])], DAY2)
    rows = await _ledger(db, mac)
    wireshark = rows[(app_title_key(*WIRESHARK), CVE)]
    assert (wireshark.first_observed_at, wireshark.first_seen_basis) == (DAY1, BASIS_BACKFILL)
    # No arrival row for Safari, so the reconcile's own clock — marked `backfill` either way.
    safari = rows[(app_title_key(*SAFARI), OTHER)]
    assert (safari.first_observed_at, safari.first_seen_basis) == (DAY2, BASIS_BACKFILL)
    # And thereafter the observation's own clock, on its own basis.
    await _sync(db, mac, [_app(WIRESHARK, "4.2.0", [CVE]), _app(SAFARI, "18.0", [OTHER, CVE])], DAY3)
    row = (await _ledger(db, mac))[(app_title_key(*SAFARI), CVE)]
    assert (row.first_observed_at, row.first_seen_basis) == (DAY3, BASIS_OBSERVED)
