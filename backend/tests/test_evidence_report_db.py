"""The evidence artefact (#472): a fixture ledger through the catalogue, the evaluator and the interval query.

These pin the artefact's *shape*, which is what next year's auditor compares against. The framework grep is the one
that rots — nothing printed today names CMMC, 800-171, SOC 2 or Cyber Essentials (#219 R5 5.3).
"""

from __future__ import annotations

import json
import os
import uuid as uuidlib
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

from app.baseline.report import REFUSAL, UNDER_ONE_INTERVAL, evidence_report  # noqa: E402

COMPUTER, SECURITY, FIREWALL = "computer", "security", "LI-0003"
LOCKED, OPEN, THIN = "v0:sec-locked", "v0:sec-open", "v0:sec-thin"
BASE = datetime(2026, 3, 1, tzinfo=UTC)  # months older than the 30-day run horizon: history outlives its runs
LAG, AS_OF = timedelta(hours=1), datetime(2026, 4, 10, tzinfo=UTC)
FRAMEWORKS = ("cmmc", "800-171", "soc 2", "cyber essentials")
AUDITOR, VIEWER = (
    ("evidence-auditor@report.example.com", "auditor-password"),
    ("evidence-viewer@report.example.com", "viewer-password"),
)

# `thin` is the aperture's own absence — a record carrying no firewall field at all, which must read as notReported
# and never as unmet.
BODIES = {
    LOCKED: {"firewallEnabled": True, "sipStatus": "ENABLED", "gatekeeperStatus": "APP_STORE"},
    OPEN: {"firewallEnabled": False, "sipStatus": "ENABLED", "gatekeeperStatus": "APP_STORE"},
    THIN: {"sipStatus": "ENABLED"},
}
# (subject, day observed, security digest). Device 1 turns the firewall off and back on; device 2 is seen once and
# goes quiet; device 3 reports the same field-less record twice; device 4 departs on day 30.
LEDGER = (("1", 0, LOCKED), ("1", 10, OPEN), ("1", 20, LOCKED), ("2", 5, LOCKED))
LEDGER += (("3", 0, THIN), ("3", 12, THIN), ("4", 0, LOCKED))


def _at(day: float) -> datetime:
    return BASE + timedelta(days=day)


@pytest_asyncio.fixture(loop_scope="session")
async def ledger(db):
    from app.models.schema import MdmConnection, ObservationSection, ObservationSpan, SubjectDeparture

    row = MdmConnection(name=f"evidence {uuidlib.uuid4().hex[:8]}", provider="jamf", base_url="https://evidence.test")
    db.add(row)
    # Content rows are shared fleet-wide, so a crashed run's copies would trip the digest constraint here.
    await db.execute(delete(ObservationSection).where(ObservationSection.digest.in_(BODIES)))
    await db.commit()
    for digest, body in BODIES.items():
        db.add(ObservationSection(digest=digest, section=SECURITY, body=body, entry_count=0))
    newest = {subject: day for subject, day, _ in LEDGER}
    fixed = {"subject_kind": COMPUTER, "contract_version": "v0", "aperture_digest": "v0:aperture", "last_trigger": "sweep"}
    for subject, day, digest in LEDGER:
        at = _at(day)
        span = fixed | {"mdm_connection_id": row.id, "subject_id": subject, "label": f"Mac {subject}"}
        span |= {"udid": f"udid-{subject}", "serial_number": f"serial-{subject}", "management_id": f"management-{subject}"}
        span |= {"head_digest": f"v0:head-{uuidlib.uuid4().hex[:12]}", "section_digests": {SECURITY: digest}}
        span |= {"first_observed_at": at, "last_observed_at": at, "first_collected_at": at + LAG}
        db.add(ObservationSpan(**span, last_collected_at=at + LAG, observation_count=1, is_current=newest[subject] == day))
    db.add(SubjectDeparture(mdm_connection_id=row.id, subject_kind=COMPUTER, subject_id="4", departed_at=_at(30)))
    await db.commit()
    connection_id = row.id  # read before the rollback below expires it
    try:
        yield row
    finally:
        await db.rollback()
        await db.execute(delete(MdmConnection).where(MdmConnection.id == connection_id))
        await db.execute(delete(ObservationSection).where(ObservationSection.digest.in_(BODIES)))
        await db.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def report(db, ledger) -> dict:
    return await evidence_report(db, connection=ledger, window_from=BASE, as_of=AS_OF)


def _rows(report: dict, device_id: str, rule_id: str = FIREWALL) -> list[dict]:
    return [r for r in report["rows"] if r["ruleID"] == rule_id and r["deviceID"] == device_id]


async def test_the_header_states_the_method_and_names_no_framework(report: dict) -> None:
    """Technical evidence with no framework claim on it reads as one unless its own header says otherwise."""
    header = report["header"]
    assert list(header) == ["method", "notVisible", "refusal", "contractVersions", "clock"]
    assert header["notVisible"]["controls"] == ["policy controls", "process controls", "personnel controls"]
    assert (header["refusal"], header["contractVersions"]) == (REFUSAL, ["v0"])
    assert header["method"]["window"] == {"start": BASE.isoformat(), "asOf": AS_OF.isoformat()}
    assert header["method"]["catalogue"]["version"] == 1
    assert [name for name in FRAMEWORKS if name in json.dumps(report).lower()] == []


async def test_a_row_carries_the_field_it_read_and_the_digest_it_hashes_to(report: dict) -> None:
    """ "Firewall: met" is a spreadsheet with better typography; the field, value and digest make it evidence."""
    first, second, third = _rows(report, "1")[:3]
    assert [r["state"] for r in (first, second, third)] == ["met", "unmet", "met"]
    assert (first["witnessed"]["field"], first["witnessed"]["value"]) == ("security.firewallEnabled", True)
    assert "security.firewallEnabled" in first["witnessed"]["statement"]
    assert (first["sectionDigest"], first["contractVersion"], first["days"]) == (LOCKED, "v0", 10)
    assert (first["duration"], first["observations"]) == ("10 days", 1)
    mac = report["devices"][0]
    assert mac == {"deviceID": "1", "name": "Mac 1", "udid": "udid-1", "serialNumber": "serial-1", "managementID": "management-1"}
    # The three rules MSCP checks the way we do cite it; the other seven carry no mapping at all.
    assert {r["ruleID"] for r in report["rules"] if "mscp" in r} == {"LI-0005", "LI-0006", "LI-0007"}


async def test_the_absences_stay_apart_and_a_quiet_device_keeps_its_name(report: dict) -> None:
    """Three different facts. Folding any into unmet reports a Mac nobody asked about as a Mac that failed."""
    (thin,) = [r for r in _rows(report, "3") if r["state"] != "noObservation"]
    assert (thin["state"], thin["days"]) == ("notReported", 12) and "value" not in thin["witnessed"]
    assert "carried no security.firewallEnabled" in thin["witnessed"]["statement"]
    # Device 2 was seen once on day 5 and has said nothing since: head, a zero-length interval, and the tail.
    seen = _rows(report, "2")
    assert [r["state"] for r in seen] == ["noObservation", "met", "noObservation"]
    assert (seen[1]["duration"], seen[1]["seconds"]) == (UNDER_ONE_INTERVAL, 0) and "days" not in seen[1]
    tail = _rows(report, "4")[-1]
    assert (tail["state"], tail["departedAt"]) == ("departed", _at(30).isoformat())
    assert {device["deviceID"] for device in report["devices"]} == {"1", "2", "3", "4"}


async def test_the_three_numbers_add_up_to_the_window(report: dict) -> None:
    """met + unmet + not observed = the window, with the third's parts named rather than folded away."""
    window = int((AS_OF - BASE).total_seconds())
    devices, rules, totals = len(report["devices"]), len(report["rules"]), report["totals"]
    scopes = ((totals["byDevice"].values(), rules), (totals["byRule"].values(), devices), ([totals["fleet"]], devices * rules))
    for buckets, folded in scopes:
        for bucket in buckets:
            three = sum(bucket[state]["seconds"] for state in ("met", "unmet", "notObserved"))
            assert three == bucket["window"]["seconds"] == window * folded
    assert set(totals["byRule"]) == {rule["ruleID"] for rule in report["rules"]}
    # Device 3 never departed, so that part is absent rather than a zero beside the two that happened.
    assert set(totals["byDevice"]["3"]["notObservedParts"]) == {"notReported", "noObservation"}
    assert "departed" in totals["byDevice"]["4"]["notObservedParts"]


async def test_an_empty_ledger_counts_nothing_rather_than_counting_zero(db, ledger) -> None:
    """No zero-priming: a connection nobody swept must not hand a reader ten rules' worth of clean zeros."""
    from app.models.schema import MdmConnection

    empty = MdmConnection(name=f"unswept {uuidlib.uuid4().hex[:8]}", provider="jamf", base_url="https://unswept.test")
    db.add(empty)
    await db.commit()
    connection_id = empty.id
    try:
        report = await evidence_report(db, connection=empty, window_from=BASE, as_of=AS_OF)
        assert (report["rows"], report["devices"]) == ([], [])
        assert report["totals"] == {"fleet": {}, "byRule": {}, "byDevice": {}}
        assert report["rules"] and report["header"]["refusal"] == REFUSAL
    finally:
        await db.rollback()
        await db.execute(delete(MdmConnection).where(MdmConnection.id == connection_id))
        await db.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def accounts(db):
    from app.core.bootstrap import create_account
    from app.models.schema import Account, LoginAttempt

    for (email, password), role in ((AUDITOR, "auditor"), (VIEWER, "viewer")):
        if (await db.execute(select(Account).where(Account.email == email))).scalars().first() is None:
            await create_account(db, email=email, display_name=role, password=password, roles=(role,))
        # A crashed run's failed logins would otherwise trip the lockout and fail this about rate limiting.
        await db.execute(delete(LoginAttempt).where(LoginAttempt.identifier == email))
    await db.commit()


async def _signed_in(credentials: tuple[str, str]) -> httpx.AsyncClient:
    """https, not http: the session cookies are Secure, and a plain-http origin discards them silently."""
    from app.main import app

    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://report.example.com")
    answer = await client.post("/api/auth/login", json={"email": credentials[0], "password": credentials[1]})
    assert answer.status_code == 200, answer.text
    return client


async def test_the_endpoint_answers_an_auditor_and_nobody_else(ledger, accounts) -> None:
    """AUDIT_READ, the permission /api/system/share-log already argued for: a Viewer holds the inventory reads and
    not this one. An id no connection has is refused rather than answered with an empty document."""
    connection_id = ledger.id
    auditor, viewer = await _signed_in(AUDITOR), await _signed_in(VIEWER)
    try:
        asked = {"connectionID": connection_id, "start": BASE.isoformat(), "asOf": AS_OF.isoformat()}
        answer = await auditor.get("/api/evidence/report", params=asked)
        assert answer.status_code == 200, answer.text
        assert answer.json()["header"]["refusal"] == REFUSAL
        assert (await auditor.get("/api/evidence/report", params={"connectionID": 10**9})).status_code == 404
        assert (await viewer.get("/api/evidence/report", params={"connectionID": connection_id})).status_code == 403
    finally:
        await auditor.aclose()
        await viewer.aclose()
