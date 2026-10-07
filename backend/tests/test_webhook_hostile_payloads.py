"""A deterministic table of hostile payloads against the Jamf webhook endpoint.

This is the negative-space companion to `test_webhook_auth.py` (the decision
functions and the identical-401 enumeration guard, in isolation) and
`test_webhook_secret_db.py` (the secret's write-only round trip). Those pin what the
endpoint does for a *well-formed* caller. This pins what it does for a malformed or
hostile one: the endpoint is the only route reachable without a session, Jamf Pro does
not sign its payloads, and a bad request must be refused cleanly rather than written,
amplified into the customer's Jamf tenant, or turned into a log line that echoes the
secret.

The cases are a fixed table, not a random fuzzer, so a failure names exactly which
shape produced it and re-runs identically. Every case is driven through the ASGI
transport against the real application — never a live URL — with Jamf Pro itself stood
in for by `tests.jamf_fake.FakeJamf`, so a case that would otherwise reach Jamf reaches
the fake instead. Each case asserts three things at once: the response is the expected
4xx (or the documented 200 "ignored" / 502), the tables a webhook can write are
untouched (row counts around the call), and no case's logs carry the secret.

What each case class is checked against, in the operator's terms:

- absent / wrong / wrong-scheme credentials -> the uniform 401, nothing written;
- a body that is not a JSON object (array, string, number, empty, non-JSON, the wrong
  content type, a form post) -> 422, nothing written;
- a non-integer connection id -> 422 from path validation, before anything else;
- an event the connector drops by design (a ComputerCheckIn heartbeat, a reactive
  event naming no computer, unicode or extra fields on a dropped event, an object
  where the payload nests one but with the wrong shape) -> 200 "ignored", nothing
  written, and not one request made to Jamf Pro;
- a replayed drop event -> the same 200 "ignored" each time, still nothing written
  (there is no replay protection and none is claimed: TLS is the integrity, per the
  route docstring and docs/auth-design.md 4.7);
- a reactive event for a device Jamf Pro no longer has -> the documented 502 and a
  single failed run recorded (the one case that writes, by design: a webhook is a run,
  and a failed fetch finishes it failed, #224).

Malformed-body shapes are refused or ignored before a read or inventory write.

Gated on RUN_DB_TESTS like every session-backed suite; see test_sad_paths.py for the
same ASGITransport-on-the-test-loop shape and the local invocation.
"""

from __future__ import annotations

import json
import logging
import os
import uuid as uuidlib

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, func, select

from tests.jamf_fake import HOST, FakeJamf

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

# Distinctive enough that finding it in a log body means something, rather than
# colliding with base64 or a uuid and passing the no-leak sweep for the wrong reason.
WEBHOOK_SECRET = "hostile-table-secret-zzq-7c1d9e"


@pytest_asyncio.fixture(loop_scope="session")
async def armed(db):
    """One connection in the operational tenant, webhooks on and a secret set — the
    state in which the endpoint actually does work, so a refusal here is the endpoint
    refusing rather than a connection that was never armed. Torn down in the order
    `test_sad_paths.py` proved: the device chain first, then the connection (its runs
    and apertures cascade)."""
    from app.models.schema import (
        Device,
        DeviceExtensionAttribute,
        InstalledApp,
        MdmConnection,
        MdmSyncState,
    )

    row = MdmConnection(
        name=f"hostile table {uuidlib.uuid4().hex[:8]}",
        provider="jamf",
        base_url=HOST,
        credentials_encrypted=json.dumps({"clientId": "client", "clientSecret": "secret"}),
        capability_webhooks=True,
        webhook_secret_encrypted=WEBHOOK_SECRET,
    )
    db.add(row)
    await db.commit()
    connection_id = row.id
    try:
        yield connection_id
    finally:
        await db.rollback()
        device_ids = select(Device.id).where(Device.mdm_connection_id == connection_id)
        await db.execute(delete(InstalledApp).where(InstalledApp.device_id.in_(device_ids)))
        await db.execute(delete(DeviceExtensionAttribute).where(DeviceExtensionAttribute.device_id.in_(device_ids)))
        await db.execute(delete(Device).where(Device.mdm_connection_id == connection_id))
        await db.execute(delete(MdmSyncState).where(MdmSyncState.mdm_connection_id == connection_id))
        await db.execute(delete(MdmConnection).where(MdmConnection.id == connection_id))
        await db.commit()


async def _write_counts() -> dict[str, int]:
    """Row counts in the tables a webhook can write, read in a fresh session so they
    see committed state. A reject or a drop leaves every one of these unchanged; the
    only case that moves them is the documented failed run."""
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import (
        Collection,
        Device,
        DeviceExtensionAttribute,
        EventOutbox,
        InstalledApp,
        ObservationAperture,
        ObservationSpan,
        Run,
        RunLogLine,
    )

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as session:
        return {
            "runs": (await session.execute(select(func.count()).select_from(Run))).scalar_one(),
            "devices": (await session.execute(select(func.count()).select_from(Device))).scalar_one(),
            "apps": (await session.execute(select(func.count()).select_from(InstalledApp))).scalar_one(),
            "events": (await session.execute(select(func.count()).select_from(EventOutbox))).scalar_one(),
            "apertures": (await session.execute(select(func.count()).select_from(ObservationAperture))).scalar_one(),
            "spans": (await session.execute(select(func.count()).select_from(ObservationSpan))).scalar_one(),
            "log_lines": (await session.execute(select(func.count()).select_from(RunLogLine))).scalar_one(),
            "eas": (await session.execute(select(func.count()).select_from(DeviceExtensionAttribute))).scalar_one(),
            "collections": (await session.execute(select(func.count()).select_from(Collection))).scalar_one(),
        }


def _transport() -> httpx.ASGITransport:
    """The whole application, so middleware and the global auth dependency run exactly
    as in production. `raise_app_exceptions=False` turns an unhandled 500 into a 500
    *response* rather than a test error, so one malformed shape cannot abort the table
    and the malformed cases can assert on a status code."""
    from app.main import app

    return httpx.ASGITransport(app=app, raise_app_exceptions=False)


async def _post(connection_id, *, headers=None, **kwargs) -> httpx.Response:
    async with httpx.AsyncClient(transport=_transport(), base_url="https://hostile.example.com") as client:
        return await client.post(f"/webhooks/jamf/{connection_id}", headers=headers or {}, **kwargs)


# A valid secret, so the body — not the credential — is what each case is testing. The
# content type is JSON unless a case is specifically about the content type.
_AUTH = {"X-API-Key": WEBHOOK_SECRET, "Content-Type": "application/json"}

# Unicode built with chr() rather than typed: a literal right-to-left override or an
# astral codepoint in the source is invisible or an editor hazard, and the point is to
# prove an identifier full of them is handled, not to smuggle one into this file. An
# Arabic-Indic digit, an RTL override, and an astral emoji.
_UNICODE_SERIAL = chr(0x0661) + chr(0x0662) + chr(0x202E) + chr(0x1F600)


# --- rejected with a 4xx, nothing written --------------------------------------------
#
# (label, headers, httpx kwargs, expected status). Credentials first, then bodies that
# are not a JSON object, then a connection id that is not an integer.
_REJECTED: list[tuple[str, dict, dict, int]] = [
    ("no credential at all", {}, {"json": {"event": {}}}, 401),
    ("wrong secret, x-api-key", {"X-API-Key": "nope"}, {"json": {"event": {}}}, 401),
    ("wrong secret, bearer", {"Authorization": "Bearer nope"}, {"json": {"event": {}}}, 401),
    # base64("nocolon"): a Basic credential with no colon is malformed, not a
    # passwordless one, so no secret is extracted and the uniform 401 stands.
    ("basic with no colon", {"Authorization": "Basic bm9jb2xvbg=="}, {"json": {"event": {}}}, 401),
    ("an unsupported scheme", {"Authorization": "Digest cnonce=abc"}, {"json": {"event": {}}}, 401),
    # The body is never read before the secret, so an oversized unauthenticated body is
    # refused without being buffered or parsed.
    (
        "oversized body, no credential",
        {"Content-Type": "application/json"},
        {"content": b'{"pad":"' + b"x" * 1_000_000 + b'"}'},
        401,
    ),
    ("a JSON array, not an object", dict(_AUTH), {"content": b"[]"}, 422),
    ("a JSON string, not an object", dict(_AUTH), {"content": b'"a string"'}, 422),
    ("a JSON number, not an object", dict(_AUTH), {"content": b"5"}, 422),
    ("JSON null, not an object", dict(_AUTH), {"content": b"null"}, 422),
    ("an empty body", dict(_AUTH), {"content": b""}, 422),
    ("not JSON at all", dict(_AUTH), {"content": b"{not json"}, 422),
    (
        "an XML body (webhook left on XML)",
        {"X-API-Key": WEBHOOK_SECRET, "Content-Type": "text/xml"},
        {"content": b"<webhook/>"},
        422,
    ),
    ("a form post, not JSON", {"X-API-Key": WEBHOOK_SECRET}, {"data": {"webhookEvent": "ComputerAdded"}}, 422),
]


@pytest.mark.parametrize(
    ("label", "headers", "kwargs", "expected"),
    [pytest.param(label, headers, kwargs, expected, id=label) for (label, headers, kwargs, expected) in _REJECTED],
)
async def test_rejected_cleanly_and_nothing_written(
    armed, jamf: FakeJamf, label: str, headers: dict, kwargs: dict, expected: int
) -> None:
    before = await _write_counts()
    response = await _post(armed, headers=headers, **kwargs)
    after = await _write_counts()

    assert response.status_code == expected, f"{label}: {response.status_code} {response.text}"
    assert after == before, f"{label}: a rejected request wrote rows {before} -> {after}"
    assert jamf.requests == [], f"{label}: a rejected request reached Jamf Pro"


async def test_a_non_integer_connection_id_is_a_422_before_anything_else(armed, jamf: FakeJamf) -> None:
    """The id is a path integer; a non-numeric one is refused by path validation before
    the connection is ever looked up, so no credential is needed to earn the 422 and
    nothing is read or written."""
    before = await _write_counts()
    response = await _post("not-a-number", headers=_AUTH, json={"event": {}})
    after = await _write_counts()

    assert response.status_code == 422, response.text
    assert response.json()["detail"][0]["type"] == "int_parsing"
    assert after == before
    assert jamf.requests == []


# --- accepted but dropped by design: 200 "ignored", nothing written, no fetch ---------
#
# The documented ACK. These carry a valid secret and a well-formed object, and the
# connector drops them before any run or API call exists: a heartbeat (#76), a reactive
# event naming no computer, or a payload whose nested shape is wrong. None reaches Jamf.
_IGNORED: list[tuple[str, dict]] = [
    ("a ComputerCheckIn heartbeat", {"webhook": {"webhookEvent": "ComputerCheckIn"}, "event": {"jssID": 1}}),
    ("a reactive event naming no computer", {"webhook": {"webhookEvent": "ComputerAdded"}, "event": {}}),
    (
        "unicode identifiers on an event with no jssID",
        {
            "webhook": {"webhookEvent": "ComputerInventoryCompleted"},
            "event": {"udid": _UNICODE_SERIAL, "serialNumber": _UNICODE_SERIAL},
        },
    ),
    (
        "extra and unknown fields on a dropped event",
        {"webhook": {"webhookEvent": "ComputerCheckIn"}, "event": {}, "extra": "x", "nested": {"a": [1, 2, 3]}},
    ),
    # Right field names, wrong (but hashable) types: the event name is compared, found
    # not to warrant a fetch, and dropped — never coerced.
    ("webhookEvent as a number", {"webhook": {"webhookEvent": 5}, "event": {"jssID": 1}}),
    ("webhookEvent as a boolean", {"webhook": {"webhookEvent": True}, "event": {"jssID": 1}}),
    ("webhookEvent as null", {"webhook": {"webhookEvent": None}, "event": {"jssID": 1}}),
    # Arrays where the payload nests objects: each is guarded with isinstance and falls
    # back to an empty object, so the event is simply not reactive and is dropped.
    ("event is an array", {"webhook": {"webhookEvent": "ComputerAdded"}, "event": [{"jssID": 1}]}),
    ("webhook is an array", {"webhook": [{"webhookEvent": "ComputerAdded"}], "event": {"jssID": 1}}),
    ("computer is an array under a heartbeat", {"webhook": {"webhookEvent": "ComputerCheckIn"}, "event": {"computer": [1]}}),
]


@pytest.mark.parametrize(
    ("label", "payload"),
    [pytest.param(label, payload, id=label) for (label, payload) in _IGNORED],
)
async def test_dropped_by_design_acks_and_writes_nothing(armed, jamf: FakeJamf, label: str, payload: dict) -> None:
    before = await _write_counts()
    response = await _post(armed, headers=_AUTH, json=payload)
    after = await _write_counts()

    assert response.status_code == 200, f"{label}: {response.status_code} {response.text}"
    assert response.json() == {"status": "ignored"}, label
    assert after == before, f"{label}: a dropped event wrote rows {before} -> {after}"
    assert jamf.requests == [], f"{label}: a dropped event reached Jamf Pro"


async def test_an_oversized_dropped_event_is_still_a_clean_ack(armed, jamf: FakeJamf) -> None:
    """A ~1 MB heartbeat: the body is parsed (the secret was proved) and then dropped by
    design, so the size buys nothing and still nothing is written. A reminder that the
    body cap is the deployment's to set, not this route's."""
    body = b'{"webhook":{"webhookEvent":"ComputerCheckIn"},"event":{"jssID":1},"pad":"' + b"x" * 1_000_000 + b'"}'
    before = await _write_counts()
    response = await _post(armed, headers=_AUTH, content=body)
    after = await _write_counts()

    assert response.status_code == 200, response.text
    assert response.json() == {"status": "ignored"}
    assert after == before
    assert jamf.requests == []


@pytest.mark.parametrize("value", [True, 1.5, [], {}, "../users", "1?section=ALL", "1/2", "1\n", "１２", "9" * 21])
@pytest.mark.parametrize("location", ["jssID", "id", "computer"])
async def test_invalid_computer_ids_never_reach_jamf_or_write(armed, jamf, value, location):
    event = {"computer": {"jssID": value}} if location == "computer" else {location: value}
    before = await _write_counts()
    response = await _post(armed, headers=_AUTH, json={"webhook": {"webhookEvent": "ComputerAdded"}, "event": event})
    assert response.status_code == 200 and response.json() == {"status": "ignored"}
    assert await _write_counts() == before
    assert jamf.requests == []


async def test_a_replayed_drop_event_is_idempotent_and_writes_nothing(armed, jamf: FakeJamf) -> None:
    """There is no replay protection and none is claimed (the route docstring: a static
    header carries no replay protection, so TLS is load-bearing). The observable that
    does hold is that replaying a dropped event changes nothing: the same 200 "ignored"
    each time, and no rows either time."""
    payload = {"webhook": {"webhookEvent": "ComputerCheckIn"}, "event": {"jssID": 7}}
    before = await _write_counts()
    first = await _post(armed, headers=_AUTH, json=payload)
    second = await _post(armed, headers=_AUTH, json=payload)
    after = await _write_counts()

    assert first.status_code == second.status_code == 200
    assert first.json() == second.json() == {"status": "ignored"}
    assert after == before
    assert jamf.requests == []


async def test_an_unknown_device_is_the_documented_502_and_writes_no_inventory(armed, jamf: FakeJamf) -> None:
    """A reactive event for a computer Jamf Pro no longer has (a plain numeric id Jamf
    answers 404 for). The documented behavior (#224, test_sad_paths.py): the fetch
    fails, the run finishes failed, the route answers 502, and no device or app row is
    written — the one case in this file that writes anything, and only the failed run's
    own bookkeeping."""
    before = await _write_counts()
    payload = {"webhook": {"webhookEvent": "ComputerInventoryCompleted"}, "event": {"jssID": "999999", "serialNumber": "GONE"}}
    response = await _post(armed, headers=_AUTH, json=payload)
    after = await _write_counts()

    assert response.status_code == 502, response.text
    assert response.json() == {"detail": "Inventory fetch from Jamf Pro failed"}
    assert after["devices"] == before["devices"], "an unknown-device webhook wrote a device"
    assert after["apps"] == before["apps"], "an unknown-device webhook wrote an app"
    assert after["runs"] == before["runs"] + 1, "the failed run was not recorded"

    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Run

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as session:
        run = (
            await session.execute(select(Run).where(Run.mdm_connection_id == armed).order_by(Run.started_at.desc()).limit(1))
        ).scalar_one()
        assert run.status == "failed"
        assert run.error and "404" in run.error


async def test_no_hostile_case_echoes_the_secret_in_the_logs(armed, jamf: FakeJamf, caplog: pytest.LogCaptureFixture) -> None:
    """The refusal is explained in the log, never in the response (the enumeration
    guard). That log must still never carry the secret itself — the stored one, or a
    wrong one a caller presented. Drive a credential refusal, a body refusal, and an
    accepted drop under capture, and sweep the whole captured text."""
    presented = "presented-wrong-secret-never-logged-4f1c"
    with caplog.at_level(logging.DEBUG):
        await _post(armed, headers={"X-API-Key": presented}, json={"event": {}})
        await _post(armed, headers=_AUTH, content=b"[]")
        await _post(armed, headers=_AUTH, json={"webhook": {"webhookEvent": "ComputerCheckIn"}, "event": {}})

    assert caplog.records, "nothing was logged, so the sweep would pass vacuously"
    assert WEBHOOK_SECRET not in caplog.text, "the stored secret reached a log line"
    assert presented not in caplog.text, "a presented secret reached a log line"


# Malformed authenticated bodies must never reach a server error.
_ROBUSTNESS: list[tuple[str, dict]] = [
    # Decoder recursion is a malformed-body refusal.
    ("a deeply nested JSON body", {"content": b"[" * 20000 + b"]" * 20000}),
    # A wrong-typed name is an ignored event.
    ("webhookEvent as a list", {"json": {"webhook": {"webhookEvent": ["ComputerAdded"]}, "event": {"jssID": 1}}}),
]


@pytest.mark.parametrize(
    ("label", "kwargs"),
    [pytest.param(label, kwargs, id=label) for (label, kwargs) in _ROBUSTNESS],
)
async def test_malformed_body_behind_a_valid_secret_should_be_a_clean_4xx(
    armed, jamf: FakeJamf, label: str, kwargs: dict
) -> None:
    headers = dict(_AUTH) if "content" in kwargs else {"X-API-Key": WEBHOOK_SECRET}
    response = await _post(armed, headers=headers, **kwargs)
    assert response.status_code == (422 if "content" in kwargs else 200), response.text
    assert not jamf.requests
