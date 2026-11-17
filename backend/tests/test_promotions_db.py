"""Promoted applications (#793): the choice, the exchange body, and the refusals, through the whole door.

What is pinned here is the area's contract (docs/data-sharing.md, "Promoted applications"):

- **Off is unchanged.** With the `app_promotion` flag off, or nothing promoted, the request
  has no `promotions` key and is byte for byte the body the builder made before the area
  existed. The flag is the area's switch, so a title promoted earlier stops leaving when it
  goes off, and can still be withdrawn.
- **What leaves is inventory's, not the caller's.** A promotion is made by title key; the name
  and bundle ID are read from `installed_apps`, and each version row repeats the `full` key and
  count the snapshot already carries for it.
- **The exclude list wins**, at both ends: an excluded title cannot be promoted, and one
  excluded afterwards is held back with the pattern named.
- **A 413 sheds the promotions** and the share-log row says so, with the assembled payload kept.
- **It is an administrator's act**, audited with the title named.

The collector is an `httpx.MockTransport`; nothing here reaches a network. Needs a real Postgres.
"""

from __future__ import annotations

import json
import os
import uuid as uuidlib

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

ADMIN = ("promotions-admin@example.com", "promotions-admin-password")
AUDITOR = ("promotions-auditor@example.com", "promotions-auditor-password")
BASE = "/api/system/data-sharing/promotions"

SUFFIX = uuidlib.uuid4().hex[:6]
TAG = "promo-"
TOOL = ("Lakeside Tool", f"io.lakeside{SUFFIX}.tool")
NOTES = ("Lakeside Notes", f"io.lakeside{SUFFIX}.notes")
NAMELESS = ("No Bundle Tool", "")


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def accounts(tenant_ready) -> None:
    from app.core.bootstrap import create_account
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Account

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        for (email, password), role in ((ADMIN, "admin"), (AUDITOR, "auditor")):
            if (await db.execute(select(Account).where(Account.email == email))).scalars().first() is None:
                await create_account(db, email=email, display_name=role, password=password, roles=(role,))
        await db.commit()


async def _signed_in(email: str, password: str) -> httpx.AsyncClient:
    from app.main import app

    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://promotions.example.com")
    response = await client.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, f"login failed: {response.status_code} {response.text}"
    client.headers["X-CSRF-Token"] = client.cookies.get("loon_csrf", "")
    return client


@pytest_asyncio.fixture(loop_scope="session")
async def client(accounts):
    signed_in = await _signed_in(*ADMIN)
    try:
        yield signed_in
    finally:
        await signed_in.aclose()


async def _set_flag(db, enabled: bool) -> None:
    from app.core.feature_flags import APP_PROMOTION_FLAG
    from app.models.schema import FeatureFlag

    await db.rollback()
    flag = (await db.execute(select(FeatureFlag).where(FeatureFlag.key == APP_PROMOTION_FLAG))).scalar_one_or_none()
    if flag is None:
        db.add(FeatureFlag(key=APP_PROMOTION_FLAG, enabled=enabled))
    else:
        flag.enabled = enabled
    await db.commit()


def _title_key(app: tuple[str, str]) -> str:
    from app.core.content_keys import app_title_key

    return app_title_key(*app)


@pytest_asyncio.fixture(loop_scope="session")
async def fleet(db, monkeypatch):
    """Three Macs. Lakeside Tool is on two of them at two versions, Lakeside Notes on one, and
    one app has no bundle identifier. Sharing is at `keys`, the tier Support refuses `reveals`
    at, because a promotion has to work there. The flag starts off; each test turns it on.
    Everything this fixture wrote, and the tier and exclusions it found, go back afterwards."""
    from app.core import sharing
    from app.core.config import settings as app_settings
    from app.core.content_keys import app_full_key, app_title_key
    from app.core.feature_flags import APP_PROMOTION_FLAG
    from app.core.sharing import get_or_create_settings
    from app.models.schema import AppPromotion, Device, FeatureFlag, InstalledApp, ShareLog

    monkeypatch.setattr(sharing, "_RETRY_DELAYS", (0, 0, 0))
    monkeypatch.setattr(app_settings, "community_sharing", True)

    await db.rollback()
    await db.execute(delete(InstalledApp))
    await db.execute(delete(AppPromotion))
    await db.execute(delete(Device).where(Device.external_id.like(f"{TAG}%")))
    await db.execute(delete(ShareLog).where(ShareLog.tier != "ai"))
    row = await get_or_create_settings(db)
    original = (row.tier, list(row.exclude_globs or []))
    row.tier, row.exclude_globs, row.pending_reveal_keys = "keys", [], []
    await db.commit()
    await _set_flag(db, False)

    macs = [
        Device(mdm_provider="jamf", external_id=f"{TAG}{SUFFIX}{n}", serial_number=f"P{SUFFIX}{n}", hostname=f"p{SUFFIX}{n}")
        for n in range(3)
    ]
    db.add_all(macs)
    await db.commit()
    mac_ids = [mac.id for mac in macs]

    def app(mac, identity, version):
        name, bundle_id = identity
        return InstalledApp(
            device_id=mac.id,
            name=name,
            bundle_id=bundle_id,
            version=version,
            app_hash=uuidlib.uuid4().hex,
            version_hash=uuidlib.uuid4().hex,
            key_title=app_title_key(name, bundle_id),
            key_full=app_full_key(name, bundle_id, version, None),
        )

    db.add_all(
        [
            app(macs[0], TOOL, "2.1"),
            app(macs[1], TOOL, "2.4"),
            app(macs[2], TOOL, "2.4"),
            app(macs[0], NOTES, "9.0"),
            app(macs[1], NAMELESS, "1.0"),
        ]
    )
    await db.commit()
    yield
    await db.rollback()
    await db.execute(delete(AppPromotion))
    await db.execute(delete(InstalledApp))
    await db.execute(delete(Device).where(Device.id.in_(mac_ids)))
    await db.execute(delete(ShareLog).where(ShareLog.tier != "ai"))
    await db.execute(delete(FeatureFlag).where(FeatureFlag.key == APP_PROMOTION_FLAG))
    row = await get_or_create_settings(db)
    row.tier, row.exclude_globs = original
    await db.commit()


async def _body(db) -> dict:
    from app.core.sharing import build_exchange_request, get_or_create_settings

    await db.rollback()
    return await build_exchange_request(db, await get_or_create_settings(db))


def _audit_events(action: str) -> list[dict]:
    from app.core.audit import audit_path_for
    from app.core.tenancy import OPERATIONAL_TENANT_ID

    path = audit_path_for(str(OPERATIONAL_TENANT_ID))
    if not path.exists():
        return []
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    return [row for row in rows if row.get("action") == action]


async def test_off_the_flag_refuses_in_words_and_the_exchange_is_unchanged(client, db, fleet) -> None:
    before = json.dumps(await _body(db), sort_keys=True)

    refused = await client.post(BASE, json={"keyTitle": _title_key(TOOL)})
    assert refused.status_code == 409
    assert "Settings › Feature Flags" in refused.json()["detail"]

    listing = (await client.get(BASE)).json()
    assert (listing["enabled"], listing["paused"], listing["items"], listing["candidates"]) == (False, "flag_off", [], [])

    after = await _body(db)
    assert "promotions" not in after
    assert json.dumps(after, sort_keys=True) == before


async def test_a_promoted_title_leaves_by_name_with_the_keys_the_snapshot_already_sent(client, db, fleet) -> None:
    await _set_flag(db, True)
    before = await _body(db)
    assert "promotions" not in before  # the flag alone sends nothing: nothing is promoted yet

    listing = (await client.get(BASE)).json()
    assert listing["paused"] is None
    # Only titles with a bundle identifier can be promoted, so the nameless one is never offered.
    assert {c["bundleId"] for c in listing["candidates"]} == {TOOL[1], NOTES[1]}
    # The most installed first, among titles no public source knows.
    assert listing["candidates"][0]["bundleId"] == TOOL[1]
    assert all(c["known"] is False for c in listing["candidates"])

    made = await client.post(BASE, json={"keyTitle": _title_key(TOOL)})
    assert made.status_code == 201, made.text
    promoted = made.json()
    assert (promoted["appName"], promoted["bundleId"], promoted["promotedBy"]) == (TOOL[0], TOOL[1], ADMIN[0])
    assert (promoted["deviceCount"], promoted["versionCount"], promoted["held"]) == (3, 2, None)

    again = await client.post(BASE, json={"keyTitle": _title_key(TOOL)})
    assert (again.status_code, again.json()["id"]) == (200, promoted["id"])

    body = await _body(db)
    # Additive: everything the request carried before is still there, unchanged.
    assert {k: v for k, v in body.items() if k != "promotions"} == before
    [row] = body["promotions"]
    assert (row["title"], row["app_name"], row["bundle_id"]) == (_title_key(TOOL), TOOL[0], TOOL[1])
    snapshot = {a["full"]: a for a in body["snapshot"]["apps"] if a["title"] == _title_key(TOOL)}
    assert len(row["versions"]) == 2
    for version in row["versions"]:
        # Each version repeats a `full` key and count the snapshot states, so the name adds
        # plaintext and nothing else.
        assert version["count"] == snapshot[version["full"]]["count"]
        assert version["platform"] == snapshot[version["full"]]["platform"]
        assert version["short_version"] is None
    assert sorted((v["version"], v["count"]) for v in row["versions"]) == [("2.1", 1), ("2.4", 2)]

    listing = (await client.get(BASE)).json()
    assert [i["bundleId"] for i in listing["items"]] == [TOOL[1]]
    assert TOOL[1] not in {c["bundleId"] for c in listing["candidates"]}

    events = [e for e in _audit_events("sharing.promotion.added") if e.get("target_id") == promoted["id"]]
    assert len(events) == 1, "one audit event for the promotion, none for the repeated click"


async def test_the_exclude_list_wins_before_and_after_promoting(client, db, fleet) -> None:
    from app.core.sharing import get_or_create_settings

    await _set_flag(db, True)
    settings_row = await get_or_create_settings(db)
    settings_row.exclude_globs = [f"io.lakeside{SUFFIX}.notes"]
    await db.commit()

    refused = await client.post(BASE, json={"keyTitle": _title_key(NOTES)})
    assert refused.status_code == 409
    assert NOTES[1] in refused.json()["detail"] and "excluded pattern" in refused.json()["detail"]

    assert (await client.post(BASE, json={"keyTitle": _title_key(TOOL)})).status_code == 201
    await db.rollback()
    settings_row = await get_or_create_settings(db)
    settings_row.exclude_globs = [f"io.lakeside{SUFFIX}.*"]
    await db.commit()

    [item] = (await client.get(BASE)).json()["items"]
    assert (item["held"], item["excludedBy"]) == ("excluded", f"io.lakeside{SUFFIX}.*")
    assert "promotions" not in await _body(db)


async def test_what_cannot_be_promoted_is_refused_and_nothing_is_written(client, db, fleet) -> None:
    from app.models.schema import AppPromotion

    await _set_flag(db, True)
    for key in (_title_key(("Not Installed Anywhere", "io.example.absent")), _title_key(NAMELESS)):
        refused = await client.post(BASE, json={"keyTitle": key})
        assert refused.status_code == 409
        assert "no device in this organization has that application installed" in refused.json()["detail"]
    assert (await client.post(BASE, json={"keyTitle": "not-a-key"})).status_code == 422

    await db.rollback()
    assert (await db.execute(select(AppPromotion))).scalars().all() == []


async def test_switching_the_area_or_sharing_off_stops_the_names_and_withdrawing_still_works(client, db, fleet) -> None:
    from app.core.sharing import get_or_create_settings

    await _set_flag(db, True)
    promoted = (await client.post(BASE, json={"keyTitle": _title_key(TOOL)})).json()
    assert "promotions" in await _body(db)

    settings_row = await get_or_create_settings(db)
    settings_row.tier = "off"
    await db.commit()
    assert (await client.get(BASE)).json()["paused"] == "sharing_off"
    await db.rollback()
    settings_row = await get_or_create_settings(db)
    settings_row.tier = "keys"
    await db.commit()

    await _set_flag(db, False)
    assert "promotions" not in await _body(db)
    listing = (await client.get(BASE)).json()
    # The choice is kept and shown; it is the sending that stopped.
    assert (listing["paused"], [i["id"] for i in listing["items"]]) == ("flag_off", [promoted["id"]])

    assert (await client.delete(f"{BASE}/{promoted['id']}")).status_code == 204
    assert (await client.delete(f"{BASE}/{promoted['id']}")).status_code == 404
    assert (await client.get(BASE)).json()["items"] == []
    assert [e for e in _audit_events("sharing.promotion.removed") if e.get("target_id") == promoted["id"]]


async def test_a_413_sheds_the_promotions_and_the_row_says_so(client, db, fleet, monkeypatch) -> None:
    await _set_flag(db, True)
    assert (await client.post(BASE, json={"keyTitle": _title_key(TOOL)})).status_code == 201

    received: list[dict] = []

    def collector(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        received.append(body)
        return httpx.Response(413 if "promotions" in body else 200, json={"contract": "v1"})

    monkeypatch.setattr("app.api.system.transport_override", httpx.MockTransport(collector))
    sent = await client.post("/api/system/data-sharing/send")
    assert sent.status_code == 200, sent.text
    exchange = sent.json()["exchange"]

    assert [("promotions" in body) for body in received] == [True, False]
    # The snapshot is never shrunk: the retry is the same body without the names.
    assert received[1] == {k: v for k, v in received[0].items() if k != "promotions"}
    assert (exchange["outcome"], exchange["promotionsShed"], exchange["revealsShed"]) == ("sent", True, False)
    # The row keeps what the run assembled, and the marker says which part did not leave.
    assert exchange["payload"]["promotions"][0]["bundle_id"] == TOOL[1]
    assert sent.json()["settings"]["lastExchangePromotionsShed"] is True

    received.clear()
    monkeypatch.setattr("app.api.system.transport_override", httpx.MockTransport(lambda request: httpx.Response(200, json={})))
    whole = (await client.post("/api/system/data-sharing/send")).json()
    assert (whole["exchange"]["promotionsShed"], whole["settings"]["lastExchangePromotionsShed"]) == (False, False)


async def test_promoting_is_an_administrators_act(accounts, db, fleet) -> None:
    await _set_flag(db, True)
    auditor = await _signed_in(*AUDITOR)
    try:
        assert (await auditor.post(BASE, json={"keyTitle": _title_key(TOOL)})).status_code == 403
        assert (await auditor.delete(f"{BASE}/{uuidlib.uuid4()}")).status_code == 403
    finally:
        await auditor.aclose()
