"""Webhook inputs fail before a database bind, outbound read, or inventory write."""

import httpx
import pytest

from app.api import webhooks
from app.mdm.jamf.client import JamfClient, computer_id, parse_webhook_event
from tests.test_webhook_auth import _SECRET, _client, _connection


@pytest.mark.parametrize("header", [b"x-api-key", b"authorization"])
@pytest.mark.parametrize("known", [True, False])
def test_non_ascii_credentials_are_refused(monkeypatch, header, known):
    client, calls = _client(_connection() if known else None, monkeypatch)
    value = b"\xe9" if header == b"x-api-key" else b"Bearer \xe9"
    response = client.post("/webhooks/jamf/1", headers=[(header, value)], json={})
    assert response.status_code == 401
    assert response.json() == {"detail": "Unauthorized"}
    assert response.headers["www-authenticate"] == 'Basic realm="jamf-webhook"'
    assert calls == []


@pytest.mark.parametrize("identifier", [-(2**31) - 1, 2**31, 10**100, -(10**100)])
def test_out_of_range_ids_do_not_reach_lookup(monkeypatch, identifier):
    client, calls = _client(_connection(), monkeypatch)

    class NoLookup:
        async def get(self, *args):
            pytest.fail("an unrepresentable id reached the database")

    client.app.dependency_overrides[webhooks.get_db] = lambda: NoLookup()
    response = client.post(f"/webhooks/jamf/{identifier}", headers={"X-API-Key": _SECRET}, json={})
    assert response.status_code == 401
    assert response.json() == {"detail": "Unauthorized"}
    assert not calls


@pytest.mark.parametrize(
    "value", [True, False, 1.5, [], {}, -1, "", "1/2", "../1", "1?q=2", "1#x", "1\n", "1\x00", "١", "1" * 21]
)
async def test_invalid_computer_id_never_reaches_http(value):
    assert computer_id(value) is None
    client = JamfClient("https://jamf.test", "client", "secret")

    def no_request(request):
        pytest.fail("an invalid id reached HTTP")

    async with httpx.AsyncClient(transport=httpx.MockTransport(no_request)) as http:
        with pytest.raises(ValueError, match="computer id"):
            await client.fetch_computer_detail(http, value)
    for nested in (False, True):
        for key in ("id", "jssID"):
            computer = {key: value}
            payload = {"webhook": {"webhookEvent": "ComputerAdded"}, "event": {"computer": computer} if nested else computer}
            assert parse_webhook_event(payload).jamf_id is None


@pytest.mark.parametrize("value,expected", [(0, "0"), (52, "52"), ("52", "52"), ("0052", "52"), (10**20 - 1, "9" * 20)])
def test_decimal_ids_are_preserved(value, expected):
    assert computer_id(value) == expected


@pytest.mark.parametrize("name", [[], {}, True, 5, None])
def test_wrong_typed_names_are_ignored(name):
    assert parse_webhook_event({"webhook": {"webhookEvent": name}}).event_name is None
