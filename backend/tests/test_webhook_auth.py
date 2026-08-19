"""The Jamf webhook is the only endpoint reachable without a session.

Jamf Pro does not sign its webhook payloads, so a per-connection shared secret is the
entire authentication. The assertion that matters most here is the negative one: an
unauthorized request must never reach `process_sync`, because that is what turns the
endpoint into an amplification vector into the customer's Jamf tenant and a way to
inject arbitrary inventory into what gets streamed onward to their SIEM.

The route tests mount the router on a bare FastAPI app rather than importing
`app.main`, which would start a scheduler and open a database.
"""

from __future__ import annotations

import base64

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import webhooks
from app.api.webhooks import extract_presented_secret, secret_matches
from app.core.database import get_db
from app.models.schema import MdmConnection

_SECRET = "s3cret-shared-with-jamf"


def _basic(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


class TestExtractPresentedSecret:
    def test_x_api_key_is_the_primary_scheme(self) -> None:
        """What auth-design.md §4.7 specifies: Jamf Pro supports Header Authentication
        natively, so the admin pastes a header name and static value."""
        assert extract_presented_secret(_SECRET, None) == _SECRET

    def test_x_api_key_wins_over_authorization(self) -> None:
        assert extract_presented_secret(_SECRET, "Bearer something-else") == _SECRET

    def test_blank_x_api_key_falls_through_to_authorization(self) -> None:
        assert extract_presented_secret("   ", f"Bearer {_SECRET}") == _SECRET

    def test_bearer(self) -> None:
        assert extract_presented_secret(None, f"Bearer {_SECRET}") == _SECRET

    def test_basic_uses_the_password_half(self) -> None:
        """Jamf Pro's webhook UI offers Basic auth, and what is stored is one opaque
        secret rather than a credential pair, so the username is ignored."""
        assert extract_presented_secret(None, _basic("jamf", _SECRET)) == _SECRET
        assert extract_presented_secret(None, _basic("", _SECRET)) == _SECRET

    def test_scheme_is_case_insensitive(self) -> None:
        assert extract_presented_secret(None, f"bearer {_SECRET}") == _SECRET
        assert extract_presented_secret(None, _basic("j", _SECRET).replace("Basic", "BASIC")) == _SECRET

    def test_secret_may_contain_a_colon(self) -> None:
        """`partition` splits once, so only the first colon separates user from
        password — a secret containing colons must survive intact."""
        assert extract_presented_secret(None, _basic("jamf", "a:b:c")) == "a:b:c"

    @pytest.mark.parametrize(
        "header",
        [
            None,
            "",
            "Bearer",
            "Bearer ",
            "Basic ",
            "Digest abc",
            "Basic !!!not-base64!!!",
            "Basic " + base64.b64encode(b"no-colon-here").decode(),
            _SECRET,
        ],
    )
    def test_unusable_headers_yield_none(self, header: str | None) -> None:
        assert extract_presented_secret(None, header) is None


class TestSecretMatches:
    def test_matching_secret_passes(self) -> None:
        assert secret_matches(_SECRET, _SECRET) is True

    def test_wrong_secret_fails(self) -> None:
        assert secret_matches("wrong", _SECRET) is False

    def test_fails_closed_when_no_secret_is_configured(self) -> None:
        """An operator who never set a secret gets an endpoint that rejects
        everything, not one that accepts everything."""
        assert secret_matches(_SECRET, None) is False
        assert secret_matches(None, None) is False
        assert secret_matches("", None) is False

    def test_missing_credential_fails(self) -> None:
        assert secret_matches(None, _SECRET) is False

    def test_empty_presented_secret_never_matches(self) -> None:
        assert secret_matches("", "") is False


def _client(connection: MdmConnection | None, monkeypatch: pytest.MonkeyPatch) -> tuple[TestClient, list]:
    """Mount the router alone, with the database and the sync path stubbed out."""
    calls: list = []

    async def _fake_process_sync(db, device, conn):
        calls.append(conn)

    def _fake_get_mdm_client(conn):
        class _Client:
            @staticmethod
            def parse_webhook(payload: dict) -> dict:
                return payload

        return _Client()

    monkeypatch.setattr(webhooks, "process_sync", _fake_process_sync)
    monkeypatch.setattr(webhooks, "get_mdm_client", _fake_get_mdm_client)

    class _FakeSession:
        async def get(self, model, primary_key):
            return connection

    api = FastAPI()
    api.include_router(webhooks.router)
    api.dependency_overrides[get_db] = lambda: _FakeSession()
    return TestClient(api), calls


def _connection(**overrides) -> MdmConnection:
    fields = {
        "id": 1,
        "is_active": True,
        "capability_webhooks": True,
        "webhook_secret_encrypted": _SECRET,
    }
    return MdmConnection(**(fields | overrides))


class TestJamfWebhookRoute:
    def test_correct_secret_is_accepted_and_syncs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client, calls = _client(_connection(), monkeypatch)

        response = client.post("/webhooks/jamf/1", json={"event": {}}, headers={"Authorization": f"Bearer {_SECRET}"})

        assert response.status_code == 200
        assert response.json() == {"status": "accepted"}
        assert len(calls) == 1

    def test_x_api_key_is_accepted_and_syncs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The scheme an admin actually configures in Jamf Pro."""
        client, calls = _client(_connection(), monkeypatch)

        response = client.post("/webhooks/jamf/1", json={"event": {}}, headers={"X-API-Key": _SECRET})

        assert response.status_code == 200
        assert len(calls) == 1

    def test_wrong_x_api_key_is_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client, calls = _client(_connection(), monkeypatch)

        response = client.post("/webhooks/jamf/1", json={"event": {}}, headers={"X-API-Key": "nope"})

        assert response.status_code == 401
        assert calls == []

    def test_jamf_style_basic_auth_is_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client, calls = _client(_connection(), monkeypatch)

        response = client.post("/webhooks/jamf/1", json={"event": {}}, headers={"Authorization": _basic("jamf", _SECRET)})

        assert response.status_code == 200
        assert len(calls) == 1

    @pytest.mark.parametrize(
        ("label", "connection", "header"),
        [
            ("no header at all", _connection(), None),
            ("wrong secret", _connection(), "Bearer nope"),
            ("unknown connection", None, f"Bearer {_SECRET}"),
            ("inactive connection", _connection(is_active=False), f"Bearer {_SECRET}"),
            ("webhooks not enabled", _connection(capability_webhooks=False), f"Bearer {_SECRET}"),
            ("no secret configured", _connection(webhook_secret_encrypted=None), f"Bearer {_SECRET}"),
        ],
    )
    def test_every_rejection_is_an_identical_401(
        self, label: str, connection: MdmConnection | None, header: str | None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The enumeration guard. A 404 for an unknown id and a 401 for a wrong secret
        would tell an unauthenticated caller which of the small sequential connection
        ids are real."""
        client, calls = _client(connection, monkeypatch)
        headers = {"Authorization": header} if header else {}

        response = client.post("/webhooks/jamf/1", json={"event": {}}, headers=headers)

        assert response.status_code == 401, label
        assert response.json() == {"detail": "Unauthorized"}, label
        assert response.headers["WWW-Authenticate"] == 'Basic realm="jamf-webhook"', label
        assert calls == [], f"{label}: unauthorized request reached process_sync"
