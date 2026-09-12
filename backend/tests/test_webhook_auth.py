"""The Jamf webhook is the only endpoint reachable without a session.

Jamf Pro does not sign its webhook payloads, so a per-connection shared secret is the
entire authentication. The assertion that matters most here is the negative one: an
unauthorized request must never reach `ingest_webhook`, because that is what turns the
endpoint into an amplification vector into the customer's Jamf tenant and a way to
inject arbitrary inventory into what gets streamed onward to their SIEM.

The route tests mount the router on a bare FastAPI app rather than importing
`app.main`, which would start a scheduler and open a database.
"""

from __future__ import annotations

import base64
import logging

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import webhooks
from app.api.webhooks import REJECTIONS, extract_presented_secret, presented_scheme, rejection_reason, secret_matches
from app.core.database import get_db
from app.models.schema import MdmConnection

_SECRET = "s3cret-shared-with-jamf"


def _basic(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


class TestExtractPresentedSecret:
    def test_x_api_key_is_the_primary_scheme(self) -> None:
        """What auth-design.md §4.7 specifies: Jamf Pro's Header Authentication takes a
        JSON object of header names to values, and the admin pastes
        `{"X-API-Key": "<secret>"}` — the object the setup panel shows (#406)."""
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
    """Mount the router alone, with the database and the ingest path stubbed out."""
    calls: list = []

    async def _fake_ingest_webhook(db, conn, payload):
        calls.append(conn)
        return None

    monkeypatch.setattr(webhooks, "ingest_webhook", _fake_ingest_webhook)

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
        assert response.json() == {"status": "ignored"}
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
        assert calls == [], f"{label}: unauthorized request reached ingest_webhook"


class TestPresentedScheme:
    """Which header a request carried, named and never valued: the half of a rejection
    that says what Jamf Pro was configured to send."""

    @pytest.mark.parametrize(
        ("api_key", "authorization", "expected"),
        [
            (_SECRET, None, "x-api-key"),
            (_SECRET, f"Bearer {_SECRET}", "x-api-key"),
            ("   ", f"Bearer {_SECRET}", "authorization-bearer"),
            (None, _basic("jamf", _SECRET), "authorization-basic"),
            (None, "BASIC abc", "authorization-basic"),
            (None, "Digest abc", "authorization-other"),
            (None, _SECRET, "authorization-other"),
            (None, None, "none"),
            (None, "   ", "none"),
            ("", "", "none"),
        ],
    )
    def test_names_the_header(self, api_key: str | None, authorization: str | None, expected: str) -> None:
        assert presented_scheme(api_key, authorization) == expected

    def test_never_carries_the_value(self) -> None:
        for api_key, authorization in ((_SECRET, None), (None, f"Bearer {_SECRET}"), (None, _basic("j", _SECRET))):
            assert _SECRET not in presented_scheme(api_key, authorization)


class TestRejectionReason:
    """Checked in the order an operator fixes them: this side's settings first, since no
    header Jamf Pro sends can be right before a secret exists to match it."""

    def test_unknown_connection_comes_first(self) -> None:
        assert rejection_reason(None, None, None) == "unknown_connection"
        assert rejection_reason(None, None, _SECRET) == "unknown_connection"

    def test_inactive_before_the_switch(self) -> None:
        connection = _connection(is_active=False, capability_webhooks=False)
        assert rejection_reason(connection, None, _SECRET) == "connection_inactive"

    def test_receiving_off_before_the_secret(self) -> None:
        connection = _connection(capability_webhooks=False, webhook_secret_encrypted=None)
        assert rejection_reason(connection, None, None) == "receiving_off"

    def test_no_secret_set_before_the_header(self) -> None:
        """No header can be right yet, so the header is not the next check."""
        assert rejection_reason(_connection(webhook_secret_encrypted=None), None, None) == "no_secret_set"
        # An empty stored value is no secret either.
        assert rejection_reason(_connection(webhook_secret_encrypted=""), "", _SECRET) == "no_secret_set"

    def test_no_header(self) -> None:
        assert rejection_reason(_connection(), _SECRET, None) == "no_header"

    def test_wrong_secret(self) -> None:
        assert rejection_reason(_connection(), _SECRET, "nope") == "wrong_secret"

    def test_every_reason_has_its_sentence(self) -> None:
        """A reason with no sentence would raise a KeyError on the rejection path —
        turning a clean 401 into a 500 for exactly the request the log was meant to
        explain."""
        reasons = {
            rejection_reason(None, None, None),
            rejection_reason(_connection(is_active=False), None, None),
            rejection_reason(_connection(capability_webhooks=False), None, None),
            rejection_reason(_connection(webhook_secret_encrypted=None), None, None),
            rejection_reason(_connection(), _SECRET, None),
            rejection_reason(_connection(), _SECRET, "nope"),
        }
        assert reasons == set(REJECTIONS)


def _rejections(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [record for record in caplog.records if record.getMessage().startswith("rejected jamf webhook: ")]


class TestTheRejectionIsExplainedInTheLogOnly:
    """The response is the same 401 for every refusal (the enumeration guard above); the
    container log is where the operator learns which refusal it was, and what to check
    next (docs/diagnosability.md rules 2 and 5, docs/troubleshooting.md §7)."""

    @pytest.mark.parametrize(
        ("connection", "headers", "reason", "presented"),
        [
            (_connection(), {}, "no_header", "none"),
            (
                _connection(),
                {"Authorization": "Basic " + base64.b64encode(b"no-colon").decode()},
                "no_header",
                "authorization-basic",
            ),
            (_connection(), {"X-API-Key": "nope"}, "wrong_secret", "x-api-key"),
            (_connection(), {"Authorization": "Bearer nope"}, "wrong_secret", "authorization-bearer"),
            (None, {"X-API-Key": _SECRET}, "unknown_connection", "x-api-key"),
            (_connection(is_active=False), {"X-API-Key": _SECRET}, "connection_inactive", "x-api-key"),
            (_connection(capability_webhooks=False), {"X-API-Key": _SECRET}, "receiving_off", "x-api-key"),
            (_connection(webhook_secret_encrypted=None), {"X-API-Key": _SECRET}, "no_secret_set", "x-api-key"),
        ],
    )
    def test_the_log_names_the_reason_and_the_response_does_not(
        self,
        connection: MdmConnection | None,
        headers: dict[str, str],
        reason: str,
        presented: str,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        client, calls = _client(connection, monkeypatch)

        with caplog.at_level(logging.WARNING, logger="app.api.webhooks"):
            response = client.post("/webhooks/jamf/1", json={"event": {}}, headers=headers)

        assert response.status_code == 401
        assert response.json() == {"detail": "Unauthorized"}
        assert calls == []

        [record] = _rejections(caplog)
        assert record.reason == reason
        assert record.presented == presented
        assert record.connection_id == 1
        assert record.getMessage() == f"rejected jamf webhook: {REJECTIONS[reason]}"

    def test_the_line_never_carries_a_secret(self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
        presented_value = "presented-value-never-logged-7c1d"
        client, _ = _client(_connection(), monkeypatch)

        with caplog.at_level(logging.DEBUG):
            client.post("/webhooks/jamf/1", json={"event": {}}, headers={"X-API-Key": presented_value})

        assert _rejections(caplog), "the rejection was not logged at all"
        assert presented_value not in caplog.text
        assert _SECRET not in caplog.text


class TestTheBodyIsReadAfterTheSecret:
    """A Jamf Pro webhook left on XML used to be refused with a 422 before the secret was
    checked, and the only trace was the request line. The body is now read only for a
    caller that proved the secret, and a body that is not JSON is refused in words."""

    def test_an_authenticated_xml_body_is_a_422_that_names_the_content_type(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        client, calls = _client(_connection(), monkeypatch)

        with caplog.at_level(logging.WARNING, logger="app.api.webhooks"):
            response = client.post(
                "/webhooks/jamf/1",
                content=b"<webhook><webhookEvent>ComputerInventoryCompleted</webhookEvent></webhook>",
                headers={"X-API-Key": _SECRET, "Content-Type": "text/xml"},
            )

        assert response.status_code == 422
        assert "content type to JSON" in response.json()["detail"]
        assert calls == []
        [record] = [r for r in caplog.records if r.getMessage().startswith("refused jamf webhook: the body is not a JSON object")]
        assert "set this webhook's content type to JSON" in record.getMessage()
        assert record.content_type == "text/xml"

    @pytest.mark.parametrize("body", [b"[]", b'"a string"', b"", b"{not json"])
    def test_anything_but_a_json_object_is_refused(self, body: bytes, monkeypatch: pytest.MonkeyPatch) -> None:
        client, calls = _client(_connection(), monkeypatch)

        response = client.post(
            "/webhooks/jamf/1", content=body, headers={"X-API-Key": _SECRET, "Content-Type": "application/json"}
        )

        assert response.status_code == 422
        assert calls == []

    def test_an_unauthenticated_xml_body_gets_the_same_401_as_everything_else(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Before the secret, the body is never read: a malformed body cannot become a
        second, distinguishable answer for an unauthenticated caller."""
        client, calls = _client(_connection(), monkeypatch)

        response = client.post(
            "/webhooks/jamf/1", content=b"<webhook/>", headers={"X-API-Key": "nope", "Content-Type": "text/xml"}
        )

        assert response.status_code == 401
        assert response.json() == {"detail": "Unauthorized"}
        assert calls == []
