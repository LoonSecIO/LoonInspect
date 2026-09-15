"""A refused request body is answered without the body (app.main's RequestValidationError
handler).

FastAPI's own 422 returns pydantic's errors with `input` on each: the value that was
refused, and for a missing field or a rule over the whole model, the whole body. So a
sign-in without its email sent the password back, a destination refused for its header
name sent the auth secret back, and a Settings > AI Save without its model sent the API
key back — into devtools, HAR files and any proxy that logs response bodies.

Two halves, neither needing a database. The public routes (sign-in, first-run setup) are
driven through the real `app.main.app`: a body is refused before the route runs, and
`get_db` only builds a session object, which connects on its first query and there is
none. The routes behind a session are covered here by the handlers `app.main` registers
over their real request schemas on a bare app, and through the real route in
test_ai_configs_db.py.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from pydantic import BaseModel, field_validator

from app import main as app_main
from app.core.security import MIN_PASSWORD_LENGTH
from app.schemas.accounts import AccountCreateRequest, PasswordChangeRequest, PasswordResetRequest
from app.schemas.ai import AIModelsIn, AITestIn
from app.schemas.connections import MdmConnectionCreate, MdmConnectionTestRequest
from app.schemas.destinations import DestinationCreate, DestinationUpdate

# Long and distinctive, so an absence assertion cannot pass by colliding with anything
# else a response carries.
SECRET = "sk-refused-body-vvq-3e9b71c4d2"
# Under the password floor, so its refusal is `string_too_short` — whose `input` is the
# password itself, not the body around it.
SHORT_PASSWORD = "pw-vvq-8c1d4"[: MIN_PASSWORD_LENGTH - 1]

JAMF = {"provider": "jamf", "baseUrl": "https://acme.jamfcloud.com"}
JAMF_CREDENTIALS = {"clientId": "looninspect", "clientSecret": SECRET}


def _refused(response: httpx.Response, *never: str) -> list[dict[str, Any]]:
    """A 422 in the shape the page reads — `detail` a list of {type, loc, msg}, with a
    `ctx` only where one survives — that carries none of `never` anywhere in its text."""
    assert response.status_code == 422, response.status_code
    for value in never:
        assert value not in response.text
    detail = response.json()["detail"]
    assert isinstance(detail, list) and detail
    for item in detail:
        assert {"type", "loc", "msg"} <= item.keys() <= {"type", "loc", "msg", "ctx"}, item.keys()
        assert item["loc"][0] == "body" and item["msg"]
    return detail


def _client(api: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=api), base_url="https://refused.example.com")


def _bare(model: type[BaseModel]) -> FastAPI:
    """POST /refused taking `model` as its body, answered by every exception handler
    `app.main` registers: the real handler over a real request schema, without the
    session the real route sits behind."""
    api = FastAPI()
    api.exception_handlers.update(app_main.app.exception_handlers)

    async def refused(body) -> None:
        return None

    # Set rather than written: the schema is this helper's argument, and a written
    # annotation is a string under this module's `from __future__`, looked up by name.
    refused.__annotations__["body"] = model
    api.post("/refused")(refused)
    return api


# --- the public routes, through the real app ---------------------------------------------------


async def test_a_sign_in_without_its_email_does_not_send_the_password_back() -> None:
    async with _client(app_main.app) as client:
        response = await client.post("/api/auth/login", json={"password": SECRET})
    assert _refused(response, SECRET) == [{"type": "missing", "loc": ["body", "email"], "msg": "Field required"}]


async def test_first_run_setup_keeps_the_password_floor_and_drops_the_password() -> None:
    """The bound is the schema's and stays; the value is the operator's and goes."""
    async with _client(app_main.app) as client:
        response = await client.post(
            "/api/auth/setup",
            json={"claimToken": SECRET, "email": "first@example.com", "displayName": "First", "password": SHORT_PASSWORD},
        )
    assert _refused(response, SECRET, SHORT_PASSWORD) == [
        {
            "type": "string_too_short",
            "loc": ["body", "password"],
            "msg": f"String should have at least {MIN_PASSWORD_LENGTH} characters",
            "ctx": {"min_length": MIN_PASSWORD_LENGTH},
        }
    ]


@pytest.mark.parametrize(
    "body",
    [[{"email": "someone@example.com", "password": SECRET}], SECRET],
    ids=["an-array", "a-string"],
)
async def test_a_json_body_that_is_not_an_object_is_refused_without_being_quoted(body: object) -> None:
    async with _client(app_main.app) as client:
        response = await client.post("/api/auth/login", json=body)
    assert _refused(response, SECRET) == [
        {
            "type": "model_attributes_type",
            "loc": ["body"],
            "msg": "Input should be a valid dictionary or object to extract fields from",
        }
    ]


async def test_a_body_that_is_not_json_is_refused_with_the_parsers_reason_and_not_the_body() -> None:
    raw = b'{"email": "someone@example.com", "password": "' + SECRET.encode() + b'"'
    async with _client(app_main.app) as client:
        response = await client.post("/api/auth/login", content=raw, headers={"content-type": "application/json"})
    assert _refused(response, SECRET) == [
        {
            "type": "json_invalid",
            "loc": ["body", len(raw)],
            "msg": "JSON decode error",
            "ctx": {"error": "Expecting ',' delimiter"},
        }
    ]


# --- the routes behind a session: their schemas, under app.main's handlers ------------------------


@pytest.mark.parametrize(
    ("model", "body", "never", "refusals"),
    [
        pytest.param(
            AITestIn,
            {"provider": "anthropic", "baseUrl": "https://api.anthropic.com", "model": "claude-opus-5", "apiKey": SECRET},
            (SECRET,),
            [("missing", ["body", "prompt"])],
            id="ai-test-box-without-a-prompt",
        ),
        pytest.param(
            AIModelsIn,
            {"provider": "anthropic", "apiKey": SECRET},
            (SECRET,),
            [("missing", ["body", "baseUrl"])],
            id="ai-model-list-without-a-url",
        ),
        pytest.param(
            AccountCreateRequest,
            {"email": "new@example.com", "displayName": "New", "password": SHORT_PASSWORD},
            (SHORT_PASSWORD,),
            [("string_too_short", ["body", "password"])],
            id="account-create-short-password",
        ),
        pytest.param(
            PasswordChangeRequest,
            {"currentPassword": SECRET},
            (SECRET,),
            [("missing", ["body", "newPassword"])],
            id="password-change-without-the-new-one",
        ),
        pytest.param(
            PasswordResetRequest,
            {"newPassword": SHORT_PASSWORD},
            (SHORT_PASSWORD,),
            [("string_too_short", ["body", "newPassword"])],
            id="password-reset-short-password",
        ),
        pytest.param(
            MdmConnectionCreate,
            {**JAMF, "credentials": JAMF_CREDENTIALS},
            (SECRET,),
            [("missing", ["body", "name"])],
            id="connection-create-without-a-name",
        ),
        pytest.param(
            MdmConnectionCreate,
            {**JAMF, "name": "Jamf", "patchManagementProvider": "loonsecio", "credentials": JAMF_CREDENTIALS},
            (SECRET,),
            [("value_error", ["body"])],
            id="connection-create-refused-by-a-model-rule",
        ),
        pytest.param(
            MdmConnectionTestRequest,
            {**JAMF, "clientSecret": SECRET},
            (SECRET,),
            [("missing", ["body", "clientId"])],
            id="connection-test-without-a-client-id",
        ),
        pytest.param(
            DestinationCreate,
            {"name": "SIEM", "url": "https://siem.example.com/hook", "authType": "header", "authSecret": SECRET},
            (SECRET,),
            [("value_error", ["body"])],
            id="destination-create-refused-by-a-model-rule",
        ),
        pytest.param(
            DestinationUpdate,
            {"authType": "header", "authSecret": SECRET},
            (SECRET,),
            [("value_error", ["body"])],
            id="destination-update-refused-by-a-model-rule",
        ),
    ],
)
async def test_a_body_carrying_a_secret_is_refused_without_it(
    model: type[BaseModel], body: dict[str, Any], never: tuple[str, ...], refusals: list[tuple[str, list[str]]]
) -> None:
    async with _client(_bare(model)) as client:
        response = await client.post("/refused", json=body)
    detail = _refused(response, *never)
    assert [(item["type"], item["loc"]) for item in detail] == refusals


async def test_a_model_rule_still_says_what_it_refused() -> None:
    """The sentence is the schema's and is the whole of what the page shows."""
    async with _client(_bare(DestinationCreate)) as client:
        response = await client.post(
            "/refused", json={"name": "SIEM", "url": "https://siem.example.com/hook", "authType": "header", "authSecret": SECRET}
        )
    assert _refused(response, SECRET) == [
        {"type": "value_error", "loc": ["body"], "msg": "Value error, authHeaderName is required when authType is 'header'"}
    ]


@pytest.mark.parametrize(
    ("model", "body", "ctx"),
    [
        pytest.param(
            DestinationCreate,
            {"name": "n" * 256, "url": "https://siem.example.com/hook", "authType": "bearer", "authSecret": SECRET},
            {"max_length": 255},
            id="a-length-bound",
        ),
        pytest.param(
            MdmConnectionCreate,
            {**JAMF, "name": "Jamf", "sweepPageSize": 5, "credentials": JAMF_CREDENTIALS},
            {"ge": 100},
            id="a-numeric-bound",
        ),
        pytest.param(
            DestinationCreate,
            {"name": "SIEM", "url": "https://siem.example.com/hook", "type": "syslog", "authSecret": SECRET},
            {"expected": "'generic_webhook', 'splunk_hec', 'elastic' or 'runreveal'"},
            id="the-allowed-values",
        ),
    ],
)
async def test_the_schemas_own_limits_stay_in_ctx(model: type[BaseModel], body: dict[str, Any], ctx: dict[str, Any]) -> None:
    async with _client(_bare(model)) as client:
        response = await client.post("/refused", json=body)
    [refusal] = _refused(response, SECRET)
    assert refusal["ctx"] == ctx


class _RefusedToken(ValueError):
    """A validator's exception that keeps the refused value on itself, as a library's
    might. FastAPI serialises an exception in `ctx` attribute by attribute."""

    def __init__(self, value: str) -> None:
        super().__init__("that token is not accepted")
        self.value = value


class _TokenIn(BaseModel):
    token: str

    @field_validator("token")
    @classmethod
    def _refuse(cls, value: str) -> str:
        raise _RefusedToken(value)


async def test_a_ctx_entry_that_is_not_the_schemas_own_is_dropped() -> None:
    """Why `ctx` is filtered and not only `input` dropped: here the value rides in `ctx`."""
    async with _client(_bare(_TokenIn)) as client:
        response = await client.post("/refused", json={"token": SECRET})
    assert _refused(response, SECRET) == [
        {"type": "value_error", "loc": ["body", "token"], "msg": "Value error, that token is not accepted"}
    ]


# --- a refusal the app words itself -------------------------------------------------------------


def test_a_partial_jamf_credential_set_is_refused_without_its_secret() -> None:
    """Not a request-validation error, so the handler above never sees it: connection create
    and update validate the credential set themselves and answer str(ValidationError), and
    pydantic's string quotes input_value — the whole set — unless the model hides it."""
    from fastapi import HTTPException

    from app.api.connections import _validate_credentials
    from app.schemas.payload import MdmProvider

    with pytest.raises(HTTPException) as refused:
        _validate_credentials(MdmProvider.jamf, {"clientSecret": SECRET})
    assert refused.value.status_code == 422
    detail = str(refused.value.detail)
    assert SECRET not in detail
    assert "clientId" in detail and "Field required" in detail


@pytest.mark.parametrize(
    "rule",
    [
        "validate_destination_url",
        "validate_mdm_base_url",
        "validate_inference_base_url",
        "validate_corpus_url",
    ],
)
def test_a_url_that_will_not_parse_is_refused_without_quoting_it(rule: str) -> None:
    """A basic-auth URL missing its host ("https://admin:<password>/…") fails to parse at the
    port, and the parser's own words quote the port — the password. The URL rules' sentences
    reach the 422's msg, so they name what to check instead of what was typed."""
    from app.core import egress

    check = getattr(egress, rule)
    url = f"https://admin:{SECRET}/services/collector"
    kwargs = {"carries_key": False} if rule == "validate_inference_base_url" else {}
    with pytest.raises(ValueError) as refused:
        check(url, **kwargs)
    assert SECRET not in str(refused.value)
    assert "not a URL this server can parse" in str(refused.value)
