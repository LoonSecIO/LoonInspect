"""Submission cases (#623): the key, the payload and each answer, against an `httpx.MockTransport`. No
database: `Stub` stands in for the session too; test_submissions_db.py runs the calls on PostgreSQL."""

import json
from datetime import UTC, datetime

import httpx
import pytest

from app.core import submissions
from app.models.schema import SubmissionCase

ACK = {"contract": "v2", "state": "received", "received_at": "2026-09-26T12:00:00Z"}
STATUS = ACK | {"closed_at": None, "release": None, "coverage": None, "note": None}
DONE = STATUS | {"closed_at": "2026-10-02T09:30:00Z", "release": "ab" * 32, "coverage": "Both builds."}
WIRESHARK = {"kind": "correction", "app_name": "Wireshark", "bundle_id": "org.wireshark.Wireshark", "platform": "macos"}
WORDS = {"versions": ["3.6.2"], "text": "3.6.2 predates the affected code.", "contact": "security@example.com"}
GONE, ELSEWHERE = (404, {"error": "Unknown or expired case key."}), (404, {"message": "Not Found"})
URL_RULE = (  # Support's refusal, verbatim (src/exchange/submissions.py at 8690bd3): 387 characters
    "public_url, when present, must be an https:// address of at most 512 visible ASCII characters (percent-encode anything"
    " else, and write an internationalized host name in its xn-- form) on a public host name of ASCII letters, digits, hyphens,"
    " underscores and dots, with a port, if any, from 1 to 65535: no IP address in any form, no .local or .localhost name, and"
    " no user name or password."
)


@pytest.fixture(autouse=True)
def preview_on(monkeypatch):
    monkeypatch.setattr(submissions.settings, "intelligence_endpoint", "https://service.example")
    monkeypatch.setattr(submissions.settings, "intelligence_access", True)


def correction(**changes) -> SubmissionCase:
    fields = {"finding": "CVE-2024-0208", "finding_release": "ab" * 32, "state": "pending", "permission_at": datetime.now(UTC)}
    return SubmissionCase(**(WIRESHARK | WORDS | fields | {"case_key": submissions.mint_case_key()} | changes))


class Stub:
    """The session and the service at once, logging both: the case comes back under its lock, a commit
    stores its key, and the answers come in turn ("lost" never arrives)."""

    def __init__(self, case, *answers):
        self.case, self.answers, self.log, self.requests = case, list(answers), [], []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        self.log.append(("sent", json.loads(request.content)["case_key"]))
        if (answer := self.answers.pop(0)) == "lost":
            raise httpx.ReadTimeout("no answer", request=request)
        return httpx.Response(answer[0], json=answer[1], headers=answer[2] if len(answer) > 2 else None)

    async def execute(self, _query):
        return self

    def scalar_one(self) -> SubmissionCase:
        return self.case

    async def commit(self) -> None:
        self.log.append(("stored", self.case.case_key))


def test_a_key_is_43_canonical_base64url_characters_and_never_repeats():
    keys = {submissions.mint_case_key() for _ in range(1000)}
    assert len(keys) == 1000 and all(submissions.KEY.fullmatch(key) for key in keys)
    assert not submissions.KEY.fullmatch("loon_case_" + "A" * 42 + "B"), "a set spare bit spells the same bytes twice"


def test_the_payload_is_exactly_the_contracts_fields_and_carries_no_count():
    payload = submissions.payload_for(correction())
    assert payload.keys() == {"contract", "case_key", *WIRESHARK, *WORDS, "finding", "finding_release"}
    assert all(isinstance(value, str) or all(isinstance(item, str) for item in value) for value in payload.values())
    coverage = correction(kind="coverage", bundle_id=None, text="", contact=None)
    expected = {"contract": "v2", "case_key": coverage.case_key, "kind": "coverage", "app_name": "Wireshark"}
    assert submissions.payload_for(coverage) == expected | {"platform": "macos", "versions": ["3.6.2"]}


@pytest.mark.parametrize(
    ("act", "state", "answer", "after", "says"),
    [
        ("send", "pending", (202, ACK), "received", None),
        ("send", "pending", (400, {"error": "versions must list 1 to 20 strings."}), "pending", 'It said: "versions'),
        pytest.param("send", "pending", (400, {"error": URL_RULE}), "pending", f'"{URL_RULE}" Nothing', id="url-rule"),
        pytest.param("send", "pending", (400, {"error": "x" * 5000}), "pending", f'"{"x" * submissions.SAID}…"', id="cut"),
        ("send", "pending", (400, {"error": "Two\nlines."}), "pending", "(HTTP 400). Nothing was stored"),
        ("send", "pending", (429, {"message": "Too Many Requests"}), "pending", "HTTP 429. Try again later"),
        ("send", "pending", (503, {"error": "Today's budget is spent."}, {"Retry-After": "120"}), "pending", "Try again after"),
        ("send", "pending", (403, {"message": "Missing Authentication Token"}), "pending", "INTELLIGENCE_ENDPOINT"),
        ("refresh", "received", (200, DONE | {"state": "published"}), "published", None),
        ("refresh", "received", (200, DONE | {"state": "withdrawn"}), "withdrawn", None),
        ("refresh", "received", (429, {"error": "At most once a minute."}, {"Retry-After": "30"}), "received", "HTTP 429"),
        ("refresh", "received", GONE, "expired", None),
        ("refresh", "received", ELSEWHERE, "received", "INTELLIGENCE_ENDPOINT"),
        ("withdraw", "received", (200, DONE | {"state": "withdrawn"}), "withdrawn", None),
        ("withdraw", "pending", GONE, "withdrawn", None),
    ],
)
async def test_each_answer_lands_on_the_case(act, state, answer, after, says):
    stub = Stub(correction(state=state, public_url="https://www.wireshark.org/security/"), answer)
    case = await getattr(submissions, act)(stub, stub.case, transport=httpx.MockTransport(stub))
    if act == "refresh" or len(answer) > 2:  # the poll floor, or Retry-After: the next attempt sends nothing
        assert await getattr(submissions, act)(stub, case, transport=httpx.MockTransport(stub)) is case
    assert case.state == after and (case.last_error is None if says is None else says in case.last_error)
    assert len(stub.requests) == 1 and "authorization" not in stub.requests[0].headers and not stub.requests[0].url.query
    assert (case.release, case.coverage) == ((DONE["release"], "Both builds.") if answer[0] == 200 else (None, None))
    assert (case.retry_at is not None) == (len(answer) > 2) and (case.last_status_at is not None) == (act == "refresh")
    typed = (case.public_url, case.text, case.contact)
    assert typed == (None, None, None) if after == "withdrawn" else all(typed), "withdrawal clears what was written"
    assert (case.withdrawn_at is not None) == (after == "withdrawn"), "whichever answer brings the withdrawal"


async def test_a_lost_withdrawal_answer_keeps_no_words_and_sends_nothing_until_an_answer_settles_it():
    """The act is stored before the request leaves. The next answer settles it, a status read's or a repeat
    withdrawal's (the contract answers a repeat with 200), and then nothing leaves again."""
    withdrawn = (200, DONE | {"state": "withdrawn"})
    for state, then in (("received", submissions.refresh), ("pending", submissions.withdraw)):
        stub = Stub(correction(state=state, public_url="https://www.wireshark.org/security/"), "lost", withdrawn)
        case = await submissions.withdraw(stub, stub.case, transport=httpx.MockTransport(stub))
        asked, typed = case.withdrawn_at, (case.public_url, case.text, case.contact)
        assert case.state == state and asked and typed == (None, None, None) and "No answer came" in case.last_error
        assert [what for what, _ in stub.log] == ["stored", "sent", "stored"], "the act is stored before it leaves"
        for act in (submissions.send, then, submissions.withdraw, submissions.send):  # only `then` asks
            case = await act(stub, case, transport=httpx.MockTransport(stub))
        assert (case.state, case.withdrawn_at, case.last_error, len(stub.requests)) == ("withdrawn", asked, None, 2)
    stale = Stub(correction(state="withdrawn"))  # withdrawn with its words still here: cleared without a request
    case = await submissions.withdraw(stale, stale.case, transport=httpx.MockTransport(stale))
    assert case.withdrawn_at and (case.text, case.contact) == (None, None) and stale.requests == []


async def test_a_lost_answer_is_retried_as_the_identical_request():
    stub = Stub(correction(), "lost", (202, ACK))
    case = await submissions.send(stub, stub.case, transport=httpx.MockTransport(stub))
    assert case.state == "pending" and "No answer came from the intelligence service" in case.last_error
    for _ in range(2):  # the second finds the case received, and nothing leaves
        case = await submissions.send(stub, case, transport=httpx.MockTransport(stub))
    first, second = stub.requests
    assert first.content == second.content and json.loads(first.content) == submissions.payload_for(case)
    assert str(first.url) == "https://service.example/v2/submissions" and case.received_at.hour == 12


async def test_a_409_gets_one_fresh_key_stored_before_it_is_sent_then_a_sentence():
    refusal = (409, {"error": "This case key already names a different submission."})
    stub = Stub(correction(), refusal, refusal)
    first = stub.case.case_key
    case = await submissions.send(stub, stub.case, transport=httpx.MockTransport(stub))
    fresh = case.case_key
    assert stub.log == [("stored", first), ("sent", first), ("stored", fresh), ("sent", fresh), ("stored", fresh)]
    assert first != fresh and case.state == "pending" and "Contact support" in case.last_error


async def test_nothing_leaves_without_permission_or_with_the_preview_off(monkeypatch):
    stub = Stub(correction(permission_at=None))
    assert "no permission" in (await submissions.send(stub, stub.case)).last_error
    monkeypatch.setattr(submissions.settings, "intelligence_access", False)
    assert "INTELLIGENCE_ACCESS" in (await submissions.send(stub, stub.case)).last_error and stub.requests == []
