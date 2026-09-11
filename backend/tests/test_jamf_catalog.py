"""The Jamf patch catalog sync, without a session.

Its pure helpers, because each one fails quietly rather than loudly: a title that does
not parse is skipped with `continue`, a requirement group collapsed wrongly still
produces well-formed JSON, and `_needs_refresh` returning the wrong answer either
re-fetches the entire catalog every hour or never refreshes it again. None of the three
raises.

And the two halves of the source seam (#382) that need no database: the fan-out bound,
which is a promise to a public server and is invisible in the rows it produces, and the
Jamf source's addresses, which now come from a setting. `sync_catalog` end to end —
fixture in, rows out — is `test_jamf_catalog_sync_db.py`.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

import httpx
import pytest

from app.core import config as config_module
from app.core.config import Settings, settings
from app.mdm.patch import jamf_catalog
from app.mdm.patch.jamf_catalog import (
    DETAIL_CONCURRENCY,
    JAMF_PATCH_BASE_URL_UNUSABLE,
    JamfApiCatalogSource,
    JamfPatchCatalogUnconfigured,
    _convert_requirements,
    _extension_attributes,
    _fetch_details,
    _needs_refresh,
    _remove_embedded_cert,
    _strip_patch_entry,
    jamf_api_source,
)
from app.models.schema import JamfPatchTitle

DOCS = Path(__file__).resolve().parents[2] / "docs"


def _requirement(name: str, *, and_linked: bool | None = True) -> dict:
    requirement = {"name": name, "operator": "is", "value": "1", "type": "recon"}
    if and_linked is not None:
        requirement["and"] = and_linked
    return requirement


class TestRemoveEmbeddedCert:
    def test_strips_the_certificate_envelope(self) -> None:
        body = '\x30\x82CERT{"name":"Slack","patches":[{"version":"4.0.1"}]}\n-----END-----'
        assert _remove_embedded_cert(body) == {"name": "Slack", "patches": [{"version": "4.0.1"}]}

    def test_passes_an_unwrapped_body_through(self) -> None:
        assert _remove_embedded_cert('{"name":"Slack","patches":[]}') == {"name": "Slack", "patches": []}

    def test_returns_empty_for_a_body_with_no_json(self) -> None:
        assert _remove_embedded_cert("no json here at all") == {}

    def test_returns_empty_for_an_empty_body(self) -> None:
        assert _remove_embedded_cert("") == {}

    def test_returns_empty_for_malformed_json(self) -> None:
        assert _remove_embedded_cert('{"a":[1,,2]}') == {}

    def test_keeps_valid_json_whatever_its_last_key_is(self) -> None:
        """The old right-hand trim walked back to `]}` and discarded a document whose final
        key was not an array; the first JSON object is now parsed as-is."""
        assert _remove_embedded_cert('{"name":"Slack","patches":{}}') == {"name": "Slack", "patches": {}}

    def test_ignores_a_trailing_certificate_that_itself_contains_the_closing_bytes(self) -> None:
        """Six real titles (Audio Hijack, JetBrains Gateway, ESET, …) were silently skipped
        because the signature after the JSON happened to contain `]}`."""
        body = '\x30\x82{"id":"5BE","name":"Audio Hijack","patches":[{"version":"4.5.0"}]}\x00\x82]}\x1f\x10'
        assert _remove_embedded_cert(body) == {"id": "5BE", "name": "Audio Hijack", "patches": [{"version": "4.5.0"}]}

    def test_skips_a_false_start_in_the_envelope(self) -> None:
        assert _remove_embedded_cert('junk{"nope  {"name":"Slack","patches":[]}') == {"name": "Slack", "patches": []}


class TestConvertRequirements:
    def test_empty_requirements_produce_no_groups(self) -> None:
        assert _convert_requirements([]) == []

    def test_and_linked_requirements_share_one_group(self) -> None:
        groups = _convert_requirements([_requirement("a"), _requirement("b")])

        assert len(groups) == 1
        assert [test["name"] for test in groups[0]["tests"]] == ["a", "b"]
        assert groups[0]["operator"] == "and"

    def test_a_non_and_linked_requirement_opens_a_new_group(self) -> None:
        """The OR seam. Flattening these into one group would turn "matches A or B"
        into "matches A and B" and stop the title matching anything."""
        groups = _convert_requirements([_requirement("a"), _requirement("b", and_linked=False)])

        assert [[test["name"] for test in group["tests"]] for group in groups] == [["a"], ["b"]]

    def test_a_missing_and_key_defaults_to_and_linked(self) -> None:
        groups = _convert_requirements([_requirement("a"), _requirement("b", and_linked=None)])

        assert len(groups) == 1

    def test_the_first_requirements_and_flag_is_ignored(self) -> None:
        """There is no preceding group to close, so a leading `and: false` must not
        open an empty one — an empty leading group would AND against nothing and match
        every title."""
        groups = _convert_requirements([_requirement("a", and_linked=False)])

        assert len(groups) == 1
        assert [test["name"] for test in groups[0]["tests"]] == ["a"]

    def test_each_test_keeps_the_four_matching_fields(self) -> None:
        """`bundle_id` is only a prefilter — these criteria are what actually decides a
        match, because duplicate bundle_ids appear across major-version titles."""
        groups = _convert_requirements([_requirement("Application Bundle ID")])

        assert groups[0]["tests"][0] == {
            "name": "Application Bundle ID",
            "operator": "is",
            "value": "1",
            "type": "recon",
        }


class TestStripPatchEntry:
    def test_drops_the_bulky_keys(self) -> None:
        patch = {
            "version": "4.0.1",
            "releaseDate": "2024-01-01",
            "standalone": True,
            "minimumOperatingSystem": "12.0",
            "reboot": False,
            "killApps": [],
            "components": [],
            "capabilities": [],
        }

        assert _strip_patch_entry(patch) == {"version": "4.0.1", "releaseDate": "2024-01-01"}

    def test_keeps_an_entry_with_nothing_to_strip(self) -> None:
        assert _strip_patch_entry({"version": "4.0.1"}) == {"version": "4.0.1"}


class TestNeedsRefresh:
    def test_an_unseen_title_needs_refreshing(self) -> None:
        assert _needs_refresh(None, {"id": "slack", "lastModified": "1", "currentVersion": "4.0.1"}) is True

    def test_an_unchanged_title_does_not(self) -> None:
        """The whole point of the check: without it every hourly tick re-fetches the
        full detail payload for every title in the catalog."""
        existing = JamfPatchTitle(id="slack", last_modified="1", current_version="4.0.1", extension_attributes=[])

        assert _needs_refresh(existing, {"id": "slack", "lastModified": "1", "currentVersion": "4.0.1"}) is False

    def test_a_changed_last_modified_triggers_a_refresh(self) -> None:
        existing = JamfPatchTitle(id="slack", last_modified="1", current_version="4.0.1")

        assert _needs_refresh(existing, {"id": "slack", "lastModified": "2", "currentVersion": "4.0.1"}) is True

    def test_a_changed_current_version_triggers_a_refresh(self) -> None:
        existing = JamfPatchTitle(id="slack", last_modified="1", current_version="4.0.1")

        assert _needs_refresh(existing, {"id": "slack", "lastModified": "1", "currentVersion": "4.1.0"}) is True

    def test_a_row_without_extension_attributes_is_refreshed_once(self) -> None:
        """Null marks a row fetched before the column existed; the next sync fills it."""
        existing = JamfPatchTitle(id="slack", last_modified="1", current_version="4.0.1", extension_attributes=None)
        summary = {"id": "slack", "lastModified": "1", "currentVersion": "4.0.1"}
        assert _needs_refresh(existing, summary) is True
        existing.extension_attributes = []
        assert _needs_refresh(existing, summary) is False


class TestExtensionAttributes:
    def test_keeps_key_and_display_name_and_drops_the_script(self) -> None:
        definition = {"key": "jamf-patch-nodejs-14", "displayName": "Node.js 14 Version", "value": "IyEvYmlu"}
        detail = {"extensionAttributes": [definition]}
        assert _extension_attributes(detail) == [{"key": "jamf-patch-nodejs-14", "displayName": "Node.js 14 Version"}]

    def test_missing_or_malformed_is_empty(self) -> None:
        assert _extension_attributes({}) == []
        assert _extension_attributes({"extensionAttributes": [{"displayName": "no key"}, "x"]}) == []


class _CountingSource:
    """A `CatalogSource` that remembers how many detail reads overlapped at its busiest
    moment — the only way to see a fan-out bound, which leaves no trace in the rows."""

    def __init__(self, *, failing: set[str] | None = None) -> None:
        self.in_flight = 0
        self.peak = 0
        self.asked: list[str] = []
        self._failing = failing or set()

    async def summaries(self) -> list[dict]:
        return []

    async def detail(self, title_id: str) -> dict:
        self.in_flight += 1
        self.peak = max(self.peak, self.in_flight)
        self.asked.append(title_id)
        try:
            # Two trips through the event loop, so everything the semaphore admitted is
            # counted together. Without an await here each read would finish before the
            # next began and the peak would be 1 whatever the bound was — the test would
            # pass with the semaphore deleted.
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            if title_id in self._failing:
                request = httpx.Request("GET", f"https://patch.example.test/v1/patch/{title_id}")
                raise httpx.HTTPStatusError("404", request=request, response=httpx.Response(404, request=request))
            return {"id": title_id}
        finally:
            self.in_flight -= 1


class TestFetchDetails:
    """The bound the cold start needed (#382): a container with no rows treats all ~1,554
    titles as changed, and the bare `asyncio.gather` this replaced dialled every one of
    them at once."""

    async def test_at_most_eight_reads_are_in_flight(self) -> None:
        source = _CountingSource()

        await _fetch_details(source, [str(n) for n in range(40)])

        assert source.peak == DETAIL_CONCURRENCY == 8

    async def test_every_title_is_fetched_in_the_order_asked_for(self) -> None:
        """The bound must not cost a title or reorder the answers: the caller zips these
        back against `to_refresh` with `strict=True`, so a short or shuffled list would
        write the wrong definition onto the wrong row."""
        source = _CountingSource()
        title_ids = [str(n) for n in range(40)]

        details = await _fetch_details(source, title_ids)

        assert [detail["id"] for detail in details] == title_ids
        assert sorted(source.asked) == sorted(title_ids)

    async def test_one_failing_title_is_returned_not_raised(self) -> None:
        """`return_exceptions=True`, kept through the change: one 404 in the fan-out is a
        title skipped, never the fifteen hundred others abandoned."""
        source = _CountingSource(failing={"7"})

        details = await _fetch_details(source, [str(n) for n in range(10)])

        assert isinstance(details[7], httpx.HTTPStatusError)
        kept = [detail["id"] for detail in details if not isinstance(detail, BaseException)]
        assert kept == ["0", "1", "2", "3", "4", "5", "6", "8", "9"]

    async def test_nothing_to_refresh_asks_for_nothing(self) -> None:
        source = _CountingSource()

        assert await _fetch_details(source, []) == []
        assert source.asked == []


class TestJamfApiCatalogSource:
    """The Jamf half of the seam. Both addresses come from `settings.jamf_patch_base_url`
    now, and its default is the server the module constant named."""

    @staticmethod
    def _client(seen: list[str]) -> httpx.AsyncClient:
        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(str(request.url))
            if request.url.path.endswith("/software"):
                return httpx.Response(200, json=[{"id": "575", "lastModified": "1", "currentVersion": "8.12.33"}])
            return httpx.Response(200, text='\x30\x82CERT{"id":"575","name":"1Password"}\x00]}')

        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    def test_the_default_is_jamfs_public_patch_server(self) -> None:
        """The field's default, not the live object. `settings` reads the environment, so
        a developer or a CI lane with `JAMF_PATCH_BASE_URL` exported would turn this red
        for a reason that has nothing to do with the code under test — and the claim being
        made here is about the default the image ships with."""
        assert Settings.model_fields["jamf_patch_base_url"].default == "https://jamf-patch.jamfcloud.com/v1"

    async def test_both_reads_use_the_configured_base_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "jamf_patch_base_url", "https://patch.example.test/v1")
        seen: list[str] = []

        async with self._client(seen) as client:
            source = JamfApiCatalogSource(client)
            summaries = await source.summaries()
            detail = await source.detail("575")

        assert seen == ["https://patch.example.test/v1/software", "https://patch.example.test/v1/patch/575"]
        assert summaries == [{"id": "575", "lastModified": "1", "currentVersion": "8.12.33"}]
        # The envelope is stripped on the way through, as it was when the fetch was a
        # module-level function.
        assert detail == {"id": "575", "name": "1Password"}

    async def test_a_trailing_slash_does_not_double(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """`https://…/v1/` is the same address a person would paste; `…/v1//software` is
        not the same request."""
        monkeypatch.setattr(settings, "jamf_patch_base_url", "https://patch.example.test/v1/")
        seen: list[str] = []

        async with self._client(seen) as client:
            await JamfApiCatalogSource(client).summaries()

        assert seen == ["https://patch.example.test/v1/software"]

    async def test_an_unlistable_catalog_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The summaries read has no `return_exceptions` behind it, deliberately: a
        catalog that cannot be listed fails the sync rather than reading as a catalog
        with nothing in it."""
        monkeypatch.setattr(settings, "jamf_patch_base_url", "https://patch.example.test/v1")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(503)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(httpx.HTTPStatusError):
                await JamfApiCatalogSource(client).summaries()


def _fan_out_comment() -> str:
    """The comment block immediately above `DETAIL_CONCURRENCY`, as text."""
    lines = Path(jamf_catalog.__file__).read_text().splitlines()
    index = next(number for number, line in enumerate(lines) if line.startswith("DETAIL_CONCURRENCY"))
    block: list[str] = []
    while index > 0 and lines[index - 1].lstrip().startswith("#"):
        index -= 1
        block.insert(0, lines[index])
    return "\n".join(block)


class TestTheFanOutCommentArguesFromTheRealClient:
    """The paragraph beside `DETAIL_CONCURRENCY` argues from two numbers it does not own:
    the connection cap httpx gives a client built with no `limits=`, and the *pool*
    component of `Timeout(30)`. Its first draft argued instead from a number that was
    never real — a socket per title, and a file-descriptor bill to go with it — which the
    pool had already made impossible. These pin the argument to the client this module
    actually builds, so the next person to widen the bound reads a true reason for it.
    """

    async def test_the_client_admits_a_hundred_and_queues_the_rest_for_thirty_seconds(self) -> None:
        async with jamf_api_source() as source:
            # httpx exposes no public accessor for a client's limits, and the comment
            # makes a claim about them; reading the pool is the only way to check it.
            client = source._client
            pool = client._transport._pool

            assert pool._max_connections == 100
            assert client.timeout.pool == 30

            comment = _fan_out_comment()
            assert str(pool._max_connections) in comment
            assert f"{int(client.timeout.pool)} s" in comment

    def test_the_comment_names_what_the_queue_did_to_a_waiting_request(self) -> None:
        """The hazard the bound removes is a request that ages out of the pool queue and
        is swallowed by `return_exceptions=True` — a title silently missing, not a socket."""
        comment = _fan_out_comment()

        assert "PoolTimeout" in comment
        assert "return_exceptions" in comment


class TestAnAddressThatIsNotAnAddress:
    """`JAMF_PATCH_BASE_URL` became a way for this to be wrong the moment the constant
    became a setting (#382). Unchecked, the value reaches httpx as `UnsupportedProtocol`
    from inside an hourly job: a traceback that never names the variable that caused it
    (`docs/diagnosability.md` rule 3)."""

    @pytest.mark.parametrize(
        "value",
        ["", "   ", "jamf-patch.jamfcloud.com/v1", "ftp://patch.example.test/v1", "/v1"],
    )
    async def test_it_is_refused_with_a_sentence_that_names_the_setting(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        monkeypatch.setattr(settings, "jamf_patch_base_url", value)

        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(200))) as client:
            with pytest.raises(JamfPatchCatalogUnconfigured) as raised:
                JamfApiCatalogSource(client)

        message = str(raised.value)
        assert "JAMF_PATCH_BASE_URL" in message  # what to change
        assert repr(value) in message  # what it holds now
        assert "https://" in message  # what it must look like
        assert "https://jamf-patch.jamfcloud.com/v1" in message  # what removing it restores
        assert "docs/troubleshooting.md" in message  # where the step-through is

    async def test_a_usable_address_is_still_built_without_complaint(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The check refuses a shape, not a host: anything dialable still passes, including
        the plain-`http` mirror an air-gapped stack would point at."""
        for value in ("https://patch.example.test/v1", "http://patch.example.test/v1/"):
            monkeypatch.setattr(settings, "jamf_patch_base_url", value)
            async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(200))) as client:
                assert JamfApiCatalogSource(client)._base_url == value.rstrip("/")

    def test_the_sentence_points_at_a_step_through_that_exists(self) -> None:
        """`docs/diagnosability.md` rule 4: the failure path and its step-through ship
        together. The sentence names a section of `troubleshooting.md`, so this reads the
        number back out of the sentence and checks that section is the one about this."""
        section = re.search(r"docs/troubleshooting\.md section (\d+)", JAMF_PATCH_BASE_URL_UNUSABLE)
        assert section is not None
        heading = f"## {section.group(1)}. "

        document = (DOCS / "troubleshooting.md").read_text()
        assert heading in document
        body = document.split(heading, 1)[1].split("\n## ", 1)[0]
        assert "JAMF_PATCH_BASE_URL" in body
        assert "docker compose" in body


def test_the_reserved_catalog_section_is_cited_where_it_is_written() -> None:
    """The module docstring and the setting both explain themselves by pointing at the
    reserved `catalog` section of the vulnerability epoch format. That reservation lives in
    LoonVD-Internal's contract; `docs/vulnerabilities.md` points at that contract rather
    than defining it, and never uses the word in this sense — so a citation of
    `docs/vulnerabilities.md` alone sends the reader to a document that cannot confirm the
    claim."""
    contract = "sharedAssets/contract/epoch.md"

    assert contract in Path(jamf_catalog.__file__).read_text()
    assert contract in Path(config_module.__file__).read_text()
    # And the chain resolves: the public document names the contract it defers to.
    assert contract in (DOCS / "vulnerabilities.md").read_text()
