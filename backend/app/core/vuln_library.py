"""The vulnerability library: the corpus epoch this container has loaded (#248).

The corpus is **Jamf-derived, compiled elsewhere, and arrives complete** — one signed
link a day, riding the response of the data-sharing exchange this container already
makes (`app.core.sharing`, docs/data-sharing.md). Ruled 2026-09-10. The container
downloads a published epoch when its signature moves, verifies every byte of it against
the manifest it carries, and replaces the previous epoch in one transaction. Nothing here
asks a server about one app, ever: the join is local, keyed on the content keys the fleet
already computes (docs/vulnerabilities.md §4f), and the answer is read from stored rows.

**Three properties, and each is a refusal rather than a hope.**

*Whole or not at all.* The manifest is verified — the signature the pointer named, every
object's digest, every object's byte count and row count, and every row's shape — before
the first row is written. A failure leaves the previous epoch serving, which is stale and
correct rather than fresh and wrong, and says so in one line an operator can read
(docs/troubleshooting.md §5).

*A row is the only thing that means "clean".* `findings()` answers with a row's
aggregates or with `None`, and never with `()` derived from a missing row — the hash-join
trap §4f names. An assessed-and-clean build ships as a row with no ids; a build nobody
assessed has no row and reads `unknown_app`.

*The tier gate is the tenant.* #281's Option A, as §8 reads it since 2026-09-11: a pod
that has not consented never exchanges, so it is never handed a link and loads nothing —
and because the library is one global artifact on a pod whose tiers are per tenant,
`loaded_corpus()` also answers `NO_CORPUS` to a tenant whose own tier is `off`, even
while the pod holds an epoch. `read_tenant_tier` below is what fills that in, once per
unit of work; `earned_corpus` is the one call every consumer makes.

**What is deliberately not here.** The per-build join at judge time and the stored answer
on `app_catalog` and `installed_apps` — #381, which owns them because they need the
tenant's own rows. What is not *anywhere* any more is the branch that would have turned a
rowless build into a clean bill because its title was compiled under an unmoved Jamf
stamp: **withdrawn by ruling R-D, 2026-09-11**, on two measurements from the Jamf
enumeration — one `key_title` is shared by sixteen Wireshark titles, so there is no single
stamp to compare against, and the two enumerations of the same catalog differ by ~5,000
versions, so a pod can hold a build the compiler never saw and that build would have read
clean. This module stores the titles object as **coverage metadata** and exposes it
(`compiled_title`) for #381's statistics; it is not a verdict input here and must not
become one there. A build with no row reads `unknown_app`.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import logging
import tarfile
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime

import httpx
from sqlalchemy import delete, insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.egress import BlockedCorpusUrl, corpus_url_for_log, validate_corpus_url
from app.core.tenancy import get_tenant_id
from app.core.user_agent import build_user_agent
from app.core.vuln import (
    SEVERITY_BANDS,
    TIER_OFF,
    AssessedBuild,
    VulnCorpus,
    VulnFinding,
    install_corpus,
    install_tenant_tier,
    loaded_corpus,
)
from app.models.schema import DataSharingSettings, VulnLibraryEpoch, VulnLibraryRow, VulnLibraryTitle

logger = logging.getLogger(__name__)

# The one format this container knows. A consumer that does not know the value refuses the
# epoch and never guesses (the epoch contract, §3) — which is what makes a future
# `epoch/2` a new format rather than a silent misread of the old one.
EPOCH_FORMAT = "epoch/1"

# The three objects this container reads. An epoch may carry more — the format's
# additive-only clause promises exactly that, and the community `verdicts` object this
# channel is next in line for is precisely a fourth entry. So an unknown member under the
# epoch-id directory, and an unknown entry in the manifest's `objects`, are **passed
# over** rather than refused: a reader that refused them would freeze every deployed
# container at its last three-object epoch the day the fourth shipped, and containers in
# the field cannot be updated in lockstep.
#
# Passing over is not silence. `read_bundle` counts and names what it ignored and the
# import line says so, because a corpus that quietly grew an object nobody reads is a fact
# an operator should be able to see (the epoch contract, §3).
#
# The path rules are still enforced whatever the member is called — one top-level
# directory named by the epoch id, no absolute path, no `..`, regular files only, the
# per-member size cap — because this arrives over a link and `tarfile` writes outside its
# destination happily if asked.
MANIFEST_NAME = "manifest.json"
ROWS_NAME = "rows.jsonl.gz"
TITLES_NAME = "titles.jsonl.gz"
_MEMBERS = (MANIFEST_NAME, ROWS_NAME, TITLES_NAME)

# Ceilings, not budgets. The bundle is gzip over tar and the objects are gzip over JSON
# Lines, so a small download can decompress into an arbitrarily large one; a cap is the
# only thing between a hostile or broken publisher and this container's memory. Generous
# enough that a real epoch — the Jamf catalog's assessed builds — is nowhere near them.
_MAX_BUNDLE_BYTES = 64 * 1024 * 1024
_MAX_OBJECT_BYTES = 256 * 1024 * 1024
_DOWNLOAD_TIMEOUT_SECONDS = 60.0
_MAX_REDIRECTS = 3

# Rows are written in chunks for the same reason `app.catalog.index` writes its index in
# chunks: one statement per epoch would build a parameter list the driver has to hold
# whole.
_CHUNK = 1000

_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class CorpusRefused(Exception):
    """An epoch this container will not import, and the state it is refused under.

    `state` is one of the words `docs/troubleshooting.md` §5 walks — `download_failed`,
    `bundle_malformed`, `signature_mismatch`, `digest_mismatch`, `object_not_utf8`,
    `epoch_malformed`, and `pointer_unusable` for a link that never became a download — and
    the message is the operator's sentence: what failed, why, and what to check
    (docs/diagnosability.md rule 3). Raised, logged once at the import site, and never
    re-raised at a device sync: a refused epoch changes nothing, so the previous one keeps
    answering.
    """

    def __init__(self, state: str, message: str) -> None:
        super().__init__(message)
        self.state = state


@dataclass(frozen=True, slots=True)
class CorpusPointer:
    """`response["corpus"]` — where the current epoch is, and whether it moved.

    `signature` is the sha256 of the epoch's own manifest, and **equality is the only
    operation** the format licenses: never ordered, never compared for distance, never
    parsed. A rollback moves the pointer to a lower epoch id and must still be imported,
    which is exactly what a signature comparison gets right and a version comparison gets
    wrong.

    **`asof` is optional, and nothing here reads it.** The format's own words: *"the
    manifest is the authority; the pointer is a copy"* — `read_bundle` dates the epoch
    from `manifest.asof` and this field is a convenience for a server answering a link
    from one object read. It was added to the pointer after the first pointers were
    written, so a pointer without it is an older pointer and not a broken one; refusing
    the epoch over a field this container never consults would be a silent `off` bought
    for nothing.
    """

    signature: str
    asof: datetime | None
    url: str


@dataclass(frozen=True, slots=True)
class TitleCoverage:
    """One line of `titles.jsonl` — **coverage metadata about a Jamf title**, and never a
    verdict input (ruling R-D, 2026-09-11: verdicts come from rows alone).

    `title_id` is Jamf's own title id and is what the object is unique on. `key_title` is
    the container's `app.title` key over `(appName, bundleId)` and **repeats** — sixteen
    Wireshark titles in Jamf's catalog share one — so it is an index and never a key. That
    is the whole reason the id arrived: keying this object on `key_title` would have
    silently collapsed fifteen of those sixteen and left one arbitrary stamp answering for
    all of them.

    `catalog_last_modified` is kept as **the string Jamf wrote**, never parsed into a
    datetime: the comparison #381 makes with it is string *equality* against the pod's own
    catalog, in either direction, and parsing invites a tolerance nobody ruled.
    """

    title_id: str
    key_title: str
    catalog_last_modified: str
    versions_compiled: int


@dataclass(frozen=True, slots=True)
class VulnLibrary:
    """One loaded epoch, in the shape the read path asks it questions in.

    Held in memory because `loaded_corpus()` is synchronous and carries no session — a
    page renders ~100 apps and must not issue ~100 queries ("cache, don't calculate").
    The rows are the epoch's, so the size is the compiler's business rather than the
    fleet's: it does not grow with devices. #381 moves the per-build answer onto
    `app_catalog` columns, at which point this becomes the loader's own view of what it
    imported rather than the read path's lookup.
    """

    epoch_id: str
    signature: str
    as_of: date
    asof_at: datetime
    loaded_at: datetime
    rows: Mapping[str, AssessedBuild]
    # Keyed by `title_id`, which is what the object is unique on. `key_title` repeats, so
    # there is deliberately no by-key map here: #381 reads the table, which carries the
    # index on `key_title` that a one-to-many lookup actually needs.
    titles: Mapping[str, TitleCoverage]
    # The object names this container passed over — additive entries a newer container
    # reads. Named on the import line, empty on every epoch published so far.
    ignored: tuple[str, ...] = ()

    def row_for(self, key_full: str) -> AssessedBuild | None:
        """The assessed build, or `None` for *this epoch did not assess this build*."""
        return self.rows.get(key_full)

    def compiled_title(self, title_id: str) -> TitleCoverage | None:
        """**Coverage metadata** for one Jamf title id: what the epoch compiled, and when
        the catalog it compiled against was last modified. `None` means this epoch did not
        compile that title.

        Not a verdict, and not an input to one (R-D). Nothing in the read path calls it;
        it exists so #381 can report how much of a tenant's catalog an epoch covered.
        """
        return self.titles.get(title_id)


class LibraryCorpus:
    """`VulnCorpus` over a loaded epoch — the seam `vuln_block` and the page both read.

    `findings()` answers with the row's `AssessedBuild` or with `None`, and with nothing
    else. It deliberately does **not** consult `key_title`, and since ruling R-D
    (2026-09-11) nothing ever will: the verdict comes from `rows.jsonl` alone, so a rowless
    build reads `unknown_app` — dated, never zero, and never a clean bill for a build this
    container cannot prove was assessed (§4f). `key_title` stays on the signature because
    the protocol is #249's and the wire's question is still "does the corpus know this app
    at all"; the library's answer to it is simply that a row is the only evidence.
    """

    __slots__ = ("library",)

    def __init__(self, library: VulnLibrary) -> None:
        self.library = library

    @property
    def as_of(self) -> date | None:
        return self.library.as_of

    def findings(self, *, key_title: str, key_full: str) -> AssessedBuild | Sequence[VulnFinding] | None:
        return self.library.row_for(key_full)


# --- the pointer, read off the exchange response ---------------------------------------


def corpus_pointer(value: object) -> CorpusPointer | None:
    """`response["corpus"]`, or `None` for "nothing today".

    Tolerant by contract, like every other field of that response: a wrong type, a missing
    signature, a missing URL and a URL this container will not dial are all "no pointer",
    never an error — a collector that answers `{}` is a valid peer, and the exchange must
    not fail on a field the server has not implemented yet.

    **An absent `corpus` key is silent; a present one that cannot be used is not.** No
    pointer at all is the ordinary case and says nothing. But a server that named a corpus
    and got nowhere is a fact an operator has to be able to find: every drop below logs
    the reason it dropped, at warning, because the alternative is a silent `off` that
    looks exactly like an epoch that never moved (docs/troubleshooting.md §5).

    `asof` is read when it parses and left `None` when it does not — it is a copy of the
    manifest's own field, the manifest is the authority, and nothing here consults it.
    """
    if value is None:
        return None
    if not isinstance(value, Mapping):
        return _no_pointer(f"the exchange's `corpus` field is a {type(value).__name__} and the format states an object")
    signature, url = value.get("signature"), value.get("url")
    if not isinstance(signature, str):
        return _no_pointer("the exchange named a corpus with no signature, so nothing could say whether it moved")
    if len(signature) != 64 or not all(c in "0123456789abcdef" for c in signature):
        return _no_pointer("the exchange named a corpus whose signature is not a sha256 digest")
    if not isinstance(url, str):
        return _no_pointer("the exchange named a corpus with no link to download it from")
    try:
        url = validate_corpus_url(url)
    except BlockedCorpusUrl as exc:
        return _no_pointer(f"the exchange named a corpus link this container refuses ({exc})")
    return CorpusPointer(signature=signature, asof=_parse_timestamp(value.get("asof")), url=url)


def _no_pointer(because: str) -> None:
    """One dropped pointer, with the reason named. Warning rather than debug: the day this
    fires, `assessment` reads `off` for every app and this line is the only thing that
    says why."""
    logger.warning(
        "vulnerability library not updated: %s. Every app reads assessment: off until a usable link arrives "
        "(docs/troubleshooting.md §5)",
        because,
        extra={"state": "pointer_unusable"},
    )
    return None


def _parse_timestamp(value: object) -> datetime | None:
    """The format's one timestamp shape: `YYYY-MM-DDTHH:MM:SSZ`, UTC, no fractional part.
    Anything else is not a timestamp this container will store as `corpusAsOf`."""
    if not isinstance(value, str):
        return None
    try:
        return datetime.strptime(value, _TIMESTAMP_FORMAT).replace(tzinfo=UTC)
    except ValueError:
        return None


# --- the download, and the verification that stands between it and the database --------


async def download_bundle(url: str, *, transport: httpx.AsyncBaseTransport | None = None) -> bytes:
    """The transfer bundle, over the exchange's own injectable transport.

    The transport is a parameter for the reason `post_exchange` has one: a test drives the
    whole loader against the committed fixture epoch with no network at all, which is also
    the only way to assert what happens to a truncated or tampered download.

    **The ceiling is enforced while the body streams, not after it lands.** Reading the
    whole response first and measuring it afterwards bounds what is *kept* and not what is
    *read*: a publisher answering with ten gigabytes would be refused only once ten
    gigabytes were in this container's memory, which is the failure the cap exists to
    prevent rather than a cap on it.
    """
    headers = {"User-Agent": build_user_agent("corpus")}
    try:
        async with httpx.AsyncClient(timeout=_DOWNLOAD_TIMEOUT_SECONDS, transport=transport, follow_redirects=False) as client:
            # Redirects are followed by hand, and **every hop is validated like the first**.
            # `follow_redirects=True` would hand the egress rules a one-hop guarantee: the
            # link passes, and a `302` then points the request at 169.254.169.254 with
            # nothing checking. Three hops is more than a signed object store needs.
            for _ in range(_MAX_REDIRECTS + 1):
                async with client.stream("GET", url, headers=headers) as response:
                    if response.is_redirect and response.has_redirect_location:
                        url = validate_corpus_url(str(response.next_request.url))
                        continue
                    response.raise_for_status()
                    data = await _read_capped(response)
                break
            else:
                raise CorpusRefused("download_failed", f"the corpus link redirected more than {_MAX_REDIRECTS} times")
    except BlockedCorpusUrl as exc:
        raise CorpusRefused("download_failed", f"the corpus link redirected somewhere this container refuses: {exc}") from exc
    except (httpx.HTTPError, ValueError) as exc:
        raise CorpusRefused("download_failed", f"the corpus download did not complete: {exc}") from exc
    return data


async def _read_capped(response: httpx.Response) -> bytes:
    """The response body, or a refusal at the first chunk that crosses the ceiling.

    Raised from inside the stream so the connection is dropped where it is: `CorpusRefused`
    is neither an `httpx.HTTPError` nor a `ValueError`, so it passes the caller's handlers
    untouched and arrives as the named state rather than as "the download did not
    complete", which would be the wrong sentence for a publisher that answered perfectly
    well with far too much.
    """
    chunks: list[bytes] = []
    size = 0
    async for chunk in response.aiter_bytes():
        size += len(chunk)
        if size > _MAX_BUNDLE_BYTES:
            raise CorpusRefused(
                "download_failed",
                f"the corpus download passed the {_MAX_BUNDLE_BYTES}-byte ceiling this container accepts and was stopped "
                "there; nothing was imported",
            )
        chunks.append(chunk)
    return b"".join(chunks)


@dataclass(frozen=True, slots=True)
class Epoch:
    """A verified epoch, in memory, before anything is written."""

    epoch_id: str
    signature: str
    asof: datetime
    manifest: Mapping[str, object]
    rows: Mapping[str, AssessedBuild]
    titles: Mapping[str, TitleCoverage]
    # Objects this epoch carries and this container does not read — the additive-only
    # clause in effect. Counted and named rather than silently dropped.
    ignored: tuple[str, ...] = ()


def read_bundle(data: bytes, *, signature: str) -> Epoch:
    """Verify a downloaded bundle whole, and answer with what it contains.

    In order, because each step is what makes the next one meaningful: the member paths
    are ones the format licenses; the manifest inside the bundle is the one the pointer
    signed; the manifest is a format this container knows; **the objects this container
    reads** are present, are the length they claim and hash to the digest they claim;
    each holds the number of lines it claims; and every line is a row this container can
    store. Only then does the caller touch the database.

    An object neither in that list is passed over and named, not refused (see `_MEMBERS`).
    """
    top, members = _bundle_members(data)
    manifest_bytes = members[MANIFEST_NAME]
    actual = hashlib.sha256(manifest_bytes).hexdigest()
    if actual != signature:
        raise CorpusRefused(
            "signature_mismatch",
            f"the downloaded corpus is not the one the exchange pointed at: its manifest hashes to {actual[:12]}… and the "
            f"exchange named {signature[:12]}…",
        )

    manifest = _manifest(manifest_bytes)
    epoch_id = str(manifest["epoch_id"])
    if top != epoch_id:
        # The directory the members live under is named by the epoch id. A bundle whose
        # two halves disagree about which epoch it is has one of them wrong, and there is
        # no way to tell which.
        raise CorpusRefused(
            "bundle_malformed", f"the corpus bundle unpacks under {top!r} and its manifest calls the epoch {epoch_id!r}"
        )
    objects = manifest.get("objects")
    if not isinstance(objects, Mapping):
        raise CorpusRefused("epoch_malformed", f"epoch {epoch_id}'s manifest does not list its objects")

    payloads: dict[str, list[Mapping[str, object]]] = {}
    for name in (ROWS_NAME, TITLES_NAME):
        described = objects.get(name)
        if not isinstance(described, Mapping):
            raise CorpusRefused("epoch_malformed", f"epoch {epoch_id}'s manifest does not describe {name}")
        payloads[name] = _verified_lines(epoch_id, name, members[name], described)

    # Everything else the epoch carries, whether the manifest listed it, the bundle held
    # it, or both. Sorted so the log line reads the same on every container.
    ignored = tuple(sorted((set(objects) | set(members)) - set(_MEMBERS)))

    rows: dict[str, AssessedBuild] = {}
    for index, line in enumerate(payloads[ROWS_NAME], start=1):
        key_full, row = _row(epoch_id, index, line)
        rows[key_full] = row
    titles: dict[str, TitleCoverage] = {}
    for index, line in enumerate(payloads[TITLES_NAME], start=1):
        coverage = _title(epoch_id, index, line)
        titles[coverage.title_id] = coverage

    asof = _parse_timestamp(manifest.get("asof"))
    if asof is None:
        raise CorpusRefused("epoch_malformed", f"epoch {epoch_id}'s manifest carries no usable `asof`, so nothing could date it")
    return Epoch(epoch_id=epoch_id, signature=signature, asof=asof, manifest=manifest, rows=rows, titles=titles, ignored=ignored)


def _bundle_members(data: bytes) -> tuple[str, dict[str, bytes]]:
    """The top-level directory and every member by bare name, or a refusal naming what the
    bundle carried instead.

    Read into memory rather than extracted: a `tarfile` asked to write a member called
    `../etc/x` will do it, and the surest way not to be traversed is never to write. The
    contract's own path rules are enforced anyway — one top-level directory named by the
    epoch id, no absolute path, no `..`, regular files only — because a bundle that breaks
    them is not one this container should be reading at all.

    **What is not enforced is the member list.** A member this container does not know is
    carried back like any other and passed over by `read_bundle`; only the three it reads
    are required. The rule the refusals here defend is *where* a member may live, which is
    a safety property of unpacking something that arrived over a link; *what* an epoch may
    contain is the format's additive-only clause and grows without this container.
    """
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as bundle:
            members: dict[str, bytes] = {}
            top: str | None = None
            for member in bundle.getmembers():
                name = member.name
                if not member.isreg():
                    raise CorpusRefused("bundle_malformed", f"the corpus bundle carries {name!r}, which is not a regular file")
                if name.startswith("/") or ".." in name.split("/"):
                    raise CorpusRefused("bundle_malformed", f"the corpus bundle carries {name!r}, a path outside the epoch")
                parts = name.split("/")
                if len(parts) != 2 or not parts[1]:
                    raise CorpusRefused(
                        "bundle_malformed",
                        f"the corpus bundle carries {name!r}, and the format puts every member directly under one directory "
                        "named by the epoch id",
                    )
                if top is not None and parts[0] != top:
                    raise CorpusRefused("bundle_malformed", "the corpus bundle carries more than one top-level directory")
                top = parts[0]
                if member.size > _MAX_OBJECT_BYTES:
                    raise CorpusRefused(
                        "bundle_malformed",
                        f"the corpus bundle's {name!r} unpacks to {member.size} bytes, past the ceiling this container accepts",
                    )
                handle = bundle.extractfile(member)
                if handle is None:
                    raise CorpusRefused("bundle_malformed", f"the corpus bundle's {name!r} could not be read")
                members[parts[1]] = handle.read()
    except tarfile.TarError as exc:
        raise CorpusRefused("bundle_malformed", f"the corpus download is not a readable bundle: {exc}") from exc
    missing = [name for name in _MEMBERS if name not in members]
    if missing:
        raise CorpusRefused("bundle_malformed", f"the corpus bundle is missing {', '.join(missing)}")
    return str(top), members


def _manifest(raw: bytes) -> Mapping[str, object]:
    try:
        manifest = json.loads(raw)
    except ValueError as exc:
        raise CorpusRefused("epoch_malformed", f"the corpus manifest is not JSON: {exc}") from exc
    if not isinstance(manifest, Mapping):
        raise CorpusRefused("epoch_malformed", "the corpus manifest is not an object")
    declared = manifest.get("format")
    if declared != EPOCH_FORMAT:
        raise CorpusRefused(
            "epoch_malformed",
            f"the corpus is published as format {declared!r} and this container reads {EPOCH_FORMAT!r}; update the container",
        )
    epoch_id = manifest.get("epoch_id")
    if not isinstance(epoch_id, str) or not epoch_id.isdigit() or len(epoch_id) < 4:
        raise CorpusRefused("epoch_malformed", f"the corpus manifest's epoch id {epoch_id!r} is not the format's zero-padded id")
    return manifest


def _verified_lines(epoch_id: str, name: str, raw: bytes, described: Mapping[str, object]) -> list[Mapping[str, object]]:
    """One object's stored bytes checked against the manifest, then decompressed and read.

    The digest is over the object **exactly as stored** — the compressed bytes — which the
    format says out loud because it is the one place two implementations pick differently,
    and a digest over the wrong bytes fails at the consumer after the publisher has
    already promised the epoch is whole.
    """
    if described.get("bytes") != len(raw):
        raise CorpusRefused(
            "digest_mismatch",
            f"epoch {epoch_id}'s {name} is {len(raw)} bytes and its manifest states {described.get('bytes')}; nothing was "
            "imported and the library still answers from the epoch it had",
        )
    actual = hashlib.sha256(raw).hexdigest()
    if actual != described.get("sha256"):
        raise CorpusRefused(
            "digest_mismatch",
            f"epoch {epoch_id}'s {name} does not match the digest its manifest states; nothing was imported and the library "
            "still answers from the epoch it had",
        )
    lines = list(_json_lines(epoch_id, name, raw))
    if described.get("rows") != len(lines):
        raise CorpusRefused(
            "digest_mismatch",
            f"epoch {epoch_id}'s {name} holds {len(lines)} rows and its manifest states {described.get('rows')}",
        )
    return lines


def _json_lines(epoch_id: str, name: str, raw: bytes) -> Iterator[Mapping[str, object]]:
    try:
        decompressed = gzip.decompress(raw)
    except (OSError, EOFError) as exc:
        raise CorpusRefused("epoch_malformed", f"epoch {epoch_id}'s {name} could not be decompressed: {exc}") from exc
    if len(decompressed) > _MAX_OBJECT_BYTES:
        raise CorpusRefused(
            "epoch_malformed",
            f"epoch {epoch_id}'s {name} decompresses to {len(decompressed)} bytes, past the ceiling this container accepts",
        )
    try:
        # Inside the guard, not outside it. An object can pass its digest and still not be
        # text — a publisher that wrote a binary object under a `.jsonl.gz` name digests
        # perfectly well — and an unguarded `.decode` makes that a `UnicodeDecodeError`
        # travelling out of the import, past `load_epoch_if_new`'s `except CorpusRefused`,
        # into the exchange tick's blanket handler, where the operator gets a traceback
        # under "sharing exchange tick failed" instead of the named state §5 promises.
        text = decompressed.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CorpusRefused(
            "object_not_utf8",
            f"epoch {epoch_id}'s {name} matches the digest its manifest states but is not UTF-8 text ({exc}); the format "
            "states gzip over UTF-8 JSON Lines, so nothing was imported and the library still answers from the epoch it had",
        ) from exc
    for index, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except ValueError as exc:
            raise CorpusRefused("epoch_malformed", f"epoch {epoch_id}'s {name} line {index} is not JSON: {exc}") from exc
        if not isinstance(parsed, Mapping):
            raise CorpusRefused("epoch_malformed", f"epoch {epoch_id}'s {name} line {index} is not an object")
        yield parsed


def _row(epoch_id: str, index: int, line: Mapping[str, object]) -> tuple[str, AssessedBuild]:
    """One `rows.jsonl` line as an `AssessedBuild`, or a refusal naming the line.

    Every invariant the wire model would refuse at enqueue is checked by `AssessedBuild`
    itself, so a malformed epoch fails **here**, once, at import — rather than in the
    middle of a device sync, on whichever fleet happened to install the app the bad row
    describes (docs/vulnerabilities.md §5).
    """
    key_full = line.get("key_full")
    if not isinstance(key_full, str) or not key_full.startswith("v1:"):
        raise CorpusRefused("epoch_malformed", f"epoch {epoch_id}'s rows line {index} carries no v1 content key")
    counts = line.get("counts")
    oldest = line.get("oldest_published")
    ids = line.get("ids")
    if not isinstance(counts, Mapping) or not isinstance(oldest, Mapping) or not isinstance(ids, list):
        raise CorpusRefused("epoch_malformed", f"epoch {epoch_id}'s rows line {index} is not the shape the format states")
    try:
        row = AssessedBuild(
            total=int(counts["total"]),
            kev=int(counts["kev"]),
            severity={band: int(counts[band]) for band in SEVERITY_BANDS},
            oldest_published=_published(oldest.get("total")),
            oldest_published_severity={band: _published(oldest.get(band)) for band in SEVERITY_BANDS},
            ids=tuple(str(value) for value in ids),
            truncated=bool(line.get("truncated")),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise CorpusRefused("epoch_malformed", f"epoch {epoch_id}'s rows line {index} was refused: {exc}") from exc
    return key_full, row


def _published(value: object) -> date | None:
    if value is None:
        return None
    parsed = _parse_timestamp(value)
    if parsed is None:
        raise ValueError(f"{value!r} is not an absolute UTC publication timestamp")
    return parsed.date()


def _title(epoch_id: str, index: int, line: Mapping[str, object]) -> TitleCoverage:
    """One `titles.jsonl` line as coverage metadata, or a refusal naming the line.

    `title_id` is required, because it is what the object is unique on and what the table
    is keyed by (R-D). A line without one cannot be stored — and, worse, could not be told
    apart from the fifteen other titles that share its `key_title`.
    """
    title_id = line.get("title_id")
    key_title = line.get("key_title")
    stamp = line.get("catalog_last_modified")
    compiled = line.get("versions_compiled")
    if not isinstance(title_id, str) or not title_id:
        raise CorpusRefused(
            "epoch_malformed",
            f"epoch {epoch_id}'s titles line {index} carries no `title_id`, which is what the object is unique on",
        )
    if not isinstance(key_title, str) or not key_title.startswith("v1:"):
        raise CorpusRefused("epoch_malformed", f"epoch {epoch_id}'s titles line {index} carries no v1 content key")
    if not isinstance(stamp, str) or not isinstance(compiled, int):
        raise CorpusRefused("epoch_malformed", f"epoch {epoch_id}'s titles line {index} is not the shape the format states")
    return TitleCoverage(title_id=title_id, key_title=key_title, catalog_last_modified=stamp, versions_compiled=compiled)


# --- storage: one epoch at a time, replaced whole --------------------------------------


async def stored_signature(db: AsyncSession) -> str | None:
    """The signature of the epoch this container holds, or `None` for none."""
    return (await db.execute(select(VulnLibraryEpoch.signature))).scalar_one_or_none()


async def store_epoch(db: AsyncSession, epoch: Epoch) -> VulnLibrary:
    """Replace the library with this epoch, in one transaction, and answer with it.

    Delete-then-insert-then-stamp inside a single commit is the whole of "replacing the
    previous epoch atomically": a reader either sees the old epoch entire or the new one
    entire, and the epoch row — the thing `stored_signature` reads and the thing the page
    dates itself from — is written last, so a crash between the rows and the stamp leaves
    a container that re-imports rather than one that claims an epoch it does not hold.
    """
    loaded_at = datetime.now(UTC)
    await db.execute(delete(VulnLibraryRow))
    await db.execute(delete(VulnLibraryTitle))
    rows = [
        {
            "key_full": key_full,
            "ids": list(row.ids),
            "truncated": row.truncated,
            "counts": {"total": row.total, "kev": row.kev, **{band: row.severity[band] for band in SEVERITY_BANDS}},
            "oldest_published": {
                "total": _stamp(row.oldest_published),
                **{band: _stamp(row.oldest_published_severity[band]) for band in SEVERITY_BANDS},
            },
        }
        for key_full, row in epoch.rows.items()
    ]
    for start in range(0, len(rows), _CHUNK):
        await db.execute(insert(VulnLibraryRow), rows[start : start + _CHUNK])
    titles = [
        {
            "title_id": coverage.title_id,
            "key_title": coverage.key_title,
            "catalog_last_modified": coverage.catalog_last_modified,
            "versions_compiled": coverage.versions_compiled,
        }
        for coverage in epoch.titles.values()
    ]
    for start in range(0, len(titles), _CHUNK):
        await db.execute(insert(VulnLibraryTitle), titles[start : start + _CHUNK])

    await db.execute(delete(VulnLibraryEpoch))
    db.add(
        VulnLibraryEpoch(
            id=1,
            epoch_id=epoch.epoch_id,
            signature=epoch.signature,
            asof=epoch.asof,
            loaded_at=loaded_at,
            row_count=len(epoch.rows),
            title_count=len(epoch.titles),
        )
    )
    await db.commit()
    return VulnLibrary(
        epoch_id=epoch.epoch_id,
        signature=epoch.signature,
        as_of=epoch.asof.date(),
        asof_at=epoch.asof,
        loaded_at=loaded_at,
        rows=dict(epoch.rows),
        titles=dict(epoch.titles),
        ignored=epoch.ignored,
    )


def _stamp(value: date | None) -> str | None:
    """A stored publication date, back in the format's own spelling. Dates are what the
    row carries — the day arithmetic belongs to the event's clock (§4d) — so the stored
    JSON keeps midnight UTC rather than inventing a time the epoch never stated."""
    return None if value is None else f"{value.isoformat()}T00:00:00Z"


async def refresh_from_db(db: AsyncSession) -> VulnLibrary | None:
    """Read the stored epoch into this process and put it behind `loaded_corpus()`.

    Called once at startup (`app.main`), and by the importer after it has replaced the
    epoch. That is the whole refresh rule: the answer changes when the epoch row changes
    and at no other time.
    """
    epoch_row = (await db.execute(select(VulnLibraryEpoch))).scalar_one_or_none()
    if epoch_row is None:
        install_corpus(None)
        return None
    try:
        library = await _library_from_rows(db, epoch_row)
    except (KeyError, TypeError, ValueError) as exc:
        install_corpus(None)
        logger.warning(
            "the stored vulnerability library could not be read (epoch %s): %s. Every app reads assessment: off until the "
            "next exchange imports an epoch (docs/troubleshooting.md §5)",
            epoch_row.epoch_id,
            exc,
            extra={"state": "epoch_malformed"},
        )
        return None
    install_corpus(LibraryCorpus(library))
    return library


async def _library_from_rows(db: AsyncSession, epoch_row: VulnLibraryEpoch) -> VulnLibrary:
    """The stored epoch, read back into the shape the read path asks questions in.

    Every row was validated when it was imported, so a refusal here means the store itself
    moved underneath us — which is why the caller names it rather than letting a
    `ValueError` out of startup.
    """
    rows = {
        row.key_full: AssessedBuild(
            total=int(row.counts["total"]),
            kev=int(row.counts["kev"]),
            severity={band: int(row.counts[band]) for band in SEVERITY_BANDS},
            oldest_published=_published(row.oldest_published.get("total")),
            oldest_published_severity={band: _published(row.oldest_published.get(band)) for band in SEVERITY_BANDS},
            ids=tuple(row.ids or ()),
            truncated=bool(row.truncated),
        )
        for row in (await db.execute(select(VulnLibraryRow))).scalars()
    }
    titles = {
        row.title_id: TitleCoverage(
            title_id=row.title_id,
            key_title=row.key_title,
            catalog_last_modified=row.catalog_last_modified,
            versions_compiled=row.versions_compiled,
        )
        for row in (await db.execute(select(VulnLibraryTitle))).scalars()
    }
    return VulnLibrary(
        epoch_id=epoch_row.epoch_id,
        signature=epoch_row.signature,
        as_of=epoch_row.asof.date(),
        asof_at=epoch_row.asof,
        loaded_at=epoch_row.loaded_at,
        rows=rows,
        titles=titles,
    )


# --- the seam the exchange calls -------------------------------------------------------


async def load_epoch_if_new(
    db: AsyncSession,
    pointer: CorpusPointer,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> VulnLibrary | None:
    """The exchange's corpus channel, end to end. Answers `None` when nothing changed.

    Signature equality decides, and nothing else: an unmoved pointer downloads nothing,
    which is what makes a daily conversation affordable for both sides. A refused epoch is
    logged as the named state it was refused under and swallowed — the previous epoch
    keeps answering, and the container tries again at tomorrow's exchange. It never raises
    into the exchange, because a corrupt corpus must not turn the once-a-day exchange into
    a crash loop.
    """
    current = await stored_signature(db)
    if current == pointer.signature:
        logger.debug("vulnerability library unchanged (signature %s…)", pointer.signature[:12])
        return None
    try:
        data = await download_bundle(pointer.url, transport=transport)
        epoch = read_bundle(data, signature=pointer.signature)
        library = await store_epoch(db, epoch)
    except CorpusRefused as exc:
        logger.warning(
            "vulnerability library not updated: %s. The library still answers from %s; the container tries again at "
            "tomorrow's exchange (docs/troubleshooting.md §5)",
            exc,
            f"the epoch it had ({current[:12]}…)" if current else "nothing, so every app reads assessment: off",
            extra={"state": exc.state, "corpus_url": corpus_url_for_log(pointer.url)},
        )
        return None
    install_corpus(LibraryCorpus(library))
    logger.info(
        "vulnerability library updated: epoch %s, generated %s, %d assessed builds and %d titles%s",
        library.epoch_id,
        library.as_of.isoformat(),
        len(library.rows),
        len(library.titles),
        _ignored_clause(library.ignored),
        extra={
            "epoch_id": library.epoch_id,
            "corpus_as_of": library.as_of.isoformat(),
            # Counted and named, in the structured fields as well as the sentence: an
            # epoch that grew an object nobody reads is a fact an operator should be able
            # to search for, and `ignored_objects: 0` is how they know nothing was hidden.
            "ignored_objects": len(library.ignored),
            "ignored_object_names": list(library.ignored),
        },
    )
    return library


def _ignored_clause(ignored: Sequence[str]) -> str:
    """The sentence's tail when an epoch carried objects this container does not read.

    Empty when it did not, so the ordinary line reads exactly as it did before there was
    anything to say — and names the next check when there is, because "why is my new
    object doing nothing" is answered by the container's version and not by this epoch.
    """
    if not ignored:
        return ""
    return (
        f"; {len(ignored)} object(s) this container does not read were passed over ({', '.join(ignored)}) — "
        "the format grows additively, so a newer container reads them"
    )


# --- who may read it: the per-tenant tier gate (#281 Option A, §8) ----------------------


async def read_tenant_tier(db: AsyncSession) -> str:
    """Read the acting tenant's data-sharing tier and put it behind `loaded_corpus()`.

    **Once per unit of work, and never per device or per app.** One sweep run, one
    re-emit, one API response, one exchange: the tier is a per-tenant row, the answer is
    the same for every device in that run, and `loaded_corpus()` then reads it from a
    dictionary however many times it is asked ("cache, don't calculate"). `earned_corpus`
    below is the pairing every consumer actually calls.

    Answers `off` outside a tenant context and for a tenant with no settings row — an
    install nobody has answered for has not consented (`get_or_create_settings`' own
    argument, one layer out), and this deliberately does **not** create the row: a read
    path must not manufacture a consent record as a side effect of rendering a page.
    """
    tenant_id = get_tenant_id()
    if tenant_id is None:
        return TIER_OFF
    tier = (await db.execute(select(DataSharingSettings.tier))).scalar_one_or_none() or TIER_OFF
    install_tenant_tier(tenant_id, tier)
    return tier


async def earned_corpus(db: AsyncSession) -> VulnCorpus:
    """The corpus this tenant has earned — read the tier once, then answer from memory.

    The one call a consumer makes. `loaded_corpus()` on its own is fail-closed by design
    (`app.core.vuln`), so a path that reaches it without having read the tier answers
    `off` rather than answering for a tenant that never consented; this is what turns that
    conservative default into the real answer, at the top of the unit of work.
    """
    await read_tenant_tier(db)
    return loaded_corpus()
