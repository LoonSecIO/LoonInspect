from __future__ import annotations

from datetime import date, datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_serializer, model_validator
from pydantic.alias_generators import to_camel


class MdmProvider(str, Enum):
    # Jamf only, deliberately (#79). The enum, the `provider` column, and the
    # credential-schema registry are the seam a second provider plugs into; the seam
    # stays, the stub implementations behind it did not survive to launch.
    jamf = "jamf"


class SyncStatus(str, Enum):
    idle = "idle"
    syncing = "syncing"
    failed = "failed"


# The wire's own version, bumped only on a BREAKING change to delivered events —
# additive changes never touch it (#188). Deliberately not `contract.CONTRACT_VERSION`,
# which versions canonicalization, the allowlist and the aperture: those two move for
# unrelated reasons, and conflating them means every digest change would look like a
# wire break to a customer's dashboards, and vice versa.
WIRE_SCHEMA_VERSION = "v0"


class NormalizedApp(BaseModel):
    """An installed app, internally snake_case and camelCase on the wire (#188).

    `bundleId` keeps Jamf's own spelling rather than taking the `ID` uppercasing ruled
    for LoonInspect-minted keys (#188, this round): the casing law leaves a vendor's
    native keys exactly as the vendor writes them, and Jamf writes `bundleId`. Every
    other alias here names a field LoonInspect invented, so those follow the house rule.
    """

    name: str
    bundle_id: str = Field(serialization_alias="bundleId")
    version: str
    # CFBundleVersion vs CFBundleShortVersionString. Jamf's inventory API exposes only
    # one version field, so this is null for recon and manual syncs and populated only
    # where the source carries both.
    short_version: str | None = Field(default=None, serialization_alias="shortVersion")

    # Populated by process_sync, not by the MDM clients — every ingest path funnels
    # through there, so hashing happens in exactly one place.
    app_hash: str | None = Field(default=None, serialization_alias="appHash")
    version_hash: str | None = Field(default=None, serialization_alias="versionHash")
    key_title: str | None = Field(default=None, serialization_alias="keyTitle")
    key_full: str | None = Field(default=None, serialization_alias="keyFull")


class NormalizedExtensionAttribute(BaseModel):
    """One extension attribute as the device reports it: Jamf's object under Jamf's keys,
    plus `source` (#197).

    Keyed by `definitionId` — the identity the observation contract and the change log
    already use — with `name` as its label, so an admin renaming an EA in Jamf changes a
    label on the wire and never the key a dashboard groups by. `values` is the whole
    list: a multi-value EA (an LDAP attribute, a pop-up menu) reports every element, as
    the ledger has always hashed it. `enabled` rides verbatim rather than filtering: a
    definition an admin disabled still holds whatever value Jamf reports for the device,
    hiding it would be the silent drop this model exists to end, and the flag is there so
    a consumer can tell a live value from a frozen one.

    `source` is the one key LoonInspect mints on this object — the Jamf response key the
    array was found under: `extensionAttributes` for the top-level array, else the
    display section (`general`, `hardware`, `operatingSystem`, `userAndLocation`,
    `purchasing`). The contract discards it on purpose, so that moving an EA between
    display sections changes nothing in the ledger; the wire carries it because an
    analyst wants to know where the admin put it. Both are right and neither is to be
    "fixed" to match the other (docs/jamf-observations.md §7). Corollary: a move changes
    the wire event and no span, so `source` is excluded from anything that derives a
    change.

    Jamf's own keys keep Jamf's spelling on the wire — `definitionId`, `multiValue`,
    `dataType`, `inputType` — because the casing law leaves a vendor's native keys alone
    (#188); the aliases are serialization-only, like NormalizedApp's.
    """

    definition_id: str = Field(serialization_alias="definitionId")
    name: str | None = None
    description: str | None = None
    enabled: bool | None = None
    multi_value: bool | None = Field(default=None, serialization_alias="multiValue")
    values: list[str] = Field(default_factory=list)
    data_type: str | None = Field(default=None, serialization_alias="dataType")
    options: list[str] = Field(default_factory=list)
    input_type: str | None = Field(default=None, serialization_alias="inputType")
    source: str


class NormalizedDevice(BaseModel):
    mdm_provider: MdmProvider
    external_id: str
    serial_number: str
    hostname: str
    managed: bool | None = None
    supervised: bool | None = None
    os_version: str | None = None
    site: str | None = None
    # Jamf's own ids for the two objects the device names by id and never by name; the
    # names are resolved at read time from `jamf_org_units` (app.mdm.org_units).
    building_id: str | None = None
    department_id: str | None = None
    last_check_in: datetime | None = None
    last_inventory_at: datetime | None = None
    # None means the applications section was not part of the read's aperture; [] means
    # it was read and the device genuinely has no apps. The two must never collapse:
    # process_sync wipes app rows on [], and a scoped webhook read must not wipe (#93).
    apps: list[NormalizedApp] | None = []
    # Same sentinel as apps: None when extension_attributes was outside the aperture,
    # [] when it was read and the device genuinely has none (#98).
    extension_attributes: list[NormalizedExtensionAttribute] | None = []
    # The read aperture this view was normalized under, as contract section names —
    # stamped by normalize_computer from the same `sections` the ledger canonicalized.
    # None means an aperture-less constructor (tests, fixtures) and reads as everything.
    sections: frozenset[str] | None = None

    def observed(self, section: str) -> bool:
        """Was this section part of the read that produced this view? The scalar-write
        gate in process_sync: a field outside the aperture holds a default, not an
        observation, and must not overwrite current state (#98)."""
        return self.sections is None or section in self.sections


class MdmSyncStatusOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, alias_generator=to_camel, populate_by_name=True)

    # Without this the UI can't tell which connection a status row belongs to, which
    # makes per-connection sync state unrenderable.
    mdm_connection_id: int
    provider: MdmProvider
    last_sync_at: datetime | None
    status: SyncStatus
    device_count: int


class InventoryChangedEvent(BaseModel):
    """One device's inventory delta, as it goes out on the wire.

    camelCase throughout, with the token `ID` uppercased on LoonInspect-minted keys —
    both ruled in #188. The aliases are serialization-only, so the Python side stays
    snake_case and only `model_dump(by_alias=True)` at the enqueue seam
    (app.mdm.service.process_sync) sees the wire spelling. That single seam is the whole
    reason the rename is safe: nothing else serializes this model.
    """

    event: str = "device.inventory.changed"

    # The run, at the event root as well as inside `deviceMeta` — ruled on #220,
    # 2026-09-02, option 1 of four. Duplicated on purpose: `deviceMeta.jobID` is a name a
    # customer's SPL may already carry and SPL fails silently on an unknown field, so it
    # stays; the root copy is what makes the cross-family join the bare `jobID=$id$`
    # docs/runs.md promises, instead of the two-term `jobID=$id$ OR deviceMeta.jobID=$id$`
    # it had to caveat. Additive under clause 1 (app.core.wire_vocabulary), and a
    # duplicate-on-purpose is not new here: `host` rides in both the envelope and the
    # body on the same reasoning (app.core.outbox).
    #
    # The cost is ~47 bytes on the most-multiplied event on the wire once the fan-out
    # lands (#242) — that is the whole argument the other three options made, and it was
    # ruled against because a join every consumer writes twice, or writes once and
    # silently under-reports on the highest-volume family, is the more expensive mistake.
    #
    # Absent rather than null when there is no run, mirroring the null-dropping rule
    # `deviceMeta` already follows (#189, and clause 3 blesses it): a run is present on
    # both the sweep and the webhook paths, so this is a defensive branch, and a null
    # here would pay the bytes on every sub-event to say nothing. Set from the meta block
    # itself in app.mdm.service.process_sync, so the two copies cannot disagree.
    job_id: str | None = Field(default=None, serialization_alias="jobID")

    provider: MdmProvider
    device_external_id: str = Field(serialization_alias="deviceExternalID")
    added_apps: list[NormalizedApp] = Field(serialization_alias="addedApps")
    removed_apps: list[NormalizedApp] = Field(serialization_alias="removedApps")
    occurred_at: datetime = Field(serialization_alias="occurredAt")

    # The device meta block (#189): the keys stamped onto every sub-event a device
    # produces, so events split apart at a destination still correlate back to the one
    # pull that produced them. Built by app.mdm.service._device_meta at enqueue time —
    # never at delivery, where the run ContextVar is already gone.
    #
    # It is the most expensive object in the schema: measured against a captured tenant
    # record it is over half the raw feed, because it is written once per app, per EA,
    # per certificate, per profile — not once per device. Keys are capped at thirteen
    # and adding one is permanent, so anything proposed here goes through #189 first.
    device_meta: dict = Field(default_factory=dict, serialization_alias="deviceMeta")


# --- the per-device snapshot (#241) --------------------------------------------------

# The state, beside the delta that says what happened to it. `device.inventory` is what
# a device IS after a pull; `device.inventory.changed` is what HAPPENED to its app list
# (#81 ruling 6's IS/HAPPENED test, applied to the discriminator) — so the delta keeps
# its name and keeps shipping unchanged, and `event=device.inventory*` collects both.
# One per device per pass that clears the ledger's monotonic guard, sweep and webhook
# alike, whether or not anything changed; enqueued by app.mdm.service.process_sync in
# the same transaction as the ledger write and the row updates. The fan-out (#242)
# expands this event and nothing else, so its shape is decided here, where the data is.
INVENTORY_EVENT_TYPE = "device.inventory"

# `vuln.assessment` — docs/vulnerabilities.md §4a. Always present on the app item, and
# `off` is the whole block until a corpus (#248) is loaded: the discriminator is populated
# from night one so presence is searchable (`vuln.assessment=off` extracts to a field;
# `{}` does not). `unknown_app` is snake_case on purpose — values are not governed by the
# casing law (§4b), it is the founder's word on the record twice, and a later conformance
# sweep must not "fix" it into `unknownApp` and break every saved search that names it.
VULN_ASSESSMENT_OFF = "off"
VULN_ASSESSMENT_UNKNOWN_APP = "unknown_app"
VULN_ASSESSMENT_COVERED = "covered"
VulnAssessment = Literal["covered", "unknown_app", "off"]


# The four states a matched build can be in, as `app.mdm.patch.matching` spells them.
# Restated rather than imported: `app.schemas` is below `app.mdm` and importing upwards to
# read four strings would invert the dependency for no gain. `test_patch_wire.py` asserts
# the two definitions are the same set, which is the same drift guard the wire registry
# and `ADDITIVE_ONLY_CLAUSES` already run.
PATCH_STATES = Literal["latest", "behind", "ahead", "unknown"]


class JamfPatchAnswer(BaseModel):
    """`patch.jamfPatch{}` — Jamf's Patch Management catalog's answer about THIS build (#311).

    **Why the source is a key and not a value** (Kyle, 2026-09-04, ruling 2). `patch{}` was
    minted with room for more than one answer: `docs/jamf-patch-matching.md` §1 says a
    connection's own patch provider "overlays" these columns later, and an overlay onto keys
    that name no source is a silent lie about provenance — every historical event becomes
    unattributable the day a second provider disagrees about "latest". Under `jamfPatch` both
    can ride at once, each keeping its own vocabulary, and `patch.jamfPatch.state` means one
    thing forever. `patch.sources` was considered and refused for v0: it costs ~25 bytes on
    every supported app to name the only source there is, and clause 1 lets it arrive with the
    second one.

    **No sourcetype is minted.** This is an inline enrichment on `loon:jamf:mac:app`, exactly
    as #249 populated `vuln{}` without stamping anything — a compound leaf would force
    `loon:jamf:mac:app:patch:vuln` on an app carrying both blocks, and `props.conf` stanzas
    take no wildcards. `loon:jamf:mac:app:patch` stays reserved and unused
    (docs/splunk-wire-vocabulary.md §7); the generated registry does not move.

    **Every value is a column read, not a calculation.** `copy_answer`
    (`app.catalog.service`) writes the whole answer onto the very `installed_apps` instances
    `process_sync` holds, so the producer reads them out of the session's identity map with no
    second query. A live re-evaluation would be ~4M runs of the matcher against a 1,543-title
    catalog per sweep, which is the thing "cache, don't calculate" exists to forbid.

    **`titleIDs` and `titleNames` are index-aligned, or `titleNames` is absent.** Two flat
    arrays rather than one array of objects because Splunk extracts flat arrays as clean
    multivalue fields and `mvzip` / `mvindex` exist to pair them; `titles{}.name` pivots worse
    and is clumsier at the SPL prompt. The alignment is load-bearing, so a name the loaded
    catalog cannot resolve — a title Jamf deleted between the judge and a scoped-read snapshot
    — drops the whole list rather than shipping a hole or the id in disguise. The producer
    logs when that happens.

    Keys absent rather than null throughout (`_only_the_keys_the_answer_carries`), under the
    same null-dropping rule clause 3 blesses for `deviceMeta`. `patchAvailableSince` and
    `releasesMissed` are #68's ruled sentence — "behind since 2024-01-03 · 14 releases missed"
    — and are absent unless a patch is actually available; both come from ONE title (the line
    whose first missed update is earliest), never a fold across titles. A day count is NOT
    minted here: #68 ruled that buckets and caps are a renderer's business and the wire carries
    the raw date and the raw integer, and a day computed at enqueue is wrong the moment the
    event is read.
    """

    # The matched titles, fully-evaluated first then by name (`summarize`). Non-empty by
    # construction: `supported` is true iff this list has something in it.
    title_ids: list[str] = Field(serialization_alias="titleIDs")
    # The only key in this block a person can read — "612" and "5F6" mean nothing in a search
    # bar, and `stats count by ...titleNames` is the query a patch dashboard opens with.
    title_names: list[str] | None = Field(default=None, serialization_alias="titleNames")
    state: PATCH_STATES
    # Kyle's #65 rule: at least one matched title says the installed version is its current
    # one — so a Firefox ESR user on the latest ESR is latest even though the rolling title
    # says behind. `state` is the folded answer; this is the bit it folds.
    on_latest: bool = Field(serialization_alias="onLatest")
    # Jamf lists this exact version on any matched title. False with `ahead` or `unknown`
    # says "running a build Jamf never published", which is a finding on its own.
    version_known: bool = Field(serialization_alias="versionKnown")
    # Absent on a row judged before #311 added the column — clause 4 exactly: absence means
    # the event predates the key. Never defaulted to `false`, which would assert that nothing
    # was assumed on a row nobody has re-judged.
    ea_assumed: bool | None = Field(default=None, serialization_alias="eaAssumed")
    # What the vendor ships now, per the reference title. The key that turns a Splunk alert
    # into a ticket a technician can act on without calling back.
    latest_version: str | None = Field(default=None, serialization_alias="latestVersion")
    latest_released_at: datetime | None = Field(default=None, serialization_alias="latestReleasedAt")
    patch_available_since: datetime | None = Field(default=None, serialization_alias="patchAvailableSince")
    releases_missed: int | None = Field(default=None, serialization_alias="releasesMissed")

    @model_validator(mode="after")
    def _a_supported_app_names_its_titles(self) -> JamfPatchAnswer:
        """An answer with no title is not an answer. `PatchEnrichment.supported` is defined as
        "this list is non-empty", so an empty one here would ship `supported: true` beside a
        block that claims nothing — refused at enqueue rather than indexed."""
        if not self.title_ids:
            raise ValueError("jamfPatch names no title; an app with no matched title is supported: false")
        if self.title_names is not None and len(self.title_names) != len(self.title_ids):
            raise ValueError("titleNames must be index-aligned with titleIDs, or absent")
        return self

    @model_serializer(mode="wrap")
    def _only_the_keys_the_answer_carries(self, handler) -> dict:
        """Drop absent keys rather than shipping them as null — the same rule `VulnEnrichment`
        runs, and the reason `{"supported": false}` stays one key wide below."""
        return {key: value for key, value in handler(self).items() if value is not None}


class PatchEnrichment(BaseModel):
    """`patch{}` on the app item — the Jamf Patch answer, riding that app's sub-event beside
    `vuln{}`.

    `supported` is a bool and always present, `false` when the app matches no Jamf Patch
    title (Kyle, 2026-09-01: "we need a default for the patching... a boolean ... set that
    equal to false. That way you can always search for it or not it easy"). Computed at
    enqueue from the `installed_apps` row already in the transaction — cache, don't
    calculate — and copied through by the fan-out, never stamped at delivery.

    **`supported` is the discriminator, and `false` ships nothing else** (#311). This is the
    rule `vuln{}` already runs one layer down with `assessment`, and it is load-bearing rather
    than tidy: on the real Mac mini 72 of 83 apps match no title, so a `false` carrying nine
    nulls would make ~87% of the highest fan-out object on the wire into padding. It also
    settles additive-only clause 4 mechanically — `supported` is always present and always
    says why the rest is missing, and an absence next to a discriminator that explains it is
    not the ambiguous absence clause 4 protects against.

    The shape is refused at enqueue if the two disagree, rather than papered over downstream.
    """

    supported: bool
    jamf_patch: JamfPatchAnswer | None = Field(default=None, serialization_alias="jamfPatch")

    @model_validator(mode="after")
    def _supported_says_whether_there_is_an_answer(self) -> PatchEnrichment:
        if self.supported and self.jamf_patch is None:
            raise ValueError("patch.supported is true with no source block; supported means a source answered")
        if not self.supported and self.jamf_patch is not None:
            raise ValueError("patch.supported is false with a jamfPatch block; false means no title matched")
        return self

    @model_serializer(mode="wrap")
    def _false_stays_one_key_wide(self, handler) -> dict:
        return {key: value for key, value in handler(self).items() if value is not None}


class VulnSeverityCounts(BaseModel):
    """`vuln.counts.severity` — findings by the corpus's severity band, this app, this
    device. The four bands are a closed set, so a corpus that invents a fifth is refused
    at enqueue rather than indexed under a name no dashboard knows.

    **Bands do not have to sum to `total`.** A finding the corpus carries with no severity
    score is counted in `counts.total` and in no band (docs/vulnerabilities.md §4). Said
    out loud in the schema as well as the doc, because the obvious `stats sum()` over the
    four bands silently under-reports otherwise.
    """

    critical: int
    high: int
    medium: int
    low: int


# The bands, worst first — read off the model rather than restated, so the schema is the
# one place a band exists. The order is load-bearing twice: it is the severity leg of the
# `vulnIDs` cap's priority (§4e), and it is the order the validator below walks.
VULN_SEVERITY_BANDS: tuple[str, ...] = tuple(VulnSeverityCounts.model_fields)


class VulnCounts(BaseModel):
    """`vuln.counts` — active findings against THIS installed version on THIS device.
    Never the fleet, never the app across the fleet (docs/vulnerabilities.md §4).

    `kev` is CISA's Known Exploited Vulnerabilities list and is **not** a severity band:
    a KEV finding is also counted in whatever band it carries, so `kev` and the four bands
    overlap by design.
    """

    total: int
    kev: int
    severity: VulnSeverityCounts


class VulnSeverityDays(BaseModel):
    """`vuln.daysOldestPublished.severity` — the same clock, per band.

    `None` is the canonical form of *never*; the `-1` the wire ships is minted at the
    HEC-shaping seam (`app.core.vuln.mint_hec_sentinels`, docs/vulnerabilities.md §4c), so
    a warehouse destination can still render SQL `NULL`.
    """

    critical: int | None
    high: int | None
    medium: int | None
    low: int | None


class VulnDaysOldestPublished(BaseModel):
    """`vuln.daysOldestPublished` — days since the publication date of the OLDEST active
    finding, overall and per band (docs/vulnerabilities.md §4d).

    Publication, not first-detected, and the key name says which clock: under a
    hand-refreshed corpus a knew-about-it basis collapses the whole backlog onto the
    refresh date, so every fleet would look better the slower we refresh — the number
    would measure our cadence, not the customer's exposure. First-detected-in-tenant is
    recoverable from the customer's own index (a snapshot stream's first appearance of an
    id); publication is not, so publication is what ships.

    `total` is not the maximum of the four bands: an unscored finding is in the total and
    in no band.
    """

    total: int | None
    severity: VulnSeverityDays


class VulnEnrichment(BaseModel):
    """`vuln{}` on the app item — LoonInspect's own answer about an app Jamf reported,
    riding that app's sub-event beside `patch{}` (docs/vulnerabilities.md §3 and §4).

    It is an INLINE enrichment on `loon:jamf:mac:app`. `loon:jamf:mac:app:vuln` is minted
    and reserved for the post-v0 lifecycle records — one event per finding transition, not
    one per app — because taking the compound here would force
    `loon:jamf:mac:app:patch:vuln` on an app carrying both blocks, and sourcetypes are
    permanent hand-written `props.conf` stanzas.

    **Which keys ride is decided by `assessment`, and the shape is refused if it is not**
    (§4a). This is the "zero is not a clean bill" rule, made unwritable rather than
    documented:

    * `off` — the whole block is `{"assessment": "off"}`. An unlicensed or unconsented
      pod, or a container with no corpus loaded, leaks nothing;
    * `unknown_app` — `assessment` and `corpusAsOf`, dated. **Never** `counts.total: 0`:
      shipping a zero beside it hands a careless `stats sum(vuln.counts.total)` a clean
      bill for a fleet nobody assessed, which is the exact failure the `assessment`
      vocabulary exists to prevent;
    * `covered` — every key. `counts.total: 0` here IS a clean bill, and it is honest
      precisely because `covered` says we looked.

    The reconciliation with additive-only clause 4 (*absence means the event predates the
    key*) is mechanical: `assessment` is always present and always says why. An absence
    next to a discriminator that explains it is not the ambiguous absence clause 4
    protects against — the same doctrine the posture tape runs one layer down.

    The cap on `vulnIDs` is deliberately **not** a wire key (§4e): ~50 ids, priority
    KEV → severity → recency, a server-side knob that can move at any time — which stays
    safe only because `vulnIDsTruncated` ships beside the list to say when it bit.
    """

    assessment: VulnAssessment = VULN_ASSESSMENT_OFF
    # Present when `assessment` is `covered` or `unknown_app`: the corpus generation this
    # answer came from, so a hand-refreshed corpus decays visibly instead of silently, and
    # the NVD ingest's eventual arrival is self-evident when the date starts moving on its
    # own (Kyle, 2026-09-01, ruling 4).
    corpus_as_of: date | None = Field(default=None, serialization_alias="corpusAsOf")
    # The four below ride `covered` only.
    counts: VulnCounts | None = None
    days_oldest_published: VulnDaysOldestPublished | None = Field(
        default=None, serialization_alias="daysOldestPublished"
    )
    vuln_ids: list[str] | None = Field(default=None, serialization_alias="vulnIDs")
    vuln_ids_truncated: bool | None = Field(default=None, serialization_alias="vulnIDsTruncated")

    @model_validator(mode="after")
    def _absence_says_why(self) -> VulnEnrichment:
        """§4a and §4c, in both directions, refused at enqueue rather than indexed.

        Two rules. Which keys are present is a function of `assessment` and nothing else —
        so a producer cannot ship a zero count under `unknown_app`, and cannot ship a
        `covered` that says nothing. And the sentinel invariant, which is the one a
        dashboard divides by:

            daysOldestPublished.severity.X is not None  <=>  counts.severity.X > 0
            daysOldestPublished.total       is not None  <=>  counts.total       > 0

        (on the wire, with the sentinel minted, that reads `>= 0` — §4c.)
        """
        dated = self.assessment != VULN_ASSESSMENT_OFF
        if (self.corpus_as_of is not None) != dated:
            raise ValueError(
                "`corpusAsOf` rides `covered` and `unknown_app` and only those, so under "
                f"`{self.assessment}` it must be {'present' if dated else 'absent'}"
            )
        populated = self.assessment == VULN_ASSESSMENT_COVERED
        for name in ("counts", "days_oldest_published", "vuln_ids", "vuln_ids_truncated"):
            if (getattr(self, name) is not None) != populated:
                raise ValueError(
                    f"`{name}` rides `covered` and only `covered`, so under `{self.assessment}` it must be "
                    f"{'present' if populated else 'absent'} — the counts, the days and the id list are "
                    "absent, not zero (docs/vulnerabilities.md §4a)"
                )
        if self.counts is None or self.days_oldest_published is None:
            return self
        pairs = [(self.counts.total, self.days_oldest_published.total, "total")]
        pairs += [
            (getattr(self.counts.severity, band), getattr(self.days_oldest_published.severity, band), band)
            for band in VULN_SEVERITY_BANDS
        ]
        for count, days, band in pairs:
            if (days is not None) != (count > 0):
                raise ValueError(f"daysOldestPublished.{band} and counts.{band} disagree about whether a finding exists")
        return self

    @model_serializer(mode="wrap")
    def _only_the_keys_the_assessment_carries(self, handler) -> dict:
        """Drop the absent keys rather than shipping them as null — §4a's "absent, not
        zero", which is also "absent, not null".

        Scoped to THIS block's own keys. It never descends: `daysOldestPublished.total` is
        `None` under a clean bill and must stay present as null, because §4c makes those
        keys always-present-and-always-int on the wire once the sentinel is minted.
        """
        return {key: value for key, value in handler(self).items() if value is not None}

    @classmethod
    def __get_pydantic_json_schema__(cls, core_schema, handler):  # type: ignore[override]
        """Describe the block in OpenAPI as the keys it has, not as a bare object (#251).

        A custom `model_serializer` makes pydantic give up on the serialization JSON
        schema and emit `{"type": "object", "additionalProperties": true}` — it cannot know
        what an arbitrary function returns. That was invisible while this model rode the
        wire alone; #251 put it on REST responses, where the generated OpenAPI is the
        documentation a client is written against, and "object" documents nothing.

        The serializer above only ever *drops* keys, so the schema pydantic would generate
        without it is already correct — every ruled key, under its serialization alias,
        with `assessment` as the three-value enum. This asks for exactly that by handing
        the generator the same core schema minus the custom serializer.

        **Schema only.** Nothing here runs during validation or serialization: the bytes on
        the wire and in a REST response are unchanged, byte for byte, and
        `test_vuln_block.py` still pins them.
        """
        model = core_schema.get("schema") if core_schema.get("type") != "model" else core_schema
        if isinstance(model, dict) and "serialization" in model:
            without = {**model}
            without.pop("serialization")
            core_schema = without if core_schema is model else {**core_schema, "schema": without}
        return handler(core_schema)


class InventoryAppItem(BaseModel):
    """One `app[]` item on the snapshot: Jamf's application object beside LoonInspect's two
    enrichment blocks.

    This is, key for key, the fan-out sub-event's body minus the three keys every
    sub-event carries (`app.core.wire_vocabulary.SUB_EVENT_KEYS`), so #242 iterates rather
    than reshapes, and every shape decision lives on this side of the outbox. It also keeps
    the enrichment keys BESIDE Jamf's object rather than inside it — namespaced, not
    flattened (docs/splunk-wire-vocabulary.md §1) — so Jamf can never add a field that
    collides with `patch`.

    `app` is Jamf's v4 `computers-inventory` application record under Jamf's own key
    names (Kyle, 2026-09-02: "Use Jamf's v4 Names Verbatim in the sections I am copying
    them"), restricted to the ledger's allowlist (`contract._APPLICATION`): `name`,
    `path`, `version`, `cfBundleShortVersionString`, `cfBundleVersion`, `bundleId`,
    `macAppStore` — each absent where Jamf sent nothing. The four minted identity fields
    (`appHash`, `versionHash`, `keyTitle`, `keyFull`) do NOT ride here (Kyle, 2026-09-02:
    "leave them out for now we can add them in the future. We can add keys later but we
    can't take them away"); they keep riding the delta's `addedApps[]` / `removedApps[]`,
    which is not the fan-out. `alert` (#229) is name-only in v0 and writes nothing.

    All three keys are required: a payload whose app item lacks a block is a producer bug
    refused here, at enqueue, not a case the fan-out papers over.
    """

    app: dict
    patch: PatchEnrichment
    vuln: VulnEnrichment


# The snapshot's own keys — everything on the event that is not a section wrapper.
SNAPSHOT_HEAD_KEYS: tuple[str, ...] = ("event", "jobID", "occurredAt", "deviceMeta")


class InventorySnapshotEvent(BaseModel):
    """One device's inventory as Jamf reported it on one pull, under the frozen vocabulary.

    Top level: the head — `event`, `jobID`, `occurredAt`, `deviceMeta` — and then one key
    per section that was inside the read's aperture, spelled exactly as
    `app.core.wire_vocabulary.SECTION_WRAPPERS` spells it (pinned in
    tests/test_inventory_snapshot.py in both directions). The seven scalar sections are
    Jamf's object; the seven list sections are lists of items, each item the fan-out
    sub-event's body minus `SUB_EVENT_KEYS` — `{"cert": {…Jamf…}}`, and for `app`
    `{"app": {…}, "patch": {…}, "vuln": {…}}`.

    Three meanings of absence, all written into docs/runs.md §4:

    * a wrapper ABSENT — the section was outside this read's aperture (the 2026-08-29
      ruling, per section): never assert an absence the read did not observe. A scoped
      webhook read of `["general", "hardware", "operating_system"]` produces three
      wrappers and no `app` key. `None` here means exactly that and is dropped from the
      dump;
    * a wrapper `{}` or `[]` — read, and genuinely empty;
    * a key absent INSIDE a Jamf object — Jamf sent no value: an older server that does
      not report the field, or a null the canonicalizer dropped.

    Every section object is pinned to the v4 `computers-inventory` shape. A field Jamf
    adds reaches the wire when the allowlist admits it — additive under clause 1, never
    automatic; a rename or removal forced by a later major endpoint version is a breaking
    wire change and ships as a `schemaVersion` bump in `deviceMeta` (clause 6), never a
    silent reshape.

    Aliases are the wire spellings, and the model is populated BY those spellings
    (`populate_by_name` keeps the Python names usable too): the producer builds the
    wrappers from the registry and never spells one by hand.

    `extra="forbid"`: a wrapper this model has no field for is refused at enqueue, not
    dropped. Pydantic's default is `ignore`, under which a fifteenth section added to the
    registry without a field here would be silently left out of every snapshot in
    production while the pure tests went red — the refuse-at-enqueue posture the app item
    already claims, made true for wrappers (PR #273's verify pass, should-fix 1). The fan-out
    (#242) relies on it from the other side: a key the registry does not name can reach it
    only through version skew, never from this producer.
    """

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    event: str = INVENTORY_EVENT_TYPE
    # The run, at the root and inside `deviceMeta`, both — #220's ruling, the same as the
    # delta's. Read off the meta block in the producer so the two copies cannot drift, and
    # absent rather than null when there is no run (`to_payload`).
    job_id: str | None = Field(default=None, alias="jobID")
    # A sweep's snapshots share the run's window; a webhook's carries the device's own
    # reportDate (app.core.runs.event_time). The snapshot and the delta from one pull
    # share this value, the meta block and its `eventID` — by design (#81 ruling 4).
    occurred_at: datetime = Field(alias="occurredAt")
    # #189's block, stamped ONCE, here. Copying it onto every sub-event is the fan-out's
    # job (#242) and the "over half the raw feed" cost is paid there, not here.
    device_meta: dict = Field(default_factory=dict, alias="deviceMeta")

    # The seven one-per-device sections — what #81 called the "device anchor"; under the
    # frozen registry the anchor is one sub-event per scalar section, which is why all
    # seven ride.
    general: dict | None = None
    hardware: dict | None = None
    operating_system: dict | None = Field(default=None, alias="operatingSystem")
    user_and_location: dict | None = Field(default=None, alias="userAndLocation")
    purchasing: dict | None = None
    security: dict | None = None
    disk_encryption: dict | None = Field(default=None, alias="diskEncryption")
    # The seven list sections. `localUserAccount` sits under the registry's "one per
    # device — long" naming comment, but that is the naming rule, not cardinality: the
    # contract's `entry_kind` makes it a list, and the list wins.
    app: list[InventoryAppItem] | None = None
    ea: list[dict] | None = None
    group: list[dict] | None = None
    profile: list[dict] | None = None
    local_user_account: list[dict] | None = Field(default=None, alias="localUserAccount")
    cert: list[dict] | None = None
    update: list[dict] | None = None

    @model_validator(mode="after")
    def _items_are_wrapped(self) -> InventorySnapshotEvent:
        """Every list item carries its section's object under the section's own wrapper
        key and nothing else — the sub-event body minus `SUB_EVENT_KEYS`. `app` is typed
        above; the other six are held to the same shape here so a bare Jamf object can
        never slip into a list the fan-out iterates."""
        for name in ("ea", "group", "profile", "local_user_account", "cert", "update"):
            items = getattr(self, name)
            if items is None:
                continue
            wrapper = type(self).model_fields[name].alias or name
            for item in items:
                if set(item) != {wrapper} or not isinstance(item[wrapper], dict):
                    raise ValueError(f"every {wrapper}[] item must be {{{wrapper!r}: <Jamf's object>}}, got {item!r}")
        return self

    def to_payload(self) -> dict:
        """The stored outbox payload: wire spellings, and the two kinds of `None` dropped
        rather than shipped as null — a wrapper outside the aperture, and a run-less
        `jobID`. Nothing INSIDE a Jamf object is touched: the app object already carries
        no nulls (the canonicalizer dropped them), and the extension-attribute object
        carries Jamf's verbatim, nulls included (#197)."""
        dumped = self.model_dump(mode="json", by_alias=True)
        return {key: value for key, value in dumped.items() if value is not None}
