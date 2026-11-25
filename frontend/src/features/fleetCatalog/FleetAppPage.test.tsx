// @vitest-environment jsdom
/** An installed app's or a Fleet title's own page (#906–#909). `./api`'s reads are stubbed, its `fleetScopeQuery` is the real one. */
import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router";
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "@/config/api";
import { FleetAppPage } from "@/features/fleetCatalog/FleetAppPage";
import type { FleetAssessment, FleetBuildAssessment, FleetCandidate, ImpactUnavailable, MigrationDetail, MigrationImpact, MigrationItem,
  PolicyUnassessed } from "@/features/fleetCatalog/migrationTypes";
import type { FleetTitleHistory } from "@/features/fleetCatalog/types";
import { policySentence } from "@/features/jamfPatch/policyRules";
import type { PatchRule, PolicyVersion } from "@/features/jamfPatch/types";
import { de } from "@/i18n/de";
import { en } from "@/i18n/en";

// West of UTC, where a corpus date read as local midnight would show the day before. Restored after.
const zone = vi.hoisted(() => { const was = process.env.TZ; process.env.TZ = "America/Los_Angeles"; return was; });
afterAll(() => { if (zone === undefined) delete process.env.TZ; else process.env.TZ = zone; });
const locale = vi.hoisted(() => ({ current: "en" as "en" | "de" }));
vi.mock("@/i18n/LocaleContext", async () => ({ useLocale: () => ({ locale: locale.current, t: locale.current === "de" ? de : en }) }));
const api = vi.hoisted(() => ({ getFleetDetail: vi.fn(), getTitleHistory: vi.fn(), readTitleHistory: vi.fn() }));
vi.mock("@/features/fleetCatalog/api", async original => ({ ...await original<typeof import("@/features/fleetCatalog/api")>(), ...api }));
const held = vi.hoisted(() => ({ permissions: [] as string[] }));
vi.mock("@/features/auth/store", () => ({ useHasPermission: (permission: string) => held.permissions.includes(permission) }));

const words = en.fleetDetail;
const candidate: FleetCandidate = { name: "Example App", slug: "example", bundleId: "com.example.app", latestVersion: "2.0" };
const local: MigrationItem = { name: "Example App.app", appHash: "a".repeat(32), bundleId: candidate.bundleId, macs: 3, versionCount: 2,
  hasJamfMatch: true, jamfEvaluated: true, match: "exact", fleetCandidates: [candidate] };
// #857's fixture, on #897's codes: partly judged (one build within its rule, one not judged), one KEV build behind Fleet's latest.
const assessment: FleetAssessment = { targetVersion: "2.0", priority: "review_now", priorityReason: "kev", management: "recurring", recentVersions: 3,
  corpusAsOf: "2026-11-20", behindBuilds: 1, unorderedBuilds: 0, oldestGapDays: 12, exactBuilds: 1, netOnlyBuilds: 0, unknownBuilds: 0, outOfPolicyBuilds: 0,
  withinPolicyBuilds: 1, policyExemptBuilds: 0, policyUnassessedBuilds: 1, kevBuilds: 1, addresses: 2, introduces: 1, remains: 1, builds: [] };
const detail: MigrationDetail = { enabled: true, asOf: "2026-11-22T17:00:00Z", fleetCatalogReady: true, fleetCatalogReadiness: "complete",
  jamfCatalogReady: true, scope: { eligibleMacs: 10, selectedMacs: 6, unknownContactMacs: 1, unknownInventoryMacs: 0 }, installedEvidence: {},
  observedChanges: { windowDays: 90, versionChanges: 3, macs: 2, lastAt: "2026-11-21T00:00:00Z", adoptionSamples: 2, medianDaysAfterFleetPublication: 2.5 },
  appAssessments: {}, assessments: {}, item: local, title: null, items: [local], installedMacs: 3, impact: null, impactUnavailable: null,
  builds: [{ appHash: local.appHash, version: "1.0", shortVersion: null, versionHash: "f".repeat(32), macs: 2 },
    { appHash: local.appHash, version: "2.0", shortVersion: null, versionHash: "e".repeat(32), macs: 1234 }], jamfTitles: [{ id: "0AB", name: "Example patch definition" }] };
const history: FleetTitleHistory = { slug: candidate.slug, name: candidate.name, latestVersion: "2.0", historyComplete: true, historyDetail: null, historyReadAt:
  "2026-11-21T12:00:00Z", historySince: "2026-11-03", historyThrough: "2026-11-20", versions: [{ version: "2.0", previousVersion: "1.9", commitSha: "c".repeat(40), seenAt: "2026-11-20T12:00:00Z" }] };
const base = "/devices/applications/fleet-catalog";
const said = (coverage: string, footprint = "3 of 6 in-scope Macs report this app.") => screen.findByText(`${footprint} ${coverage}`);
const href = (name: string | RegExp) => screen.getByRole("link", { name }).getAttribute("href");
const shown = (...texts: string[]) => texts.map(text => Boolean(screen.queryByText(text)));
const hang = () => api.getFleetDetail.mockImplementation(() => new Promise(() => {}));
function open(path: string, answer: Partial<MigrationDetail> | Error = {}) {
  cleanup();
  api.getFleetDetail.mockImplementation(async () => { if (answer instanceof Error) throw answer; return { ...detail, ...answer }; });
  render(<MemoryRouter initialEntries={[base + path]}><Routes><Route path={base + "/apps/:appHash"} element={<FleetAppPage />} />
    <Route path={base + "/titles/:slug"} element={<FleetAppPage />} /></Routes></MemoryRouter>);
}
beforeEach(() => { vi.clearAllMocks(); api.getTitleHistory.mockResolvedValue(history); held.permissions = []; locale.current = "en"; });
afterEach(cleanup);

it("reads an exact app once, on the list's device filter alone, with its builds, links and history", async () => {
  const scope = JSON.stringify({ match: "all", connectionId: 3, rules: [] }), query = "?" + new URLSearchParams({ deviceScope: scope, q: "app", filter: "outside", sort: "name", page: "2" });
  open(`/apps/${local.appHash}${query}`);
  expect(await said(words.exact)).toBeTruthy();
  expect(api.getFleetDetail).toHaveBeenCalledExactlyOnceWith("apps", local.appHash, `deviceScope=${encodeURIComponent(scope)}`, undefined, expect.any(AbortSignal));
  expect([href(words.back), href(/^Fleet manifest/), href(words.record), href("Example patch definition")]).toEqual([base + query,
    "https://github.com/fleetdm/fleet/blob/main/ee/maintained-apps/outputs/example/darwin.json", `/devices/applications/${local.appHash}`, "/devices/applications/jamf-patch/0AB"]);
  expect(shown(local.bundleId, "6 of 10 current Jamf Macs selected", words.planLink)).toEqual([true, true, false]); // no plan without patch:plan-write
  const builds = within(screen.getByRole("heading", { name: words.installed }).closest("section")!);
  const rows = () => builds.getAllByRole("row").slice(1).map(row => row.textContent);
  expect(rows()).toEqual(["1.02", "2.01,234"]);
  fireEvent.change(builds.getByLabelText(words.filterVersion), { target: { value: "0" } });
  expect(rows()).toEqual(["1.02"]);
  expect(await screen.findByRole("searchbox", { name: en.fleetCatalog.historySearch })).toBeTruthy(); // #901's detail layout
  expect(screen.getAllByRole("button").map(button => button.textContent)).toEqual(["Compare 2.0"]); // no Read history without patch:catalog-sync
});

it("lists a shared bundle ID's channels with the list's query and no history, and says why coverage is unknown", async () => {
  const uncertain: MigrationItem = { ...local, match: "ambiguous", fleetCandidates: [candidate, { ...candidate, name: "Example ESR", slug: "example@esr" }] };
  held.permissions = ["patch:plan-write"];
  open(`/apps/${local.appHash}?q=example`, { item: uncertain, items: [uncertain] });
  expect(await said(words.ambiguous)).toBeTruthy();
  expect([href("Example ESR"), href(words.planLink)]).toEqual([`${base}/titles/example%40esr?q=example`, `/patch-plans?appHash=${local.appHash}`]); // planned all the same
  expect([screen.queryByRole("heading", { name: words.versions }), screen.queryByRole("link", { name: /^Fleet manifest/ }), api.getTitleHistory.mock.calls]).toEqual([null, null, []]);
  const unnamed: MigrationItem = { ...local, bundleId: local.name, match: "unknown", fleetCandidates: [] };
  open(`/apps/${local.appHash}`, { item: unnamed, items: [unnamed], fleetCatalogReadiness: "partial" });
  expect([await said(words.catalogUnknown(true)), ...shown(words.bundleMissing, en.fleetPlanning.partialCatalog)].every(Boolean)).toBe(true);
  const unread: MigrationItem = { ...local, match: "unknown", fleetCandidates: [] }; // a bundle ID, and a catalog not read whole
  open(`/apps/${local.appHash}`, { item: unread, items: [unread] });
  expect(await said(words.catalogUnknown(false))).toBeTruthy();
});

it("opens a title on its history and identities, and a history read reads the page again without blanking it", async () => {
  const beta: MigrationItem = { ...local, name: "Example Beta.app", appHash: "b".repeat(32), macs: 1, match: "ambiguous" };
  open("/titles/example?view=catalog", { item: null, title: candidate, items: [local, beta],
    builds: [...detail.builds, { appHash: beta.appHash, version: "3.0", shortVersion: null, versionHash: "d".repeat(32), macs: 1 }] });
  expect([await said(words.catalogFirst), screen.getByText(words.ambiguous)].every(Boolean)).toBe(true);
  expect([href(local.name), href(beta.name)]).toEqual([`${base}/apps/${local.appHash}?view=catalog`, `${base}/apps/${beta.appHash}?view=catalog`]);
  expect(within(screen.getByRole("heading", { name: words.installed }).closest("section")!).getAllByRole("row").slice(1).map(row => row.textContent))
    .toEqual(["1.0Example App.app2", "2.0Example App.app1,234", "3.0Example Beta.app1"]); // each build names its app
  held.permissions = ["patch:catalog-sync"];
  open("/titles/example", { item: null, items: [], title: candidate, builds: [], installedMacs: 0, jamfTitles: [] });
  expect(await said(words.catalogFirst, "0 of 6 in-scope Macs report this app.")).toBeTruthy();
  const read = await screen.findByRole("button", { name: en.fleetCatalog.historyReadAgain });
  expect([screen.getAllByRole("button"), shown(words.noBuilds, words.jamfMissing, words.jamfPending, words.jamfUnavailable)]).toEqual([[read], [true, false, false, false]]);
  api.readTitleHistory.mockResolvedValue(history);
  hang();
  await act(async () => fireEvent.click(read));
  expect([api.getFleetDetail.mock.calls.length, ...shown(words.noBuilds, words.loading)]).toEqual([3, true, false]);
});

it("keeps unmatched inventory, with exactly one reason no Jamf Patch title matched", async () => {
  const unmatched: MigrationItem = { ...local, match: "none", hasJamfMatch: false, fleetCandidates: [] };
  for (const [n, change] of [{}, { items: [{ ...unmatched, jamfEvaluated: false }] }, { jamfCatalogReady: false }].entries()) {
    open(`/apps/${local.appHash}`, { item: unmatched, items: [unmatched], jamfTitles: [], ...change });
    expect(await said(words.noMatch)).toBeTruthy();
    expect(shown(words.jamfMissing, words.jamfPending, words.jamfUnavailable)).toEqual([0, 1, 2].map(i => i === n));
  }
});

it("shows a refusal's own sentence beside Retry, which clears it and reads again; a 409 and no sentence in the page's words", async () => {
  const refusal = "No Mac the device filter selects has this app in its inventory.";
  open(`/apps/${local.appHash}`, new ApiError(404, refusal));
  const alert = await screen.findByRole("alert");
  hang();
  fireEvent.click(within(alert).getByRole("button", { name: words.retry }));
  expect([alert.textContent, screen.queryByRole("alert"), screen.getByRole("status").textContent]).toEqual([refusal + words.retry, null, words.loading]);
  for (const [failure, language, sentence] of [[new ApiError(409, "sent"), "de", de.fleetCatalog.emptyFlagOff],
    [new ApiError(409, null), "en", en.fleetCatalog.emptyFlagOff], [new TypeError("Failed to fetch"), "en", words.readFailed]] as const) {
    locale.current = language;
    open(`/apps/${local.appHash}`, failure);
    expect((await screen.findByRole("alert")).textContent).toBe(sentence + (language === "de" ? de : en).fleetDetail.retry);
  }
});

it("reads in German with German numbers, and words one Mac in the singular", async () => {
  locale.current = "de";
  open(`/apps/${local.appHash}`, { installedMacs: 1, scope: { ...detail.scope, selectedMacs: 1234, eligibleMacs: 12345 } });
  expect(await said(de.fleetDetail.exact, "1 von 1.234 Macs im Gerätefilter meldet diese App.")).toBeTruthy();
  expect(shown("1.234 von 12.345 aktuellen Jamf-Macs ausgewählt", "1.234", de.fleetDetail.back)).toEqual([true, true, true]);
  expect([words.footprint("1", true, "1", true), words.scopeMacs("1", "1", true)]).toEqual(["1 of 1 in-scope Mac reports this app.", "1 of 1 current Jamf Mac selected"]);
  for (const t of [en, de]) expect([t.fleetDetail.jamfUnavailable, t.fleetDetail.jamfPending].every(s => s.includes(`${t.jamfPatch.eyebrow} › ${t.jamfPatch.tabLabel}`) && s.includes(t.jamfPatch.syncNow))).toBe(true);
});

it("says the list's verdict and policy word for an app, its update review, and hands its Macs to Patch Plans, in both languages", async () => {
  const scope = JSON.stringify({ match: "all", connectionId: 3, rules: [] }), query = new URLSearchParams({ deviceScope: scope, q: "app", sort: "name" });
  held.permissions = ["patch:plan-write"];
  for (const [t, policy] of [[en, "Partly judged"], [de, "Teilweise beurteilt"]] as const) {
    locale.current = t === en ? "en" : "de";
    open(`/apps/${local.appHash}?${query}`, { appAssessments: { [local.appHash]: assessment } });
    expect(await screen.findByText(t.fleetPlanning.reasons.kev)).toBeTruthy();
    expect([screen.getByText(t.fleetPlanning.columns.policy).nextElementSibling?.textContent, ...shown(t.fleetDetail.findingsLag)]).toEqual([policy, true]);
    expect(href(t.fleetDetail.planLink)).toBe(`/patch-plans?${new URLSearchParams({ deviceScope: scope })}&appHash=${local.appHash}`); // the filter as sent, no q
  }
  expect(screen.getByText(/^Fleet hat in den letzten 90 Tagen/).textContent).toBe(
    "Regelmäßige Update-Prüfung. Fleet hat in den letzten 90 Tagen 3 Versionen dieses Titels datiert; ab zwei empfiehlt sich eine regelmäßige Prüfung.");
});

it("reads a title's verdict from its own assessment, plans each identity a selected Mac has, and judges nothing with no installs", async () => {
  held.permissions = ["patch:plan-write"];
  const beta: MigrationItem = { ...local, name: "Example Beta.app", appHash: "b".repeat(32), macs: 1 }, gone = { ...beta, name: "Gone.app", appHash: "c".repeat(32), macs: 0 };
  open("/titles/example", { item: null, title: candidate, items: [local, beta, gone], assessments: { example: { ...assessment, priorityReason: "comparable", recentVersions: 1 } } });
  expect(await screen.findByText(en.fleetPlanning.reasons.comparable)).toBeTruthy();
  expect([href(words.planLink), screen.getByText(en.fleetPlanning.columns.policy).nextElementSibling?.textContent]).toEqual([`/patch-plans?appHash=${local.appHash}&appHash=${beta.appHash}`, "Partly judged"]);
  expect(screen.getByText(/^Fleet dated 1 version /).textContent).toBe("Recurring update review. Fleet dated 1 version of this title in the past 90 days; two or more suggest recurring review.");
  open("/titles/example", { item: null, title: candidate, items: [], builds: [], installedMacs: 0, assessments: { example: { ...assessment, priorityReason: "none_behind",
    management: "observe", recentVersions: null, behindBuilds: 0, exactBuilds: 0, kevBuilds: null, withinPolicyBuilds: 0, policyUnassessedBuilds: 0 } },
    impact: { targetVersion: "2.0", installedMacs: 0, olderMacs: 0, atOrAboveMacs: 0, unknownMacs: 0 } }); // #899's answer with no installs: zeros, no reason
  expect(await said(words.catalogFirst, "0 of 6 in-scope Macs report this app.")).toBeTruthy();
  expect([...shown(en.fleetPlanning.reasons.none_behind, words.installedFindings, words.observedTitle, words.planLink, words.installedScope, words.findings,
    words.monitorCurrent("2.0"), "Not judged", words.guidance), screen.getByText(words.cadenceUnread).textContent])
    .toEqual([false, false, false, false, false, false, false, true, true, words.cadenceUnread]); // no management word or pilot line either, but the guide
});

it("counts each identity's builds in the reader's numbers, never a null as 0, on the day the corpus is dated", async () => {
  expect(new Date("2026-11-20T00:00:00Z").getDate()).toBe(19); // this file runs west of UTC
  const [beta, gamma, delta] = ["b", "c", "d"].map(c => ({ ...local, name: `${c.toUpperCase()}.app`, appHash: c.repeat(32) }));
  const unread = { assessedBuilds: 0, affectedBuilds: null, highOrCriticalBuilds: null, kevBuilds: null };
  open("/titles/example", { item: null, title: candidate, items: [local, beta, gamma, delta], installedEvidence: {
    [local.appHash]: { assessment: "partial", asOf: "2026-11-20", assessedBuilds: 1234, unknownBuilds: 1, affectedBuilds: 2, highOrCriticalBuilds: null, kevBuilds: 0 },
    [beta.appHash]: { assessment: "unknown_app", asOf: "2026-11-20", unknownBuilds: 3, ...unread }, [gamma.appHash]: { assessment: "off", asOf: null, unknownBuilds: 2, ...unread } } });
  const block = async (name: string) => (await screen.findByRole("heading", { name })).parentElement!.textContent;
  expect(await Promise.all([local.name, "B.app", "C.app", "D.app"].map(block))).toEqual([
    "Example App.appVulnerability corpus as of 11/20/2026Assessed builds1,234Unassessed builds1With findings2With high or critical findings—With known exploited findings0",
    "B.appVulnerability corpus as of 11/20/2026Outside the corpusUnassessed builds3", "C.appVulnerabilities: not assessed", "D.appVulnerabilities: not assessed"]);
  expect(shown(words.findingsLag)).toEqual([false]); // no verdict on the page to differ from
  locale.current = "de";
  open(`/apps/${local.appHash}`, { installedEvidence: { [local.appHash]: { assessment: "covered", asOf: "2026-11-20", assessedBuilds: 1234, unknownBuilds: 0,
    affectedBuilds: 1234, highOrCriticalBuilds: 0, kevBuilds: 0 } } });
  const findings = within((await screen.findByRole("heading", { name: de.fleetDetail.installedFindings })).closest("section")!);
  expect([findings.getByText("Schwachstellen-Korpus vom 20.11.2026"), findings.getByText("Bewertete Builds").nextElementSibling?.textContent,
    findings.getAllByRole("heading").length]).toEqual([expect.anything(), "1.234", 1]); // one identity: its block is not named
});

it("words observed upgrades one at a time, measured or not, in the reader's numbers", async () => {
  open(`/apps/${local.appHash}`, { installedMacs: 1, scope: { ...detail.scope, selectedMacs: 1, eligibleMacs: 1 },
    observedChanges: { windowDays: 90, versionChanges: 1, macs: 1, lastAt: null, adoptionSamples: 1, medianDaysAfterFleetPublication: 1 } });
  expect(await said(words.exact, "1 of 1 in-scope Mac reports this app.")).toBeTruthy();
  expect([...shown("1 of 1 current Jamf Mac selected", "1 recorded version change on 1 Mac in the last 90 days.",
    "Median 1 day after Fleet dated the version, across 1 Mac/version pair."), screen.queryByText(/^Last recorded/)]).toEqual([true, true, true, null]); // lastAt null
  for (const [samples, sentence] of [[null, words.observedNotMeasured], [0, words.observedNoLag]] as const) {
    open(`/apps/${local.appHash}`, { observedChanges: { ...detail.observedChanges, adoptionSamples: samples, medianDaysAfterFleetPublication: null } });
    expect(await screen.findByText(sentence)).toBeTruthy();
  }
  locale.current = "de";
  open(`/apps/${local.appHash}`, { observedChanges: { ...detail.observedChanges, versionChanges: 1234 } });
  expect(await screen.findByText("1.234 erfasste Versionswechsel auf 2 Macs in den letzten 90 Tagen.")).toBeTruthy();
  expect(shown("Median 2,5 Tage nach Fleets Datierung der Version, bei 2 Mac/Versions-Paaren.", "Zuletzt erfasst am 20.11.2026.")).toEqual([true, true]);
  expect([de.fleetDetail.observedCount("1", true, "1", true, "90"), de.fleetDetail.observedLag("1", true, "1", true)]).toEqual(
    ["1 erfasster Versionswechsel auf 1 Mac in den letzten 90 Tagen.", "Median 1 Tag nach Fleets Datierung der Version, bei 1 Mac/Versions-Paar."]);
});

describe("Compare a target version", () => {
  // #857's rows on #897's codes. Out by the releases limit, a row keeps the days limit's date, which can still be ahead (#914).
  const rule: PatchRule = { maxDaysBehind: 30, maxReleasesBehind: 2, maxDaysBehindSevere: null };
  const verdict = (state: PolicyVersion["state"], reason: PolicyVersion["reason"] = null): PolicyVersion => ({ state, reason,
    since: reason === "days" ? "2026-11-10T12:00:00Z" : null, daysBehind: 42, releasesBehind: 3, limitDays: 30, severe: null });
  const row = (version: string, change: Partial<FleetBuildAssessment> = {}): FleetBuildAssessment => ({ name: local.name, version, deviceCount: 1234,
    comparison: "exact", addresses: 2, introduces: 1, remains: 1, addressedIds: null, introducedIds: null, remainingIds: null, net: null, installedKev: null,
    policyState: "out", policySource: "default", policyUnassessed: null, policyTitleId: "0AB", policyRule: rule, policyVerdict: verdict("out", "days"), policyDueAt: "2026-11-10T12:00:00Z", ...change });
  const unjudged = (version: string, why: PolicyUnassessed | null, change: Partial<FleetBuildAssessment> = {}) => row(version,
    { policyState: why ? "unassessed" : "exempt", policyUnassessed: why, policySource: null, policyRule: null, policyVerdict: null, policyDueAt: null, ...change });
  const impact = { targetVersion: "2.0", installedMacs: 1234, olderMacs: 2, atOrAboveMacs: 1, unknownMacs: 0 };
  const compared = (builds: FleetBuildAssessment[], change: Partial<FleetAssessment> = {}) => ({ impact, appAssessments: { [local.appHash]: { ...assessment, builds, ...change } } });
  const section = (name: string) => within(screen.getByRole("heading", { name }).closest("section")!);
  const column = (name: string, at: number) => section(name).getAllByRole("row").slice(1).map(tr => (tr as HTMLTableRowElement).cells[at].textContent);
  beforeEach(() => { api.getTitleHistory.mockResolvedValue({ ...history, versions: [...history.versions, { ...history.versions[0], version: "1.9", previousVersion: null }] }); });

  it("compares Fleet's latest from the page's one read, a dated version on Compare, and goes back with no request", async () => {
    held.permissions = ["vuln:read"];
    const scope = `deviceScope=${encodeURIComponent(JSON.stringify({ match: "all", connectionId: 3, rules: [] }))}`;
    open(`/apps/${local.appHash}?${scope}&q=app`, compared([row("1.0", { addressedIds: ["CVE-2025-10001", "CVE-2025-10002"], introducedIds: ["CVE-2025-10003"],
      remainingIds: ["LoonVD-2025-000101"], installedKev: 1, policySource: "override" }), row("1.1", { comparison: "net_only", net: 1, policyVerdict: verdict("out", "releases"),
      policyDueAt: "2026-12-30T12:00:00Z" })]));
    api.getFleetDetail.mockImplementation(async () => ({ ...detail, ...compared([row("1.0", { comparison: "net_only", net: -1, policyState: "within",
      policyVerdict: verdict("within"), policyDueAt: "2026-12-05T12:00:00Z" })], { targetVersion: "1.9" }), impact: { ...impact, targetVersion: "1.9" } }));
    expect(await screen.findByText("2 addressed · 1 introduced · 1 remaining")).toBeTruthy();
    expect([words.installedScope, words.older, words.atOrAbove, words.unknown].map(name => screen.getByText(name).nextElementSibling?.textContent)).toEqual(["1,234", "2", "1", "0"]);
    expect([api.getFleetDetail.mock.calls.length, ...shown("1 fewer finding in total", "Known exploited on installed build: 1", words.noOlder, words.chooseFromHistory),
      href(words.overrideRule)]).toEqual([1, true, true, false, true, "/devices/applications/jamf-patch/0AB"]); // no pinning note for Fleet's latest
    expect(column(words.findings, 3)).toEqual([policySentence(verdict("out", "days"), rule, en) + words.overrideRule + "Due 11/10/2026",
      policySentence(verdict("out", "releases"), rule, en) + words.defaultRule]); // out by releases: no date, though one is sent
    fireEvent.click(screen.getByText(words.proof));
    expect([href("CVE-2025-10001"), href("LoonVD-2025-000101")]).toEqual(["/posture/vulnerabilities/CVE-2025-10001", "/posture/vulnerabilities/LoonVD-2025-000101"]);
    fireEvent.click(await screen.findByRole("button", { name: en.fleetCatalog.historyCompare("1.9") }));
    expect(api.getFleetDetail).toHaveBeenLastCalledWith("apps", local.appHash, scope, "1.9", expect.any(AbortSignal));
    expect([await screen.findByText("1 more finding in total"), screen.getByText(words.capped), screen.getByText("Fleet target 1.9")].every(Boolean)).toBe(true);
    expect([...shown("2 addressed · 1 introduced · 1 remaining", "CVE-2025-10001", "Due 12/5/2026", `${words.chooseFromHistory} ${words.pinCheck}`),
      document.activeElement === screen.getByText(words.impact).closest("[tabindex]")]).toEqual([false, false, true, true, true]); // focused
    fireEvent.click(screen.getByRole("button", { name: words.resetTarget }));
    expect([await screen.findByText("2 addressed · 1 introduced · 1 remaining"), api.getFleetDetail.mock.calls.length]).toEqual([expect.anything(), 2]);
  });

  it("words each build's change and verdict from its codes in German, in German numbers, on the corpus's own day", async () => {
    locale.current = "de";
    const t = de.fleetDetail, rules = de.jamfPatch.rules;
    const server = { ...row("1.0", { comparison: "net_only", net: -1, policyState: "within", policyVerdict: verdict("within"), policyDueAt: "2026-12-05T12:00:00Z" }),
      policyReason: "The confirmed title rule expired." } as FleetBuildAssessment; // no such field: nothing the server words can show
    open(`/apps/${local.appHash}`, compared([server, unjudged("1.1", null, { comparison: "off", policySource: "override" }), unjudged("1.2", "no_rule", { comparison: "unknown_source" }),
      unjudged("1.3", "not_judged", { comparison: "unknown_target", policySource: "default" }), unjudged("1.4", "identity", { comparison: "ambiguous" }), unjudged("1.5", "no_jamf_title", { addresses: 1234 })],
      { policyExemptBuilds: 1234 }));
    expect(await screen.findByText("Insgesamt 1 Fund mehr")).toBeTruthy();
    expect(column(t.findings, 3)).toEqual([policySentence(verdict("within"), rule, de) + t.defaultRule + "Fällig am 5.12.2026", rules.titleExempt + t.overrideRule, rules.titleNone,
      rules.verdictNotJudged + t.defaultRule, t.policyIdentity, t.policyNoTitle]);
    expect([column(t.findings, 2), column(t.findings, 1)[0]]).toEqual([["Insgesamt 1 Fund mehr" + t.capped, t.off, t.unknown_source, t.unknown_target, t.ambiguousBuild,
      "1.234 behoben · 1 neu · 1 verbleibend"], "1.234"]);
    expect([t.installedScope, t.exempt].map(name => screen.getByText(name).nextElementSibling?.textContent)).toEqual(["1.234", "1.234"]);
    expect(screen.getByText(`${de.vulnerabilities.corpusHeading("20.11.2026")} · ${t.findingScope}`)).toBeTruthy(); // 2026-11-20, read west of UTC
    expect([words.policyIdentity, words.policyNoTitle, en.jamfPatch.rules.titleExempt, en.jamfPatch.rules.verdictWithin, "The confirmed title rule expired."]
      .filter(text => document.body.textContent?.includes(text))).toEqual([]);
  });

  it("says once why there is no device impact, from #899's code, and counts the builds a target cannot order", async () => {
    const unmatched: MigrationItem = { ...local, match: "none", fleetCandidates: [] }, uncertain: MigrationItem = { ...local, appHash: "b".repeat(32), match: "ambiguous" };
    const cases: [string, Partial<MigrationDetail>, ImpactUnavailable, boolean, boolean][] = [["/titles/example", { item: null, title: candidate }, "catalog_incomplete", true, false],
      [`/apps/${local.appHash}`, { item: unmatched, items: [unmatched] }, "no_fleet_title", false, true],
      ["/titles/example", { item: null, title: candidate, items: [local, uncertain] }, "identity_review", false, true], // a title, yet no panel and no Compare
      [`/apps/${local.appHash}`, { ...compared([], { unorderedBuilds: 1 }), impact: null }, "unordered_target", true, true]];
    for (const [path, answer, reason, panel, evidence] of cases) {
      open(path, { ...answer, impactUnavailable: reason });
      expect([(await screen.findAllByText(words.impactUnavailable(reason, "2.0"))).length, ...shown(words.older, words.impact, words.findings)]).toEqual([1, false, panel, evidence]);
      if (reason !== "no_fleet_title") await screen.findByRole("searchbox"); // the history, once read
      expect(screen.queryAllByRole("button", { name: /^Compare / }).length > 0).toBe(panel);
    }
    expect(screen.getByText(words.unordered("1", true, "2.0"))).toBeTruthy();
  });

  it("puts a refused comparison's own sentence under its lead, asks again on Retry, says when no reason came back, and words the flag's 409 as the page does", async () => {
    const refusal = "Fleet's version history, as this instance holds it, does not list 1.9 for Example App.";
    open(`/apps/${local.appHash}`, compared([]));
    api.getFleetDetail.mockRejectedValue(new ApiError(422, refusal));
    fireEvent.click(await screen.findByRole("button", { name: en.fleetCatalog.historyCompare("1.9") }));
    expect((await screen.findByRole("alert")).textContent).toBe(words.impactError + refusal + words.retry);
    api.getFleetDetail.mockRejectedValue(new TypeError("Failed to fetch"));
    fireEvent.click(screen.getByRole("button", { name: words.retry }));
    expect([(await screen.findByText(words.impactNoReason)).parentElement?.textContent, api.getFleetDetail.mock.calls.length])
      .toEqual([words.impactError + words.impactNoReason + words.retry, 3]);
    api.getFleetDetail.mockRejectedValue(new ApiError(409, "Fleet's catalog is not read while the Fleet catalog flag is off for this organization."));
    fireEvent.click(screen.getByRole("button", { name: words.retry }));
    expect((await screen.findByText(en.fleetCatalog.emptyFlagOff)).parentElement?.textContent).toBe(words.impactError + en.fleetCatalog.emptyFlagOff + words.retry);
  });

  it("keys the panel by target, so a pending target never shows the last one's rows, and aborts the request the reader left", async () => {
    api.getTitleHistory.mockResolvedValue({ ...history, versions: [history.versions[0], ...["1.9", "1.8"].map(version => ({ ...history.versions[0], version, previousVersion: null }))] });
    open(`/apps/${local.appHash}`, compared([]));
    const signals: Record<string, AbortSignal> = {};
    api.getFleetDetail.mockImplementation((_kind: string, _id: string, _scope: string, version: string, signal: AbortSignal) => {
      signals[version] = signal;
      return version === "1.8" ? new Promise(() => {}) : Promise.resolve({ ...detail, ...compared([row("1.0", { comparison: "net_only", net: -1 })], { targetVersion: "1.9" }), impact: { ...impact, targetVersion: "1.9" } });
    });
    const compare = async (version: string) => fireEvent.click(await screen.findByRole("button", { name: en.fleetCatalog.historyCompare(version) }));
    await compare("1.9");
    expect(await screen.findByText("1 more finding in total")).toBeTruthy();
    await compare("1.8");
    expect([...shown("Fleet target 1.8", words.fetchImpact, "1 more finding in total"), signals["1.8"].aborted]).toEqual([true, true, false, false]);
    await compare("1.9");
    expect([await screen.findByText("1 more finding in total"), signals["1.8"].aborted, screen.getByText(words.pilotBelow("2", false, "2.0"))])
      .toEqual([expect.anything(), true, expect.anything()]); // the header's line keeps Fleet's latest
  });

  it("keeps the policy counts when no build is older, and shows no finding ID without vuln:read", async () => {
    open(`/apps/${local.appHash}`, compared([], { behindBuilds: 0, withinPolicyBuilds: 2 }));
    expect([await screen.findByText(words.noOlder), screen.getByText(en.jamfPatch.rules.legendWithin).nextElementSibling?.textContent]).toEqual([expect.anything(), "2"]);
    open(`/apps/${local.appHash}`, compared([row("1.0")])); // the server sends no IDs without it
    expect([await screen.findByText("2 addressed · 1 introduced · 1 remaining"), screen.queryByText(words.proof), screen.queryByRole("link", { name: /^CVE-/ })])
      .toEqual([expect.anything(), null, null]);
  });
});

describe("Plan a Fleet pilot", () => {
  // Every address the guide links, as each answered on 2026-11-25.
  const guides = { patch: "https://fleetdm.com/guides/how-to-use-policies-for-patch-management-in-fleet", self: "https://fleetdm.com/guides/software-self-service",
    missing: "https://fleetdm.com/guides/automatic-software-install-in-fleet", custom: "https://fleetdm.com/guides/deploy-software-packages",
    contribute: "https://github.com/fleetdm/fleet/blob/main/ee/maintained-apps/README.md", installomator: "https://github.com/Installomator/Installomator",
    munki: "https://www.munki.org/munki/", appStore: "https://fleetdm.com/guides/install-app-store-apps" } as const;
  const request = "https://fleetdm.com/articles/inside-fleet-maintained-apps#where-the-catalog-comes-from";
  const to = (text: string) => screen.queryByText(text)?.closest("a")?.getAttribute("href") ?? null;
  const impact = (change: Partial<MigrationImpact>) => ({ impact: { targetVersion: "2.0", installedMacs: 3, olderMacs: 0, atOrAboveMacs: 0, unknownMacs: 0, ...change } });
  const intents = async () => [...(await screen.findByLabelText<HTMLSelectElement>(words.workflow)).options].map(option => option.value);
  const pick = (id: string) => fireEvent.change(screen.getByLabelText(words.workflow), { target: { value: id } });

  it("starts the pilot with the Macs below Fleet's latest, in the reader's numbers and one Mac in the singular, and says nothing with no impact", async () => {
    for (const [change, sentence] of [[{ olderMacs: 1234, unknownMacs: 5 }, "Start the pilot with the 1,234 in-scope Macs below 2.0. Later inventory shows whether they updated."],
      [{ olderMacs: 1 }, "Start the pilot with the in-scope Mac below 2.0. Later inventory shows whether it updated."],
      [{ unknownMacs: 3 }, "No in-scope Mac is known to be below 2.0, but 3 run versions that cannot be ordered against it. Check them under Installed builds before choosing a rollout target."],
      [{ unknownMacs: 1 }, "No in-scope Mac is known to be below 2.0, but 1 runs a version that cannot be ordered against it. Check it under Installed builds before choosing a rollout target."],
      [{ atOrAboveMacs: 3 }, "Every in-scope Mac with this app is at or above 2.0. Look again when Fleet publishes a newer version."]] as const) {
      open(`/apps/${local.appHash}`, impact(change));
      expect(await screen.findByText(sentence)).toBeTruthy();
    }
    open(`/apps/${local.appHash}`, { impactUnavailable: "catalog_incomplete" });
    expect([await said(words.exact), screen.queryByText(/^(Start the pilot|No in-scope Mac|Every in-scope Mac)/)]).toEqual([expect.anything(), null]);
    locale.current = "de";
    for (const [older, sentence] of [[1234, "Beginnen Sie den Pilotbetrieb mit den 1.234 Macs im Gerätefilter unter Version 2.0. Spätere Inventare zeigen, ob sie aktualisiert wurden."],
      [1, "Beginnen Sie den Pilotbetrieb mit dem Mac im Gerätefilter unter Version 2.0. Spätere Inventare zeigen, ob er aktualisiert wurde."]] as const) {
      open(`/apps/${local.appHash}`, impact({ olderMacs: older }));
      expect(await screen.findByText(sentence)).toBeTruthy();
    }
    expect([screen.queryByRole("heading", { name: "Fleet-Pilot planen" }), screen.queryByRole("option", { name: "Bestehende Installationen patchen" }),
      screen.queryByText(words.guidance)]).toEqual([expect.anything(), expect.anything(), null]); // the guide in German, not in English
  });

  it("offers a title's three Fleet workflows by id, with the three API reads, and the GitOps draft for patching alone", async () => {
    open("/titles/example", { item: null, title: candidate });
    expect(await intents()).toEqual(["patch", "self", "missing"]);
    for (const id of ["patch", "self", "missing"] as const) {
      pick(id);
      expect([...shown(words.intents[id].text, words.gitOps), to(words.intents[id].guide), to(words.requestGuide)]).toEqual([true, id === "patch", guides[id], null]);
    }
    expect(screen.getAllByText(/^GET /).map(code => code.textContent)).toEqual(["GET /api/v1/fleet/software/fleet_maintained_apps?fleet_id={fleet_id}&platform=darwin&query=Example%20App",
      "GET /api/v1/fleet/software/fleet_maintained_apps/{id}?fleet_id={fleet_id}", "GET /api/v1/fleet/software/install/{install_uuid}/results"]);
    pick("patch");
    expect([...shown("example/darwin"), screen.getByText(/^software:/).textContent?.split("\n").slice(-2), to(words.apiReference), to(words.gitOpsReference)]).toEqual([true,
      ["    type: patch", "    fleet_maintained_app_slug: example/darwin"], "https://fleetdm.com/docs/api/rest-api#list-fleet-maintained-apps", "https://fleetdm.com/docs/configuration/yaml-files#patch-policy"]);
  });

  it("offers the five other paths only where a catalog read whole has no title, the request link with contribute, and no guide while unconfirmed", async () => {
    const unmatched: MigrationItem = { ...local, match: "none", fleetCandidates: [] };
    open(`/apps/${local.appHash}`, { item: unmatched, items: [unmatched] });
    expect(await intents()).toEqual(["custom", "contribute", "installomator", "munki", "appStore"]);
    for (const id of ["custom", "contribute", "installomator", "munki", "appStore"] as const) {
      pick(id);
      expect([...shown(words.intents[id].text), to(words.intents[id].guide), to(words.requestGuide)]).toEqual([true, guides[id], id === "contribute" ? request : null]);
    }
    expect(shown(words.apiCheck, words.gitOps, words.pilotFoot)).toEqual([false, false, true]);
    for (const item of [{ ...unmatched, match: "unknown" }, { ...local, match: "ambiguous", fleetCandidates: [candidate, { ...candidate, slug: "example@esr" }] }] as MigrationItem[]) {
      open(`/apps/${local.appHash}`, { item, items: [item] });
      expect([await said(item.match === "unknown" ? words.catalogUnknown(false) : words.ambiguous), ...shown(words.guidance)]).toEqual([expect.anything(), false]);
    }
  });

  it("starts the guide over on the other list when a history read re-reads an exact app as one Fleet has no title for", async () => {
    held.permissions = ["patch:catalog-sync"];
    const unmatched: MigrationItem = { ...local, match: "none", fleetCandidates: [] };
    open(`/apps/${local.appHash}`);
    expect(await intents()).toEqual(["patch", "self", "missing"]);
    pick("self");
    api.readTitleHistory.mockResolvedValue(history);
    api.getFleetDetail.mockResolvedValue({ ...detail, item: unmatched, items: [unmatched] });
    fireEvent.click(await screen.findByRole("button", { name: en.fleetCatalog.historyReadAgain }));
    expect(await said(words.noMatch)).toBeTruthy();
    expect([await intents(), screen.getByLabelText<HTMLSelectElement>(words.workflow).value, ...shown(words.intents.custom.text, words.intents.self.text)])
      .toEqual([["custom", "contribute", "installomator", "munki", "appStore"], "custom", true, false]);
  });
});
