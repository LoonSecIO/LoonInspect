// @vitest-environment jsdom
/** An installed app's or a Fleet title's own page (#906, #907). `./api`'s reads are stubbed, its `fleetScopeQuery` is the real one. */
import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router";
import { afterAll, afterEach, beforeEach, expect, it, vi } from "vitest";
import { ApiError } from "@/config/api";
import { FleetAppPage } from "@/features/fleetCatalog/FleetAppPage";
import type { FleetAssessment, FleetCandidate, MigrationDetail, MigrationItem } from "@/features/fleetCatalog/migrationTypes";
import type { FleetTitleHistory } from "@/features/fleetCatalog/types";
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
  expect(screen.queryAllByRole("button")).toHaveLength(0); // no Compare, and no Read history without patch:catalog-sync
});

it("lists a shared bundle ID's channels with the list's query and no history, and says why coverage is unknown", async () => {
  const uncertain: MigrationItem = { ...local, match: "ambiguous", fleetCandidates: [candidate, { ...candidate, name: "Example ESR", slug: "example@esr" }] };
  open(`/apps/${local.appHash}?q=example`, { item: uncertain, items: [uncertain] });
  expect(await said(words.ambiguous)).toBeTruthy();
  expect(href("Example ESR")).toBe(`${base}/titles/example%40esr?q=example`);
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
    management: "observe", recentVersions: null, behindBuilds: 0, exactBuilds: 0, kevBuilds: null, withinPolicyBuilds: 0, policyUnassessedBuilds: 0 } } });
  expect(await said(words.catalogFirst, "0 of 6 in-scope Macs report this app.")).toBeTruthy();
  expect([...shown(en.fleetPlanning.reasons.none_behind, words.installedFindings, words.observedTitle, words.planLink, "Not judged"),
    screen.getByText(words.cadenceUnread).textContent]).toEqual([false, false, false, false, true, `Monitor for changes. ${words.cadenceUnread}`]);
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
  expect([findings.getByText("Schwachstellen-Korpus vom 20.11.2026"), findings.getByText("Bewertete Builds").nextElementSibling?.textContent]).toEqual([expect.anything(), "1.234"]);
});

it("words observed upgrades one at a time, measured or not, in the reader's numbers", async () => {
  open(`/apps/${local.appHash}`, { installedMacs: 1, scope: { ...detail.scope, selectedMacs: 1, eligibleMacs: 1 },
    observedChanges: { windowDays: 90, versionChanges: 1, macs: 1, lastAt: null, adoptionSamples: 1, medianDaysAfterFleetPublication: 1 } });
  expect(await said(words.exact, "1 of 1 in-scope Mac reports this app.")).toBeTruthy();
  expect(shown("1 of 1 current Jamf Mac selected", "1 recorded version change on 1 Mac in the last 90 days.",
    "Median 1 day after Fleet dated the version, across 1 Mac/version pair.")).toEqual([true, true, true]);
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
