// @vitest-environment jsdom
/** An installed app's or a Fleet title's own page (#906). `./api`'s reads are stubbed, its `fleetScopeQuery` is the real one. */
import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { ApiError } from "@/config/api";
import { FleetAppPage } from "@/features/fleetCatalog/FleetAppPage";
import type { FleetCandidate, MigrationDetail, MigrationItem } from "@/features/fleetCatalog/migrationTypes";
import type { FleetTitleHistory } from "@/features/fleetCatalog/types";
import { de } from "@/i18n/de";
import { en } from "@/i18n/en";

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
const detail: MigrationDetail = { enabled: true, asOf: "2026-11-22T17:00:00Z", fleetCatalogReady: true, fleetCatalogReadiness: "complete",
  jamfCatalogReady: true, scope: { eligibleMacs: 10, selectedMacs: 6, unknownContactMacs: 1, unknownInventoryMacs: 0 }, installedEvidence: {},
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
  expect(shown(local.bundleId, "6 of 10 eligible Macs selected")).toEqual([true, true]);
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
});

it("opens a title on its history and identities, and a history read reads the page again without blanking it", async () => {
  const beta: MigrationItem = { ...local, name: "Example Beta.app", appHash: "b".repeat(32), macs: 1, match: "ambiguous" };
  open("/titles/example?view=catalog", { item: null, title: candidate, items: [local, beta] });
  expect([await said(words.catalogFirst), screen.getByText(words.ambiguous)].every(Boolean)).toBe(true);
  expect([href(local.name), href(beta.name)]).toEqual([`${base}/apps/${local.appHash}?view=catalog`, `${base}/apps/${beta.appHash}?view=catalog`]);
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
  expect([words.footprint("1", true, "1", true), words.scopeMacs("1", "1", true)]).toEqual(["1 of 1 in-scope Mac reports this app.", "1 of 1 eligible Mac selected"]);
  for (const t of [en, de]) expect([t.fleetDetail.jamfUnavailable, t.fleetDetail.jamfPending].every(s => s.includes(`${t.jamfPatch.eyebrow} › ${t.jamfPatch.tabLabel}`) && s.includes(t.jamfPatch.syncNow))).toBe(true);
});
