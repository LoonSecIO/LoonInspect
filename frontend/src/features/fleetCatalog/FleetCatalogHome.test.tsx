// @vitest-environment jsdom
/** Migration review on main's device filter (#904): the report is asked for the address's `deviceScope` as it stands,
 *  an answer the filter has moved past never paints, and every word is #903's. `apiRequest` is stubbed by URL. */
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { ApiError, apiRequest } from "@/config/api";
import { FleetCatalogHome } from "@/features/fleetCatalog/FleetCatalogHome";
import type { FleetAssessment, MigrationItem, MigrationPortfolio, MigrationScope } from "@/features/fleetCatalog/migrationTypes";
import type { PortfolioEmpty } from "@/features/fleetCatalog/portfolioView";
import { de } from "@/i18n/de";
import { en } from "@/i18n/en";
import { LocaleProvider } from "@/i18n/LocaleContext";

vi.mock("@/config/api", async original => ({ ...await original<typeof import("@/config/api")>(), apiRequest: vi.fn() }));
vi.mock("@/features/auth/store", () => ({ useAuthStore: () => ({ id: "operator", tenant: { id: "org" } }), useHasPermission: () => false }));

const request = vi.mocked(apiRequest);
const words = en.fleetPlanning;
const counted: MigrationScope = { eligibleMacs: 12, selectedMacs: 4, unknownContactMacs: 2, unknownInventoryMacs: 1 };
const options = { devices: 4, connections: [{ id: 3, name: "Jamf 3" }, { id: 7, name: "Jamf 7" }], groups: [], attributes: [] };
const app = (name: string, overrides: Partial<MigrationItem> = {}): MigrationItem => ({ name, bundleId: "org.example." + name.toLowerCase(),
  appHash: name.toLowerCase(), hasJamfMatch: false, jamfEvaluated: true, versionCount: 1, macs: 1, match: "none", fleetCandidates: [], ...overrides });
const report = (items: MigrationItem[], overrides: Partial<MigrationPortfolio> = {}): MigrationPortfolio => ({ enabled: true,
  asOf: "2026-11-20T00:00:00Z", fleetCatalogReady: true, fleetCatalogReadiness: "complete", jamfCatalogReady: true, scope: counted,
  installedEvidence: {}, appAssessments: {}, fleetDeviceCounts: {}, items, ...overrides });
/** The report on the migration route, the builder's options on its own, and no AI for anything else. */
const serve = (answer: (path: string) => unknown) => request.mockImplementation(async path => path.startsWith("/fleet-catalog/migration")
  ? answer(path) : path.includes("scope-options") ? options : { available: false, providers: [] });
const asked = () => request.mock.calls.filter(([path]) => path.startsWith("/fleet-catalog/migration"));
const filterOf = (path: string) => new URLSearchParams(path.split("?")[1]).get("deviceScope");
const row = (name: string) => within(screen.getByText(name).closest("tr")!);
const open = (query = "") =>
  render(<MemoryRouter initialEntries={["/devices/applications/fleet-catalog" + query]}><LocaleProvider><FleetCatalogHome /></LocaleProvider></MemoryRouter>);
function deferred<T>() {
  let resolve!: (value: T) => void;
  return { promise: new Promise<T>(done => { resolve = done; }), resolve: (value: T) => resolve(value) };
}
beforeEach(() => localStorage.clear());
afterEach(() => { cleanup(); vi.clearAllMocks(); });

it("asks for the address's filter as it stands, aborts it for an applied one, and never paints the late answer", async () => {
  const first = JSON.stringify({ match: "all", connectionId: 3, rules: [{ field: "inventory", operator: "within", value: "30", key: "" }] });
  const stale = deferred<MigrationPortfolio>(), fresh = deferred<MigrationPortfolio>();
  serve(path => filterOf(path) === first ? stale.promise : fresh.promise);
  open(`?${new URLSearchParams({ deviceScope: first })}`);
  await screen.findByRole("option", { name: "Jamf 7" });
  fireEvent.change(screen.getByRole("combobox", { name: "Jamf connection" }), { target: { value: "7" } });
  fireEvent.click(screen.getByRole("button", { name: "Apply device filter" }));
  expect(filterOf(asked()[0][0])).toBe(first);
  expect(JSON.parse(filterOf(asked()[1][0])!)).toEqual({ ...JSON.parse(first), connectionId: 7 });
  expect(asked()[0][1]?.signal?.aborted).toBe(true);
  await act(async () => fresh.resolve(report([app("Current")])));
  await act(async () => stale.resolve(report([app("Stale")])));
  expect(screen.getByText("Current")).toBeTruthy();
  expect(screen.queryByText("Stale")).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Clear filter" })); // These rows go at once, not when its answer lands.
  expect(screen.queryByText("Current")).toBeNull();
  expect(await screen.findByText("Current")).toBeTruthy();
  // No app page until #906, and no briefing until #911.
  expect(within(screen.getByRole("table")).queryAllByRole("link")).toHaveLength(0);
  expect(screen.queryByRole("button", { name: /briefing/i })).toBeNull();
});

it("counts only verified gaps in both catalogs, and words each row in #903's copy", async () => {
  const data = report([app("Private"), app("Waiting", { jamfEvaluated: false }), app("Jamf", { hasJamfMatch: true }),
    app("Channel", { match: "ambiguous" }), app("Unidentified", { match: "unknown" }), app("Maintained", { match: "exact" })], {
    installedEvidence: { private: { assessment: "covered", asOf: "2026-11-19", assessedBuilds: 1, unknownBuilds: 0, affectedBuilds: 0, highOrCriticalBuilds: 0, kevBuilds: 0 } },
    appAssessments: { maintained: { priority: "review_now", priorityReason: "kev", outOfPolicyBuilds: 1, behindBuilds: 1, oldestGapDays: 40, addresses: 2 } as FleetAssessment }
  });
  serve(() => data);
  open();
  expect(await screen.findByText(words.clean)).toBeTruthy();
  expect(asked().map(([path]) => path)).toEqual(["/fleet-catalog/migration"]);
  expect(row("Waiting").getByText(words.unassessedBuilds(1))).toBeTruthy();
  for (const text of [words.policy.overdue, words.gapAge(40), words.reasons.kev, words.addressed(2)]) expect(row("Maintained").getByText(text)).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: `${words.filters.outside} 1` }));
  expect(screen.getAllByRole("row")).toHaveLength(2);
  expect(screen.getByText(words.outsideNote)).toBeTruthy();
  cleanup();
  data.jamfCatalogReady = false;
  open("?filter=outside");
  expect(await screen.findByRole("button", { name: `${words.filters.outside} ${words.unknownCount}` })).toBeTruthy();
  expect(screen.getByText(words.noJamf)).toBeTruthy();
  for (const text of [words.outsideNote, "Private"]) expect(screen.queryByText(text)).toBeNull();
});

it("shows a refused filter's own sentence beside Retry, asks for that filter again, and words a failure with none", async () => {
  const refusal = "The device filter is invalid. Check each condition or clear the filter and try again.";
  serve(() => Promise.reject(new ApiError(422, refusal)));
  open("?deviceScope=%7Bbroken");
  fireEvent.click(within(await screen.findByRole("alert")).getByRole("button", { name: words.retry }));
  expect((await screen.findByRole("alert")).textContent).toContain(refusal);
  expect(asked().map(([path]) => filterOf(path))).toEqual(["{broken", "{broken"]);
  cleanup();
  serve(() => Promise.reject(new TypeError("Failed to fetch")));
  open();
  expect((await screen.findByRole("alert")).textContent).toContain(words.loadFailed);
});

it("says which kind of empty the list is, and only that the flag is off when it is", async () => {
  const cases: [Partial<MigrationScope>, MigrationItem[], string, PortfolioEmpty][] = [[{ eligibleMacs: 0, selectedMacs: 0 }, [], "", "noSweep"],
    [{ selectedMacs: 0 }, [], "", "noMacs"], [{}, [], "", "noApps"], [{}, [app("Alpha")], "?q=zzz", "noMatch"]];
  for (const [scope, items, query, cause] of cases) {
    serve(() => report(items, { scope: { ...counted, ...scope } }));
    open(query);
    expect(await screen.findByText(words.empty[cause])).toBeTruthy();
    expect(screen.getByRole("link", { name: words.browse }).getAttribute("href")).toContain("view=catalog");
    cleanup();
  }
  serve(() => report([], { enabled: false, scope: { eligibleMacs: 0, selectedMacs: 0, unknownContactMacs: 0, unknownInventoryMacs: 0 } }));
  open();
  expect(await screen.findByText(en.fleetCatalog.emptyFlagOff)).toBeTruthy();
  for (const text of [words.empty.noSweep, words.scope.selectedMacs]) expect(screen.queryByText(text)).toBeNull();
});

it("draws main's Fleet titles for view=catalog with no report, and keeps the filter across the segments", async () => {
  const scope = JSON.stringify({ match: "all", connectionId: 3, rules: [] });
  serve(() => report([]));
  open(`?view=catalog&${new URLSearchParams({ deviceScope: scope, q: "chrome" })}`);
  expect(await screen.findByPlaceholderText(en.fleetCatalog.searchPlaceholder)).toBeTruthy();
  await waitFor(() => expect(request.mock.calls.map(([path]) => path)).toEqual(["/fleet-catalog?installedOnly=true&pageSize=5000"]));
  fireEvent.click(screen.getByRole("link", { name: "Migration review" })); // #893's name, as the German case holds Migrationsprüfung.
  expect(await screen.findByText(words.empty.noApps)).toBeTruthy();
  expect(asked().map(([path]) => filterOf(path))).toEqual([scope]);
  const titles = new URL(screen.getByRole("link", { name: words.segments.titles }).getAttribute("href")!, "https://example.invalid");
  expect(Object.fromEntries(titles.searchParams)).toEqual({ deviceScope: scope, q: "chrome", view: "catalog" });
});

it("reads in German, its own numbers grouped the German way", async () => {
  localStorage.setItem("locale", "de");
  serve(() => report([app("Alpha", { macs: 1234 })], { scope: { ...counted, eligibleMacs: 12345, selectedMacs: 2468 } }));
  open();
  expect(await screen.findByText("1.234")).toBeTruthy();
  expect(screen.getByText("50 %")).toBeTruthy();
  expect(screen.getByText(de.fleetPlanning.scope.eligibleMacs).nextSibling?.textContent).toBe("12.345");
  expect(screen.getByRole("link", { name: "Migrationsprüfung" }).getAttribute("aria-current")).toBe("page");
  expect(screen.getByRole("link", { name: "Fleet-Titel" })).toBeTruthy();
  expect(screen.getByRole("button", { name: `${de.fleetPlanning.filters.outside} 1` })).toBeTruthy();
});
