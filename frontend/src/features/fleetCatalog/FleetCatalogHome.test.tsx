// @vitest-environment jsdom
/** The Fleet catalog tab on main's device filter (#904, #905): each view asks for the report for the address's `deviceScope`
 *  as it stands, an answer the filter has moved past never paints, and every word is #903's or main's. `apiRequest` is stubbed by URL. */
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { ApiError, apiRequest } from "@/config/api";
import { readScope } from "@/features/catalog/deviceScope";
import { FleetCatalogHome } from "@/features/fleetCatalog/FleetCatalogHome";
import type { FleetAssessment, MigrationItem, MigrationPortfolio, MigrationScope } from "@/features/fleetCatalog/migrationTypes";
import type { PortfolioEmpty } from "@/features/fleetCatalog/portfolioView";
import type { FleetCatalog, FleetCatalogTitle } from "@/features/fleetCatalog/types";
import { de } from "@/i18n/de";
import { en } from "@/i18n/en";
import { LocaleProvider } from "@/i18n/LocaleContext";

const permission = vi.hoisted(() => ({ held: false }));
vi.mock("@/config/api", async original => ({ ...await original<typeof import("@/config/api")>(), apiRequest: vi.fn() }));
vi.mock("@/features/auth/store", () => ({ useAuthStore: () => ({ id: "operator", tenant: { id: "org" } }), useHasPermission: () => permission.held }));

const request = vi.mocked(apiRequest);
const words = en.fleetPlanning;
const counted: MigrationScope = { eligibleMacs: 12, selectedMacs: 4, unknownContactMacs: 2, unknownInventoryMacs: 1 };
const options = { devices: 4, connections: [{ id: 3, name: "Jamf 3" }, { id: 7, name: "Jamf 7" }], groups: [], attributes: [] };
const app = (name: string, overrides: Partial<MigrationItem> = {}): MigrationItem => ({ name, bundleId: "org.example." + name.toLowerCase(),
  appHash: name.toLowerCase(), hasJamfMatch: false, jamfEvaluated: true, versionCount: 1, macs: 1, match: "none", fleetCandidates: [], ...overrides });
const report = (items: MigrationItem[], overrides: Partial<MigrationPortfolio> = {}): MigrationPortfolio => ({ enabled: true,
  asOf: "2026-11-20T00:00:00Z", fleetCatalogReady: true, fleetCatalogReadiness: "complete", jamfCatalogReady: true, scope: counted,
  installedEvidence: {}, appAssessments: {}, fleetDeviceCounts: {}, items, ...overrides });
const title = (slug: string): FleetCatalogTitle => ({ slug, name: "Public " + slug, bundleId: "org.example." + slug, latestVersion: "2.1",
  previousVersion: null, versionChangedAt: null, firstSeenAt: "2026-10-01T00:00:00Z", deviceCount: 99, devicesCurrent: 88, devicesBehind: 11,
  inCatalogSince: null, versionBefore: null, historyReadAt: null });
const titles: FleetCatalog = { enabled: true, source: "fleetdm/fleet", total: 3, page: 1, pageSize: 5000, installedTitles: 3,
  installedTitlesWithHistory: 0, items: [title("stable"), title("example@esr"), title("new")],
  state: { checkedAt: "2026-11-20T00:00:00Z", changedAt: "2026-11-19T00:00:00Z", outcome: "ok", detail: null, appCount: 3,
    historyCheckedAt: null, historyDetail: null, historyOutcome: null } };
/** The report, Fleet's titles, Check now and the builder's options on their own routes, and no AI for anything else. */
const serve = (answer: (path: string) => unknown, check: () => unknown = () => ({})) => request.mockImplementation(async path =>
  path.startsWith("/fleet-catalog/migration") ? answer(path) : path.startsWith("/fleet-catalog?") ? titles
    : path === "/fleet-catalog/refresh" ? check() : path.includes("scope-options") ? options : { available: false, providers: [] });
const asked = () => request.mock.calls.filter(([path]) => path.startsWith("/fleet-catalog/migration"));
const filterOf = (path: string) => new URLSearchParams(path.split("?")[1]).get("deviceScope");
const row = (name: string) => within(screen.getByText(name).closest("tr")!);
const open = (query = "") =>
  render(<MemoryRouter initialEntries={["/devices/applications/fleet-catalog" + query]}><LocaleProvider><FleetCatalogHome /></LocaleProvider></MemoryRouter>);
function deferred<T>() {
  let resolve!: (value: T) => void;
  return { promise: new Promise<T>(done => { resolve = done; }), resolve: (value: T) => resolve(value) };
}
beforeEach(() => { localStorage.clear(); permission.held = false; });
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
  for (const text of [words.noJamf, words.partialCatalog, words.notRead]) expect(screen.queryByText(text)).toBeNull(); // both are read
  expect(row("Waiting").getByText(words.unassessedBuilds(1))).toBeTruthy();
  for (const text of [words.policy.overdue, words.gapAge(40), words.reasons.kev, words.addressed(2)]) expect(row("Maintained").getByText(text)).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: `${words.filters.outside} 1` }));
  expect(screen.getAllByRole("row")).toHaveLength(2);
  expect(screen.getByText(words.outsideNote)).toBeTruthy();
  cleanup();
  data.jamfCatalogReady = data.fleetCatalogReady = false;
  data.fleetCatalogReadiness = "partial";
  open("?filter=outside");
  expect(await screen.findByRole("button", { name: `${words.filters.outside} ${words.unknownCount}` })).toBeTruthy();
  expect(screen.getByText(words.noJamf)).toBeTruthy();
  expect(within(screen.getByText(words.partialCatalog)).getByRole("link", { name: words.segments.titles }).getAttribute("href")).toContain("view=catalog");
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

it("drops the page when a filter is applied, and from both segment links", async () => {
  serve(() => report(Array.from({ length: 51 }, (_, n) => app(`App${String(n).padStart(2, "0")}`))));
  open("?page=2");
  expect(await screen.findByText(words.range(51, 51, 51))).toBeTruthy();
  for (const name of [words.segments.review, words.segments.titles]) expect(screen.getByRole("link", { name }).getAttribute("href")).not.toContain("page");
  await screen.findByRole("option", { name: "Jamf 7" });
  fireEvent.change(screen.getByRole("combobox", { name: "Jamf connection" }), { target: { value: "7" } });
  fireEvent.click(screen.getByRole("button", { name: "Apply device filter" }));
  expect(await screen.findByText(words.range(1, 50, 51))).toBeTruthy();
});

it("keeps the filter, the search and the box across the segments, and each view asks for that filter's report", async () => {
  const scope = JSON.stringify({ match: "all", connectionId: 3, rules: [] });
  serve(() => report([]));
  open(`?view=catalog&${new URLSearchParams({ deviceScope: scope, q: "stable", installedOnly: "1" })}`); // as after a reload
  expect((await screen.findByRole<HTMLInputElement>("textbox", { name: en.fleetCatalog.searchPlaceholder })).value).toBe("stable");
  expect(screen.getByRole<HTMLInputElement>("checkbox").checked).toBe(true);
  fireEvent.click(screen.getByRole("link", { name: "Migration review" })); // #893's name, as the German case holds Migrationsprüfung.
  expect(await screen.findByText(words.empty.noApps)).toBeTruthy();
  expect(screen.getByRole("heading", { level: 1, name: en.fleetCatalog.title })).toBeTruthy(); // the same heading over both views
  expect(asked().map(([path]) => filterOf(path))).toEqual([scope, scope]);
  const titles = new URL(screen.getByRole("link", { name: words.segments.titles }).getAttribute("href")!, "https://example.invalid");
  expect(Object.fromEntries(titles.searchParams)).toEqual({ deviceScope: scope, q: "stable", installedOnly: "1", view: "catalog" });
});

it("counts each Fleet title on the filter's Macs beside the organization's, and plans only on Macs the filter selects", async () => {
  const scope = JSON.stringify({ match: "all", connectionId: 3, rules: [{ field: "contact", operator: "within", value: "30", key: "" }] });
  serve(() => report([], { fleetDeviceCounts: { stable: 3, "example@esr": 0 } })); // Fleet listed `new` after these were read.
  open(`?view=catalog&${new URLSearchParams({ deviceScope: scope })}`);
  await screen.findByText("Public new");
  const [page, ...more] = screen.getAllByRole("heading", { level: 1 }); // #904's heading, once: the view draws none of its own.
  expect([page.textContent, more.length, screen.getAllByText(en.fleetCatalog.eyebrow).length]).toEqual([en.fleetCatalog.title, 0, 1]);
  expect(page.compareDocumentPosition(screen.getByRole("heading", { level: 2, name: en.fleetCatalog.titlesHeading })) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  const counted = (name: string) => row(name).getAllByRole("cell").slice(3, 5).map(cell => cell.textContent); // with app, in scope
  expect([counted("Public stable"), counted("Public example@esr"), counted("Public new")]).toEqual([["99", "3"], ["99", "0"], ["99", en.fleetCatalog.scopedUnknown]]);
  expect(row("Public new").getByText(en.fleetCatalog.scopedUnknown).getAttribute("title")).toBe(en.fleetCatalog.scopedUnknownHint);
  expect(screen.getByRole("columnheader", { name: en.fleetCatalog.tableScopedCount }).getAttribute("title")).toBe(en.fleetCatalog.tableScopedCountHint);
  const plan = () => new URL(row("Public stable").getByRole("link", { name: en.fleetCatalog.buildPlan }).getAttribute("href")!, "https://example.invalid");
  expect([plan().pathname, Object.fromEntries(plan().searchParams)]).toEqual(["/devices/applications", { deviceScope: scope, q: "org.example.stable" }]);
  expect(readScope(plan().searchParams.get("deviceScope")!)).not.toBeNull();
  for (const name of ["Public example@esr", "Public new"]) expect(row(name).queryByRole("link", { name: en.fleetCatalog.buildPlan })).toBeNull();
  expect(screen.getAllByRole("link").filter(link => link.getAttribute("href")?.includes("/fleet-catalog/titles/"))).toHaveLength(0); // #906's
  fireEvent.click(screen.getByRole("checkbox"));
  expect(screen.getByText("Public stable")).toBeTruthy();
  for (const name of ["Public example@esr", "Public new"]) expect(screen.queryByText(name)).toBeNull();
  expect(request.mock.calls.map(([path]) => path).filter(path => path.startsWith("/fleet-catalog?"))).toEqual(["/fleet-catalog?installedOnly=false&pageSize=5000"]);
  cleanup();
  open("?view=catalog"); // No filter applied: Installed apps reads every current Jamf Mac, as the counts did.
  expect(Object.fromEntries((await waitFor(plan)).searchParams)).toEqual({ q: "org.example.stable" });
  // A router link moves the app's own address (here, off view=catalog); a plain <a> would leave it and reload the page.
  fireEvent.click(row("Public stable").getByRole("link", { name: en.fleetCatalog.buildPlan }));
  expect(screen.getByRole("link", { name: words.segments.review }).getAttribute("aria-current")).toBe("page");
});

it("keeps Check now's refusal, the sort and the table while the counts are read again for the same filter, and on Retry", async () => {
  permission.held = true;
  const refusal = "A check of Fleet's catalog is already running. It finishes within a minute or two; reload this page then.";
  let reads = 0; // the second read of the counts gets no answer
  serve(() => ++reads === 2 ? Promise.reject(new TypeError("Failed to fetch")) : report([], { fleetDeviceCounts: { stable: 3, "example@esr": 0 } }),
    () => Promise.reject(new ApiError(409, refusal)));
  open("?view=catalog");
  await screen.findByText("Public new");
  fireEvent.click(screen.getByRole("columnheader", { name: en.fleetCatalog.tableScopedCount }));
  const order = () => screen.getAllByRole("row").slice(1).map(tr => tr.querySelector("button")?.textContent);
  const sorted = ["Public stable", "Public example@esr", "Public new"]; // most first, and the title not counted yet last
  expect(order()).toEqual(sorted);
  fireEvent.click(screen.getByRole("button", { name: en.fleetCatalog.checkNow }));
  const alert = await screen.findByRole("alert"); // the re-read got no answer: its sentence and Retry stand above the same table
  expect([asked().length, alert.textContent?.includes(words.loadFailed), Boolean(screen.queryByText(refusal)), order()]).toEqual([2, true, true, sorted]);
  fireEvent.click(within(alert).getByRole("button", { name: words.retry }));
  await waitFor(() => expect(asked()).toHaveLength(3));
  await waitFor(() => expect(screen.queryByText(words.loading)).toBeNull());
  expect([screen.queryByRole("alert"), Boolean(screen.queryByText(refusal)), order()]).toEqual([null, true, sorted]);
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
