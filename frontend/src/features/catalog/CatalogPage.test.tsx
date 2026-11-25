// @vitest-environment jsdom
/** The Catalog tab's *Refresh* (#931): the control troubleshooting §5 and the Vulnerabilities
 *  page send the operator to. `./api` is stubbed, and so is the device filter, which reads
 *  connections of its own and is not what this file is about. */
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { ApiError } from "@/config/api";
import { CatalogPage } from "@/features/catalog/CatalogPage";
import type { CatalogListResponse, CatalogRefreshResult } from "@/features/catalog/types";
import { de } from "@/i18n/de";
import { en } from "@/i18n/en";

const locale = vi.hoisted(() => ({ current: "en" as "en" | "de" }));
vi.mock("@/i18n/LocaleContext", async () => ({ useLocale: () => ({ locale: locale.current, t: locale.current === "de" ? de : en }) }));
const api = vi.hoisted(() => ({ listCatalog: vi.fn(), refreshCatalog: vi.fn() }));
vi.mock("@/features/catalog/api", () => api);
vi.mock("@/features/catalog/DeviceScopeBuilder", () => ({ DeviceScopeBuilder: () => null }));
const held = vi.hoisted(() => ({ permissions: [] as string[] }));
vi.mock("@/features/auth/store", () => ({ useHasPermission: (permission: string) => held.permissions.includes(permission) }));

const empty: CatalogListResponse = {
  items: [], total: 0, page: 1, pageSize: 5000, summary: { entries: 0, installed: 0, matched: 0, unmatched: 0 },
  corpusAsOf: null, corpusRelease: null, vulnJudged: false
};

function open() {
  render(<MemoryRouter initialEntries={["/devices/applications/catalog"]}><CatalogPage /></MemoryRouter>);
}

/** A press whose answer the test settles by hand, so the in-flight state can be read. */
function pending() {
  let settle!: { resolve: (value: CatalogRefreshResult) => void; reject: (reason: unknown) => void };
  api.refreshCatalog.mockImplementation(() => new Promise<CatalogRefreshResult>((resolve, reject) => { settle = { resolve, reject }; }));
  return () => settle;
}

beforeEach(() => {
  vi.clearAllMocks();
  api.listCatalog.mockResolvedValue(empty);
  held.permissions = ["patch:catalog-sync"];
  locale.current = "en";
});
afterEach(cleanup);

it("is not drawn for an account without patch:catalog-sync, which the route would refuse", async () => {
  held.permissions = [];
  open();
  expect(await screen.findByText(en.catalog.empty)).toBeTruthy();
  expect(screen.queryByRole("button", { name: en.catalog.refresh })).toBeNull();
});

it("re-judges, says how many rows, and reads the list again", async () => {
  const settle = pending();
  open();
  expect(await screen.findByText(en.catalog.empty)).toBeTruthy();
  expect(api.listCatalog).toHaveBeenCalledTimes(1);

  fireEvent.click(screen.getByRole("button", { name: en.catalog.refresh }));
  const busy = screen.getByRole("button", { name: en.catalog.refreshing }) as HTMLButtonElement;
  expect(busy.disabled).toBe(true);
  expect(api.refreshCatalog).toHaveBeenCalledExactlyOnceWith();

  await act(async () => settle().resolve({ evaluated: 3 }));
  expect(screen.getByRole("status").textContent).toBe("Re-judged 3 app versions of this organization.");
  expect((screen.getByRole("button", { name: en.catalog.refresh }) as HTMLButtonElement).disabled).toBe(false);
  expect(api.listCatalog).toHaveBeenCalledTimes(2);
});

it("names the empty catalog rather than reporting a zero", async () => {
  api.refreshCatalog.mockResolvedValue({ evaluated: 0 });
  open();
  fireEvent.click(await screen.findByRole("button", { name: en.catalog.refresh }));
  expect((await screen.findByRole("status")).textContent).toBe(en.catalog.refreshedNone);
});

it("says what to check when the instance gives no reason, and leaves the list as it was", async () => {
  api.refreshCatalog.mockRejectedValue(new ApiError(500, null));
  open();
  fireEvent.click(await screen.findByRole("button", { name: en.catalog.refresh }));
  expect((await screen.findByRole("alert")).textContent).toBe(en.catalog.refreshFailed);
  expect(screen.queryByRole("status")).toBeNull();
  expect(api.listCatalog).toHaveBeenCalledTimes(1);
  expect((screen.getByRole("button", { name: en.catalog.refresh }) as HTMLButtonElement).disabled).toBe(false);
});

it("shows the server's own sentence when it sent one", async () => {
  api.refreshCatalog.mockRejectedValue(new ApiError(403, "Insufficient permissions"));
  open();
  fireEvent.click(await screen.findByRole("button", { name: en.catalog.refresh }));
  expect((await screen.findByRole("alert")).textContent).toBe("Insufficient permissions");
});

it("is labelled in German as the German sentence names it", async () => {
  locale.current = "de";
  api.refreshCatalog.mockResolvedValue({ evaluated: 1 });
  open();
  fireEvent.click(await screen.findByRole("button", { name: "Aktualisieren" }));
  expect((await screen.findByRole("status")).textContent).toBe("1 App-Version dieser Organisation neu beurteilt.");
});

// The sentences that send the operator here name the tab and this button by their labels, so
// renaming either without the other fails here rather than on an operator's screen.
it.each([["en", en], ["de", de]] as const)("the Vulnerabilities page's %s sentence names this button", (_, words) => {
  expect(words.vulnerabilities.notYetJudged).toContain(`${words.catalog.tabLabel} › ${words.catalog.refresh}`);
});
