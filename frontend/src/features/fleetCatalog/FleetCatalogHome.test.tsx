// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FleetCatalogHome } from "./FleetCatalogHome";
import type { MigrationItem, MigrationPortfolio } from "./migrationTypes";
import type { FleetCatalog, FleetCatalogTitle } from "./types";

const request = vi.hoisted(() => vi.fn());
vi.mock("@/config/api", async original => ({ ...await original<typeof import("@/config/api")>(), apiRequest: request }));
vi.mock("@/features/auth/store", () => ({ useHasPermission: () => false }));
vi.mock("@/i18n/LocaleContext", async () => {
  const { en: t } = await import("@/i18n/en");
  return { useLocale: () => ({ t, locale: "en" }) };
});

const base = "/devices/applications/fleet-catalog";
const remoteStatus = { available: true, reason: null, providers: [
  { provider: "ollama", model: "gemma" }, { provider: "openai", model: "saved-model" }
] };
const noAI = { available: false, reason: "consent_off", providers: [] };
function app(name: string, overrides: Partial<MigrationItem> = {}): MigrationItem {
  return { name, bundleId: "org.example." + name.toLowerCase(), appHash: name.toLowerCase(), hasJamfMatch: false, jamfEvaluated: true,
    versionCount: 1, macs: 1, match: "none", fleetCandidates: [], ...overrides };
}
function report(items: MigrationItem[], overrides: Partial<MigrationPortfolio> = {}): MigrationPortfolio {
  return { enabled: true, asOf: "2026-11-20T00:00:00Z", items, fleetCatalogReady: true, jamfCatalogReady: true,
    connections: [], installedEvidence: {}, appAssessments: {}, assessments: {}, fleetDeviceCounts: {},
    scope: { connectionId: 7, days: 30, clock: "contact", eligibleMacs: 12, activeMacs: 4, staleMacs: 6, unknownMacs: 2 },
    ...overrides };
}
function title(slug: string): FleetCatalogTitle {
  return { slug, name: "Public " + slug, bundleId: "org.example." + slug, latestVersion: "2.1", previousVersion: null,
    versionChangedAt: null, firstSeenAt: "2026-10-01T00:00:00Z", deviceCount: 99, devicesCurrent: 88, devicesBehind: 11,
    inCatalogSince: null, versionBefore: null, historyReadAt: null };
}
const titles: FleetCatalog = { enabled: true, source: "fleetdm/fleet", total: 3, page: 1, pageSize: 5000, installedTitles: 3,
  installedTitlesWithHistory: 0, items: [title("stable"), title("example@esr"), title("new")],
  state: { checkedAt: "2026-11-20T00:00:00Z", changedAt: "2026-11-19T00:00:00Z", outcome: "ok", detail: null,
    appCount: 3, historyCheckedAt: null, historyDetail: null, historyOutcome: null } };
function open(query: string) {
  render(<MemoryRouter initialEntries={[base + query]}><FleetCatalogHome/></MemoryRouter>);
}
function linkRow(name: string) {
  return within(screen.getByRole("link", { name }).closest("tr")!);
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(r => { resolve = r; });
  return { resolve, promise };
}
const posts = () => request.mock.calls.filter(([, options]) => options?.method === "POST");
beforeEach(() => { request.mockReset(); });
afterEach(cleanup);

describe("scoped Fleet catalog and briefing", () => {
  it("drops stale inventory responses and keeps a deep-linked connection and custom window visible to a reader", async () => {
    const stale = deferred<MigrationPortfolio>();
    const fresh = deferred<MigrationPortfolio>();
    request.mockImplementation((url: string) => {
      if (url.includes("/briefing")) return Promise.resolve(noAI);
      return url.includes("clock=inventory") ? fresh.promise : stale.promise;
    });
    open("?connectionId=7&days=42");
    const staleSignal = request.mock.calls[0][1].signal as AbortSignal;
    expect(screen.getByRole("combobox", { name: "Jamf connection" }).textContent).toContain("Jamf connection #7");
    expect(screen.getByRole("option", { name: "Last 42 days" })).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Activity measured by"), { target: { value: "inventory" } });
    expect(staleSignal.aborted).toBe(true);
    await act(async () => fresh.resolve(report([app("Current")])));
    await act(async () => stale.resolve(report([app("Stale")])));
    expect(screen.getByRole("link", { name: "Current" }).getAttribute("href")).toContain("clock=inventory");
    expect(screen.queryByText("Stale")).toBeNull();
    expect(screen.queryByRole("button", { name: "Generate briefing" })).toBeNull();
    expect(posts()).toHaveLength(0);
  });

  it("counts only verified gaps in both catalogs and distinguishes covered zero from missing findings", async () => {
    const data = report([app("Private"), app("Waiting", { jamfEvaluated: false }), app("Jamf", { hasJamfMatch: true }),
      app("Channel", { match: "ambiguous" }), app("Unidentified", { match: "unknown" })], {
      installedEvidence: { private: { assessedBuilds: 1, unknownBuilds: 0, affectedBuilds: 0, highOrCriticalBuilds: 0, kevBuilds: 0, asOf: "2026-11-19" } }
    });
    request.mockImplementation(async (url: string) => url.includes("/briefing") ? noAI : data);
    open("?connectionId=7&days=30");
    expect(await screen.findByText("No findings in assessed builds")).toBeTruthy();
    expect(linkRow("Waiting").getByText("Installed builds unassessed")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Outside both catalogs 1" }));
    expect(screen.getAllByRole("row")).toHaveLength(2);
    fireEvent.change(screen.getByRole("searchbox"), { target: { value: "org.example.private" } });
    const link = new URL(screen.getByRole("link", { name: "Private" }).getAttribute("href")!, "https://example.invalid");
    expect(Object.fromEntries(link.searchParams)).toEqual({ connectionId: "7", days: "30", filter: "outside", q: "org.example.private" });
    cleanup();
    data.jamfCatalogReady = false;
    open("?filter=outside");
    expect(await screen.findByRole("button", { name: "Outside both catalogs Unknown" })).toBeTruthy();
    expect(screen.queryByRole("link", { name: "Private" })).toBeNull();
  });

  it("browses absent and installed public titles with scoped counts and preserves a catalog search on the detail link", async () => {
    const counts = { stable: 3, "example@esr": 0 }; // 'new' arrived after the cohort report.
    request.mockImplementation(async (url: string) => {
      if (url.startsWith("/fleet-catalog?")) return titles;
      return url.includes("/briefing") ? noAI : report([], { fleetDeviceCounts: counts });
    });
    open("?connectionId=7&days=30");
    fireEvent.click(await screen.findByRole("link", { name: "Search all Fleet titles" }));
    await screen.findByRole("link", { name: "Public new" });
    expect(linkRow("Public stable").getByRole("cell", { name: "3" })).toBeTruthy();
    expect(linkRow("Public example@esr").getByRole("cell", { name: "0" })).toBeTruthy();
    expect(linkRow("Public new").getByRole("cell", { name: "Unknown" })).toBeTruthy();
    const installedOnly = screen.getByRole("checkbox");
    fireEvent.click(installedOnly);
    expect(screen.queryByRole("link", { name: "Public new" })).toBeNull();
    expect(screen.getByRole("link", { name: "Public stable" }).getAttribute("href")).toContain("installedOnly=1");
    fireEvent.click(installedOnly);
    fireEvent.change(screen.getByRole("textbox", { name: /Search name/ }), { target: { value: "esr" } });
    const href = screen.getByRole("link", { name: "Public example@esr" }).getAttribute("href")!;
    const url = new URL(href, "https://example.invalid");
    expect(url.pathname).toBe(base + "/titles/example%40esr");
    expect(Object.fromEntries(url.searchParams)).toEqual({ connectionId: "7", days: "30", view: "catalog", q: "esr" });
    expect(request.mock.calls.filter(([address]) => address.startsWith("/fleet-catalog?"))).toHaveLength(1);
  });

  it("sends only on click, pins the displayed provider, and identifies a fallback and the actual responding model", async () => {
    const fallback = deferred<object>();
    request.mockImplementation(async (url: string, options?: { method?: string; json?: { provider: string } }) => {
      if (!url.includes("/briefing")) return report([app("Private")]);
      if (options?.method !== "POST") return remoteStatus;
      if (options.json?.provider === "ollama") return fallback.promise;
      return { outcome: "selected", provider: "openai", model: "actual-model", detail: null, highlights: [] };
    });
    open("?connectionId=7&clock=inventory&days=30&q=private");
    const generate = await screen.findByRole("button", { name: "Generate briefing" });
    const select = screen.getByLabelText("Provider and model");
    expect(posts()).toHaveLength(0);
    fireEvent.click(generate);
    expect(posts()).toHaveLength(1);
    expect(posts()[0][0]).toBe("/fleet-catalog/briefing?connectionId=7&clock=inventory&days=30");
    expect(posts()[0][1].json).toEqual({ provider: "ollama" });
    expect(screen.getByRole("button", { name: "Preparing briefing…" }).hasAttribute("disabled")).toBe(true);
    await act(async () => fallback.resolve({ outcome: "fallback", provider: "ollama", model: "attempted", detail: "Local counts shown.",
      highlights: [{ code: "gap", count: 1, text: "One app needs identity review." }] }));
    expect(screen.getByText("Local summary")).toBeTruthy();
    expect(screen.getByText("One app needs identity review.")).toBeTruthy();
    fireEvent.change(select, { target: { value: "openai" } });
    expect(posts()).toHaveLength(1);
    expect(screen.queryByText("Local summary")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Generate briefing" }));
    expect(await screen.findByText("Model · openai · actual-model")).toBeTruthy();
    expect(posts()[1][1].json).toEqual({ provider: "openai" });
  });

  it("discards a pending briefing when the operator changes the cohort", async () => {
    const stale = deferred<object>();
    request.mockImplementation(async (url: string, options?: { method?: string }) => {
      if (!url.includes("/briefing")) return report([app("ScopedApp")]);
      return options?.method === "POST" ? stale.promise : remoteStatus;
    });
    open("?days=7");
    fireEvent.click(await screen.findByRole("button", { name: "Generate briefing" }));
    const oldSignal = posts()[0][1].signal;
    fireEvent.change(screen.getByLabelText("Activity window"), { target: { value: "30" } });
    await screen.findByRole("button", { name: "Generate briefing" });
    expect(oldSignal.aborted).toBe(true);
    await act(async () => stale.resolve({ outcome: "fallback", highlights: [], detail: "Previous week's counts" }));
    expect(screen.queryByText("Previous week's counts")).toBeNull();
    expect(posts()).toHaveLength(1);
  });
});
