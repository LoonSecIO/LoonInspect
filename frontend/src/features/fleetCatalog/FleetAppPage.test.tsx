// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FleetAppPage } from "./FleetAppPage";
import type { FleetAssessment, FleetCandidate, MigrationDetail, MigrationItem } from "./migrationTypes";
import type { FleetTitleHistory } from "./types";

const request = vi.hoisted(() => vi.fn());
vi.mock("@/config/api", async importOriginal => ({
  ...await importOriginal<typeof import("@/config/api")>(), apiRequest: request
}));
vi.mock("@/features/auth/store", () => ({ useHasPermission: (permission: string) => permission === "vuln:read" }));
vi.mock("@/i18n/LocaleContext", async () => {
  const { en: t } = await import("@/i18n/en"); return { useLocale: () => ({ t, locale: "en" }) };
});
const candidate: FleetCandidate = { name: "Example App", slug: "example", bundleId: "com.example.app", latestVersion: "2.0" };
const local: MigrationItem = { name: "Example App.app", appHash: "a".repeat(32), bundleId: candidate.bundleId,
  macs: 3, versionCount: 2, hasJamfMatch: true, jamfEvaluated: true, match: "exact", fleetCandidates: [candidate] };
const assessment: FleetAssessment = {
  targetVersion: "2.0", priority: "plan_update", reason: "An older build was observed.",
  management: "recurring", managementReason: "Three versions appeared recently.", recentVersions: 3, historyComplete: true,
  historyReadAt: null, historySince: null, historyThrough: null, historyDetail: null, corpusAsOf: "2026-11-20",
  behindBuilds: 1, unorderedBuilds: 0, exactBuilds: 1, netOnlyBuilds: 0, unknownBuilds: 0, outOfPolicyBuilds: 1,
  withinPolicyBuilds: 0, policyExemptBuilds: 0, policyUnassessedBuilds: 0, kevBuilds: 1, addresses: 2, introduces: 1, remains: 1,
  builds: [{ name: local.name, version: "1.0", deviceCount: 2, comparison: "exact", addresses: 2, introduces: 1, remains: 1,
    addressedIds: ["CVE-2025-10001", "CVE-2025-10002"], introducedIds: ["CVE-2025-10003"], remainingIds: ["LoonVD-2025-000101"],
    net: null, installedKev: 1, policyState: "out", policySource: "override", policyReason: "The confirmed title rule expired.", policyDueAt: "2026-11-10T00:00:00Z" }]
};
const detail: MigrationDetail = {
  enabled: true, asOf: "2026-11-22T17:00:00Z", fleetCatalogReady: true, jamfCatalogReady: true, item: local, title: null, items: [local],
  scope: { clock: "inventory", days: 30, connectionId: 8, eligibleMacs: 10, activeMacs: 6, staleMacs: 3, unknownMacs: 1 },
  installedMacs: 3, builds: [{ appHash: local.appHash, version: "1.0", shortVersion: null, versionHash: "f".repeat(32), macs: 2 },
    { appHash: local.appHash, version: "2.0", shortVersion: null, versionHash: "e".repeat(32), macs: 2 }],
  jamfTitles: [{ id: "0AB", name: "Example patch definition" }], assessments: {}, appAssessments: { [local.appHash]: assessment },
  installedEvidence: { [local.appHash]: { assessedBuilds: 1, unknownBuilds: 1, affectedBuilds: 0, highOrCriticalBuilds: 0, kevBuilds: 0, asOf: "2026-11-20" } },
  observedChanges: { windowDays: 90, versionChanges: 3, macs: 2, firstAt: null, lastAt: "2026-11-21T00:00:00Z", adoptionSamples: 2, medianDaysAfterFleetPublication: 2.5 },
  impact: { targetVersion: "2.0", installedMacs: 3, olderMacs: 2, atOrAboveMacs: 1, unknownMacs: 0 }
};
const history: FleetTitleHistory = {
  slug: candidate.slug, name: candidate.name, latestVersion: candidate.latestVersion, historyComplete: true, historyDetail: null,
  historyReadAt: "2026-11-21T12:00:00Z", historySince: "2026-11-03", historyThrough: "2026-11-20",
  versions: [{ version: "2.0", previousVersion: "1.9", commitSha: "c".repeat(40), seenAt: "2026-11-20T12:00:00Z" },
    { version: "1.9", previousVersion: null, commitSha: "d".repeat(40), seenAt: "2026-11-03T12:00:00Z" }]
};
const base = "/devices/applications/fleet-catalog";
function open(url: string) {
  render(<MemoryRouter initialEntries={[url]}><Routes>
    <Route path={base + "/apps/:appHash"} element={<FleetAppPage/>}/>
    <Route path={base + "/titles/:slug"} element={<FleetAppPage/>}/>
  </Routes></MemoryRouter>);
}
afterEach(cleanup);
beforeEach(() => { request.mockReset(); });

describe("Fleet application evidence", () => {
  it("keeps the cohort, counts distinct Macs, and compares an earlier commit without treating capped IDs as exact", async () => {
    request.mockImplementation(async (url: string) => {
      if (url.endsWith("/history")) return history;
      if (url.includes("targetVersion=1.9")) return { ...detail, impact: { ...detail.impact, targetVersion: "1.9" },
        appAssessments: { [local.appHash]: { ...assessment, targetVersion: "1.9", builds: [{ ...assessment.builds[0], comparison: "net_only", addresses: null, introduces: null, remains: null, net: -2 }] } } };
      return detail;
    });
    const query = "?connectionId=8&clock=inventory&days=30&q=example";
    open(base + "/apps/" + local.appHash + query);
    await screen.findByText("2 addressed · 1 introduced · 1 remaining");
    expect(screen.getByRole("link", { name: "Back to Fleet catalog" }).getAttribute("href")).toBe(base + query);
    expect(request).toHaveBeenCalledWith("/fleet-catalog/migration/apps/" + local.appHash + "?connectionId=8&clock=inventory&days=30");
    expect(request.mock.calls.filter(([url]) => url.includes("/migration/"))).toHaveLength(1);
    expect(screen.getByText("Matched Macs").nextElementSibling?.textContent).toBe("3");
    expect(screen.getByText("Title-specific rule")).toBeTruthy();
    expect(screen.getByText("Median 2.5 days across 2 Mac/version pairs.")).toBeTruthy();
    expect(screen.getByText("With findings").nextElementSibling?.textContent).toBe("0");
    expect(screen.getByText("Unassessed builds").nextElementSibling?.textContent).toBe("1");
    expect(screen.getByText(/Independent scanner evidence is unavailable/)).toBeTruthy();
    fireEvent.click(screen.getByText("Inspect finding IDs"));
    expect(screen.getByRole("link", { name: "CVE-2025-10001" }).getAttribute("href")).toBe("/posture/vulnerabilities/CVE-2025-10001");
    expect(screen.getByRole("link", { name: "LoonVD-2025-000101" }).getAttribute("href")).toBe("/posture/vulnerabilities/LoonVD-2025-000101");
    const installed = screen.getByRole("heading", { name: "Installed builds" }).closest("section")!;
    fireEvent.change(within(installed).getByLabelText("Filter by exact installed version"), { target: { value: "0" } });
    expect(within(installed).getAllByRole("row")).toHaveLength(2);
    expect(within(installed).queryByRole("cell", { name: "2.0" })).toBeNull();
    const filter = await screen.findByRole("searchbox", { name: "Find a Fleet version" });
    fireEvent.change(filter, { target: { value: "1.9" } });
    const row = screen.getByRole("button", { name: "Compare 1.9" }).closest("tr")!;
    expect(within(row).getByRole("link", { name: /Manifest at this commit/ }).getAttribute("href")).toContain("/blob/" + "d".repeat(40) + "/");
    expect(screen.queryByRole("button", { name: "Compare 2.0" })).toBeNull();
    fireEvent.click(within(row).getByRole("button", { name: "Compare 1.9" }));
    expect(await screen.findByText("2 more findings in total")).toBeTruthy();
    expect(screen.getByText(/Finding IDs are capped/)).toBeTruthy();
    expect(screen.queryByText("2 addressed · 1 introduced · 1 remaining")).toBeNull();
    expect(screen.queryByText("CVE-2025-10001")).toBeNull();
  });

  it("keeps a shared bundle ID as an unconfirmed release channel", async () => {
    const esr = { ...candidate, name: "Example ESR", slug: "example@esr" };
    const uncertain = { ...local, match: "ambiguous", fleetCandidates: [candidate, esr] };
    request.mockResolvedValue({ ...detail, item: uncertain, items: [uncertain], impact: null, appAssessments: {} });
    open(base + "/apps/" + local.appHash + "?days=14");
    expect(await screen.findByText(/Several channels or identities/)).toBeTruthy();
    expect(screen.getByRole("link", { name: "Example ESR" }).getAttribute("href")).toEqual(base + "/titles/example%40esr?days=14");
    expect(screen.queryByText("Below target")).toBeNull();
    expect(request).toHaveBeenCalledTimes(1);
  });

  it("shows public title history and pilot guidance even with zero scoped installations", async () => {
    request.mockImplementation(async (url: string) => url.endsWith("/history") ? history : {
      ...detail, item: null, items: [], title: candidate, builds: [], installedMacs: 0, jamfTitles: [], appAssessments: {}, assessments: {},
      impact: { targetVersion: "2.0", installedMacs: 0, olderMacs: 0, atOrAboveMacs: 0, unknownMacs: 0 }
    });
    open(base + "/titles/example");
    expect(await screen.findByText("No matching installations were observed in the selected scope.")).toBeTruthy();
    expect(await screen.findByRole("searchbox")).toBeTruthy();
    expect(screen.getByText("Macs with matching inventory").nextElementSibling?.textContent).toBe("0");
    expect(screen.queryByRole("button", { name: "Read history" })).toBeNull();
    fireEvent.change(screen.getByRole("combobox"), { target: { value: "1" } });
    expect(screen.getByRole("link", { name: /Self-service guide/ })).toBeTruthy();
    fireEvent.click(screen.getByText("Verify in the Fleet API"));
    expect(screen.getByText(/fleet_maintained_apps\?fleet_id=/)).toBeTruthy();
  });

  it("keeps unmatched inventory visible and offers the custom package path", async () => {
    const unmatched = { ...local, match: "none", hasJamfMatch: false, fleetCandidates: [] };
    request.mockResolvedValue({ ...detail, item: unmatched, items: [unmatched], jamfTitles: [], appAssessments: {}, installedEvidence: {}, impact: null });
    open(base + "/apps/" + local.appHash);
    await screen.findByText(/The Fleet catalog has no matching macOS title for this inventory identity/);
    expect(screen.getByRole("link", { name: /Custom package guide/ })).toBeTruthy();
    expect(screen.getByRole("link", { name: "Application record" }).getAttribute("href")).toBe("/devices/applications/" + local.appHash);
    expect(screen.queryByRole("heading", { name: "Fleet release history" })).toBeNull();
    expect(screen.queryByText("0 addressed")).toBeNull();
    expect(screen.getByText("No vulnerability corpus assessment is available for these installed builds.")).toBeTruthy();
    expect(screen.queryByText("With findings")).toBeNull();
    expect(screen.getByText(/A helper, launcher, or extension/)).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Deployment intent"), { target: { value: "2" } });
    expect(screen.getByRole("link", { name: /Installomator/ }).getAttribute("href")).toBe("https://github.com/Installomator/Installomator");
    fireEvent.change(screen.getByLabelText("Deployment intent"), { target: { value: "3" } });
    expect(screen.getByRole("link", { name: /Munki/ })).toBeTruthy();
  });

  it("retains policy evidence when every comparable build already meets the Fleet target", async () => {
    request.mockImplementation(async (url: string) => url.endsWith("/history") ? history : {
      ...detail, appAssessments: { [local.appHash]: { ...assessment, builds: [], behindBuilds: 0, outOfPolicyBuilds: 0, withinPolicyBuilds: 2 } }
    });
    open(base + "/apps/" + local.appHash);
    expect(await screen.findByText("No comparable older build in this scope.")).toBeTruthy();
    expect(screen.getByText("Within policy").nextElementSibling?.textContent).toBe("2");
  });
});
