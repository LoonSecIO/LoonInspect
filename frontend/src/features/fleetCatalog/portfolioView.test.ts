import { describe, expect, it, vi } from "vitest";
import { apiRequest } from "@/config/api";
import { fleetScopeQuery, getFleetDetail, getMigrationReport } from "@/features/fleetCatalog/api";
import type { FleetAssessment, InstalledEvidence, MigrationItem, MigrationPortfolio } from "@/features/fleetCatalog/migrationTypes";
import { coverage, outsideCatalogs, policySummary, portfolioRows, quickCounts, readFilter, readSort } from "@/features/fleetCatalog/portfolioView";

vi.mock("@/config/api", () => ({ apiRequest: vi.fn() }));

function item(name: string, overrides: Partial<MigrationItem> = {}): MigrationItem {
  return { appHash: name.toLowerCase(), name, bundleId: `com.example.${name.toLowerCase()}`, macs: 1, versionCount: 1,
    match: "exact", hasJamfMatch: false, jamfEvaluated: true, fleetCandidates: [], ...overrides };
}

function assessment(overrides: Partial<FleetAssessment> = {}): FleetAssessment {
  return { targetVersion: "2.0", priority: "monitor", priorityReason: "none_behind", management: "observe", recentVersions: null,
    corpusAsOf: null, oldestGapDays: null, behindBuilds: 0, unorderedBuilds: 0, exactBuilds: 0, netOnlyBuilds: 0, unknownBuilds: 0,
    outOfPolicyBuilds: 0, withinPolicyBuilds: 0, policyExemptBuilds: 0, policyUnassessedBuilds: 0, kevBuilds: 0, addresses: 0,
    introduces: 0, remains: 0, builds: [], ...overrides };
}

const covered: InstalledEvidence = { assessment: "covered", asOf: "2026-11-24", assessedBuilds: 1, unknownBuilds: 0,
  affectedBuilds: 0, highOrCriticalBuilds: 0, kevBuilds: 0 };

// Both catalogs read, and every app's builds `covered` with no finding, unless `overrides` says otherwise.
function report(items: MigrationItem[], overrides: Partial<MigrationPortfolio> = {}): MigrationPortfolio {
  return { enabled: true, asOf: "2026-11-25T00:00:00Z", fleetCatalogReady: true, fleetCatalogReadiness: "complete",
    jamfCatalogReady: true, scope: { eligibleMacs: 900, selectedMacs: 900, unknownContactMacs: 0, unknownInventoryMacs: 0 },
    installedEvidence: Object.fromEntries(items.map(app => [app.appHash, covered])), appAssessments: {}, fleetDeviceCounts: {},
    items, ...overrides };
}

const names = (rows: MigrationItem[]) => rows.map(row => row.name);

describe("fleetScopeQuery", () => {
  // What a form encoding could mangle: a space, +, &, =, %, a quote and a non-ASCII letter.
  const scope = '{"match":"any","rules":[{"field":"ea","operator":"like","value":"a+b & c=100% \\"é\\"","key":"Dept"}]}';

  it("carries the device filter byte for byte and nothing else, malformed or not, and is empty without one", () => {
    const page = (deviceScope: string) => new URLSearchParams(`q=zoom&filter=outside&days=30&deviceScope=${encodeURIComponent(deviceScope)}`);
    expect([...new URLSearchParams(fleetScopeQuery(page(scope)))]).toEqual([["deviceScope", scope]]);
    // Never parsed or dropped, which would widen the request to every Mac: the server refuses it.
    expect(fleetScopeQuery(page('{"match":'))).toBe("deviceScope=%7B%22match%22%3A");
    expect(fleetScopeQuery(new URLSearchParams("q=zoom&filter=outside&days=30"))).toBe("");
  });

  it("is what the list and detail requests send, with the caller's signal", () => {
    const signal = new AbortController().signal;
    const query = fleetScopeQuery(new URLSearchParams({ deviceScope: scope }));
    void getMigrationReport("", signal);
    void getMigrationReport(query);
    void getFleetDetail("apps", "0123456789abcdef0123456789abcdef", query, undefined, signal);
    void getFleetDetail("titles", "example@esr", "", "2.1");
    expect(vi.mocked(apiRequest).mock.calls).toEqual([
      ["/fleet-catalog/migration", { signal }],
      [`/fleet-catalog/migration?${query}`, { signal: undefined }],
      [`/fleet-catalog/migration/apps/0123456789abcdef0123456789abcdef?${query}`, { signal }],
      ["/fleet-catalog/migration/titles/example%40esr?targetVersion=2.1", { signal: undefined }]
    ]);
  });
});

describe("portfolioRows", () => {
  it("ranks a build out of policy on 1 Mac above an app on 900 Macs with no finding", () => {
    const held = report([item("Common", { macs: 900 }), item("Breach")],
      { appAssessments: { common: assessment(), breach: assessment({ behindBuilds: 1, outOfPolicyBuilds: 1 }) } });
    expect(names(portfolioRows(held, "", "all", "priority"))).toEqual(["Breach", "Common"]);
  });

  it("sorts by Macs or by name, ties falling back to the name, then the app hash", () => {
    const held = report([item("Beta", { appHash: "b2", macs: 5 }), item("Alpha", { macs: 5 }),
      item("Beta", { appHash: "b1", macs: 5 }), item("Zeta", { macs: 9 })]);
    expect(portfolioRows(held, "", "all", "reach").map(row => row.appHash)).toEqual(["zeta", "alpha", "b1", "b2"]);
    expect(portfolioRows(held, "", "all", "name").map(row => row.appHash)).toEqual(["alpha", "b1", "b2", "zeta"]);
  });

  it("sorts an app whose evidence counts are null exactly like one whose counts are 0", () => {
    const unknown: InstalledEvidence = { ...covered, assessment: "unknown_app", assessedBuilds: 0, unknownBuilds: 1,
      affectedBuilds: null, highOrCriticalBuilds: null, kevBuilds: null };
    const zeros = report([item("Alpha", { macs: 4 }), item("Beta", { macs: 4 }), item("Gamma", { macs: 2 })],
      { appAssessments: { alpha: assessment(), beta: assessment() } });
    expect(names(portfolioRows(zeros, "", "all", "priority"))).toEqual(["Alpha", "Beta", "Gamma"]);
    for (const hash of ["alpha", "beta"]) {
      const nulls = { ...zeros, installedEvidence: { ...zeros.installedEvidence, [hash]: unknown },
        appAssessments: { ...zeros.appAssessments, [hash]: assessment({ kevBuilds: null, addresses: null }) } };
      expect(names(portfolioRows(nulls, "", "all", "priority"))).toEqual(["Alpha", "Beta", "Gamma"]);
      expect(portfolioRows(nulls, "", "exposure", "priority")).toEqual([]);
    }
  });

  it("searches the name, the bundle ID and the Fleet title's name, in any case", () => {
    const zoom = item("Zoom", { bundleId: "us.zoom.xos",
      fleetCandidates: [{ slug: "zoom", name: "Zoom Workplace", bundleId: "us.zoom.xos", latestVersion: "6.2" }] });
    const held = report([zoom, item("Slack")]);
    for (const term of ["  ZOOM ", "Us.Zoom", "workPLACE"]) expect(names(portfolioRows(held, term, "all", "name"))).toEqual(["Zoom"]);
    expect(names(portfolioRows(held, "", "all", "name"))).toEqual(["Slack", "Zoom"]);
  });

  it("keeps what each filter names, and counts the quick filters over the whole scope", () => {
    const held = report([item("Now"), item("Plan"), item("Calm"), item("Outside", { match: "none" }), item("Partial"), item("Missing")], {
      appAssessments: { now: assessment({ priority: "review_now", outOfPolicyBuilds: 1 }), plan: assessment({ priority: "plan_update" }),
        calm: assessment(), partial: assessment(), missing: assessment() } });
    held.installedEvidence.partial = { ...covered, assessment: "partial", unknownBuilds: 1 };
    delete held.installedEvidence.missing;
    const expected = { candidates: ["Now", "Plan"], overdue: ["Now"], outside: ["Outside"], unknown: ["Missing", "Partial"] };
    for (const [filter, apps] of Object.entries(expected)) expect(names(portfolioRows(held, "", readFilter(filter), "name"))).toEqual(apps);
    expect(quickCounts(held)).toEqual({ candidates: 2, overdue: 1, outside: 1 });
    // A URL value this build does not know reads as the default.
    expect([readFilter("Outside"), readFilter(null), readSort("macs"), readSort(null), readSort("age")]).toEqual(["all", "all", "priority", "priority", "age"]);
  });
});

describe("the keys the page words", () => {
  it("never claim an app is outside both catalogs, and count null, until Fleet's is read whole and Jamf's is synced", () => {
    const outside = item("Outside", { match: "none" });
    const unread: Partial<MigrationPortfolio>[] = [{ fleetCatalogReady: false, fleetCatalogReadiness: "partial" },
      { fleetCatalogReady: false, fleetCatalogReadiness: "unread" }, { jamfCatalogReady: false }];
    for (const overrides of unread) {
      const held = report([outside], overrides);
      expect(outsideCatalogs(outside, held)).toBe(false);
      expect(portfolioRows(held, "", "outside", "name")).toEqual([]);
      expect(quickCounts(held).outside).toBeNull();
    }
  });

  it("say which catalogs carry an app and how its builds stand against the rule", () => {
    const held = report([]);
    expect(coverage(item("A", { match: "none", jamfEvaluated: false }), held)).toEqual(["noFleet"]);
    expect(coverage(item("B", { match: "ambiguous", hasJamfMatch: true }), held)).toEqual(["channels", "jamf"]);
    expect(coverage(item("C", { match: "unknown" }), held)).toEqual(["unavailable"]);
    expect(coverage(item("D", { match: "none" }), held)).toEqual(["outside"]);
    expect(policySummary(assessment({ outOfPolicyBuilds: 1, withinPolicyBuilds: 2 }))).toBe("overdue");
    expect(policySummary(assessment({ policyUnassessedBuilds: 1, policyExemptBuilds: 1 }))).toBe("partial");
    expect(policySummary(assessment({ policyUnassessedBuilds: 1 }))).toBe("unassessed");
    expect(policySummary(undefined)).toBe("unassessed");
  });
});
