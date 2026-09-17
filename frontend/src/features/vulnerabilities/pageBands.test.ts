import { describe, expect, it } from "vitest";
import type { AffectedRow, PostureRow } from "./pageBands";
import { exploreByApp, planNumbers, readNumbers } from "./pageBands";

/** Roles as `backend/app/core/permissions.py` grants them, transcribed by hand the way
 *  `overviewPlan.test.ts` transcribes them: fixtures, not a drift guard. */
const VIEWER = ["device:read", "app:read", "vuln:read"];
const ANALYST = [...VIEWER, "connection:read", "audit:read", "destination:read"];
const NO_DAYS = { total: null, severity: { critical: null, high: null, medium: null, low: null } };
const KEYS = ["vuln.apps_affected", "vuln.apps_kev_affected", "vuln.apps_unknown", "vuln.devices_affected"];

function affected(name: string, deviceCount: number, total: number): AffectedRow {
  const counts = { total, kev: 0, severity: { critical: 0, high: 0, medium: 0, low: 0 } };
  return { name, deviceCount, vuln: { assessment: "covered", corpusAsOf: "2026-09-16", counts, daysOldestPublished: NO_DAYS, vulnIDs: [], vulnIDsTruncated: false } };
}

function captured(key: string, value: number, fullSweepRunId: string | null = "run-1"): PostureRow {
  return { key, value, capturedAt: "2026-09-17T04:00:00Z", fullSweepRunId };
}

describe("exploreByApp", () => {
  // Wireshark is two builds and 12 + 9 is the sum it is — which is why the number is a ranking key
  // and never printed: one Mac carrying both builds is counted twice. The last three rank nothing:
  // nobody assessed them, or the corpus did and found none, and neither is an affected Mac.
  it("ranks the affected builds in hand by their Macs, most first, and ranks no other", () => {
    const rows: AffectedRow[] = [
      affected("Wireshark", 12, 94), affected("Zoom", 40, 3), affected("Wireshark", 9, 17), affected("Slack", 6, 1),
      { name: "Xcode", deviceCount: 99, vuln: { assessment: "off" } },
      { name: "Numbers", deviceCount: 80, vuln: { assessment: "unknown_app", corpusAsOf: "2026-09-16" } },
      affected("Pages", 70, 0)
    ];
    expect(exploreByApp(rows)).toEqual([{ name: "Zoom", rank: 40 }, { name: "Wireshark", rank: 21 }, { name: "Slack", rank: 6 }]);
  });

  it("keeps eight chips, breaking a tie by name so the row is stable across renders", () => {
    const rows = ["i", "h", "g", "f", "e", "d", "c", "b", "a"].map((name) => affected(name, 5, 1));
    expect(exploreByApp(rows).map((chip) => chip.name)).toEqual(["a", "b", "c", "d", "e", "f", "g", "h"]);
    expect(exploreByApp([])).toEqual([]);
  });
});

describe("planNumbers", () => {
  // A viewer gets the lists and no tile — never a 403 from a read it cannot make.
  it("plans the tile only for an account that may read the tape", () => {
    expect([planNumbers(VIEWER), planNumbers(["vuln:read"]), planNumbers([])]).toEqual([false, false, false]);
    expect(planNumbers(ANALYST)).toBe(true);
  });
});

describe("readNumbers", () => {
  it("reads the capture's rows in the foot's order, and names the keys it has no row for", () => {
    const read = readNumbers([captured("vuln.devices_affected", 37), captured("vuln.apps_affected", 12)]);
    expect([read.capturedAt, read.runId]).toEqual(["2026-09-17T04:00:00Z", "run-1"]);
    expect(read.present).toEqual([{ key: "vuln.apps_affected", value: 12 }, { key: "vuln.devices_affected", value: 37 }]);
    expect(read.absent).toEqual(["vuln.apps_kev_affected", "vuln.apps_unknown"]);
  });

  // The tape writes none of the four until a corpus has judged the tenant, so an empty capture is
  // the ordinary first answer: the page prints the absence sentence, and nothing fills it with 0.
  it("answers an empty capture with four absences and not one zero", () => {
    expect(readNumbers([])).toEqual({ capturedAt: null, runId: null, present: [], absent: KEYS });
  });

  it("keeps a real zero apart from an absence, and survives a purged run", () => {
    const read = readNumbers([captured("vuln.apps_kev_affected", 0, null)]);
    expect(read.present).toEqual([{ key: "vuln.apps_kev_affected", value: 0 }]);
    expect([read.runId, read.absent.length]).toEqual([null, 3]);
  });
});
