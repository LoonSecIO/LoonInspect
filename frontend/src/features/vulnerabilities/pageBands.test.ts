import { describe, expect, it } from "vitest";
import type { AffectedRow, PostureRow } from "./pageBands";
import { agedList, emptySays, exploreByApp, listQuery, payoffList, planNumbers, readNumbers } from "./pageBands";

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

describe("agedList", () => {
  // The defect: *see all* on Longest exposed, then a Popular chip — or **Back** onto one — left the
  // heading and its *always the builds with findings* hint standing over `vuln=clean` rows.
  it("is the aged list only where the words for it are true", () => {
    expect([agedList(true, "age", "findings", null), agedList(true, "age", "clean", null), agedList(true, "age", "unknown_app", null), agedList(true, "age", "findings", "critical"), agedList(false, "age", "findings", null), agedList(true, "exposure", "findings", null)]).toEqual([true, false, false, false, false, false]);
  });
});

describe("payoffList", () => {
  // The defect: `?vuln=patchable` typed or forwarded without `order=payoff` was headed *Most
  // exposed* and printed the *Easily patchable* band below it — one answer, twice, under two
  // headings. The chip still writes the order; the page no longer needs it to know the list.
  it("is the ranked list off the filter alone, and is no other list", () => {
    expect([payoffList("patchable"), payoffList("findings"), payoffList("kev"), payoffList("clean"), payoffList("unknown_app")]).toEqual([true, false, false, false, false]);
  });
});

/** A search that ran, minted as the page mints it — the only way to hand `emptySays` one. */
const q = (text: string) => listQuery(false, text, "");

describe("emptySays", () => {
  // The defect this exists for. Pressing *No Jamf fix path* on a fleet where every build with
  // findings HAS a Patch title left the table saying *no build the fleet carries has a finding
  // against it in this corpus* — directly under *Most exposed* listing those builds. The chip is
  // empty because the fix path is there, which is the good news the chip was added to surface.
  it("does not let the fix-path chip speak for the fleet", () => {
    expect(emptySays("findings", null, "unmatched", q(""))).toBe("noFixPathNone");
    expect(emptySays("findings", null, null, q(""))).toBe("noFindings");
  });

  // A claim about every build with findings holds only where nothing else narrowed the set: a
  // search, a band or another filter beside the chip and the honest sentence is *this filter*.
  it("hands the chip's own sentence back the moment anything narrows it further", () => {
    expect([emptySays("findings", null, "unmatched", q("wireshark")), emptySays("findings", "critical", "unmatched", q("")), emptySays("kev", null, "unmatched", q(""))]).toEqual(["noRows", "noRows", "noRows"]);
  });

  // #538's four routes, unmoved: the fleet sentence for the unnarrowed list, the search sentence
  // for a search over it, and the filter sentence for every narrowing of it.
  it("keeps the search, the filter and the fleet apart", () => {
    expect([emptySays("findings", null, null, q("wireshark")), emptySays("findings", null, null, q("   ")), emptySays("findings", "high", null, q("")), emptySays("clean", null, null, q("")), emptySays("unknown_app", null, null, q("zoom"))]).toEqual(["noMatches", "noFindings", "noRows", "noRows", "noRows"]);
  });

  // The ranked list is its own state too: expanded and empty it said *no build matches that
  // filter*, when the band it came from had a sentence naming all three reasons (§18 step 8).
  it("gives the ranked list the sentence its own band already had", () => {
    expect([emptySays("patchable", null, null, q("")), emptySays("patchable", null, null, q("zoom"))]).toEqual(["easilyPatchableNone", "noRows"]);
  });

  // The call site's own defect (#534): the sentence was chosen from the BOX while the lists asked
  // with `listQuery`'s answer. Lever on, the box holds a question — so *do we have anything at
  // all?* left standing over an applied `vuln=findings` printed *No build with findings matches
  // that search* for a search that was never sent, and the fleet's own sentence was unreachable
  // for every question the lever answers. Composed here as the page composes it, both ways.
  it("answers for the search that ran, never for the question still in the box", () => {
    const asked = (applied: string) => listQuery(true, "do we have anything at all?", applied);
    expect(listQuery(false, "wireshark", "ignored")).toBe("wireshark");
    expect([emptySays("findings", null, null, asked("")), emptySays("patchable", null, null, asked("")), emptySays("findings", null, null, asked("Wireshark"))])
      .toEqual(["noFindings", "easilyPatchableNone", "noMatches"]);
    // The same conflation the box could reach without the lever: an id is routed, never filtered
    // by, so it is no more a search that ran than a question is.
    expect([listQuery(false, "CVE-2024-1234", ""), emptySays("findings", null, null, listQuery(false, "CVE-2024-1234", ""))])
      .toEqual(["", "noFindings"]);
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
