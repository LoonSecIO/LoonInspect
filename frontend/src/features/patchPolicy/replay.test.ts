/** The replay file's check (#614, first slice): what the page reads, and what it refuses whole. The
 *  shipped Wireshark file is read here through the same function the page uses, so a file the page
 *  would refuse fails this lane and not a reader. */

import { describe, expect, it } from "vitest";
import { pickerApps } from "@/features/patchPolicy/apps";
import { SLIDER_STOPS, TABLED_POLICY, heldFix, isSliderStop, readReplay, replayedRows, type PatchPolicyReplay } from "@/features/patchPolicy/replay";
import { REPLAY_INDEX, loadReplay } from "@/features/patchPolicy/replayIndex";
import wireshark from "./replays/wireshark-2026-10-02.json";

/** A deep copy with one edit, so no test can leak a change into the next. */
function edited(edit: (file: Record<string, any>) => void): unknown { // eslint-disable-line @typescript-eslint/no-explicit-any
  const copy = structuredClone(wireshark) as Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
  edit(copy);
  return copy;
}
const read = (raw: unknown) => readReplay(raw).replay as PatchPolicyReplay;

describe("the shipped Wireshark replay", () => {
  const replay = read(wireshark);

  it("reads clean, with the counts the page prints", () => {
    expect(readReplay(wireshark).refusal).toBeUndefined();
    expect(replay.run_id).toBe("8e578b5804537684112659c2bcc38695ce6e8db412851f147d194d216001fe4c");
    expect(replay.counts).toMatchObject({ cves_in_window: 122, cves_replayed: 101, cves_excluded: 21 });
    expect(replay.window).toEqual({ since: "2024-10-02", until: "2026-10-02" });
  });

  it("never seen is 100, 39, 13, 13, 13, 13 along the slider, and 13 of each were never in range", () => {
    expect(SLIDER_STOPS.map((stop) => replay.policies[stop].never_seen)).toEqual([100, 39, 13, 13, 13, 13]);
    expect(SLIDER_STOPS.map((stop) => replay.policies[stop].never_seen_outside_affected_range)).toEqual([13, 13, 13, 13, 13, 13]);
  });

  it("the tabled policy is in the file and is not a stop", () => {
    expect(replay.policies[TABLED_POLICY]).toBeDefined();
    expect(SLIDER_STOPS).not.toContain(TABLED_POLICY);
    expect(isSliderStop(TABLED_POLICY)).toBe(false);
    expect(isSliderStop("14d")).toBe(true);
    expect(isSliderStop(null)).toBe(false);
  });

  it("the ledger's replayed rows are the 101, and the held line's fix is the one shown", () => {
    const rows = replayedRows(replay);
    expect(rows).toHaveLength(101);
    const row = rows.find((each) => each.cve_id === "CVE-2024-11595");
    expect(heldFix(row!, "4.4")).toMatchObject({ fixed_version: "4.4.2", release_date_reported_by_jamf: "2024-11-20" });
    // A CVE that affects only 4.6 names no fix on the line this device is held to.
    expect(heldFix(rows.find((each) => each.cve_id === "CVE-2025-13674")!, "4.4")).toBeNull();
  });
});

describe("every indexed replay", () => {
  it("loads, reads clean, and is indexed under bundle IDs its own file names", async () => {
    for (const entry of REPLAY_INDEX) {
      const { replay, refusal } = await loadReplay(entry);
      expect(refusal, entry.id).toBeUndefined();
      for (const bundleId of entry.bundleIds) expect(replay?.product?.bundle_ids, entry.id).toContain(bundleId);
    }
  });

  it("a file that will not load is refused, not thrown", async () => {
    const broken = { ...REPLAY_INDEX[0], load: () => Promise.reject(new Error("chunk failed")) };
    expect(await loadReplay(broken)).toEqual({ refusal: { why: "unreadable" } });
  });
});

describe("readReplay refuses", () => {
  it("what is not an object", () => {
    for (const raw of [null, undefined, "{}", 7, []]) expect(readReplay(raw)).toEqual({ refusal: { why: "unreadable" } });
  });

  it("another kind, and names the one it found", () => {
    expect(readReplay(edited((file) => { file.kind = "vuln_summary"; }))).toEqual({ refusal: { why: "kind", found: '"vuln_summary"' } });
    expect(readReplay(edited((file) => { delete file.kind; }))).toEqual({ refusal: { why: "kind", found: "absent" } });
  });

  it("another schema, including the same number as text", () => {
    expect(readReplay(edited((file) => { file.schema = 2; }))).toEqual({ refusal: { why: "schema", found: "2" } });
    expect(readReplay(edited((file) => { file.schema = "1"; }))).toEqual({ refusal: { why: "schema", found: '"1"' } });
  });

  it("a file that lacks something the page draws, by its dotted name", () => {
    expect(readReplay(edited((file) => { delete file.policies["30d"]; }))).toEqual({ refusal: { why: "missing", key: "policies.30d" } });
    expect(readReplay(edited((file) => { file.policies["7d"].exposure_days = "357"; }))).toEqual({ refusal: { why: "missing", key: "policies.7d.exposure_days" } });
    expect(readReplay(edited((file) => { delete file.run_id; }))).toEqual({ refusal: { why: "missing", key: "run_id" } });
    expect(readReplay(edited((file) => { delete file.evidence.catalog_fetched_at; }))).toEqual({ refusal: { why: "missing", key: "evidence.catalog_fetched_at" } });
    expect(readReplay(edited((file) => { delete file.ledger; }))).toEqual({ refusal: { why: "missing", key: "ledger" } });
  });

  it("a policy whose never seen and exposed do not sum to the replayed count", () => {
    expect(readReplay(edited((file) => { file.policies["7d"].exposed = 61; }))).toEqual({
      refusal: { why: "totals", detail: "policies.7d: never_seen 39 + exposed 61 ≠ counts.cves_replayed 101" }
    });
  });

  it("the tabled policy too, though none of it is drawn", () => {
    const result = readReplay(edited((file) => { file.policies[TABLED_POLICY].never_seen = 37; }));
    expect(result.refusal).toEqual({ why: "totals", detail: "policies.critical_or_kev: never_seen 37 + exposed 63 ≠ counts.cves_replayed 101" });
  });

  it("excluded counts that do not sum", () => {
    expect(readReplay(edited((file) => { file.exclusions.by_reason.rejected = 1; })).refusal).toEqual({
      why: "totals", detail: "exclusions.by_reason sums to 22 ≠ counts.cves_excluded 21"
    });
    expect(readReplay(edited((file) => { file.exclusions.cves.pop(); })).refusal).toEqual({
      why: "totals", detail: "exclusions.cves lists 20 ≠ counts.cves_excluded 21"
    });
    expect(readReplay(edited((file) => { file.counts.cves_in_window = 123; })).refusal).toEqual({
      why: "totals", detail: "counts: cves_replayed 101 + cves_excluded 21 ≠ cves_in_window 123"
    });
  });

  it("a ledger that would print a different count than the headline above it", () => {
    const result = readReplay(edited((file) => {
      const row = file.ledger.find((each: { cve_id: string }) => each.cve_id === "CVE-2024-11595");
      row.outcomes["1d"] = { outcome: "exposed", exposure_days: 1, cleared_by: "4.4.2", cleared_on: "2024-11-22", open_at_window_end: false };
    }));
    expect(result.refusal).toEqual({ why: "totals", detail: "ledger under 1d: never_seen 99 ≠ policies.1d.never_seen 100" });
  });

  it("more never-in-range than never seen", () => {
    const result = readReplay(edited((file) => { file.policies.never.never_seen_outside_affected_range = 14; }));
    expect(result.refusal).toEqual({ why: "totals", detail: "policies.never: never_seen_outside_affected_range 14 > never_seen 13" });
  });
});

describe("readReplay ignores what it does not know", () => {
  it("unknown keys at every level, and a policy this build has no stop for", () => {
    const result = readReplay(edited((file) => {
      file.added_later = { anything: true };
      file.counts.cves_reconsidered = 4;
      file.policies["90d"] = { never_seen: 1, exposed: 1 };
      file.policies["14d"].median_days = 9;
      file.ledger[0].cwe = "CWE-125";
    }));
    expect(result.refusal).toBeUndefined();
    expect(result.replay?.policies["14d"].never_seen).toBe(13);
  });
});

describe("pickerApps", () => {
  const index = REPLAY_INDEX.map(({ id, name, bundleIds }) => ({ id, name, bundleIds }));

  it("lists the replays when there is no catalog to read", () => {
    expect(pickerApps([], index)).toEqual([{ key: "wireshark", name: "Wireshark", replayId: "wireshark" }]);
  });

  it("puts the replays first, folds a replay's own Jamf titles into its row, and marks the rest as having none", () => {
    const apps = pickerApps(
      [
        { name: "Zoom", bundleId: "us.zoom.xos" },
        { name: "Wireshark 4.4", bundleId: "org.wireshark.Wireshark" },
        { name: "Wireshark", bundleId: "ORG.wireshark.Wireshark " },
        { name: "Google Chrome", bundleId: "com.google.Chrome" }
      ],
      index
    );
    expect(apps).toEqual([
      { key: "wireshark", name: "Wireshark", replayId: "wireshark" },
      { key: "com.google.chrome", name: "Google Chrome", replayId: null },
      { key: "us.zoom.xos", name: "Zoom", replayId: null }
    ]);
  });

  it("makes one row of the titles that share a bundle ID, under the shortest name, and keeps a title with none", () => {
    const apps = pickerApps(
      [
        { name: "Firefox ESR 140", bundleId: "org.mozilla.firefox" },
        { name: "Firefox", bundleId: "org.mozilla.firefox" },
        { name: "Some Driver", bundleId: null }
      ],
      []
    );
    expect(apps).toEqual([
      { key: "org.mozilla.firefox", name: "Firefox", replayId: null },
      { key: "title:Some Driver", name: "Some Driver", replayId: null }
    ]);
  });
});
