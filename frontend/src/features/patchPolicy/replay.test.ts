/** The replay file's check (#614, first slice): what the page reads, and what it refuses whole. Every
 *  shipped replay is read here through the same function the page uses, so a file the page would
 *  refuse fails this lane and not a reader, and its headline numbers are pinned, so a replaced file
 *  changes them in a reviewed diff. The rules themselves are pinned on hand-made schema-2 files
 *  (`testing/replayFixtures.ts`), whose numbers are invented and describe no app. */

import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { pickerApps } from "@/features/patchPolicy/apps";
import { patchPolicyEnglish, patchPolicyGerman } from "@/features/patchPolicy/copy";
import {
  REPLAY_SCHEMA,
  SLIDER_STOPS,
  TABLED_POLICY,
  affectedBounds,
  heldFixes,
  isSliderStop,
  readReplay,
  replayedRows,
  windowCut,
  type PatchPolicyReplay
} from "@/features/patchPolicy/replay";
import { REPLAY_INDEX, loadReplay } from "@/features/patchPolicy/replayIndex";
import { heldLineReplay, singleLineReplay } from "@/features/patchPolicy/testing/replayFixtures";

/** A fresh fixture with one edit, so no test can leak a change into the next. */
function edited(edit: (file: Record<string, any>) => void, make = heldLineReplay): unknown { // eslint-disable-line @typescript-eslint/no-explicit-any
  const copy = make() as Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
  edit(copy);
  return copy;
}
const read = (raw: unknown) => readReplay(raw).replay as PatchPolicyReplay;
const replayFile = (name: string) => new URL(`./replays/${name}`, import.meta.url);

/** Every key, and every string value, in a file, with its dotted path: what the item-4 check reads. */
function walk(value: unknown, path: string, visit: (path: string, key: string | null, text: string | null) => void): void {
  if (typeof value === "string") visit(path, null, value);
  else if (Array.isArray(value)) value.forEach((each, index) => walk(each, `${path}[${index}]`, visit));
  else if (value && typeof value === "object") {
    for (const [key, each] of Object.entries(value)) {
      visit(`${path}.${key}`, key, null);
      walk(each, `${path}.${key}`, visit);
    }
  }
}

/** Where a replay names Jamf or Fleet: in a key anywhere, in any string, or in its `timeline`. A
 *  shipped replay is dated from a vendor's own release record and names that record, so none of
 *  these may appear in one. */
function namesJamfOrFleet(file: unknown): string[] {
  const found: string[] = [];
  walk(file, "", (path, key, text) => {
    if (key !== null && /jamf|fleet/i.test(key)) found.push(path);
    if (text !== null && (/jamf/i.test(text) || (path.startsWith(".timeline.") && /fleet/i.test(text)))) found.push(path);
  });
  return found;
}

describe("the hand-made schema-2 replays", () => {
  const held = read(heldLineReplay());
  const single = read(singleLineReplay());

  it("read clean, with the counts the page prints", () => {
    expect(REPLAY_SCHEMA).toBe(2);
    expect(readReplay(heldLineReplay()).refusal).toBeUndefined();
    expect(readReplay(singleLineReplay()).refusal).toBeUndefined();
    expect(held.counts).toMatchObject({ cves_in_window: 5, cves_replayed: 4, cves_excluded: 1 });
    expect(single.counts).toMatchObject({ cves_in_window: 3, cves_replayed: 2, cves_excluded: 1 });
    expect(SLIDER_STOPS.map((stop) => held.policies[stop].never_seen)).toEqual([3, 2, 1, 1, 1, 1]);
  });

  it("carry their release-date source and the CVE clock, which the page prints", () => {
    expect(held.timeline).toMatchObject({ name: "Example App's release tags", fetched_at: "2026-11-24T09:15:42Z" });
    expect(held.clocks.published).toBe("NVD `published`, truncated to the UTC date.");
  });

  it("name neither Jamf nor Fleet, and the check finds a Jamf key or source where there is one", () => {
    expect(namesJamfOrFleet(heldLineReplay())).toEqual([]);
    expect(namesJamfOrFleet(singleLineReplay())).toEqual([]);
    const jamfDated = edited((file) => {
      file.releases[0].release_date_reported_by_jamf = "2024-11-27";
      file.timeline.name = "Jamf's patch catalog";
      file.early_stable_choice = { promotion_table_behind_jamf: false };
    });
    expect(namesJamfOrFleet(jamfDated)).toEqual([".timeline.name", ".releases[0].release_date_reported_by_jamf", ".early_stable_choice.promotion_table_behind_jamf"]);
  });

  it("the held line's fix is the one shown, and a CVE with no fix on that line shows none", () => {
    const rows = replayedRows(held);
    expect(rows).toHaveLength(4);
    expect(heldFixes(rows.find((each) => each.cve_id === "CVE-2099-0001")!, "4.4")).toEqual([{ branch: "4.4", fixed_version: "4.4.2", release_date: "2024-11-27" }]);
    expect(heldFixes(rows.find((each) => each.cve_id === "CVE-2099-0002")!, "4.4")).toEqual([]);
  });

  it("an app replayed as one line holds no line, and its fixes are on the line that has no name", () => {
    expect(single.branch_choice.held_at_branch).toBeNull();
    const rows = replayedRows(single);
    expect(rows).toHaveLength(2);
    expect(heldFixes(rows[0], null)).toEqual([{ branch: "", fixed_version: "131.0.5", release_date: "2024-12-10" }]);
    // A file with several lines but no held one would show no fix on any row, never another line's.
    expect(heldFixes(read(heldLineReplay()).ledger[0], null)).toEqual([]);
  });

  it("every fix on the line, oldest first, never only the first the file lists: one per range NVD states", () => {
    const esr = { kind: "range", bounds: { versionStartIncluding: "115.0", versionEndExcluding: "115.18.0" } };
    const release = { kind: "range", bounds: { versionStartIncluding: "131.0", versionEndExcluding: "131.0.5" } };
    const row = read(edited((file) => {
      // The file's order puts the ESR range's fix first, as LoonVD sorts by the statement.
      file.ledger[0].fixes = [
        { branch: "", fixed_version: "131.0.5", release_date: "2024-12-10", affected: release },
        { branch: "", fixed_version: "116.0", release_date: "2023-08-01", affected: esr },
        { branch: "", fixed_version: null, release_date: null }
      ].reverse();
    }, singleLineReplay)).ledger[0];
    expect(heldFixes(row, null).map((fix) => fix.fixed_version)).toEqual(["116.0", "131.0.5"]);
    expect(affectedBounds(heldFixes(row, null)[1])).toEqual({ start: { version: "131.0", including: true }, end: { version: "131.0.5", including: false } });
  });

  it("words NVD's statement a fix closes from the file, and words none it cannot read", () => {
    const range = (bounds: Record<string, unknown>) => affectedBounds({ affected: { kind: "range", bounds } })!;
    expect(patchPolicyEnglish.affected(range({ versionStartIncluding: "154.0.0", versionEndExcluding: "157.0.0" }))).toBe(
      "for versions from 154.0.0 (including) up to 157.0.0 (excluding)"
    );
    expect(patchPolicyEnglish.affected(range({ versionEndIncluding: "4.4.5" }))).toBe("for versions up to 4.4.5 (including)");
    expect(patchPolicyEnglish.affected(range({ versionStartExcluding: "4.2.0", versionEndExcluding: "4.2.9" }))).toBe(
      "for versions from 4.2.0 (excluding) up to 4.2.9 (excluding)"
    );
    expect(patchPolicyEnglish.affected(affectedBounds({ affected: { kind: "exact", version: "131.0.2" } })!)).toBe("for version 131.0.2");
    expect(patchPolicyGerman.affected(range({ versionStartIncluding: "154.0.0", versionEndExcluding: "157.0.0" }))).toBe(
      "für Versionen ab 154.0.0 (einschließlich) bis 157.0.0 (ausschließlich)"
    );
    for (const affected of [undefined, { kind: "range", bounds: {} }, { kind: "range" }, { kind: "prerelease", version: "1.0" }, { kind: "exact" }]) {
      expect(affectedBounds({ affected }), JSON.stringify(affected)).toBeNull();
    }
  });

  it("the tabled policy is in the file and is not a stop", () => {
    expect(held.policies[TABLED_POLICY]).toBeDefined();
    expect(SLIDER_STOPS).not.toContain(TABLED_POLICY);
    expect(isSliderStop(TABLED_POLICY)).toBe(false);
    expect(isSliderStop("14d")).toBe(true);
    expect(isSliderStop(null)).toBe(false);
  });
});

describe("every indexed replay", () => {
  it("loads, reads clean, and is indexed under the one bundle ID its own file replays", async () => {
    for (const entry of REPLAY_INDEX) {
      const { replay, refusal } = await loadReplay(entry);
      expect(refusal, entry.id).toBeUndefined();
      for (const bundleId of entry.bundleIds) expect(replay?.product?.bundle_ids, entry.id).toContain(bundleId);
      // Not a beta, canary or developer edition the file also names: those are other channels.
      const product = replay?.product as { device_bundle_id?: string } | undefined;
      expect(entry.bundleIds, entry.id).toEqual([product?.device_bundle_id]);
    }
  });

  it("is every file in replays/, and each is indexed once", () => {
    const files = readdirSync(new URL("./replays/", import.meta.url)).filter((name) => name.endsWith(".json")).sort();
    expect(REPLAY_INDEX.map((entry) => entry.file).sort()).toEqual(files);
    expect(new Set(REPLAY_INDEX.map((entry) => entry.id)).size).toBe(REPLAY_INDEX.length);
  });

  it("counts each CVE from NVD's publication date, which is the clock the page states", async () => {
    for (const entry of REPLAY_INDEX) {
      const file = (await entry.load()) as { cve_clock?: string; clocks?: { cve?: string } };
      expect(file.cve_clock, entry.file).toBe("published");
      expect(file.clocks?.cve, entry.file).toMatch(/^The CVE clock is NVD's publication date/);
    }
  });

  it("has words for every exclusion reason it counts, in both languages", async () => {
    for (const entry of REPLAY_INDEX) {
      const { replay } = await loadReplay(entry);
      for (const reason of Object.keys(replay!.exclusions.by_reason)) {
        expect(patchPolicyEnglish.reasons[reason], `${entry.file}: ${reason}`).toBeDefined();
        expect(patchPolicyGerman.reasons[reason], `${entry.file}: ${reason}`).toBeDefined();
      }
    }
  });

  it("is the file its entry names, listed in the README's sources table with that file's bytes and SHA-256", async () => {
    const readme = readFileSync(replayFile("README.md"), "utf8");
    // One row per file, and one file per row: every row of the table, read by its file name.
    const header = readme.split("\n").find((each) => each.startsWith("| File |"))!.split("|").map((cell) => cell.trim());
    const [bytesAt, digestAt] = [header.indexOf("Bytes"), header.indexOf("SHA-256")];
    const listed = readme
      .split("\n")
      .filter((each) => /^\| `[^`]+\.json` \|/.test(each))
      .map((each) => {
        const cells = each.split("|").map((cell) => cell.trim());
        return [cells[1].slice(1, -1), { bytes: cells[bytesAt], digest: cells[digestAt] }] as const;
      });
    expect(listed.map(([file]) => file).sort(), "replays/README.md lists a file the index does not, or lists one twice").toEqual(
      REPLAY_INDEX.map((entry) => entry.file).sort()
    );
    const rows = new Map(listed);
    for (const entry of REPLAY_INDEX) {
      expect(existsSync(replayFile(entry.file)), entry.file).toBe(true);
      const bytes = readFileSync(replayFile(entry.file));
      expect(await entry.load(), entry.file).toEqual(JSON.parse(bytes.toString("utf8")));
      const row = rows.get(entry.file);
      expect(row, `${entry.file} has no row in replays/README.md`).toBeDefined();
      expect(Number(row!.bytes.replace(/,/g, "")), `${entry.file}: Bytes`).toBe(bytes.length);
      expect(row!.digest, `${entry.file}: SHA-256`).toBe(`\`${createHash("sha256").update(bytes).digest("hex")}\``);
    }
  });

  it("is dated from a vendor's records it names, and carries no Jamf or Fleet key or source", async () => {
    for (const entry of REPLAY_INDEX) expect(namesJamfOrFleet(await entry.load()), entry.file).toEqual([]);
  });

  it("a file that will not load is refused, not thrown", async () => {
    const broken = { load: () => Promise.reject(new Error("chunk failed")) };
    expect(await loadReplay(broken)).toEqual({ refusal: { why: "unreadable" } });
  });

  it("a file that loads is read through the page's check", async () => {
    expect((await loadReplay({ load: () => Promise.resolve(singleLineReplay()) })).refusal).toBeUndefined();
  });
});

/** What each shipped file says, as it says it. A replaced file fails here until these are updated in
 *  the same change, so a reviewer sees every headline number that moved. */
const SHIPPED: Record<string, {
  source: string;
  window: [string, string];
  counts: [inWindow: number, replayed: number, excluded: number];
  neverSeen: number[];
  held: string | null;
  device: string;
  cut: string[];
}> = {
  wireshark: {
    source: "wireshark",
    window: ["2024-11-23", "2026-11-23"],
    counts: [155, 115, 40],
    neverSeen: [114, 59, 16, 16, 16, 16],
    held: "4.4",
    device: "take",
    cut: []
  },
  firefox: {
    source: "firefox-release",
    window: ["2024-11-23", "2026-11-23"],
    counts: [1121, 718, 403],
    neverSeen: [717, 6, 5, 2, 1, 17],
    held: null,
    device: "take",
    cut: []
  },
  chrome: {
    // Cut short: the timeline dates a major the promotion table had no row for the day after.
    source: "chrome-stable",
    window: ["2024-11-23", "2026-11-17"],
    counts: [4382, 3415, 967],
    neverSeen: [3400, 149, 50, 29, 15, 6],
    held: null,
    device: "skip",
    cut: ["promotion_table"]
  },
  thunderbird: {
    source: "thunderbird-release",
    window: ["2024-11-23", "2026-11-23"],
    counts: [1011, 601, 410],
    neverSeen: [493, 6, 3, 1, 1, 19],
    held: null,
    device: "take",
    cut: []
  }
};

describe("the shipped replays", () => {
  it("are the four this build lists, and no other", () => {
    expect(REPLAY_INDEX.map((entry) => entry.id)).toEqual(["wireshark", "firefox", "chrome", "thunderbird"]);
    expect(Object.keys(SHIPPED).sort()).toEqual(REPLAY_INDEX.map((entry) => entry.id).sort());
  });

  for (const entry of REPLAY_INDEX) {
    it(`${entry.name}: the window, counts, headline at every stop, held line and waiting device the file states`, async () => {
      const expected = SHIPPED[entry.id];
      const { replay } = await loadReplay(entry);
      expect(replay!.timeline.source).toBe(expected.source);
      expect([replay!.window.since, replay!.window.until]).toEqual(expected.window);
      const { cves_in_window: inWindow, cves_replayed: replayed, cves_excluded: excluded } = replay!.counts;
      expect([inWindow, replayed, excluded]).toEqual(expected.counts);
      expect(SLIDER_STOPS.map((stop) => replay!.policies[stop].never_seen)).toEqual(expected.neverSeen);
      expect(replay!.branch_choice.held_at_branch).toBe(expected.held);
      expect(replay!.early_stable_choice?.device).toBe(expected.device);
      expect((replay!.window.shortened_by ?? []).map((cut) => cut.reason)).toEqual(expected.cut);
    });
  }

  it("Chrome's window ends where its file cut it, and says why in its own words", async () => {
    const chrome = REPLAY_INDEX.find((entry) => entry.id === "chrome")!;
    const { replay } = await loadReplay(chrome);
    const cut = windowCut(replay!);
    expect(cut?.requested).toBe("2026-11-23");
    expect(cut?.reasons).toHaveLength(1);
    expect(cut?.reasons[0]).toMatch(/^The timeline dates 159\.0\.8154\.13 on 2026-11-18, and the promotion table's newest row is major 158/);
    for (const entry of REPLAY_INDEX.filter((each) => each.id !== "chrome")) {
      expect(windowCut((await loadReplay(entry)).replay!), entry.id).toBeNull();
    }
  });
});

describe("windowCut", () => {
  it("is null for a window that runs as asked, and reads a cut without trusting its shape", () => {
    expect(windowCut(read(heldLineReplay()))).toBeNull();
    const asked = read(edited((file) => { file.window.requested_until = "2026-11-30"; }) as Record<string, unknown>);
    expect(windowCut(asked)).toEqual({ requested: "2026-11-30", reasons: [] });
    const cut = read(edited((file) => {
      file.window.requested_until = file.window.until;
      file.window.shortened_by = [{ reason: "timeline_as_of", sentence: "The table was fetched the next day." }, { reason: "line_start" }, "loose", null];
    }) as Record<string, unknown>);
    expect(windowCut(cut)).toEqual({ requested: null, reasons: ["The table was fetched the next day.", "line_start"] });
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

  it("schema 1, the format with no timeline block, in words that say so", () => {
    const refusal = readReplay(edited((file) => { file.schema = 1; })).refusal;
    expect(refusal).toEqual({ why: "schema", found: "1" });
    expect(patchPolicyEnglish.refused(refusal!)).toBe(
      "Its schema is 1, the earlier replay format, which has no timeline block, the part of the file this page reads to name and link where its release dates come from. This page reads schema 2 only."
    );
    expect(patchPolicyGerman.refused(refusal!)).toBe(
      "Ihr schema ist 1, das frühere Replay-Format ohne timeline-Block, den Teil der Datei, aus dem diese Seite die Quelle ihrer Release-Daten benennt und verlinkt. Diese Seite liest nur schema 2."
    );
  });

  it("a file on a CVE clock other than NVD's publication date, which the page's words would misstate", () => {
    const refusal = readReplay(edited((file) => { file.cve_clock = "detectable_at"; })).refusal;
    expect(refusal).toEqual({ why: "clock", found: '"detectable_at"' });
    expect(patchPolicyEnglish.refused(refusal!)).toBe(
      `Its CVE clock is "detectable_at". This page states one CVE clock, NVD's publication date (published), and would misstate any other.`
    );
    expect(patchPolicyGerman.refused(refusal!)).toBe(
      `Ihre CVE-Uhr ist "detectable_at". Diese Seite nennt nur eine CVE-Uhr, das Veröffentlichungsdatum bei NVD (published), und würde jede andere falsch angeben.`
    );
    // Refused even when every other key is there, a definition of `published` included: that is the
    // definition of a field, not the clock the file is on.
    expect(read(heldLineReplay()).clocks.published).toBeDefined();
    expect(readReplay(edited((file) => { file.cve_clock = null; })).refusal).toEqual({ why: "clock", found: "null" });
    expect(readReplay(edited((file) => { delete file.cve_clock; })).refusal).toEqual({ why: "missing", key: "cve_clock" });
  });

  it("another schema, including the same number as text", () => {
    expect(readReplay(edited((file) => { file.schema = 3; }))).toEqual({ refusal: { why: "schema", found: "3" } });
    expect(readReplay(edited((file) => { file.schema = "2"; }))).toEqual({ refusal: { why: "schema", found: '"2"' } });
    expect(patchPolicyEnglish.refused({ why: "schema", found: "3" })).toBe("Its schema is 3, and this page reads schema 2 only.");
  });

  it("a file that lacks something the page draws, by its dotted name", () => {
    expect(readReplay(edited((file) => { delete file.policies["30d"]; }))).toEqual({ refusal: { why: "missing", key: "policies.30d" } });
    expect(readReplay(edited((file) => { file.policies["7d"].exposure_days = "12"; }))).toEqual({ refusal: { why: "missing", key: "policies.7d.exposure_days" } });
    expect(readReplay(edited((file) => { delete file.run_id; }))).toEqual({ refusal: { why: "missing", key: "run_id" } });
    expect(readReplay(edited((file) => { delete file.ledger; }))).toEqual({ refusal: { why: "missing", key: "ledger" } });
  });

  it("a file that does not say where its release dates come from, or what its CVE clock is", () => {
    expect(readReplay(edited((file) => { delete file.timeline; }))).toEqual({ refusal: { why: "missing", key: "timeline.name" } });
    expect(readReplay(edited((file) => { file.timeline.name = ""; }))).toEqual({ refusal: { why: "missing", key: "timeline.name" } });
    expect(readReplay(edited((file) => { delete file.timeline.clock; }))).toEqual({ refusal: { why: "missing", key: "timeline.clock" } });
    expect(readReplay(edited((file) => { delete file.timeline.fetched_at; }))).toEqual({ refusal: { why: "missing", key: "timeline.fetched_at" } });
    expect(readReplay(edited((file) => { delete file.clocks.published; }))).toEqual({ refusal: { why: "missing", key: "clocks.published" } });
    // The schema-1 evidence is not asked for: a schema-2 file reads clean without it.
    expect(readReplay(edited((file) => { delete file.evidence; })).refusal).toBeUndefined();
  });

  it("a file that does not say which release line it holds, where null is one line and absent is not", () => {
    expect(readReplay(edited((file) => { delete file.branch_choice.held_at_branch; }))).toEqual({ refusal: { why: "missing", key: "branch_choice.held_at_branch" } });
    expect(readReplay(edited((file) => { delete file.branch_choice; }))).toEqual({ refusal: { why: "missing", key: "branch_choice.held_at_branch" } });
    expect(readReplay(edited((file) => { file.branch_choice.held_at_branch = 4.4; }))).toEqual({ refusal: { why: "missing", key: "branch_choice.held_at_branch" } });
  });

  it("a policy whose never seen and exposed do not sum to the replayed count", () => {
    expect(readReplay(edited((file) => { file.policies["7d"].exposed = 3; }))).toEqual({
      refusal: { why: "totals", detail: "policies.7d: never_seen 2 + exposed 3 ≠ counts.cves_replayed 4" }
    });
  });

  it("the tabled policy too, though none of it is drawn", () => {
    const result = readReplay(edited((file) => { file.policies[TABLED_POLICY].never_seen = 2; }));
    expect(result.refusal).toEqual({ why: "totals", detail: "policies.critical_or_kev: never_seen 2 + exposed 3 ≠ counts.cves_replayed 4" });
  });

  it("excluded counts that do not sum", () => {
    expect(readReplay(edited((file) => { file.exclusions.by_reason.rejected = 1; })).refusal).toEqual({
      why: "totals", detail: "exclusions.by_reason sums to 2 ≠ counts.cves_excluded 1"
    });
    expect(readReplay(edited((file) => { file.exclusions.cves.pop(); })).refusal).toEqual({
      why: "totals", detail: "exclusions.cves lists 0 ≠ counts.cves_excluded 1"
    });
    expect(readReplay(edited((file) => { file.counts.cves_in_window = 6; })).refusal).toEqual({
      why: "totals", detail: "counts: cves_replayed 4 + cves_excluded 1 ≠ cves_in_window 6"
    });
  });

  it("a ledger that would print a different count than the headline above it", () => {
    const result = readReplay(edited((file) => {
      const row = file.ledger.find((each: { cve_id: string }) => each.cve_id === "CVE-2099-0001");
      row.outcomes["1d"] = { outcome: "exposed", exposure_days: 1, cleared_by: "4.4.2", cleared_on: "2024-11-29", open_at_window_end: false };
    }));
    expect(result.refusal).toEqual({ why: "totals", detail: "ledger under 1d: never_seen 2 ≠ policies.1d.never_seen 3" });
  });

  it("more never-in-range than never seen", () => {
    const result = readReplay(edited((file) => { file.policies.never.never_seen_outside_affected_range = 2; }));
    expect(result.refusal).toEqual({ why: "totals", detail: "policies.never: never_seen_outside_affected_range 2 > never_seen 1" });
  });
});

describe("readReplay ignores what it does not know", () => {
  it("unknown keys at every level, and a policy this build has no stop for", () => {
    const result = readReplay(edited((file) => {
      file.added_later = { anything: true };
      file.counts.cves_reconsidered = 4;
      file.timeline.terms = "https://example.com/terms";
      file.policies["90d"] = { never_seen: 1, exposed: 1 };
      file.policies["14d"].median_days = 9;
      file.ledger[0].cwe = "CWE-125";
    }));
    expect(result.refusal).toBeUndefined();
    expect(result.replay?.policies["14d"].never_seen).toBe(1);
  });
});

describe("pickerApps", () => {
  // A stand-in index: what the picker does with replays does not depend on which ones ship.
  const index = [{ id: "wireshark", name: "Wireshark", bundleIds: ["org.wireshark.Wireshark"] }];

  it("lists the replays when there is no catalog to read", () => {
    expect(pickerApps([], index)).toEqual([{ key: "wireshark", name: "Wireshark", replayId: "wireshark" }]);
  });

  it("puts the replays first, folds a replay's own catalog titles into its row, and marks the rest as having none", () => {
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
