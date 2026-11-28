/** The replay file's check (#614, first slice; schema 3, #953): what the page reads, and what it
 *  refuses whole. Every shipped replay is read here through the same function the page uses, so what
 *  the page does with it is what this lane says, and its own facts are pinned, so a replaced file
 *  changes them in a reviewed diff. The rules themselves are pinned on hand-made schema-3 files
 *  (`testing/replayFixtures.ts`), plainly synthetic: their numbers are invented and describe no app.
 *
 *  The four files that ship today are LoonVD's schema-2 output, on the old count (an N-day row is
 *  N - 1 days waited), so the page refuses each in words. LoonVD-Internal#151 writes them again on
 *  the new count, as schema 3 with each day row's delay stated; when those files replace these, the
 *  tests below that say "refused as the old count" flip to "reads clean", and their pins move. */

import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { pickerApps } from "@/features/patchPolicy/apps";
import { patchPolicyEnglish, patchPolicyGerman } from "@/features/patchPolicy/copy";
import { POLICY_DEFINITION_IDS } from "@/features/patchPolicy/definitions";
import {
  DAY_STOPS,
  REPLAY_OLD_COUNT_SCHEMA,
  REPLAY_SCHEMA,
  SLIDER_STOPS,
  SUPERSEDED_POLICY,
  affectedBounds,
  heldFixes,
  isSliderStop,
  readReplay,
  replayedRows,
  stopDays,
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

describe("the hand-made schema-3 replays", () => {
  const held = read(heldLineReplay());
  const single = read(singleLineReplay());

  it("read clean, with the counts the page prints", () => {
    expect([REPLAY_SCHEMA, REPLAY_OLD_COUNT_SCHEMA]).toEqual([3, 2]);
    expect(readReplay(heldLineReplay()).refusal).toBeUndefined();
    expect(readReplay(singleLineReplay()).refusal).toBeUndefined();
    expect(held.counts).toMatchObject({ cves_in_window: 5, cves_replayed: 4, cves_excluded: 1 });
    expect(single.counts).toMatchObject({ cves_in_window: 3, cves_replayed: 2, cves_excluded: 1 });
    // Derived by hand in `testing/replayFixtures.ts` from the release dates, on the days-waited rule.
    expect(SLIDER_STOPS.map((stop) => held.policies[stop].never_seen)).toEqual([3, 3, 2, 2, 1, 1, 1, 1]);
    expect(SLIDER_STOPS.map((stop) => held.policies[stop].exposure_days)).toEqual([1, 2, 6, 14, 35, 83, 173, 2031]);
    expect(SLIDER_STOPS.map((stop) => single.policies[stop].exposure_days)).toEqual([1, 3, 7, 15, 29, 61, 121, 1372]);
  });

  it("take the eight stops, and each day row waits the days its label says", () => {
    expect(SLIDER_STOPS).toEqual(["0d", "1d", "3d", "7d", "14d", "30d", "60d", "never"]);
    expect(DAY_STOPS.map(stopDays)).toEqual([0, 1, 3, 7, 14, 30, 60]);
    for (const replay of [held, single]) {
      expect(DAY_STOPS.map((stop) => replay.policies[stop].install_delay_days)).toEqual([0, 1, 3, 7, 14, 30, 60]);
    }
    // A CVE published the day its fix is dated is exposed under each stop for exactly the days it waits.
    const sameDay = replayedRows(single).find((row) => row.cve_id === "CVE-2099-1001")!;
    expect(DAY_STOPS.map((stop) => sameDay.outcomes?.[stop]?.exposure_days ?? 0)).toEqual([0, 1, 3, 7, 14, 30, 60]);
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

  it("the superseded policy is in the file and is not a stop", () => {
    expect(held.policies[SUPERSEDED_POLICY]).toBeDefined();
    expect(SLIDER_STOPS).not.toContain(SUPERSEDED_POLICY);
    expect(isSliderStop(SUPERSEDED_POLICY)).toBe(false);
    expect(isSliderStop("14d")).toBe(true);
    // A saved address keeps resolving: ?policy=7d is the 7-day stop, now seven days waited.
    expect(isSliderStop("7d")).toBe(true);
    expect(isSliderStop("0d") && isSliderStop("3d")).toBe(true);
    expect(isSliderStop("2d")).toBe(false);
    expect(isSliderStop(null)).toBe(false);
  });
});

/** A shipped file as it stands, before the page's check: what is pinned of a file the page refuses. */
const raw = async (entry: (typeof REPLAY_INDEX)[number]) => (await entry.load()) as Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

describe("every indexed replay", () => {
  // What is true until LoonVD-Internal#151's files land in replays/: each shipped file is schema 2,
  // on the old count, and refused whole in the page's words, so the fallback says why rather than
  // drawing numbers a day early. Those files replace these, and flip this test to "reads clean".
  it("is refused whole as the old count, in words, and its own definition says it counts that way", async () => {
    for (const entry of REPLAY_INDEX) {
      const file = await raw(entry);
      expect(file.schema, entry.file).toBe(REPLAY_OLD_COUNT_SCHEMA);
      expect(file.definitions.install, entry.file).toContain("the install date is the release date + (D - 1) days");
      expect(Object.keys(file.policies).sort(), entry.file).toEqual(["14d", "1d", "30d", "60d", "7d", "critical_or_kev", "never"]);
      expect(await loadReplay(entry), entry.file).toEqual({ refusal: { why: "old_count" } });
    }
    expect(patchPolicyEnglish.refused({ why: "old_count" })).toBe(
      "Its schema is 2, the replay that counts the old way: its N-day row is N − 1 days waited, so it cannot be drawn under this page's stops, whose labels are the days waited. This page reads schema 3 only."
    );
  });

  it("is indexed under the one bundle ID its own file replays", async () => {
    for (const entry of REPLAY_INDEX) {
      const product = (await raw(entry)).product as { bundle_ids?: string[]; device_bundle_id?: string } | undefined;
      for (const bundleId of entry.bundleIds) expect(product?.bundle_ids, entry.id).toContain(bundleId);
      // Not a beta, canary or developer edition the file also names: those are other channels.
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
      const file = await raw(entry);
      for (const reason of Object.keys(file.exclusions.by_reason)) {
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

/** What each shipped file says, as it says it, read before the page's check (the page draws none of
 *  it while the file counts the old way). A replaced file fails here until these are updated in the
 *  same change, so a reviewer sees every one that moved; LoonVD-Internal#151's files add the headline
 *  at each of the eight stops back, from their own rows. */
const SHIPPED: Record<string, {
  source: string;
  window: [string, string];
  counts: [inWindow: number, replayed: number, excluded: number];
  held: string | null;
  device: string;
  cut: string[];
}> = {
  wireshark: {
    source: "wireshark",
    window: ["2024-11-23", "2026-11-23"],
    counts: [155, 115, 40],
    held: "4.4",
    device: "take",
    cut: []
  },
  firefox: {
    source: "firefox-release",
    window: ["2024-11-23", "2026-11-23"],
    counts: [1121, 718, 403],
    held: null,
    device: "take",
    cut: []
  },
  chrome: {
    // Cut short: the timeline dates a major the promotion table had no row for the day after.
    source: "chrome-stable",
    window: ["2024-11-23", "2026-11-17"],
    counts: [4382, 3415, 967],
    held: null,
    device: "skip",
    cut: ["promotion_table"]
  },
  thunderbird: {
    source: "thunderbird-release",
    window: ["2024-11-23", "2026-11-23"],
    counts: [1011, 601, 410],
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
    it(`${entry.name}: the window, counts, held line and waiting device the file states`, async () => {
      const expected = SHIPPED[entry.id];
      const file = await raw(entry);
      expect(file.timeline.source).toBe(expected.source);
      expect([file.window.since, file.window.until]).toEqual(expected.window);
      const { cves_in_window: inWindow, cves_replayed: replayed, cves_excluded: excluded } = file.counts;
      expect([inWindow, replayed, excluded]).toEqual(expected.counts);
      expect(file.branch_choice.held_at_branch).toBe(expected.held);
      expect(file.early_stable_choice?.device).toBe(expected.device);
      expect((file.window.shortened_by ?? []).map((cut: { reason: string }) => cut.reason)).toEqual(expected.cut);
    });
  }

  it("Chrome's window ends where its file cut it, and says why in its own words", async () => {
    // Read from the file as it stands: `windowCut` reads only its window.
    const chrome = REPLAY_INDEX.find((entry) => entry.id === "chrome")!;
    const cut = windowCut((await raw(chrome)) as PatchPolicyReplay);
    expect(cut?.requested).toBe("2026-11-23");
    expect(cut?.reasons).toHaveLength(1);
    expect(cut?.reasons[0]).toMatch(/^The timeline dates 159\.0\.8154\.13 on 2026-11-18, and the promotion table's newest row is major 158/);
    for (const entry of REPLAY_INDEX.filter((each) => each.id !== "chrome")) {
      expect(windowCut((await raw(entry)) as PatchPolicyReplay), entry.id).toBeNull();
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
      "Its schema is 1, the earlier replay format, which has no timeline block, the part of the file this page reads to name and link where its release dates come from. This page reads schema 3 only."
    );
    expect(patchPolicyGerman.refused(refusal!)).toBe(
      "Ihr schema ist 1, das frühere Replay-Format ohne timeline-Block, den Teil der Datei, aus dem diese Seite die Quelle ihrer Release-Daten benennt und verlinkt. Diese Seite liest nur schema 3."
    );
  });

  it("schema 2, the old count, whole and in words that say why, whatever else the file holds", () => {
    // The same file as a schema-3 one, every row present and every total closing: refused all the
    // same, before anything else is read, because its N-day row is N - 1 days waited.
    const refusal = readReplay(edited((file) => { file.schema = 2; })).refusal;
    expect(refusal).toEqual({ why: "old_count" });
    expect(readReplay(edited((file) => { file.schema = 2; delete file.policies["0d"]; delete file.timeline; })).refusal).toEqual({ why: "old_count" });
    expect(patchPolicyEnglish.refused(refusal!)).toBe(
      "Its schema is 2, the replay that counts the old way: its N-day row is N − 1 days waited, so it cannot be drawn under this page's stops, whose labels are the days waited. This page reads schema 3 only."
    );
    expect(patchPolicyGerman.refused(refusal!)).toBe(
      "Ihr schema ist 2, das Replay, das nach der alten Regel zählt: Seine N-Tage-Zeile entspricht N − 1 gewarteten Tagen; es lässt sich daher nicht unter den Stufen dieser Seite darstellen, deren Beschriftung die gewarteten Tage nennt. Diese Seite liest nur schema 3."
    );
  });

  it("a day row that does not state the days it waits, or states other days than its label", () => {
    expect(readReplay(edited((file) => { delete file.policies["7d"].install_delay_days; })).refusal).toEqual({ why: "delay", stop: "7d", found: "absent" });
    // Six days waited under the 7-day label is the old count's row, in a schema-3 file.
    const six = readReplay(edited((file) => { file.policies["7d"].install_delay_days = 6; })).refusal;
    expect(six).toEqual({ why: "delay", stop: "7d", found: "6" });
    expect(readReplay(edited((file) => { file.policies["3d"].install_delay_days = "3"; })).refusal).toEqual({ why: "delay", stop: "3d", found: '"3"' });
    expect(readReplay(edited((file) => { file.policies["0d"].install_delay_days = null; })).refusal).toEqual({ why: "delay", stop: "0d", found: "null" });
    // Never waits for nothing, so its row is not asked for a delay.
    expect(readReplay(edited((file) => { delete file.policies.never.install_delay_days; })).refusal).toBeUndefined();
    expect(patchPolicyEnglish.refused(six!)).toBe(
      "Its 7d row states install_delay_days 6, but its label means 7 days waited after a release's date, so it is not drawn under that label."
    );
    expect(patchPolicyGerman.refused(six!)).toBe(
      "Ihre Zeile 7d nennt install_delay_days 6, ihre Beschriftung meint aber 7 gewartete Tage nach dem Datum eines Release; sie wird daher nicht unter dieser Beschriftung dargestellt."
    );
    expect(patchPolicyEnglish.refused({ why: "delay", stop: "1d", found: "0" })).toContain("its label means 1 day waited");
    expect(patchPolicyGerman.refused({ why: "delay", stop: "1d", found: "0" })).toContain("meint aber 1 gewarteten Tag nach");
    expect(patchPolicyEnglish.refused({ why: "delay", stop: "7d", found: "absent" })).toBe(
      "Its 7d row does not state the days it waits after a release's date (install_delay_days), so this page cannot tell whether it counts the days waited, which its label means."
    );
    expect(patchPolicyGerman.refused({ why: "delay", stop: "7d", found: "absent" })).toBe(
      "Ihre Zeile 7d nennt nicht die Tage, die sie nach dem Datum eines Release wartet (install_delay_days); diese Seite kann daher nicht erkennen, ob sie die gewarteten Tage zählt, die ihre Beschriftung meint."
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
    expect(readReplay(edited((file) => { file.schema = 4; }))).toEqual({ refusal: { why: "schema", found: "4" } });
    expect(readReplay(edited((file) => { file.schema = "3"; }))).toEqual({ refusal: { why: "schema", found: '"3"' } });
    expect(readReplay(edited((file) => { file.schema = "2"; }))).toEqual({ refusal: { why: "schema", found: '"2"' } });
    expect(patchPolicyEnglish.refused({ why: "schema", found: "4" })).toBe("Its schema is 4, and this page reads schema 3 only.");
  });

  it("a file that lacks something the page draws, by its dotted name", () => {
    expect(readReplay(edited((file) => { delete file.policies["30d"]; }))).toEqual({ refusal: { why: "missing", key: "policies.30d" } });
    // A schema-3 file carries every one of the eight stops, the two the six-stop slider lacked included.
    expect(readReplay(edited((file) => { delete file.policies["3d"]; }))).toEqual({ refusal: { why: "missing", key: "policies.3d" } });
    expect(readReplay(edited((file) => { delete file.policies["0d"]; }))).toEqual({ refusal: { why: "missing", key: "policies.0d" } });
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
    // The schema-1 evidence is not asked for: a schema-3 file reads clean without it.
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

  it("the superseded policy too, though none of it is drawn", () => {
    const result = readReplay(edited((file) => { file.policies[SUPERSEDED_POLICY].never_seen = 2; }));
    expect(result.refusal).toEqual({ why: "totals", detail: "policies.critical_or_kev: never_seen 2 + exposed 3 ≠ counts.cves_replayed 4" });
  });

  it("a row keyed by a built-in definition's id too, though none of it is drawn", () => {
    const row = { ...(heldLineReplay().policies as Record<string, object>)["30d"], never_seen: 3 };
    const result = readReplay(edited((file) => { file.policies["kev-only"] = { ...row, install_delay_days: null }; }));
    expect(result.refusal).toEqual({ why: "totals", detail: "policies.kev-only: never_seen 3 + exposed 3 ≠ counts.cves_replayed 4" });
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

  it("whether a schema-3 file carries the superseded row, does not, or carries rows on the ruled definitions instead (ruled 2026-11-28)", () => {
    const withIt = readReplay(heldLineReplay());
    expect(withIt.replay?.policies[SUPERSEDED_POLICY]).toBeDefined();
    const without = readReplay(edited((file) => { delete file.policies[SUPERSEDED_POLICY]; delete file.definitions[SUPERSEDED_POLICY]; }));
    expect(without.refusal).toBeUndefined();
    // LoonSec's rewrite replaces the row with rows on the ruled definitions: they read, and their totals close.
    const rewritten = readReplay(edited((file) => {
      delete file.policies[SUPERSEDED_POLICY];
      for (const id of POLICY_DEFINITION_IDS) {
        file.policies[id] = { ...file.policies.never, install_delay_days: null };
        file.definitions[id] = `${id}, as the file defines it (fixture).`;
        for (const row of file.ledger) if (row.outcomes) row.outcomes[id] = row.outcomes.never;
      }
    }));
    expect(rewritten.refusal).toBeUndefined();
    expect(Object.keys(rewritten.replay!.policies)).toEqual([...SLIDER_STOPS, ...POLICY_DEFINITION_IDS]);
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
