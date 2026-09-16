import { describe, expect, it } from "vitest";
import type { PatchAnswer } from "@/features/catalog/patchAnswer";
import { describeUpdate } from "./appUpdate";
import type { AppUpdate, AppVulnerability } from "./types";

/** Wireshark 4.2.0 on the real record: two titles, so the answer has a subject to name
 *  (docs/jamf-patch-matching.md §7). The reference title 612 is the one that names 4.6.8. */
const WIRESHARK: PatchAnswer = {
  jamfTitleIds: ["612", "5F6"],
  jamfTitles: [
    { id: "612", name: "Wireshark" },
    { id: "5F6", name: "Wireshark 4.2" }
  ],
  patchState: "behind",
  patchAvailable: true,
  patchAvailableSince: "2024-01-03T18:00:00Z",
  releasesMissed: 14,
  latestVersion: "4.6.8",
  eaAssumed: false,
  referenceTitleId: "612",
  sentenceTitleId: "5F6"
};

/** 17 findings, the lab's own number for 4.2.0 (#428). */
const COVERED: AppVulnerability = {
  assessment: "covered",
  corpusAsOf: "2026-09-13",
  counts: { total: 17, kev: 0, severity: { critical: 0, high: 9, medium: 8, low: 0 } },
  daysOldestPublished: { total: 400, severity: { critical: null, high: 400, medium: 300, low: null } },
  vulnIDs: ["CVE-2024-1", "CVE-2024-2"],
  vulnIDsTruncated: false
};

const EXACT: AppUpdate = { version: "4.6.8", assessment: "covered", closes: 17, opens: 94, net: null };

describe("describeUpdate", () => {
  it("prints one line per named title, attributed to the title that names the release", () => {
    // The whole reason the line carries a subject: 4.6.8 is "Wireshark"'s latest, not
    // "Wireshark 4.2"'s (which is 4.2.14), and a difference floated between the two is
    // true of neither (#311/#313).
    const lines = describeUpdate(COVERED, EXACT, WIRESHARK);
    expect(lines).toHaveLength(1);
    expect(lines[0]).toEqual({
      version: "4.6.8",
      subject: { id: "612", name: "Wireshark" },
      unknown: false,
      closes: 17,
      opens: 94,
      net: null
    });
  });

  it("names no subject when one title matched — it is the subject, and the titles line says so", () => {
    const one: PatchAnswer = {
      ...WIRESHARK,
      jamfTitleIds: ["3A1"],
      jamfTitles: [{ id: "3A1", name: "Slack" }],
      latestVersion: "4.47.0",
      referenceTitleId: "3A1",
      sentenceTitleId: "3A1"
    };
    const lines = describeUpdate(COVERED, { ...EXACT, version: "4.47.0" }, one);
    expect(lines[0].subject).toBeNull();
  });

  it("names no subject for a release the patch answer no longer points at", () => {
    // The row was judged against 4.6.8; Jamf has since moved to 4.6.9. Naming 612 anyway
    // would attribute an answer about one release to a title now saying another.
    const lines = describeUpdate(COVERED, EXACT, { ...WIRESHARK, latestVersion: "4.6.9" });
    expect(lines[0].subject).toBeNull();
    expect(lines[0].version).toBe("4.6.8");
  });

  it("carries the capped pair as net and never as an exact count", () => {
    const lines = describeUpdate(COVERED, { version: "4.6.8", assessment: "covered", closes: null, opens: null, net: -77 }, WIRESHARK);
    expect(lines[0].net).toBe(-77);
    expect(lines[0].closes).toBeNull();
    expect(lines[0].opens).toBeNull();
  });

  it("marks a target the corpus holds no row for as unknown, with no numbers to read", () => {
    const lines = describeUpdate(COVERED, { version: "4.6.8", assessment: "unknown_app", closes: null, opens: null, net: null }, WIRESHARK);
    expect(lines[0].unknown).toBe(true);
    expect([lines[0].closes, lines[0].opens, lines[0].net]).toEqual([null, null, null]);
  });

  it("prints nothing at all on unknown_app and on off, whatever the row carries", () => {
    // §4g's three renderings do not collapse: neither state has counts, so there is
    // nothing for an update to close and no fourth state to invent.
    expect(describeUpdate({ assessment: "unknown_app", corpusAsOf: "2026-09-13" }, EXACT, WIRESHARK)).toEqual([]);
    expect(describeUpdate({ assessment: "off" }, EXACT, WIRESHARK)).toEqual([]);
  });

  it("prints nothing when the row carries no update at all", () => {
    expect(describeUpdate(COVERED, null, WIRESHARK)).toEqual([]);
  });
});
