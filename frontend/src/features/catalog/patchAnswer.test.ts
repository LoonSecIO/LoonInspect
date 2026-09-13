import { describe, expect, it } from "vitest";
import { describePatchAnswer, namedTitles, type PatchAnswer } from "./patchAnswer";

/** Wireshark 4.2.0 on the real record: two titles, two subjects (docs/jamf-patch-matching.md §7). */
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

describe("describePatchAnswer", () => {
  it("names the subject of each half on a multi-title app, and they differ", () => {
    const described = describePatchAnswer(WIRESHARK);
    expect(described?.sentence).toEqual({ since: "2024-01-03T18:00:00Z", missed: 14, subject: { id: "5F6", name: "Wireshark 4.2" } });
    expect(described?.latest).toEqual({ version: "4.6.8", subject: { id: "612", name: "Wireshark" } });
    expect(described?.titles.map((title) => title.name)).toEqual(["Wireshark", "Wireshark 4.2"]);
  });

  it("names no subject when one title matched, even though the row stores the ids", () => {
    // REST carries the subject columns as stored; with one title there is nothing to
    // disambiguate and the titles line already names it (the wire's rule, #311).
    const slack: PatchAnswer = {
      ...WIRESHARK,
      jamfTitleIds: ["3A1"],
      jamfTitles: [{ id: "3A1", name: "Slack" }],
      latestVersion: "4.47.0",
      releasesMissed: 3,
      referenceTitleId: "3A1",
      sentenceTitleId: "3A1"
    };
    const described = describePatchAnswer(slack);
    expect(described?.sentence?.subject).toBeNull();
    expect(described?.latest?.subject).toBeNull();
  });

  it("carries no sentence on latest or ahead: two states that are not a problem", () => {
    const ahead = describePatchAnswer({ ...WIRESHARK, patchState: "ahead", patchAvailable: false, patchAvailableSince: null, releasesMissed: 0 });
    expect(ahead?.state).toBe("ahead");
    expect(ahead?.sentence).toBeNull();
    expect(ahead?.latest?.version).toBe("4.6.8");
    const latest = describePatchAnswer({ ...WIRESHARK, patchState: "latest", patchAvailable: false, patchAvailableSince: null, releasesMissed: 0 });
    expect(latest?.sentence).toBeNull();
  });

  it("keeps unknown its own state and still carries the sentence when a patch is available", () => {
    // A build Jamf never listed, with listed versions newer than it: a different finding
    // from behind, and the pre-#65 booleans could not tell the two apart.
    const unknown = describePatchAnswer({ ...WIRESHARK, patchState: "unknown" });
    expect(unknown?.state).toBe("unknown");
    expect(unknown?.sentence?.missed).toBe(14);
  });

  it("shows the assumption only when the row says so, never on a row that says nothing", () => {
    expect(describePatchAnswer({ ...WIRESHARK, eaAssumed: true })?.assumed).toBe(true);
    expect(describePatchAnswer({ ...WIRESHARK, eaAssumed: false })?.assumed).toBe(false);
    // Judged before the column existed: not "not assumed", just unknown — no marker.
    expect(describePatchAnswer({ ...WIRESHARK, eaAssumed: null })?.assumed).toBe(false);
  });

  it("renders a row judged before #311 without subjects rather than not at all", () => {
    const old = describePatchAnswer({ ...WIRESHARK, referenceTitleId: null, sentenceTitleId: null });
    expect(old?.sentence?.subject).toBeNull();
    expect(old?.latest?.subject).toBeNull();
    expect(old?.titles).toHaveLength(2);
  });

  it("is null when no title matched, which is a different fact from a dash", () => {
    expect(
      describePatchAnswer({
        ...WIRESHARK,
        jamfTitleIds: null,
        jamfTitles: [],
        patchState: null,
        patchAvailable: null,
        patchAvailableSince: null,
        releasesMissed: null,
        latestVersion: null,
        eaAssumed: null,
        referenceTitleId: null,
        sentenceTitleId: null
      })
    ).toBeNull();
  });
});

describe("namedTitles", () => {
  it("keeps the stored order and stands the id in where the catalog could not name a title", () => {
    // A title the catalog holds no name for: the named list the server sends is shorter,
    // the id list is whole, and the page prints two titles.
    const lines = namedTitles({ jamfTitleIds: ["612", "5F6"], jamfTitles: [{ id: "5F6", name: "Wireshark 4.2" }] });
    expect(lines).toEqual([
      { id: "612", name: null },
      { id: "5F6", name: "Wireshark 4.2" }
    ]);
    // And the subject of the sentence is still found, by id, on the line that has no name.
    const described = describePatchAnswer({ ...WIRESHARK, jamfTitles: [{ id: "5F6", name: "Wireshark 4.2" }] });
    expect(described?.latest?.subject).toEqual({ id: "612", name: null });
  });
});
