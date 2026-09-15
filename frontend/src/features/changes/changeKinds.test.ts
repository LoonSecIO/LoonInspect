/** The Change filter's two vocabularies and the Changes page's empty table (#437). Frontend lane (#285). */

import { describe, expect, it } from "vitest";
import { changeResetLine, emptyTable, isFiltered, neverMatchesReason } from "@/features/changes/changeKinds";
import { CHANGE_KINDS, ENTRY_SECTIONS, SECTION_ORDER, canMatch, kindsRecordedBy, sectionShape } from "@/features/changes/render";
import type { ChangeFilters } from "@/features/changes/types";
import { de } from "@/i18n/de";
import { en } from "@/i18n/en";

const FIELD_SECTIONS = SECTION_ORDER.filter((name) => !(ENTRY_SECTIONS as readonly string[]).includes(name));
const UNFILTERED: ChangeFilters = { page: 1 };

describe("the list sections", () => {
  it("are the last seven of the section order, in its order", () => {
    // SECTION_ORDER is the eight scalar sections, then the seven list sections.
    expect([...ENTRY_SECTIONS]).toEqual(SECTION_ORDER.slice(8));
    expect(FIELD_SECTIONS).toEqual(SECTION_ORDER.slice(0, 8));
  });
});

describe("the change kinds a section records", () => {
  it.each(ENTRY_SECTIONS)("%s records added, removed and updated", (section) => {
    expect(sectionShape(section)).toBe("entry");
    expect(kindsRecordedBy(section)).toEqual(["added", "removed", "updated"]);
  });

  it.each(FIELD_SECTIONS)("%s records only changed", (section) => {
    expect(sectionShape(section)).toBe("field");
    expect(kindsRecordedBy(section)).toEqual(["changed"]);
  });

  it("with no section chosen, every kind", () => {
    for (const section of [undefined, null, ""]) {
      expect(sectionShape(section)).toBeNull();
      expect(kindsRecordedBy(section)).toEqual(CHANGE_KINDS);
    }
  });

  it("claims nothing about a section the page does not know", () => {
    // Only a hand-edited link carries one; the API matches it against no row.
    expect(sectionShape("applicatons")).toBeNull();
    expect(kindsRecordedBy("applicatons")).toEqual(CHANGE_KINDS);
  });

  it("between the two sides, every kind exactly once", () => {
    const kinds = [...kindsRecordedBy("applications"), ...kindsRecordedBy("hardware")];
    expect([...kinds].sort()).toEqual([...CHANGE_KINDS].sort());
  });
});

describe("canMatch", () => {
  it("refuses a pair from the wrong side", () => {
    expect(canMatch("applications", "changed")).toBe(false);
    expect(canMatch("hardware", "added")).toBe(false);
    expect(canMatch("definition", "updated")).toBe(false);
    expect(canMatch("certificates", "changed")).toBe(false);
  });

  it("allows a pair from the right side", () => {
    expect(canMatch("applications", "added")).toBe(true);
    expect(canMatch("software_updates", "updated")).toBe(true);
    expect(canMatch("hardware", "changed")).toBe(true);
  });

  it("allows anything with either one unset", () => {
    for (const kind of CHANGE_KINDS) expect(canMatch(undefined, kind)).toBe(true);
    for (const section of SECTION_ORDER) expect(canMatch(section, undefined)).toBe(true);
    expect(canMatch(undefined, undefined)).toBe(true);
  });

  it("allows anything with a section the page does not know", () => {
    for (const kind of CHANGE_KINDS) expect(canMatch("applicatons", kind)).toBe(true);
  });
});

describe("the line when choosing a section resets Change", () => {
  it("names the section and what it records, in English", () => {
    expect(changeResetLine("applications", en.changes)).toBe(
      "Change reset to Any change: Applications records Added, Removed and Updated."
    );
    expect(changeResetLine("hardware", en.changes)).toBe("Change reset to Any change: Hardware records only Changed values.");
  });

  it("and in German", () => {
    expect(changeResetLine("applications", de.changes)).toBe(
      "Änderung auf „Alle Änderungen“ zurückgesetzt: Der Abschnitt Anwendungen verzeichnet Hinzugefügt, Entfernt und Aktualisiert."
    );
    expect(changeResetLine("hardware", de.changes)).toBe(
      "Änderung auf „Alle Änderungen“ zurückgesetzt: Der Abschnitt Hardware verzeichnet nur geänderte Werte."
    );
  });

  it("has a line, with its label, for every section the dropdown offers", () => {
    for (const strings of [en.changes, de.changes]) {
      for (const section of SECTION_ORDER) {
        const line = changeResetLine(section, strings);
        expect(line).not.toBeNull();
        expect(line).toContain(strings.sections[section]);
      }
    }
  });

  it("says nothing for a section the page does not know", () => {
    expect(changeResetLine("applicatons", en.changes)).toBeNull();
  });
});

describe("the reason a pair can never match", () => {
  it("names both sides, in English", () => {
    expect(neverMatchesReason("applications", "changed", en.changes)).toBe(
      "Applications records Added, Removed and Updated — never Changed."
    );
    expect(neverMatchesReason("hardware", "added", en.changes)).toBe(
      "Hardware records only Changed values — never Added, Removed or Updated."
    );
  });

  it("and in German", () => {
    expect(neverMatchesReason("applications", "changed", de.changes)).toBe(
      "Der Abschnitt Anwendungen verzeichnet Hinzugefügt, Entfernt und Aktualisiert – nie Geändert."
    );
    expect(neverMatchesReason("hardware", "added", de.changes)).toBe(
      "Der Abschnitt Hardware verzeichnet nur geänderte Werte – nie Hinzugefügt, Entfernt oder Aktualisiert."
    );
  });

  it("uses the words the Change list and column show, all four of them", () => {
    // Both sentences name every kind — the ones recorded and the ones never — so a label
    // renamed in `changeKinds` and not here would put two words for one kind on a page.
    for (const strings of [en.changes, de.changes]) {
      for (const [section, change] of [
        ["applications", "changed"],
        ["hardware", "added"]
      ] as const) {
        const reason = (neverMatchesReason(section, change, strings) ?? "").toLowerCase();
        for (const kind of CHANGE_KINDS) expect(reason).toContain(strings.changeKinds[kind].toLowerCase());
      }
    }
  });

  it("is null for a pair that can match, or with either one unset", () => {
    expect(neverMatchesReason("applications", "added", en.changes)).toBeNull();
    expect(neverMatchesReason("hardware", "changed", en.changes)).toBeNull();
    expect(neverMatchesReason(undefined, "changed", en.changes)).toBeNull();
    expect(neverMatchesReason("applications", undefined, en.changes)).toBeNull();
    expect(neverMatchesReason("applicatons", "changed", en.changes)).toBeNull();
  });
});

describe("isFiltered", () => {
  it("is false for the bare feed, whatever the page", () => {
    expect(isFiltered(UNFILTERED)).toBe(false);
    expect(isFiltered({ page: 4 })).toBe(false);
    expect(isFiltered({ q: "", artifact: "" })).toBe(false);
  });

  it.each<[string, ChangeFilters]>([
    ["q", { q: "KY4QVD7430" }],
    ["artifact", { artifact: "Wiresharc" }],
    ["level", { level: "high" }],
    ["minLevel", { minLevel: "normal" }],
    ["change", { change: "added" }],
    ["section", { section: "applications" }],
    ["since", { since: "2026-09-01T00:00:00Z" }],
    ["connectionId", { connectionId: 1 }],
    ["subjectId", { subjectId: "42" }],
    ["subjectKind", { subjectKind: "computer" }]
  ])("is true with %s set", (_key, filters) => {
    expect(isFiltered(filters)).toBe(true);
  });
});

describe("what an empty table says", () => {
  it("'No changes yet' only for an unfiltered, empty log", () => {
    expect(emptyTable(UNFILTERED, 0, en.changes)).toEqual({ lead: en.changes.empty, reason: null });
    expect(emptyTable(UNFILTERED, 0, de.changes)).toEqual({ lead: de.changes.empty, reason: null });
  });

  it("'No changes match these filters.' for a filtered page — a mistyped name among them", () => {
    expect(emptyTable({ artifact: "Wiresharc" }, 0, en.changes)).toEqual({
      lead: "No changes match these filters.",
      reason: null
    });
    expect(emptyTable({ since: "2026-09-14T00:00:00Z" }, 0, de.changes)).toEqual({
      lead: "Keine Änderungen entsprechen diesen Filtern.",
      reason: null
    });
  });

  it("adds the reason for a pair that can never match", () => {
    // The issue's two demo pairs: Applications + Changed returned 0 of 195 rows, and
    // Hardware + Added 0 of 2, under "No changes yet".
    expect(emptyTable({ section: "applications", change: "changed" }, 0, en.changes)).toEqual({
      lead: "No changes match these filters.",
      reason: "Applications records Added, Removed and Updated — never Changed."
    });
    expect(emptyTable({ section: "hardware", change: "added" }, 0, en.changes)).toEqual({
      lead: "No changes match these filters.",
      reason: "Hardware records only Changed values — never Added, Removed or Updated."
    });
  });

  it("a page past the last one, where rows do match, is neither", () => {
    expect(emptyTable({ page: 9 }, 120, en.changes)).toEqual({ lead: en.changes.emptyPastEnd, reason: null });
    expect(emptyTable({ section: "applications", page: 9 }, 120, en.changes)).toEqual({
      lead: en.changes.emptyPastEnd,
      reason: null
    });
  });
});
