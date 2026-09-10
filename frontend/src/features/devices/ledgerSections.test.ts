import { describe, expect, it } from "vitest";
import { LEDGER_SECTIONS, SECTIONS_ON_DEVICE_PAGE, collectedNotOnPage } from "@/features/devices/ledgerSections";

describe("collectedNotOnPage", () => {
  it("is the registry minus the sections the page renders, in registry order", () => {
    const listed = collectedNotOnPage();
    expect(listed).toHaveLength(LEDGER_SECTIONS.length - SECTIONS_ON_DEVICE_PAGE.length);
    for (const section of SECTIONS_ON_DEVICE_PAGE) expect(listed).not.toContain(section);
    // Registry order, not alphabetical: the footer and the Splunk event enumerate alike.
    const positions = listed.map((section) => LEDGER_SECTIONS.indexOf(section));
    expect(positions).toEqual([...positions].sort((a, b) => a - b));
  });

  it("is empty since the observation block renders every registry section (#368)", () => {
    expect(SECTIONS_ON_DEVICE_PAGE).toEqual(LEDGER_SECTIONS);
    expect(collectedNotOnPage()).toEqual([]);
  });
});
