import { describe, expect, it } from "vitest";
import { sumFault, type Totals } from "@/features/compliance/api";
import { de } from "@/i18n/de";
import { en } from "@/i18n/en";

/** The four `backend/tests/test_evidence_report_db.py` refuses on the object (#219 R5 5.3). */
const FRAMEWORKS = ["cmmc", "800-171", "soc 2", "cyber essentials"];
const DAY = 86400;
const span = (seconds: number) => ({ seconds, days: seconds / DAY });
const totals = (met: number, unmet: number, notObserved: number, window: number): Totals =>
  ({ met: span(met), unmet: span(unmet), notObserved: span(notObserved), window: span(window) });

// The backend's rule, one layer up: the object names no framework, and neither does the page drawn over
// it. Every sentence the page prints that is not the object's own is in these blocks, so grepping them is
// grepping the page. Both locales, because a claim translated is still a claim.
describe("the page names no framework", () => {
  it.each([["en", en.compliance], ["de", de.compliance]])("%s", (_locale, block) => {
    // A key whose value is a function is a sentence too: call it, so its literal parts are searched.
    const said = JSON.stringify(block, (_key, value: unknown) =>
      typeof value === "function" ? String((value as (...args: never[]) => string)(1 as never, 2 as never)) : value
    ).toLowerCase();

    expect(FRAMEWORKS.filter((name) => said.includes(name))).toEqual([]);
  });
});

describe("sumFault", () => {
  it("closes on the exact seconds, is silent when it does, and names the mismatch when it does not", () => {
    expect(sumFault(totals(10 * DAY, 20 * DAY, 60 * DAY, 90 * DAY))).toBeNull();
    // A bucket that counted nothing is absent-not-zero, never a failed sum (docs/compliance-evidence.md §4).
    expect(sumFault({})).toBeNull();
    // One second out — the smallest disagreement the object can hold, and the one a page adding up the
    // printed days would round away. Both figures, so the reader can report them.
    expect(sumFault(totals(10 * DAY, 20 * DAY, 60 * DAY, 90 * DAY + 1))).toEqual({ sum: 90 * DAY, window: 90 * DAY + 1 });
    expect(en.compliance.sumFault(7776000, 7776001)).toContain("7776001");
  });
});
