/** A sentence's ISO dates kept whole (#614): a browser breaks "2026-09-01" at a hyphen wherever
 *  a line runs out, so each date is a span that does not wrap, and the rest is the sentence as it was.
 *  Node lane: rendered to markup. */

import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { KeepDates } from "@/features/patchPolicy/KeepDates";

const drawn = (text: string) => renderToStaticMarkup(<KeepDates text={text} />);

describe("KeepDates", () => {
  it("makes each ISO date a span that does not wrap, and leaves the rest as it was", () => {
    expect(drawn("4.4.3, dated 2025-01-09")).toBe('4.4.3, dated <span class="whitespace-nowrap">2025-01-09</span>');
    expect(drawn("2024-11-23 → 2026-11-17 · asked for 2 years, 2024-11-23 → 2026-11-23")).toBe(
      '<span class="whitespace-nowrap">2024-11-23</span> → <span class="whitespace-nowrap">2026-11-17</span> · asked for 2 years, ' +
        '<span class="whitespace-nowrap">2024-11-23</span> → <span class="whitespace-nowrap">2026-11-23</span>'
    );
    expect(drawn("135.0.7049.41: bis 135.0.7049.42 am 2025-04-02.")).toBe('135.0.7049.41: bis 135.0.7049.42 am <span class="whitespace-nowrap">2025-04-02</span>.');
  });

  it("leaves a sentence with no date, a version or a partial date as plain text", () => {
    expect(drawn("Never seen: the fix was installed first")).toBe("Never seen: the fix was installed first");
    expect(drawn("135.0.7049.52 and 2025-04")).toBe("135.0.7049.52 and 2025-04");
    expect(drawn("")).toBe("");
  });
});
