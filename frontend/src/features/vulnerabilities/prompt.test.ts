/**
 * The Vulnerabilities AI lever's wire and its one move on the page (#534). Frontend lane (#285):
 * node only, pure modules, the ones that encode rulings.
 *
 * The first two describes are for defects the first cut shipped, and both are one mistake — a
 * fact the page already held, re-derived rather than asked for. Each module says which.
 */

import { describe, expect, it } from "vitest";
import { bannerKind } from "@/features/changes/prompt";
import { payoffList } from "@/features/vulnerabilities/pageBands";
import {
  LEVER_BANDS,
  LEVER_ORDERS,
  LEVER_STATES,
  filtersOnArrival,
  isVulnPromptResult,
  leverOrder,
  leverParams,
  leverReadback,
  stillShows,
  type LeverShown,
  type VulnPromptFilters,
  type VulnPromptResult
} from "@/features/vulnerabilities/prompt";
import { en } from "@/i18n/en";

const FILTERS: VulnPromptFilters = { q: null, vuln: "findings", band: null, order: "exposure" };

const result = (over: Partial<VulnPromptResult> = {}): VulnPromptResult => ({
  outcome: "applied",
  filters: { ...FILTERS },
  unsupported: null,
  repairs: [],
  widening: [],
  summary: { total: 3 },
  provider: "apple_fm",
  model: "system",
  destination: "127.0.0.1:1976",
  latencyMs: 12,
  error: null,
  ...over
});

describe("the banner an answer is headed with", () => {
  it("names the invalid state, which always arrives with no filters", () => {
    // The route answers every refusal `filters: null` (`_answer("invalid", …)`), so a chain
    // that asks about the filters first can never reach this state.
    const invalid = result({ outcome: "invalid", filters: null, summary: null });
    expect(bannerKind(invalid)).toBe("invalid");
    expect(bannerKind(invalid, true)).toBe("invalid");
  });

  it("keeps the other states apart", () => {
    expect(bannerKind(result({ outcome: "error", filters: null, summary: null }))).toBe("error");
    expect(bannerKind(result({ outcome: "unparseable", filters: null, summary: null }))).toBe("unparseable");
    expect(bannerKind(result({ filters: null }))).toBe("unparseable");
    expect(bannerKind(result({ outcome: "proposed", widening: ["wider"] }))).toBe("proposal");
    expect(bannerKind(result({ outcome: "proposed", widening: ["wider"] }), true)).toBe("readback");
    expect(bannerKind(result())).toBe("readback");
  });

  it("says the lever's own name, on a page that has no Prompt bar", () => {
    expect(en.changes.prompt.invalid(en.vulnerabilities.aiLeverName)).toContain("the AI lever");
  });
});

describe("the order an answer is judged by", () => {
  it("is the page's own, so Easily patchable is always payoff", () => {
    // `payoffList` reads the FILTER alone, so the page shows this list ranked by payoff
    // whatever the answer names; judged by the raw order, an applied answer would read as
    // stale at once and the card — readback, count, caveat — would never be drawn.
    for (const order of LEVER_ORDERS) {
      expect(leverOrder({ ...FILTERS, vuln: "patchable", order })).toBe("payoff");
    }
    expect(payoffList("patchable")).toBe(true);
  });

  it("is the answer's own everywhere else", () => {
    expect(leverOrder({ ...FILTERS, vuln: "findings", order: "age" })).toBe("age");
    expect(leverOrder({ ...FILTERS, vuln: "kev", order: "exposure" })).toBe("exposure");
  });
});

describe("whether an applied answer still describes the page", () => {
  const SHOWN: LeverShown = { vuln: "findings", band: null, jamf: null, order: "exposure" };

  it("watches all three filter dimensions, so no chip moves the list behind the count", () => {
    expect(stillShows(FILTERS, SHOWN)).toBe(true);
    // The defect: `jamf` is not in the lever's vocabulary, so `leverParams` writes none and an
    // applied answer is that chip OFF. Unwatched, *No Jamf fix path* narrowed the list without
    // changing anything compared, and the Postgres count outlived the list it had described.
    expect(stillShows(FILTERS, { ...SHOWN, jamf: "unmatched" })).toBe(false);
    expect([stillShows(FILTERS, { ...SHOWN, vuln: "kev" }), stillShows(FILTERS, { ...SHOWN, band: "critical" }), stillShows(FILTERS, { ...SHOWN, order: "age" })])
      .toEqual([false, false, false]);
  });

  it("judges the order the page will rank by, not the one the answer wrote", () => {
    const patchable: VulnPromptFilters = { ...FILTERS, vuln: "patchable", order: "exposure" };
    expect(stillShows(patchable, { vuln: "patchable", band: null, jamf: null, order: "payoff" })).toBe(true);
  });
});

describe("what the page does with an answer", () => {
  it("runs an applied one and nothing else", () => {
    expect(filtersOnArrival(result())).toEqual(FILTERS);
    expect(filtersOnArrival(result({ outcome: "proposed", widening: ["wider"] }))).toBeNull();
    expect(filtersOnArrival(result({ outcome: "invalid", filters: null }))).toBeNull();
  });

  it("reads the filters back in the page's own words, never the model's", () => {
    const words = leverReadback({ q: "Zoom", vuln: "patchable", band: "high", order: "payoff" }, en.vulnerabilities);
    expect(words).toBe(
      [en.vulnerabilities.filterPatchable, en.vulnerabilities.bandHigh, en.vulnerabilities.aiForApp("Zoom"), en.vulnerabilities.easilyPatchable].join(" · ")
    );
  });

  it("writes one whole URL, with the search and the age order left off it", () => {
    expect(leverParams({ q: "Zoom", vuln: "patchable", band: null, order: "payoff" }).toString()).toBe("vuln=patchable&order=payoff");
    expect(leverParams({ q: null, vuln: "findings", band: "critical", order: "age" }).toString()).toBe("vuln=findings&band=critical");
  });
});

describe("a body that is not this answer is refused before anything reads it", () => {
  it("takes the shape the route promises", () => {
    expect(isVulnPromptResult(result())).toBe(true);
    expect(isVulnPromptResult(result({ outcome: "invalid", filters: null, summary: null }))).toBe(true);
  });

  it("refuses a value outside this page's vocabulary rather than rendering an unknown chip", () => {
    expect(isVulnPromptResult(null)).toBe(false);
    expect(isVulnPromptResult({ ...result(), outcome: "fine" })).toBe(false);
    expect(isVulnPromptResult({ ...result(), filters: { ...FILTERS, vuln: "all" } })).toBe(false);
    expect(isVulnPromptResult({ ...result(), filters: { ...FILTERS, order: "name" } })).toBe(false);
    expect(isVulnPromptResult({ ...result(), summary: { total: "3" } })).toBe(false);
  });

  it("holds the page's four filter keys and no fifth", () => {
    // The vocabulary is the page's; the backend pins the same three tuples to `GET /api/catalog`.
    expect([...LEVER_STATES]).toEqual(["findings", "kev", "unknown_app", "clean", "patchable"]);
    expect([...LEVER_BANDS]).toEqual(["critical", "high", "medium", "low"]);
    expect([...LEVER_ORDERS]).toEqual(["exposure", "age", "payoff"]);
    expect(Object.keys(FILTERS)).toEqual(["q", "vuln", "band", "order"]);
  });
});
