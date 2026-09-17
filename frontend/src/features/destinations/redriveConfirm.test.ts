/** The Redrive confirmation (#469): what it re-sends, and the deadline it is decided
 *  against. Frontend lane (#285) — the sentence is the decision, so it is pinned here. */

import { describe, expect, it } from "vitest";
import { de } from "@/i18n/de";
import { en } from "@/i18n/en";

describe("redriveConfirm", () => {
  it("names the count, the destination and the deadline", () => {
    const sentence = en.destinations.redriveConfirm(12, "Splunk", "16/10/2026");
    expect(sentence).toContain("Redrive 12 dead letters to Splunk.");
    expect(sentence).toContain("The oldest expires 16/10/2026 — after that a redrive cannot reach them.");
  });

  it("says it about one dead letter without saying oldest", () => {
    const sentence = en.destinations.redriveConfirm(1, "Splunk", "16/10/2026");
    expect(sentence).toContain("Redrive 1 dead letter to Splunk.");
    expect(sentence).toContain("It expires 16/10/2026 — after that a redrive cannot reach it.");
    expect(sentence).not.toContain("oldest");
  });

  it("says no deadline when there is none to say", () => {
    const sentence = en.destinations.redriveConfirm(2, "Splunk", null);
    expect(sentence).not.toMatch(/expires/);
    // What the confirmation was there for before the deadline joined it: a redrive re-sends
    // tenant data, and that warning is not what the deadline replaces.
    expect(sentence).toContain("will arrive again");
  });

  it("carries both in German", () => {
    expect(de.destinations.redriveConfirm(12, "Splunk", "16.10.2026")).toContain("verfällt am 16.10.2026");
    expect(de.destinations.redriveConfirm(2, "Splunk", null)).not.toMatch(/verfällt/);
  });
});
