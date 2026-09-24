import { describe, expect, it, vi, afterEach } from "vitest";
import { apiRequest } from "@/config/api";
import {
  changedValue,
  dotLabel,
  formatHistoryValue,
  loadHistoryPoint,
  saveHistorySlots,
  type HistoryPoint,
} from "./history";
import { historyEnglish as copy, historyGerman } from "./historyCopy";
vi.mock("@/config/api", () => ({ apiRequest: vi.fn() }));
afterEach(() => vi.clearAllMocks());
it("preserves unknown, zero and false and compares only comparable values", () => {
  const format = (state: string, value: unknown) =>
    formatHistoryValue({ state, value }, copy.states, copy.yes, copy.no);
  expect(format("present", 0)).toBe("0");
  expect(format("present", false)).toBe("Disabled");
  expect(format("not_recorded", null)).toBe("Not recorded");
  expect(
    changedValue(
      { state: "present", value: 0 },
      { state: "not_recorded", value: null },
    ),
  ).toBe(false);
  expect(
    changedValue(
      { state: "present", value: false },
      { state: "present", value: true },
    ),
  ).toBe(true);
});
it("keys reads and writes to the selected point, not a date guess", async () => {
  await loadHistoryPoint(7, "p:abc");
  await saveHistorySlots(7, "p:abc", ["security.firewallEnabled"]);
  expect(apiRequest).toHaveBeenCalledWith(
    "/devices/7/history/point?point=p%3Aabc",
  );
  expect(apiRequest).toHaveBeenCalledWith("/devices/7/history/preferences", {
    method: "PUT",
    json: { point: "p:abc", slots: ["security.firewallEnabled"] },
  });
});
describe("localized history states", () => {
  it("covers every state in both languages", () => {
    expect(Object.keys(historyGerman.states)).toEqual(Object.keys(copy.states));
    expect(Object.keys(historyGerman.summaries)).toEqual(
      Object.keys(copy.summaries),
    );
    expect(historyGerman.personal).toContain("Mandanten");
  });
  it("points the paging controls the way the timeline reads (#618)", () => {
    // Oldest on the left, newest on the right: Older pages left, Newer pages right.
    for (const c of [copy, historyGerman]) {
      expect(c.older.startsWith("←")).toBe(true);
      expect(c.newer.endsWith("→")).toBe(true);
    }
  });
});
describe("timeline dot labels (#645)", () => {
  it("dates every dot by when the state was recorded, so the line never runs backwards", () => {
    // Device 1 on the demo pod, 2026-09-24: five states share one report time and two assessment
    // points sit between them; labelled by the report time the newest dot read "Sep 18" to the
    // right of "Sep 23". Noon UTC keeps the calendar day the same in any test zone.
    const observed = "2026-09-18T12:00:00Z";
    const newestFirst: HistoryPoint[] = [
      { id: "p:1", kind: "inventory", observedAt: observed, collectedAt: "2026-09-24T12:00:00Z" },
      { id: "p:2", kind: "assessment", observedAt: observed, collectedAt: "2026-09-23T12:00:00Z" },
      { id: "p:3", kind: "assessment", observedAt: observed, collectedAt: "2026-09-21T12:00:00Z" },
      { id: "p:4", kind: "inventory", observedAt: observed, collectedAt: "2026-09-21T12:00:00Z" },
      { id: "p:5", kind: "inventory", observedAt: observed, collectedAt: "2026-09-19T12:00:00Z" },
      { id: "p:6", observedAt: "2026-09-11T12:00:00Z", collectedAt: "2026-09-14T12:00:00Z" },
    ];
    const leftToRight = [...newestFirst].reverse().map((p) => dotLabel(p, "en-US"));
    expect(leftToRight).toEqual(["Sep 14", "Sep 19", "Sep 21", "Sep 21", "Sep 23", "Sep 24"]);
    // The label reads one clock only: an inventory point is not dated by its report time.
    expect(dotLabel({ collectedAt: "2026-09-24T12:00:00Z" }, "en-US")).toBe("Sep 24");
  });
});
