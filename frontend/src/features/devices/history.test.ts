import { describe, expect, it, vi, afterEach } from "vitest";
import { apiRequest } from "@/config/api";
import {
  changedValue,
  formatHistoryValue,
  loadHistoryPoint,
  saveHistorySlots,
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
