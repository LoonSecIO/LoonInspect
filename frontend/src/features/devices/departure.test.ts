import { describe, expect, it } from "vitest";
import { DEPARTURE_TAIL_DAYS, departureState, includeDepartedFrom, leavesTheFleetAt } from "@/features/devices/departure";

const NOW = new Date("2026-09-16T12:00:00Z");
const daysBefore = (days: number) => new Date(NOW.getTime() - days * 86_400_000).toISOString();

describe("the tail, as the chip and the toggle read it", () => {
  // Seven days exactly is `left` (the backend's `departed_at <= now - 7 days` has let go); an instant
  // the browser cannot parse is departed — the row's own column — but never *left*, which needs a date.
  it.each([
    [null, "present"],
    [daysBefore(0), "in_tail"],
    [daysBefore(DEPARTURE_TAIL_DAYS - 1), "in_tail"],
    [daysBefore(DEPARTURE_TAIL_DAYS), "left"],
    ["not an instant", "in_tail"]
  ])("reads %s as %s", (departedAt, state) => {
    expect(departureState(departedAt, NOW)).toBe(state);
  });

  it("counts the tail in elapsed time as `left_the_fleet` does, and writes no date it cannot read", () => {
    expect(leavesTheFleetAt("2026-08-28T09:30:00Z").toISOString()).toBe("2026-09-04T09:30:00.000Z");
    // The second crosses a DST change, which local calendar arithmetic lands an hour off; the third
    // is why the device page skips its sentence rather than rendering "Invalid Date".
    expect(leavesTheFleetAt("2026-10-30T12:00:00Z").toISOString()).toBe("2026-11-06T12:00:00.000Z");
    expect(Number.isNaN(leavesTheFleetAt("not an instant").getTime())).toBe(true);
  });

  it("keeps the toggle off unless the URL says exactly true", () => {
    for (const query of ["", "includeDeparted=false", "includeDeparted=1"]) {
      expect(includeDepartedFrom(new URLSearchParams(query))).toBeUndefined();
    }
    expect(includeDepartedFrom(new URLSearchParams("includeDeparted=true"))).toBe(true);
  });
});
