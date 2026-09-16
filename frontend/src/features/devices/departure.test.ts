import { describe, expect, it } from "vitest";
import { DEPARTURE_TAIL_DAYS, departureState, includeDepartedFrom, leavesTheFleetAt } from "@/features/devices/departure";

const NOW = new Date("2026-09-16T12:00:00Z");
const daysBefore = (days: number) => new Date(NOW.getTime() - days * 86_400_000).toISOString();

describe("the tail, as the chip and the toggle read it", () => {
  it("says nothing about a Mac Jamf is still returning", () => {
    expect(departureState(null, NOW)).toBe("present");
  });

  it("is the tail until the seventh day, and left on it", () => {
    expect(departureState(daysBefore(0), NOW)).toBe("in_tail");
    expect(departureState(daysBefore(DEPARTURE_TAIL_DAYS - 1), NOW)).toBe("in_tail");
    // Exactly seven days: the backend's `departed_at <= now - 7 days` has already let go.
    expect(departureState(daysBefore(DEPARTURE_TAIL_DAYS), NOW)).toBe("left");
    expect(departureState(daysBefore(30), NOW)).toBe("left");
  });

  it("calls an unparseable instant departed, never left, and dates the rest from departedAt", () => {
    expect(departureState("not an instant", NOW)).toBe("in_tail");
    expect(leavesTheFleetAt("2026-08-28T09:30:00Z").toISOString()).toBe("2026-09-04T09:30:00.000Z");
  });

  it("keeps the toggle off unless the URL says exactly true", () => {
    for (const query of ["", "includeDeparted=false", "includeDeparted=1"]) {
      expect(includeDepartedFrom(new URLSearchParams(query))).toBeUndefined();
    }
    expect(includeDepartedFrom(new URLSearchParams("includeDeparted=true"))).toBe(true);
  });
});
