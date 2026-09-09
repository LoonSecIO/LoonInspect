import { describe, expect, it } from "vitest";
import type { Run } from "@/features/mdm/types";
import {
  RECENT_RUNS_LIMIT,
  STALE_CHECK_IN_DAYS,
  coveragePercent,
  recentRuns,
  staleCheckInBefore,
  webhookRunsToday
} from "./hygiene";

function run(overrides: Partial<Run> & { id: string; startedAt: string }): Run {
  return {
    mdmConnectionId: 1,
    collectionId: null,
    trigger: "sweep",
    comparison: "delta",
    lockClass: "device_sweep",
    status: "succeeded",
    windowStart: overrides.startedAt,
    windowEnd: null,
    finishedAt: null,
    heartbeatAt: overrides.startedAt,
    deviceCount: 0,
    groupCount: 0,
    devicesProcessed: 0,
    devicesFailed: 0,
    observations: null,
    error: null,
    actorLabel: null,
    ...overrides
  };
}

const NOON = new Date("2026-09-09T12:00:00Z");

describe("staleCheckInBefore", () => {
  it("is an absolute instant seven days back, on the minute", () => {
    expect(STALE_CHECK_IN_DAYS).toBe(7);
    expect(staleCheckInBefore(NOON)).toBe("2026-09-02T12:00:00.000Z");
    expect(staleCheckInBefore(new Date("2026-09-09T12:34:56.789Z"))).toBe("2026-09-02T12:34:00.000Z");
  });
});

describe("coveragePercent", () => {
  it("rounds, and refuses to divide by nothing", () => {
    expect(coveragePercent(214, 275)).toBe(78);
    expect(coveragePercent(0, 10)).toBe(0);
    expect(coveragePercent(0, 0)).toBeNull();
  });
});

describe("webhookRunsToday", () => {
  it("counts webhook runs that started today, in UTC", () => {
    const result = webhookRunsToday(
      [
        run({ id: "a", trigger: "webhook", startedAt: "2026-09-09T11:00:00Z" }),
        run({ id: "b", trigger: "webhook", startedAt: "2026-09-09T00:30:00Z" }),
        run({ id: "c", trigger: "sweep", startedAt: "2026-09-09T01:00:00Z" }),
        run({ id: "d", trigger: "webhook", startedAt: "2026-09-08T23:59:00Z" })
      ],
      NOON
    );
    expect(result).toEqual({ count: 2, complete: true });
  });

  it("is a floor when the list never reached yesterday", () => {
    const result = webhookRunsToday(
      [
        run({ id: "a", trigger: "webhook", startedAt: "2026-09-09T11:00:00Z" }),
        run({ id: "b", trigger: "webhook", startedAt: "2026-09-09T10:00:00Z" })
      ],
      NOON
    );
    expect(result).toEqual({ count: 2, complete: false });
  });

  it("an empty list is a complete zero", () => {
    expect(webhookRunsToday([], NOON)).toEqual({ count: 0, complete: true });
  });
});

describe("recentRuns", () => {
  it("is newest first and capped at ten", () => {
    const runs = Array.from({ length: 14 }, (_, i) =>
      run({ id: String(i), startedAt: new Date(Date.UTC(2026, 8, 1 + i)).toISOString() })
    );
    const recent = recentRuns([...runs].reverse());
    expect(recent).toHaveLength(RECENT_RUNS_LIMIT);
    expect(recent[0].id).toBe("13");
    expect(recent[9].id).toBe("4");
    expect(runs[0].id).toBe("0");
  });
});
