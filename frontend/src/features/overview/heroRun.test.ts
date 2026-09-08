/** The hero reclaim rule (#104) and the clocks beside it, pinned in the frontend lane (#285). */

import { describe, expect, it } from "vitest";
import {
  findBaselineRun,
  findRunningHeroRun,
  formatDuration,
  formatUtc,
  formatUtcClock,
  runDuration,
  takesTheHero
} from "@/features/overview/heroRun";
import type { Run } from "@/features/mdm/types";

const run = (over: Partial<Run> = {}): Run =>
  ({
    id: "job-1",
    mdmConnectionId: 1,
    collectionId: 1,
    trigger: "sweep",
    comparison: "delta",
    lockClass: "device_sweep",
    status: "succeeded",
    windowStart: "2026-09-08T01:00:00Z",
    windowEnd: "2026-09-08T01:10:00Z",
    startedAt: "2026-09-08T01:00:00Z",
    finishedAt: "2026-09-08T01:10:00Z",
    heartbeatAt: "2026-09-08T01:10:00Z",
    deviceCount: 10,
    groupCount: 2,
    devicesProcessed: 10,
    devicesFailed: 0,
    observations: null,
    error: null,
    ...over
  }) as Run;

describe("takesTheHero — first sync and manual or scheduled full syncs only", () => {
  it("a scheduled or manual device sweep takes the hero", () => {
    expect(takesTheHero(run({ trigger: "sweep" }))).toBe(true);
    expect(takesTheHero(run({ trigger: "manual" }))).toBe(true);
  });

  it("a webhook sweep is one record landing, not the fleet arriving", () => {
    expect(takesTheHero(run({ trigger: "webhook" }))).toBe(false);
  });

  it("a catalog refresh reads metadata, not devices", () => {
    expect(takesTheHero(run({ lockClass: "catalog" }))).toBe(false);
    expect(takesTheHero(run({ lockClass: "webhook", trigger: "webhook" }))).toBe(false);
  });
});

describe("findBaselineRun / findRunningHeroRun over a newest-first list", () => {
  it("the newest succeeded baseline that takes the hero wins", () => {
    const runs = [
      run({ id: "webhook-baseline", trigger: "webhook", comparison: "baseline" }),
      run({ id: "failed-baseline", comparison: "baseline", status: "failed" }),
      run({ id: "the-one", comparison: "baseline" }),
      run({ id: "older", comparison: "baseline" })
    ];
    expect(findBaselineRun(runs)?.id).toBe("the-one");
  });

  it("no baseline, no hero line", () => {
    expect(findBaselineRun([run({ comparison: "delta" })])).toBeNull();
    expect(findBaselineRun([])).toBeNull();
  });

  it("the run in flight that should show, and only one that takes the hero", () => {
    const runs = [run({ id: "hook", trigger: "webhook", status: "running" }), run({ id: "sweep", status: "running" })];
    expect(findRunningHeroRun(runs)?.id).toBe("sweep");
    expect(findRunningHeroRun([run({ status: "succeeded" })])).toBeNull();
  });
});

describe("the clocks — UTC by ruling, because the Splunk search runs on UTC", () => {
  it("formatUtc renders the run stamp an operator pastes into Splunk", () => {
    expect(formatUtc("2026-08-29T14:03:00Z")).toBe("2026-08-29 14:03 UTC");
    expect(formatUtc("2026-08-29T23:59:30-01:00")).toBe("2026-08-30 00:59 UTC");
  });

  it("formatUtcClock is the time-only half", () => {
    expect(formatUtcClock("2026-08-29T14:32:00Z")).toBe("14:32 UTC");
  });

  it("an unparseable stamp is returned as it came rather than as Invalid Date", () => {
    expect(formatUtc("not a date")).toBe("not a date");
    expect(formatUtcClock("")).toBe("");
  });

  it("formatDuration reads the same in both shipped languages", () => {
    expect(formatDuration(38_000)).toBe("38s");
    expect(formatDuration(252_000)).toBe("4m 12s");
    expect(formatDuration(4_020_000)).toBe("1h 07m");
    expect(formatDuration(0)).toBe("0s");
    expect(formatDuration(-5_000)).toBe("0s");
  });

  it("runDuration measures a finished run from its own stamps and a running one to now", () => {
    expect(runDuration(run())).toBe("10m 00s");
    const running = run({ status: "running", finishedAt: null });
    const now = Date.parse("2026-09-08T01:00:38Z");
    expect(runDuration(running, now)).toBe("38s");
  });
});
