/** "Since you last looked" (#107): the anchor is absolute, never relative. Frontend lane (#285). */

import { describe, expect, it } from "vitest";
import type { DeviceChange } from "@/features/changes/types";
import {
  FALLBACK_HOURS,
  changesHref,
  readLastVisit,
  resolveAnchor,
  summarise,
  writeLastVisit
} from "@/features/overview/sinceAnchor";

const NOW = new Date("2026-09-08T12:00:00.000Z");

describe("resolveAnchor", () => {
  it("a stored visit becomes a fixed ISO instant", () => {
    expect(resolveAnchor("2026-09-07T08:30:00Z", NOW)).toBe("2026-09-07T08:30:00.000Z");
    expect(resolveAnchor("2026-09-07T08:30:00+02:00", NOW)).toBe("2026-09-07T06:30:00.000Z");
  });

  it("no stored visit reaches back a day rather than showing nothing", () => {
    expect(resolveAnchor(null, NOW)).toBe("2026-09-07T12:00:00.000Z");
    expect(FALLBACK_HOURS).toBe(24);
  });

  it("a corrupt value falls back instead of becoming since=Invalid%20Date", () => {
    expect(resolveAnchor("last tuesday", NOW)).toBe("2026-09-07T12:00:00.000Z");
    expect(resolveAnchor("", NOW)).toBe("2026-09-07T12:00:00.000Z");
  });
});

describe("changesHref carries the anchor and the level floor", () => {
  it("both parameters, encoded", () => {
    expect(changesHref("2026-09-07T12:00:00.000Z")).toBe("/devices/changes?since=2026-09-07T12%3A00%3A00.000Z&minLevel=normal");
    expect(changesHref("2026-09-07T12:00:00.000Z", "low")).toContain("minLevel=low");
  });
});

describe("summarise — the header's four numbers", () => {
  const change = (over: Partial<DeviceChange>): DeviceChange =>
    ({ id: 1, subjectId: "d1", level: "normal", ...over }) as DeviceChange;

  it("counts distinct devices and the notable rows, and takes total from the API", () => {
    const rows = [
      change({ id: 1, subjectId: "d1", level: "high" }),
      change({ id: 2, subjectId: "d1", level: "normal" }),
      change({ id: 3, subjectId: "d2", level: "low" })
    ];
    const summary = summarise(rows, 40);
    expect(summary).toEqual({ rows, total: 40, devices: 2, notable: 2 });
  });

  it("an empty window is honest zeros", () => {
    expect(summarise([], 0)).toEqual({ rows: [], total: 0, devices: 0, notable: 0 });
  });
});

describe("the stored visit survives an environment with no storage", () => {
  it("reads null and writes silently when window is absent", () => {
    expect(readLastVisit()).toBeNull();
    expect(() => writeLastVisit(NOW)).not.toThrow();
  });
});
