import { describe, expect, it, vi } from "vitest";
import { filtersFromParams, localTime, paramsFromFilters, timeBound } from "./filters";
import { filtersFromPrompt, stillShowing } from "./prompt";
import type { ChangeFilters, PromptFilters } from "./types";

const query: ChangeFilters = { q: "Synthetic Mac", section: "operating_system", field: "version", changedTo: "27.2.1",
  since: "2026-11-01T01:30:00-06:00", until: "2026-11-23T19:31:12.123Z", connectionId: 7,
  model: "Air", osVersion: "27", fileVault: "BOOT_ENCRYPTED", site: "9", department: "3", managed: "false", user: "u_synthetic", page: 2 };

describe("historical change query", () => {
  it("round trips every historical/scalar/time filter and page through a shareable URL", () => {
    expect(filtersFromParams(paramsFromFilters(query))).toMatchObject(query);
    expect(paramsFromFilters(filtersFromParams(paramsFromFilters(query))).toString()).toBe(paramsFromFilters(query).toString());
    expect(filtersFromParams(paramsFromFilters({ section: "hardware", field: "model", changedTo: "" })).changedTo).toBe("");
  });
  it("converts edited local inputs to UTC and preserves unchanged shared instants including a repeated hour", () => {
    expect(timeBound(localTime(query.since), query.since)).toBe(query.since);
    expect(timeBound(localTime(query.until), query.until)).toBe(query.until);
    expect(timeBound("2026-11-23T12:34", undefined)).toBe(new Date("2026-11-23T12:34").toISOString());
    expect(timeBound("", query.since)).toBeUndefined();
    expect(() => timeBound("not-a-time", undefined)).toThrow();
    expect(() => timeBound("2026-02-30T12:00", undefined)).toThrow();
  });
  it("refuses skipped daylight-saving times and keeps the later repeated-hour instant", () => {
    vi.stubEnv("TZ", "America/Chicago");
    try {
      expect(() => timeBound("2026-03-08T02:30", undefined)).toThrow();
      const later = "2026-11-01T01:30:00-06:00";
      expect(timeBound(localTime(later), later)).toBe(later);
    } finally { vi.unstubAllEnvs(); }
  });
  it("an AI-applied query replaces exact field/end-bound filters and an edited one invalidates its counts", () => {
    const answer: PromptFilters = { q: null, artifact: "Synthetic App", section: "applications", change: "updated", level: null,
      model: null, osVersion: null, department: null, managed: null, departmentName: null, since: null };
    const applied = filtersFromPrompt(answer);
    expect({ ...query, ...applied }).toMatchObject({ field: undefined, changedTo: undefined, since: undefined, until: undefined, connectionId: undefined });
    for (const extra of [{ field: "version" }, { changedTo: "27.2.1" }, { until: query.until }]) {
      expect(stillShowing(applied, { ...applied, ...extra })).toBe(false);
    }
  });
});
