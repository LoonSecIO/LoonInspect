import { describe, expect, it } from "vitest";
import type { JamfPatchTitle } from "@/features/jamfPatch/types";
import { LAGGARD_LIMIT, rankLaggards } from "./patchLaggards";

function title(overrides: Partial<JamfPatchTitle> & { id: string; name: string }): JamfPatchTitle {
  return {
    publisher: null,
    appName: null,
    bundleId: null,
    currentVersion: "1.0",
    lastModified: "",
    syncedAt: "2026-09-09T00:00:00Z",
    deviceCount: 0,
    devicesOnLatest: 0,
    devicesBehind: 0,
    ...overrides
  };
}

describe("rankLaggards", () => {
  it("ranks by devices behind, most behind first, and drops titles with none", () => {
    const ranked = rankLaggards([
      title({ id: "a", name: "Slack", deviceCount: 40, devicesOnLatest: 38, devicesBehind: 2 }),
      title({ id: "b", name: "Wireshark", deviceCount: 12, devicesOnLatest: 1, devicesBehind: 11 }),
      title({ id: "c", name: "Xcode", deviceCount: 9, devicesOnLatest: 9, devicesBehind: 0 }),
      title({ id: "d", name: "Zoom", deviceCount: 30, devicesOnLatest: 25, devicesBehind: 5 })
    ]);
    expect(ranked.map((t) => t.id)).toEqual(["b", "d", "a"]);
  });

  it("is the honest number, not the subtraction: a device ahead of the catalog is not behind", () => {
    // #314: 10 devices, 7 on latest, 3 ahead — the subtraction says 3 behind; nobody is.
    const ranked = rankLaggards([
      title({ id: "beta", name: "Safari", deviceCount: 10, devicesOnLatest: 7, devicesBehind: 0 }),
      title({ id: "late", name: "Chrome", deviceCount: 10, devicesOnLatest: 9, devicesBehind: 1 })
    ]);
    expect(ranked.map((t) => t.id)).toEqual(["late"]);
  });

  it("breaks ties on footprint, then on name, and never reorders across renders", () => {
    const titles = [
      title({ id: "1", name: "Bravo", deviceCount: 5, devicesBehind: 3 }),
      title({ id: "2", name: "Alpha", deviceCount: 5, devicesBehind: 3 }),
      title({ id: "3", name: "Charlie", deviceCount: 9, devicesBehind: 3 })
    ];
    expect(rankLaggards(titles).map((t) => t.id)).toEqual(["3", "2", "1"]);
    expect(rankLaggards([...titles].reverse()).map((t) => t.id)).toEqual(["3", "2", "1"]);
  });

  it("takes five, and leaves the input alone", () => {
    const titles = Array.from({ length: 8 }, (_, i) =>
      title({ id: String(i), name: `Title ${i}`, deviceCount: 10, devicesBehind: 8 - i })
    );
    const before = titles.map((t) => t.id);
    const ranked = rankLaggards(titles);
    expect(ranked).toHaveLength(LAGGARD_LIMIT);
    expect(ranked.map((t) => t.id)).toEqual(["0", "1", "2", "3", "4"]);
    expect(titles.map((t) => t.id)).toEqual(before);
    expect(rankLaggards(titles, 2)).toHaveLength(2);
  });

  it("an empty catalog ranks nothing", () => {
    expect(rankLaggards([])).toEqual([]);
  });
});
