import { describe, expect, it } from "vitest";
import { filterTitles, hasDevices } from "./titleFilter";

type Row = { id: string; name: string; deviceCount: number };

const CATALOG: Row[] = [
  { id: "612", name: "Wireshark", deviceCount: 1 },
  { id: "5F6", name: "Wireshark 4.2", deviceCount: 0 },
  { id: "0C9", name: "Slack", deviceCount: 12 },
  { id: "FFX", name: "Mozilla Firefox", deviceCount: 0 },
  { id: "0C3", name: "Apple Xcode", deviceCount: 3 }
];

const byName = (term: string) => (row: Row) => row.name.toLowerCase().includes(term);

describe("hasDevices", () => {
  it("is the Devices with app count above zero, and nothing else", () => {
    expect(hasDevices({ deviceCount: 1 })).toBe(true);
    expect(hasDevices({ deviceCount: 0 })).toBe(false);
  });
});

describe("filterTitles", () => {
  it("ticked, no search: only titles with a device, and the rest counted as hidden", () => {
    const result = filterTitles(CATALOG, { matches: () => true, searching: false, onlyWithDevices: true });
    expect(result.visible.map((row) => row.id)).toEqual(["612", "0C9", "0C3"]);
    expect(result.hidden).toBe(2);
    expect(result.empty).toBeNull();
  });

  it("unticked: the whole catalog, nothing hidden", () => {
    const result = filterTitles(CATALOG, { matches: () => true, searching: false, onlyWithDevices: false });
    expect(result.visible).toHaveLength(5);
    expect(result.hidden).toBe(0);
  });

  it("ticked with a search: the search first, then the box, and the hidden count is among the matches", () => {
    const result = filterTitles(CATALOG, { matches: byName("wireshark"), searching: true, onlyWithDevices: true });
    expect(result.visible.map((row) => row.id)).toEqual(["612"]);
    expect(result.hidden).toBe(1);
  });
});

describe("the four empty states", () => {
  it("an empty catalog is noCatalog, ticked or not — the checkbox never produces it", () => {
    for (const onlyWithDevices of [true, false]) {
      expect(filterTitles([], { matches: () => true, searching: false, onlyWithDevices }).empty).toBe("noCatalog");
    }
  });

  it("a fresh pod before its first sweep: every title hidden by the box, and it says so", () => {
    const fresh = CATALOG.map((row) => ({ ...row, deviceCount: 0 }));
    const result = filterTitles(fresh, { matches: () => true, searching: false, onlyWithDevices: true });
    expect(result).toMatchObject({ empty: "noneWithDevices", hidden: 5, visible: [] });
    // Untick, and the same catalog is simply listed.
    expect(filterTitles(fresh, { matches: () => true, searching: false, onlyWithDevices: false }).empty).toBeNull();
  });

  it("a search that matches only titles with no device says how many the box hid", () => {
    const result = filterTitles(CATALOG, { matches: byName("firefox"), searching: true, onlyWithDevices: true });
    expect(result).toMatchObject({ empty: "matchesOnlyWithoutDevices", hidden: 1, visible: [] });
  });

  it("a search that matches nothing is noMatch, with the box ticked or not", () => {
    for (const onlyWithDevices of [true, false]) {
      const result = filterTitles(CATALOG, { matches: byName("tableau"), searching: true, onlyWithDevices });
      expect(result).toMatchObject({ empty: "noMatch", hidden: 0 });
    }
  });
});
