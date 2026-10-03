import { describe, expect, it } from "vitest";
import { filterVersionRows, hideEmptyByDefault, versionRows } from "@/features/jamfPatch/versionRows";

const title = {
  currentVersion: "4.6.0",
  patches: [
    { version: "4.6.0", releaseDate: "2026-09-01T00:00:00Z" },
    { version: "4.4.2", releaseDate: "2026-06-01T00:00:00Z" },
    { version: "4.2.0" }
  ],
  versionDeviceCounts: { "4.6.0": 3, "4.2.0": 1, "4.7.0rc1": 2, "3.9.9": 5, "0.0.1": 0 }
};

describe("versionRows", () => {
  it("lists Jamf's versions in catalog order with their devices, then unlisted ones by devices", () => {
    const rows = versionRows(title);
    expect(rows.map((row) => [row.version, row.devices, row.listed])).toEqual([
      ["4.6.0", 3, true],
      ["4.4.2", 0, true],
      ["4.2.0", 1, true],
      ["3.9.9", 5, false],
      ["4.7.0rc1", 2, false]
    ]);
  });

  it("marks only the title's current version as latest, and a missing release date as null", () => {
    const rows = versionRows(title);
    expect(rows.filter((row) => row.latest).map((row) => row.version)).toEqual(["4.6.0"]);
    expect(rows[2].releaseDate).toBeNull();
  });

  it("does not repeat a version the catalog lists twice", () => {
    const rows = versionRows({ ...title, patches: [...title.patches, { version: "4.6.0" }] });
    expect(rows.filter((row) => row.version === "4.6.0")).toHaveLength(1);
  });
});

describe("filterVersionRows", () => {
  it("hides versions with no devices and counts what it hid", () => {
    const result = filterVersionRows(versionRows(title), true);
    expect(result.visible.map((row) => row.version)).toEqual(["4.6.0", "4.2.0", "3.9.9", "4.7.0rc1"]);
    expect(result.hidden).toBe(1);
  });

  it("hides nothing when the box is unticked", () => {
    const result = filterVersionRows(versionRows(title), false);
    expect(result.visible).toHaveLength(5);
    expect(result.hidden).toBe(0);
  });
});

describe("hideEmptyByDefault", () => {
  it("starts ticked only where a version has a device", () => {
    expect(hideEmptyByDefault(versionRows(title))).toBe(true);
    expect(hideEmptyByDefault(versionRows({ ...title, versionDeviceCounts: {} }))).toBe(false);
  });
});
