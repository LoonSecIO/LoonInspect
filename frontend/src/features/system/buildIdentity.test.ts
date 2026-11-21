import { describe, expect, it } from "vitest";
import { buildLabel, buildRows, copyableBuild } from "@/features/system/buildIdentity";
import { en } from "@/i18n/en";
import { de } from "@/i18n/de";

const mac = { version: "2026.11.21+1234567", kind: "mac-app" as const, appVersion: "1.2.0", appBuild: "42" };

describe("the identity a person sees and copies", () => {
  it("leads with the app release and copies all three labelled identities", () => {
    expect(buildLabel(mac, en.support)).toBe("LoonInspect.app 1.2.0");
    expect(copyableBuild(mac, en.support)).toBe("App version: 1.2.0\nApp build: 42\nBackend build: 2026.11.21+1234567");
    expect(buildRows(mac, de.support)).toEqual([
      ["App-Version", "1.2.0"], ["App-Build", "42"], ["Backend-Build", "2026.11.21+1234567"]
    ]);
  });

  it("preserves the backend stamp for containers and older backends", () => {
    for (const identity of [{ version: mac.version }, { ...mac, kind: "container" as const }]) {
      expect(buildLabel(identity, en.support)).toBe(mac.version);
      expect(copyableBuild(identity, en.support)).toBe(mac.version);
      expect(buildRows(identity, en.support)).toEqual([["Backend build", mac.version]]);
    }
  });

  it("never guesses an app release or build when an older package did not record it", () => {
    const identity = { ...mac, appVersion: null, appBuild: " " };
    expect(buildLabel(identity, en.support)).toBe("LoonInspect.app");
    expect(copyableBuild(identity, en.support)).toContain("App version: Not recorded\nApp build: Not recorded");
  });

  it("offers nothing to copy until a nonempty backend identity arrives", () => {
    expect(copyableBuild(null, en.support)).toBeNull();
    expect(copyableBuild({ version: " " }, en.support)).toBeNull();
  });
});
