import { describe, expect, it } from "vitest";
import { DEFAULT_TOKEN_CACHE_MODE, TOKEN_CACHE_MODES, tokenCacheModeOf } from "@/features/mdm/signInReuse";
import { en } from "@/i18n/en";

describe("sign-in reuse", () => {
  it("offers the three modes, least kept to most", () => {
    expect(TOKEN_CACHE_MODES).toEqual(["no_cache", "cache_and_hold", "perpetual"]);
  });

  it("defaults to Cache and hold, as ruled on #412", () => {
    expect(DEFAULT_TOKEN_CACHE_MODE).toBe("cache_and_hold");
    expect(tokenCacheModeOf()).toBe("cache_and_hold");
    expect(tokenCacheModeOf(null)).toBe("cache_and_hold");
  });

  it("starts an existing connection on its own mode", () => {
    expect(tokenCacheModeOf({ tokenCacheMode: "perpetual" })).toBe("perpetual");
    expect(tokenCacheModeOf({ tokenCacheMode: "no_cache" })).toBe("no_cache");
  });

  it("names every mode in the words Kyle chose, and says what each costs", () => {
    const modes = en.connectionForm.signInReuse.modes;
    expect(TOKEN_CACHE_MODES.map((mode) => modes[mode].label)).toEqual(["No cache", "Cache and hold", "Perpetual cache"]);
    for (const mode of TOKEN_CACHE_MODES) expect(modes[mode].description.length).toBeGreaterThan(0);
    expect(modes.perpetual.description).toMatch(/580/);
  });
});
