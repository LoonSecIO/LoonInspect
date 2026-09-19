import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import { describe, expect, it } from "vitest";
import tokens from "./tokens.json";

const script = readFileSync(new URL("../../public/theme.js", import.meta.url), "utf8");

describe("brand theme before first paint", () => {
  it.each([
    ["dark", false, "dark"], ["light", true, "light"],
    [null, true, "dark"], [null, false, "light"], ["invalid", true, "dark"],
  ])("keeps feature and brand themes aligned for %s / OS dark %s", (stored, osDark, expected) => {
    const root = { dataset: {} as Record<string, string>, classList: { toggle: (_name: string, value: boolean) => { dark = value; } } };
    let dark = false;
    runInNewContext(script, { localStorage: { getItem: () => stored }, window: { matchMedia: () => ({ matches: osDark }) }, document: { documentElement: root } });
    expect(root.dataset.loonTheme).toBe(expected);
    expect(dark).toBe(expected === "dark");
  });

  it("uses system appearance when storage is unavailable", () => {
    const root = { dataset: {} as Record<string, string>, classList: { toggle: () => {} } };
    runInNewContext(script, { localStorage: { getItem: () => { throw new Error("blocked"); } }, window: { matchMedia: () => ({ matches: true }) }, document: { documentElement: root } });
    expect(root.dataset.loonTheme).toBe("dark");
  });
});

function luminance(hex: string) {
  const channels = [1, 3, 5].map(i => parseInt(hex.slice(i, i + 2), 16) / 255)
    .map(v => v <= .04045 ? v / 12.92 : ((v + .055) / 1.055) ** 2.4);
  return channels[0] * .2126 + channels[1] * .7152 + channels[2] * .0722;
}

describe("semantic brand contrast", () => {
  for (const [theme, values] of Object.entries(tokens.themes)) {
    it(`${theme} keeps text readable in operational surfaces`, () => {
      const pairs: [keyof typeof values, keyof typeof values][] = [
        ["text", "surface"], ["text-secondary", "surface-raised"],
        ["action-text", "action"], ["selected-text", "selected"],
        ["navigation-text", "navigation"], ["danger-surface", "danger"],
      ];
      for (const [fg, bg] of pairs) {
        const [low, high] = [luminance(values[fg]), luminance(values[bg])].sort((a, b) => a - b);
        expect((high + .05) / (low + .05), `${fg} on ${bg}`).toBeGreaterThanOrEqual(4.5);
      }
    });
  }
});
