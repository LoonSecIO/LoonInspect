import { describe, expect, it } from "vitest";
import { formatBytes } from "@/features/support/formatBytes";

describe("formatBytes", () => {
  it("counts the way README.md and KNOWN_ISSUES.md do: GB = 10⁹, one decimal", () => {
    expect(formatBytes(15_000_000_000, "en-US")).toBe("15 GB");
    expect(formatBytes(3_700_000_000, "en-US")).toBe("3.7 GB");
    expect(formatBytes(24_117_248, "en-US")).toBe("24.1 MB");
    expect(formatBytes(688_128, "en-US")).toBe("688.1 kB");
    expect(formatBytes(0, "en-US")).toBe("0 kB");
  });

  it("follows the locale's separators", () => {
    expect(formatBytes(3_700_000_000, "de-DE")).toBe("3,7 GB");
  });
});
