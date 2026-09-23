import { afterEach, describe, expect, it, vi } from "vitest";
import { apiRequest } from "@/config/api";
import { INTELLIGENCE_ACCESS, useIntelligenceStore } from "./intelligenceStore";

vi.mock("@/config/api", () => ({ apiRequest: vi.fn(), setUnauthorizedHandler: vi.fn() }));

afterEach(() => {
  vi.clearAllMocks();
  useIntelligenceStore.setState({ enabled: false, answering: new Set() });
});

describe("intelligenceStore (#622)", () => {
  it("offers the Settings entry only when the instance says the preview is enabled", async () => {
    vi.mocked(apiRequest).mockResolvedValue({ enabled: true });
    await useIntelligenceStore.getState().load();
    expect(apiRequest).toHaveBeenCalledWith("/system/intelligence");
    expect(useIntelligenceStore.getState().enabled).toBe(true);
    expect(useIntelligenceStore.getState().answering.has(INTELLIGENCE_ACCESS)).toBe(true);

    vi.mocked(apiRequest).mockResolvedValue({ enabled: false });
    await useIntelligenceStore.getState().load();
    expect(useIntelligenceStore.getState().enabled).toBe(false);
    expect(useIntelligenceStore.getState().answering.size).toBe(0);
  });

  it("a refused or failed read hides the entry rather than guessing", async () => {
    vi.mocked(apiRequest).mockRejectedValue(new Error("403"));
    await useIntelligenceStore.getState().load();
    expect(useIntelligenceStore.getState().enabled).toBe(false);
    expect(useIntelligenceStore.getState().answering.size).toBe(0);
  });
});
