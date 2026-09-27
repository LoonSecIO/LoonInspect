import { afterEach, describe, expect, it, vi } from "vitest";
import { apiRequest } from "@/config/api";
import { INTELLIGENCE_ACCESS, useIntelligenceStore } from "./intelligenceStore";

vi.mock("@/config/api", () => ({ apiRequest: vi.fn(), setUnauthorizedHandler: vi.fn() }));

afterEach(() => {
  vi.clearAllMocks();
  useIntelligenceStore.setState({ enabled: false, submissions: false, answering: new Set() });
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
    useIntelligenceStore.setState({ submissions: true });
    vi.mocked(apiRequest).mockRejectedValue(new Error("403"));
    await useIntelligenceStore.getState().load();
    expect(useIntelligenceStore.getState().enabled).toBe(false);
    expect(useIntelligenceStore.getState().submissions).toBe(false);
    expect(useIntelligenceStore.getState().answering.size).toBe(0);
  });

  it("holds INTELLIGENCE_SUBMISSIONS apart from the preview, as the instance reports it, and absent as off (#692)", async () => {
    const read = async (status: object) => {
      vi.mocked(apiRequest).mockResolvedValue(status);
      await useIntelligenceStore.getState().load();
      const { enabled, submissions, answering } = useIntelligenceStore.getState();
      return [enabled, submissions, answering.size];
    };
    expect(await read({ enabled: true, submissions: false })).toEqual([true, false, 1]);
    expect(await read({ enabled: true, submissions: true })).toEqual([true, true, 1]);
    expect(await read({ enabled: true })).toEqual([true, false, 1]);
    expect(await read({ enabled: false, submissions: true })).toEqual([false, true, 0]);
  });
});
