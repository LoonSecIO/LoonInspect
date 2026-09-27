import { afterEach, describe, expect, it, vi } from "vitest";
import { visibleNavigation } from "@/components/layout/navigation";
import { apiRequest } from "@/config/api";
import { PERMISSIONS } from "@/features/auth/types";
import { INTELLIGENCE_ACCESS, sharingPointer, useIntelligenceStore } from "./intelligenceStore";

vi.mock("@/config/api", () => ({ apiRequest: vi.fn(), setUnauthorizedHandler: vi.fn() }));

afterEach(() => {
  vi.clearAllMocks();
  useIntelligenceStore.setState({ enabled: false, submissions: false, receipts: false, answering: new Set() });
});

describe("intelligenceStore (#622)", () => {
  it("offers the Settings entry when the instance says the preview is enabled", async () => {
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
    useIntelligenceStore.setState({ submissions: true, receipts: true });
    vi.mocked(apiRequest).mockRejectedValue(new Error("403"));
    await useIntelligenceStore.getState().load();
    expect(useIntelligenceStore.getState().enabled).toBe(false);
    expect(useIntelligenceStore.getState().submissions).toBe(false);
    expect(useIntelligenceStore.getState().receipts).toBe(false);
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

describe("Settings › Intelligence Access in an administrator's sidebar (#706)", () => {
  /** Whether the entry is listed once the store has read `answer`: the store and the tree, as the layout joins them. */
  async function listed(answer: object | Error): Promise<boolean> {
    if (answer instanceof Error) vi.mocked(apiRequest).mockRejectedValue(answer);
    else vi.mocked(apiRequest).mockResolvedValue(answer);
    await useIntelligenceStore.getState().load();
    const tree = visibleNavigation(Object.values(PERMISSIONS), new Set(), useIntelligenceStore.getState().answering);
    const settings = tree.find((item) => item.labelKey === "settings");
    return settings?.children?.some((child) => child.labelKey === "intelligenceAccess") ?? false;
  }

  it.each([
    ["only contribution receipts on", { enabled: false, receipts: true, casesToWithdraw: false }, true],
    ["only paid access on", { enabled: true, receipts: false, casesToWithdraw: false }, true],
    ["only a case left to withdraw", { enabled: false, receipts: false, casesToWithdraw: true }, true],
    ["both routes off and no case", { enabled: false, receipts: false, casesToWithdraw: false }, false],
    ["an answer without the #706 fields, the preview off", { enabled: false }, false]
  ])("%s", async (_name, answer, expected) => {
    expect(await listed(answer)).toBe(expected);
  });

  it("a failed read hides it, whatever the read before said", async () => {
    expect(await listed({ enabled: false, receipts: true })).toBe(true);
    expect(await listed(new Error("503"))).toBe(false);
  });

  it("receipts and cases never widen `enabled`, which the row actions read as the paid preview", async () => {
    expect(await listed({ enabled: false, submissions: true, receipts: true, casesToWithdraw: true })).toBe(true);
    expect(useIntelligenceStore.getState()).toMatchObject({ enabled: false, submissions: true, receipts: true });
  });

  it("Data sharing links to the page where either route is on, naming which", () => {
    const pointers = [sharingPointer(true, false), sharingPointer(false, true), sharingPointer(true, true), sharingPointer(false, false)];
    expect(pointers).toEqual(["paid", "receipts", "both", null]);
  });
});
