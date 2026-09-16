import { beforeEach, describe, expect, it, vi } from "vitest";
import type { FeatureFlag } from "@/features/settings/types";

const listFeatureFlags = vi.fn();
vi.mock("@/features/settings/api", () => ({
  listFeatureFlags: () => listFeatureFlags()
}));

const { enabledKeys, flagGate, useFeatureFlagStore, withFlag } = await import("@/features/settings/flagStore");

const flag = (key: string, enabled: boolean): FeatureFlag => ({
  key,
  label: key,
  description: `the ${key} switch`,
  enabled
});

const AI = "ai_features";

beforeEach(() => {
  listFeatureFlags.mockReset();
  useFeatureFlagStore.setState({ read: "loading", enabled: new Set<string>() });
});

describe("the flag set", () => {
  it("a confirmed toggle lands in the set, in both directions", async () => {
    listFeatureFlags.mockResolvedValue([flag(AI, false), flag("other", true)]);
    await useFeatureFlagStore.getState().load();
    expect([...useFeatureFlagStore.getState().enabled]).toEqual(["other"]);

    // What the PATCH came back saying, not what the button was showing when pressed.
    useFeatureFlagStore.getState().apply(flag(AI, true));
    expect(useFeatureFlagStore.getState().enabled.has(AI)).toBe(true);

    useFeatureFlagStore.getState().apply(flag(AI, false));
    expect(useFeatureFlagStore.getState().enabled.has(AI)).toBe(false);
    // The other switches are untouched by a toggle of this one.
    expect(useFeatureFlagStore.getState().enabled.has("other")).toBe(true);
  });

  it("a read that failed is its own state, and holds no keys", async () => {
    listFeatureFlags.mockRejectedValue(new Error("no answer"));
    await useFeatureFlagStore.getState().load();

    // Never throws — the failure is a state — and an empty set keeps every flag-gated
    // nav entry hidden, which is what it did before this store existed.
    expect(useFeatureFlagStore.getState().read).toBe("failed");
    expect([...useFeatureFlagStore.getState().enabled]).toEqual([]);
  });

  it("only the enabled keys are kept, and a set is never mutated in place", () => {
    const read = enabledKeys([flag(AI, true), flag("other", false)]);
    expect([...read]).toEqual([AI]);
    expect([...withFlag(read, flag("other", true))]).toEqual([AI, "other"]);
    // The caller's set is the one the last render read; folding a toggle into it must
    // return a new one or React sees no change.
    expect([...read]).toEqual([AI]);
  });
});

describe("the guard's decision", () => {
  const on = new Set([AI]);
  const none = new Set<string>();

  it("says loading while the read is out, so no refusal flashes", () => {
    expect(flagGate("loading", none, AI)).toBe("loading");
    // Even with an older answer still in the set: the read decides, not the leftovers.
    expect(flagGate("loading", on, AI)).toBe("loading");
  });

  it("says on or off once the flags have been read", () => {
    expect(flagGate("read", on, AI)).toBe("on");
    expect(flagGate("read", none, AI)).toBe("off");
  });

  it("says unreadable, never off, when the flags could not be read (#150)", () => {
    expect(flagGate("failed", none, AI)).toBe("unreadable");
    expect(flagGate("failed", on, AI)).toBe("unreadable");
  });
});
