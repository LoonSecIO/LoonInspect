import { beforeEach, describe, expect, it, vi } from "vitest";
import type { FeatureFlag } from "@/features/settings/types";

const listFeatureFlags = vi.fn();
vi.mock("@/features/settings/api", () => ({ listFeatureFlags: () => listFeatureFlags() }));

const { enabledKeys, flagGate, useFeatureFlagStore, withFlag } = await import("@/features/settings/flagStore");

const AI = "ai_features";
const flag = (key: string, enabled: boolean): FeatureFlag => ({ key, label: key, description: key, enabled });
const store = () => useFeatureFlagStore.getState();

beforeEach(() => {
  listFeatureFlags.mockReset();
  useFeatureFlagStore.setState({ read: "loading", enabled: new Set<string>() });
});

describe("the flag set", () => {
  it("a confirmed toggle lands in the set, in both directions", async () => {
    listFeatureFlags.mockResolvedValue([flag(AI, false), flag("other", true)]);
    await store().load();
    expect([...store().enabled]).toEqual(["other"]);

    // What the PATCH came back saying, not what the button showed when it was pressed.
    store().apply(flag(AI, true));
    expect(store().enabled.has(AI)).toBe(true);
    store().apply(flag(AI, false));
    // A toggle of one switch leaves the others alone.
    expect([...store().enabled]).toEqual(["other"]);
  });

  it("a second read starts at loading, not at the last account's answer", async () => {
    listFeatureFlags.mockResolvedValue([flag(AI, true)]);
    await store().load();
    // Signing out and back in mounts the layout again on a store that still holds the
    // previous answer; the set stands until the new one lands, but `read` may not.
    listFeatureFlags.mockReturnValue(new Promise<FeatureFlag[]>(() => {}));
    void store().load();
    expect([store().read, store().enabled.has(AI)]).toEqual(["loading", true]);
  });

  it("a read that failed is its own state, and holds no keys", async () => {
    listFeatureFlags.mockRejectedValue(new Error("no answer"));
    await store().load();

    // Never throws — the failure is a state — and the empty set keeps every flag-gated
    // nav entry hidden, as it was before this store existed.
    expect(store().read).toBe("failed");
    expect([...store().enabled]).toEqual([]);
  });

  it("keeps only the enabled keys, and never mutates a set in place", () => {
    const read = enabledKeys([flag(AI, true), flag("other", false)]);
    expect([...withFlag(read, flag("other", true))]).toEqual([AI, "other"]);
    // The caller's set is the one the last render read: fold into a new one or React
    // sees no change.
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
