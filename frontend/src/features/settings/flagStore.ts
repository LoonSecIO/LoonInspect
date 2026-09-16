import { create } from "zustand";
import { listFeatureFlags } from "@/features/settings/api";
import type { FeatureFlag } from "@/features/settings/types";

/**
 * One flag state for the whole signed-in session (#402).
 *
 * The flags used to be read into `NavigationProvider`'s own state, which is mounted once
 * for every page and never refetches, so a toggle on Settings › Feature Flags reached the
 * sidebar only after a reload — in both directions. A store instead: read once where the
 * read already happened, written by the toggle that confirmed it, and read by everything
 * that judges a flag (the sidebar, the drawer below `md` — #141, the route guard, the AI
 * page). A flag is instance-wide, not per-account, so one set serves every surface.
 *
 * Not covered, deliberately (#402 Out): a toggle made in another tab or by another
 * administrator. It reaches an open session at the next reload or sign-in; there is no
 * polling.
 */

/** Whether the flags have been read at all, and whether the read worked. `failed` is a
 *  third state on purpose: a read that failed says so, and is never reported as "off"
 *  (#150 — failure is not emptiness). */
export type FlagRead = "loading" | "read" | "failed";

/** What one flag-gated surface may say. `unreadable` is `failed` seen from a surface:
 *  the answer is missing, which is not the same as the flag being off. */
export type FlagGate = "loading" | "on" | "off" | "unreadable";

/** The enabled keys of a listing, which is the only part of a flag the gates read. */
export function enabledKeys(flags: readonly FeatureFlag[]): ReadonlySet<string> {
  return new Set(flags.filter((flag) => flag.enabled).map((flag) => flag.key));
}

/** One confirmed `PATCH /api/feature-flags/{key}` folded into the set: the server's own
 *  answer decides, never what the button was showing when it was pressed. */
export function withFlag(current: ReadonlySet<string>, updated: FeatureFlag): ReadonlySet<string> {
  const next = new Set(current);
  if (updated.enabled) next.add(updated.key);
  else next.delete(updated.key);
  return next;
}

/** The decision every flag-gated surface makes, as a function so the test lane can hold
 *  all four states (`flagStore.test.ts`) without rendering anything. */
export function flagGate(read: FlagRead, enabled: ReadonlySet<string>, flag: string): FlagGate {
  if (read === "loading") return "loading";
  if (read === "failed") return "unreadable";
  return enabled.has(flag) ? "on" : "off";
}

interface FeatureFlagStore {
  read: FlagRead;
  enabled: ReadonlySet<string>;
  /** Read the flags once, where the signed-in layout mounts. Never throws: the failure
   *  is a state, and an empty set with it, so a nav entry whose flag could not be read
   *  stays hidden exactly as it did before this store existed. */
  load: () => Promise<void>;
  /** The Feature Flags page's confirmed toggle. */
  apply: (updated: FeatureFlag) => void;
}

export const useFeatureFlagStore = create<FeatureFlagStore>((set) => ({
  read: "loading",
  enabled: new Set<string>(),

  async load() {
    try {
      set({ enabled: enabledKeys(await listFeatureFlags()), read: "read" });
    } catch {
      set({ enabled: new Set<string>(), read: "failed" });
    }
  },

  apply(updated) {
    // A toggle is the newest truth there is about that key, so it does not wait for a
    // re-read, and it leaves `read` alone: a set that could not be read is still a set
    // that could not be read, whatever one PATCH afterwards confirmed.
    set((state) => ({ enabled: withFlag(state.enabled, updated) }));
  }
}));

/** The gate one surface asks about one flag. */
export function useFlagGate(flag: string): FlagGate {
  return useFeatureFlagStore((state) => flagGate(state.read, state.enabled, flag));
}
