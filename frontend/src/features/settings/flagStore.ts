import { create } from "zustand";
import { listFeatureFlags } from "@/features/settings/api";
import type { FeatureFlag } from "@/features/settings/types";

/**
 * One flag state for the whole signed-in session (#402).
 *
 * The flags used to be read into `NavigationProvider`'s own state, which mounts once and
 * never refetches, so a toggle on Settings › Feature Flags reached the sidebar only after
 * a reload — in both directions. A store instead, like `useAuthStore`: read once where the
 * read already happened, written by the toggle the server confirmed, and read by every
 * surface that judges a flag (the sidebar, the drawer below `md` — #141, the route guard,
 * the AI page). Out of scope on purpose: a toggle in another tab or by another
 * administrator, which reaches an open session at its next reload. There is no polling.
 */

/** How the read went, and what a flag-gated surface may say about it. `failed` and its
 *  `unreadable` are a third state because a read that failed says so, and is never
 *  reported as "off" (#150). */
export type FlagRead = "loading" | "read" | "failed";
export type FlagGate = "loading" | "on" | "off" | "unreadable";

/** The enabled keys of a listing — the only part of a flag a gate reads. */
export function enabledKeys(flags: readonly FeatureFlag[]): ReadonlySet<string> {
  return new Set(flags.filter((flag) => flag.enabled).map((flag) => flag.key));
}

/** One confirmed `PATCH /api/feature-flags/{key}` folded in, as a new set so React sees
 *  the change: the server's answer decides, never what the button showed when pressed. */
export function withFlag(current: ReadonlySet<string>, updated: FeatureFlag): ReadonlySet<string> {
  const next = new Set(current);
  if (updated.enabled) next.add(updated.key);
  else next.delete(updated.key);
  return next;
}

/** The decision every flag-gated surface makes, as a function, so the node test lane can
 *  hold all four states without rendering anything (`flagStore.test.ts`). */
export function flagGate(read: FlagRead, enabled: ReadonlySet<string>, flag: string): FlagGate {
  if (read === "loading") return "loading";
  if (read === "failed") return "unreadable";
  return enabled.has(flag) ? "on" : "off";
}

interface FeatureFlagStore {
  read: FlagRead;
  enabled: ReadonlySet<string>;
  /** Read where the signed-in layout mounts, and again if it mounts again — it puts `read`
   *  back to "loading" first, so one session never reads the last one's answer as its own,
   *  while the set stands until the new answer lands. Never throws: the failure is a state,
   *  and the empty set with it keeps a flag-gated nav entry hidden exactly as before. */
  load: () => Promise<void>;
  /** The Feature Flags page's confirmed toggle. It leaves `read` alone — a set that could
   *  not be read is still one, whatever a single later PATCH confirmed. */
  apply: (updated: FeatureFlag) => void;
}

export const useFeatureFlagStore = create<FeatureFlagStore>((set) => ({
  read: "loading",
  enabled: new Set<string>(),

  async load() {
    set({ read: "loading" });
    try {
      set({ enabled: enabledKeys(await listFeatureFlags()), read: "read" });
    } catch {
      set({ enabled: new Set<string>(), read: "failed" });
    }
  },

  apply(updated) {
    set((state) => ({ enabled: withFlag(state.enabled, updated) }));
  }
}));

/** The gate one surface asks about one flag. */
export function useFlagGate(flag: string): FlagGate {
  return useFeatureFlagStore((state) => flagGate(state.read, state.enabled, flag));
}
