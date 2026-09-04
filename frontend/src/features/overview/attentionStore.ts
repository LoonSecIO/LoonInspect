import { create } from "zustand";
import { ApiError } from "@/config/api";
import { useAuthStore } from "@/features/auth/store";
import { PERMISSIONS, type PermissionName } from "@/features/auth/types";
import { listDestinations } from "@/features/destinations/api";
import { listAllCollections, listConnections, listRuns } from "@/features/mdm/api";
import { getUpdateStatus } from "@/features/system/api";
import {
  composeAttention,
  type AttentionKind,
  type AttentionRow,
  type Fetched
} from "@/features/overview/needsAttention";

/** Enough recent runs to hold the newest one of every connection and lock class on a
 *  pod with a handful of connections, without paging. The page already asks for fifty
 *  for the hero. */
const RUN_WINDOW = 50;

interface AttentionStore {
  rows: AttentionRow[];
  dropped: number;
  degraded: AttentionKind[];
  /** Null until the first load finishes. The panel shows nothing rather than an
   *  all-clear line dated to a check that has not run yet. */
  checkedAt: string | null;
  loading: boolean;
  loadAttention: () => Promise<void>;
}

/**
 * Wrap a request so a refusal is distinguishable from a failure.
 *
 * `allowed` is the session's own permission check: not asking is `denied`, which is
 * silent. Asking and being refused by the server is also `denied` — a 403 means the same
 * thing whichever side noticed. Anything else is `error`, which withholds the all-clear
 * line, and that difference is the reason this helper exists rather than a bare
 * `.catch(() => null)`.
 */
async function attempt<T>(allowed: boolean, request: () => Promise<T>): Promise<Fetched<T>> {
  if (!allowed) return { ok: false, reason: "denied" };
  try {
    return { ok: true, value: await request() };
  } catch (error) {
    const refused = error instanceof ApiError && error.status === 403;
    return { ok: false, reason: refused ? "denied" : "error" };
  }
}

/**
 * The one place Needs Attention is composed (#106).
 *
 * A store rather than a hook in the panel, because the composition has exactly **one**
 * implementation by ruling and two surfaces read it: the panel on `/` and the sidebar's
 * count badge. A badge that counted rows itself would be a second implementation of the
 * list, which is the thing the ruling forbids — and a second set of four requests on
 * every page besides.
 *
 * The cost of that choice, stated rather than hidden: the badge is only as fresh as the
 * last `loadAttention()`, so on a cold load of `/devices` it is blank until `/` has been
 * visited once. Mounting the loader app-wide would fix it and would spend five requests
 * on every page in the product to keep a number on a nav item warm.
 */
export const useAttentionStore = create<AttentionStore>((set) => ({
  rows: [],
  dropped: 0,
  degraded: [],
  checkedAt: null,
  loading: false,

  async loadAttention() {
    set({ loading: true });
    // `permissions` arrives from the server as plain strings, so the set is of strings
    // and the constants are what narrow it — the reverse would make an unknown
    // permission a type error at runtime rather than an ignored grant.
    const granted = new Set<string>(useAuthStore.getState().user?.permissions ?? []);
    const can = (permission: PermissionName) => granted.has(permission);

    const [runs, collections, connections, destinations, update] = await Promise.all([
      attempt(can(PERMISSIONS.CONNECTION_READ), () => listRuns(undefined, RUN_WINDOW)),
      attempt(can(PERMISSIONS.CONNECTION_READ), listAllCollections),
      attempt(can(PERMISSIONS.CONNECTION_READ), listConnections),
      attempt(can(PERMISSIONS.DESTINATION_READ), listDestinations),
      attempt(can(PERMISSIONS.SYSTEM_READ), getUpdateStatus)
    ]);

    const result = composeAttention({
      now: new Date(),
      runs,
      collections,
      connections,
      destinations,
      update
    });
    set({
      rows: result.rows,
      dropped: result.dropped,
      degraded: result.degraded,
      checkedAt: result.checkedAt,
      loading: false
    });
  }
}));
