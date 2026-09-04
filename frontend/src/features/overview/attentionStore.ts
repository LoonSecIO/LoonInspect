import { create } from "zustand";
import { ApiError } from "@/config/api";
import { listAlerts } from "@/features/alerts/api";
import { useAuthStore } from "@/features/auth/store";
import { PERMISSIONS, type PermissionName } from "@/features/auth/types";
import { listDestinations } from "@/features/destinations/api";
import { listAllCollections, listConnections } from "@/features/mdm/api";
import { getUpdateStatus } from "@/features/system/api";
import {
  composeAttention,
  MAX_ROWS,
  type AttentionKind,
  type AttentionRow,
  type Fetched
} from "@/features/overview/needsAttention";

/** How many open latches to fetch (#101). Twice the cap, and no more: the endpoint
 *  returns them oldest first — the same order the composition ranks by within a level —
 *  so this page is the one whose rows would actually show, and the response's `total`
 *  carries the rest as a number rather than as a payload. A pod mid-rollout has thousands
 *  of open latches, and this poll runs every minute. */
const ALERT_WINDOW = MAX_ROWS * 2;

interface AttentionStore {
  rows: AttentionRow[];
  dropped: number;
  degraded: AttentionKind[];
  /** True when not one of the panel's checks could run — every input was `denied`. The
   *  panel says so instead of attesting; see `needsAttention.ts`. */
  blind: boolean;
  /** Everything the panel would render, uncapped — the number on the sidebar badge. */
  total: number;
  /** Null until the first load finishes. The panel shows nothing rather than an
   *  all-clear line dated to a check that has not run yet. */
  checkedAt: string | null;
  loading: boolean;
  loadAttention: () => Promise<void>;
}

/** What the store holds before anything has been checked, and what it is put back to
 *  when the session changes underneath it. Written once so "empty" cannot come to mean
 *  two different things in two places. */
const NOTHING_CHECKED = {
  rows: [] as AttentionRow[],
  dropped: 0,
  degraded: [] as AttentionKind[],
  blind: false,
  total: 0,
  checkedAt: null,
  loading: false
};

/**
 * Which session the current contents belong to.
 *
 * Bumped on every reset, and read back by `loadAttention` after its awaits. A load that
 * started as the admin can finish after the viewer has signed in — five requests take
 * long enough for that to be ordinary, not exotic — and without this guard it would
 * write the admin's rows into the viewer's store *after* the reset cleared them.
 */
let generation = 0;

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
 * list, which is the thing the ruling forbids — and a second set of five requests on
 * every page besides.
 *
 * The cost of that choice, stated rather than hidden: the badge is only as fresh as the
 * last `loadAttention()`, so on a cold load of `/devices` it is blank until `/` has been
 * visited once. Mounting the loader app-wide would fix it and would spend five requests
 * on every page in the product to keep a number on a nav item warm.
 *
 * The other cost of a module singleton is that it outlives the session, and that one is
 * not acceptable — see the subscription at the bottom of this file.
 */
export const useAttentionStore = create<AttentionStore>((set) => ({
  ...NOTHING_CHECKED,

  async loadAttention() {
    const mine = generation;
    set({ loading: true });
    // `permissions` arrives from the server as plain strings, so the set is of strings
    // and the constants are what narrow it — the reverse would make an unknown
    // permission a type error at runtime rather than an ignored grant.
    const granted = new Set<string>(useAuthStore.getState().user?.permissions ?? []);
    const can = (permission: PermissionName) => granted.has(permission);

    const [collections, connections, destinations, update, alerts] = await Promise.all([
      // Three of the six checks read this one list — failed run, overdue, stale — and
      // it is the tenant-wide summary rather than a page of `/api/runs`, for the reason
      // written out in `needsAttention.ts`: the webhook path mints a run row per Jamf
      // event and a 50-row window over that is blind by 03:25.
      attempt(can(PERMISSIONS.CONNECTION_READ), listAllCollections),
      attempt(can(PERMISSIONS.CONNECTION_READ), listConnections),
      attempt(can(PERMISSIONS.DESTINATION_READ), listDestinations),
      attempt(can(PERMISSIONS.SYSTEM_READ), getUpdateStatus),
      // `device:read`, which every role including Viewer holds — deliberately, because
      // the read-only account is exactly the persona told to watch for software nobody
      // deployed (docs/alerts.md §3).
      attempt(can(PERMISSIONS.DEVICE_READ), () => listAlerts({ open: true, pageSize: ALERT_WINDOW }))
    ]);

    // The session changed while these were in flight. Whatever came back describes
    // somebody else's pod, or somebody else's permissions, and must not be shown.
    if (mine !== generation) return;

    const result = composeAttention({
      now: new Date(),
      collections,
      connections,
      destinations,
      update,
      alerts
    });
    set({
      rows: result.rows,
      dropped: result.dropped,
      degraded: result.degraded,
      blind: result.blind,
      total: result.total,
      checkedAt: result.checkedAt,
      loading: false
    });
  }
}));

/**
 * Forget everything the moment the session changes.
 *
 * A module singleton survives sign-out, a 401 (`setUnauthorizedHandler` clears the auth
 * store without unmounting the app), and a same-tab account switch. Without this, an
 * admin's count stays on the sidebar badge into a viewer's session — on *every* page,
 * because the badge renders app-wide — and the viewer has no way to clear it from the
 * page they are on: `loadAttention` is only ever called from the panel on `/`, and every
 * check it makes is denied to their role. A stale red number counting somebody else's
 * problems, on every page, is worse than no badge at all.
 *
 * Keyed on the user id rather than on `status`, because the case this exists for is two
 * *authenticated* states in a row. Subscribing here rather than resetting inside
 * `logout()` keeps the one path that clears this store from depending on which of the
 * three ways out of a session was taken.
 */
let signedInAs: string | null = useAuthStore.getState().user?.id ?? null;
useAuthStore.subscribe((state) => {
  const id = state.user?.id ?? null;
  if (id === signedInAs) return;
  signedInAs = id;
  generation += 1;
  useAttentionStore.setState({ ...NOTHING_CHECKED });
});
