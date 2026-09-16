import { PERMISSIONS } from "@/features/auth/types";
import type { PermissionName } from "@/features/auth/types";

/**
 * Which story `/` tells, decided from the signed-in account's permissions and nothing
 * else (#115). Pure on purpose, like `heroRun.ts`: the way this goes wrong is that
 * somebody *else's* session sees the other branch, which no screenshot of one's own page
 * reveals. Pinned by `overviewPlan.test.ts`.
 *
 * **The ruled predicate is `destination:read`** (Kyle, 2026-09-16, re-scoping #115).
 * Pipeline Health is the flagship story on `/` and it needs destinations, so whole-board
 * gating handed a viewer-role account one sentence where a board should be. The answer is
 * not to leak destinations — it is to tell the story that account *can* read. On a pod
 * with only the built-in roles that account is exactly `Role.viewer`
 * (`backend/app/core/permissions.py`); this function is the one place to change if a role
 * composition ever splits those two readings.
 *
 * **Every tile is planned against the permission its own source demands**, so none is
 * rendered into a 403 — which is why per-connection freshness is not a tile here:
 * `/api/mdm/status` is `connection:read`-gated, which no session reaching this board holds.
 * Fleet size comes from the `/api/devices` total instead; a viewer-readable freshness fact
 * is Kyle's to rule, and #115 stays open carrying that question.
 */

/** The tiles the story is built from, in laid-out order: each a claim plus the source
 *  that answers it, never a slot to be filled later. */
export type InventoryTile = "fleet" | "hygiene" | "catalog" | "topApps";

export interface OverviewPlan {
  /** `pipeline` is the operator front door (#104–#110); `inventory` is this issue's
   *  board. Never both. */
  story: "pipeline" | "inventory";
  /** Empty on `pipeline`, and possibly empty on `inventory` too: a principal with neither
   *  `destination:read` nor any inventory read is owed a sentence, not an empty grid. */
  tiles: InventoryTile[];
}

export function planOverview(permissions: readonly string[]): OverviewPlan {
  const held = (permission: PermissionName): boolean => permissions.includes(permission);
  if (held(PERMISSIONS.DESTINATION_READ)) return { story: "pipeline", tiles: [] };

  const tiles: InventoryTile[] = [];
  // The hygiene counts are `/api/devices` totals under fixed thresholds; the third of
  // those tiles asks for Jamf Patch coverage and hides itself without `app:read`.
  if (held(PERMISSIONS.DEVICE_READ)) tiles.push("fleet", "hygiene");
  if (held(PERMISSIONS.APP_READ)) tiles.push("catalog", "topApps");
  return { story: "inventory", tiles };
}
