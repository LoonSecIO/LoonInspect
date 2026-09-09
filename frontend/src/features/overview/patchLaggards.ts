import type { JamfPatchTitle } from "@/features/jamfPatch/types";

/**
 * The patch-laggards ranking (#110) — the top titles by how many devices are behind.
 *
 * Pure on purpose, and separate from the tile for the reason `heroRun.ts` and
 * `sinceAnchor.ts` are: the ranking is a ruling, and a ruling that lives in a component
 * can only be checked by eye. It is pinned by `patchLaggards.test.ts` in the frontend
 * test lane (#285).
 *
 * **Ranked by `devicesBehind`, not by `deviceCount − devicesOnLatest`.** The issue was
 * filed with the subtraction; #314 then found that a device *ahead* of the catalog (a
 * beta, a build Jamf never listed) has no key of its own, so the subtraction absorbed it
 * and the fastest-patching tenant scored worst. `devicesBehind` is the honest number the
 * API has carried since, and the tile ranks by it.
 */

/** Five: the tile is a glance, and the Jamf Patch page is one click away for the rest. */
export const LAGGARD_LIMIT = 5;

/** The titles with at least one device behind, most behind first. Ties break on the
 *  title's device count (a bigger footprint matters more) and then on the name, so two
 *  titles that tie come back in the same order on every render. */
export function rankLaggards(titles: readonly JamfPatchTitle[], limit = LAGGARD_LIMIT): JamfPatchTitle[] {
  return titles
    .filter((title) => title.devicesBehind > 0)
    .sort(
      (a, b) =>
        b.devicesBehind - a.devicesBehind || b.deviceCount - a.deviceCount || a.name.localeCompare(b.name)
    )
    .slice(0, limit);
}
