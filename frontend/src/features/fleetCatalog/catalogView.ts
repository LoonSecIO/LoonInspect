import type { FleetCatalog, FleetCatalogOutcome, FleetCatalogState, FleetCatalogTitle } from "@/features/fleetCatalog/types";

/**
 * What the Fleet catalog tab shows, decided without rendering anything (#794), so the node
 * test lane can hold every state (`catalogView.test.ts`).
 *
 * An empty table here has five different reasons, and docs/diagnosability.md rule 1 is that
 * the page says which: the flag is off, GitHub has never been asked, every check so far
 * failed, Fleet lists nothing this organization has installed, or the search matched nothing.
 */

const FAILED: ReadonlySet<FleetCatalogOutcome> = new Set(["refused", "unreachable", "unexpected"]);

/** A check that got no answer. `ok` and `unchanged` are answers, and so is no check yet. */
export function checkFailed(state: FleetCatalogState | null): boolean {
  return state?.outcome != null && FAILED.has(state.outcome);
}

export type FleetStatus = "never" | "answered" | "failed";

export function statusOf(state: FleetCatalogState | null): FleetStatus {
  if (state === null || state.checkedAt === null) return "never";
  return checkFailed(state) ? "failed" : "answered";
}

/**
 * Fleet's manifest for a title on GitHub, the one place its address is written (#901): on `main`
 * for the tab's source link, or at a commit, where it is what Fleet would install for the version
 * that commit dated.
 */
export function manifestUrl(slug: string, ref = "main"): string {
  return `https://github.com/fleetdm/fleet/blob/${ref}/ee/maintained-apps/outputs/${encodeURIComponent(slug)}/darwin.json`;
}

export function titleMatches(title: FleetCatalogTitle, term: string): boolean {
  const needle = term.trim().toLowerCase();
  if (needle === "") return true;
  return [title.name, title.bundleId, title.slug, title.latestVersion].some((value) =>
    value.toLowerCase().includes(needle)
  );
}

export type FleetEmpty =
  | "flagOff"
  | "neverChecked"
  | "neverRead"
  | "noneInstalled"
  | "noMatchInstalled"
  | "noMatch"
  | null;

/**
 * Why the table is empty, or null when it has rows.
 *
 * `visible` is what the search left of `catalog.items`. `neverRead` is a catalog with no
 * title after a failed check: the failure is the status line's to say, and the table says
 * only that there is nothing to list yet, never that Fleet lists nothing.
 */
export function emptyState(
  catalog: FleetCatalog,
  visible: readonly FleetCatalogTitle[],
  view: { searching: boolean; installedOnly: boolean }
): FleetEmpty {
  if (!catalog.enabled) return "flagOff";
  if (visible.length > 0) return null;
  if (statusOf(catalog.state) === "never") return "neverChecked";
  if ((catalog.state?.appCount ?? 0) === 0) return "neverRead";
  if (view.searching && catalog.items.length > 0) return view.installedOnly ? "noMatchInstalled" : "noMatch";
  if (view.installedOnly) return "noneInstalled";
  return "noMatch";
}

export type FleetSortKey = "name" | "bundleId" | "latestVersion" | "deviceCount" | "scopedCount" | "devicesBehind" | "versionChangedAt";
export type SortDir = "asc" | "desc";
/** Each title's Macs among those the device filter selects, by slug: the migration report's `fleetDeviceCounts`. */
export type ScopedCounts = Readonly<Record<string, number>>;

/** A title's *Macs in scope* (#905), or null when Fleet listed it after the counts were read. Own keys only. */
export function scopedCount(counts: ScopedCounts, slug: string): number | null {
  return Object.hasOwn(counts, slug) ? counts[slug] : null;
}

function sortValue(title: FleetCatalogTitle, key: FleetSortKey, counts: ScopedCounts): string | number {
  switch (key) {
    case "name":
      return title.name.toLowerCase();
    case "bundleId":
      return title.bundleId.toLowerCase();
    case "latestVersion":
      return title.latestVersion;
    case "deviceCount":
      return title.deviceCount;
    case "scopedCount":
      return scopedCount(counts, title.slug) ?? 0;
    case "devicesBehind":
      return title.devicesBehind;
    case "versionChangedAt":
      return movedAt(title) ?? "";
  }
}

/**
 * When the title's latest version arrived, as far as this instance can say (#838): the date the
 * version history gives Fleet's catalog taking it, else the move this instance saw, else null.
 */
export function movedAt(title: FleetCatalogTitle): string | null {
  return title.inCatalogSince ?? title.versionChangedAt;
}

export type FleetHistoryStatus = "none" | "ok" | "waiting" | "failed";

/** The version history line under the status: nothing read yet, reading, holding back, or a failure. */
export function historyStatusOf(state: FleetCatalogState | null): FleetHistoryStatus {
  if (state === null || state.historyOutcome === null || state.historyCheckedAt === null) return "none";
  if (state.historyOutcome === "ok") return "ok";
  return state.historyOutcome === "waiting" ? "waiting" : "failed";
}

/**
 * A new array, sorted; ties fall back to the name so the order is stable across reloads.
 *
 * By the date the version moved, a title with no date goes last in both directions: its
 * version has not moved while this instance was watching and its history is not read, which
 * is neither the oldest move nor the newest. By *Macs in scope*, a title `counts` does not
 * hold yet goes last the same way: it is neither the most nor the fewest.
 */
export function sortTitles(
  titles: readonly FleetCatalogTitle[],
  key: FleetSortKey,
  dir: SortDir,
  counts: ScopedCounts = {}
): FleetCatalogTitle[] {
  const sign = dir === "asc" ? 1 : -1;
  return [...titles].sort((a, b) => {
    if (key === "versionChangedAt" && (movedAt(a) === null) !== (movedAt(b) === null)) {
      return movedAt(a) === null ? 1 : -1;
    }
    if (key === "scopedCount" && (scopedCount(counts, a.slug) === null) !== (scopedCount(counts, b.slug) === null)) {
      return scopedCount(counts, a.slug) === null ? 1 : -1;
    }
    const left = sortValue(a, key, counts);
    const right = sortValue(b, key, counts);
    const order =
      typeof left === "number" && typeof right === "number"
        ? left - right
        : String(left).localeCompare(String(right), undefined, { numeric: true });
    return order !== 0 ? sign * order : a.name.localeCompare(b.name);
  });
}
