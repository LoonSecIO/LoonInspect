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

export type FleetSortKey = "name" | "bundleId" | "latestVersion" | "deviceCount" | "devicesBehind" | "versionChangedAt";
export type SortDir = "asc" | "desc";

function sortValue(title: FleetCatalogTitle, key: FleetSortKey): string | number {
  switch (key) {
    case "name":
      return title.name.toLowerCase();
    case "bundleId":
      return title.bundleId.toLowerCase();
    case "latestVersion":
      return title.latestVersion;
    case "deviceCount":
      return title.deviceCount;
    case "devicesBehind":
      return title.devicesBehind;
    case "versionChangedAt":
      return title.versionChangedAt ?? "";
  }
}

/**
 * A new array, sorted; ties fall back to the name so the order is stable across reloads.
 *
 * By the date the version moved, a title with no date goes last in both directions: its
 * version has not moved while this instance was watching, which is neither the oldest
 * move nor the newest.
 */
export function sortTitles(
  titles: readonly FleetCatalogTitle[],
  key: FleetSortKey,
  dir: SortDir
): FleetCatalogTitle[] {
  const sign = dir === "asc" ? 1 : -1;
  return [...titles].sort((a, b) => {
    if (key === "versionChangedAt" && (a.versionChangedAt === null) !== (b.versionChangedAt === null)) {
      return a.versionChangedAt === null ? 1 : -1;
    }
    const left = sortValue(a, key);
    const right = sortValue(b, key);
    const order =
      typeof left === "number" && typeof right === "number"
        ? left - right
        : String(left).localeCompare(String(right), undefined, { numeric: true });
    return order !== 0 ? sign * order : a.name.localeCompare(b.name);
  });
}
