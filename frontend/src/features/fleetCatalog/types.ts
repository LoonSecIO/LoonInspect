/** `ok` and `unchanged` are answers; the other three are a check that got none (#794). */
export type FleetCatalogOutcome = "ok" | "unchanged" | "refused" | "unreachable" | "unexpected";

/** What the last check of Fleet's catalog found. Null on the response before the first check. */
export interface FleetCatalogState {
  /** When GitHub was last asked, whatever it answered. */
  checkedAt: string | null;
  /** When the titles held here last changed: older than `checkedAt` after a quiet day or a failed check. */
  changedAt: string | null;
  outcome: FleetCatalogOutcome | null;
  /** The server's sentence: on a failed check what failed and what to check; on `ok`, manifests it skipped. */
  detail: string | null;
  appCount: number;
}

export interface FleetCatalogTitle {
  slug: string;
  name: string;
  bundleId: string;
  latestVersion: string;
  /** Both null until the version moves while this instance is watching. */
  previousVersion: string | null;
  versionChangedAt: string | null;
  firstSeenAt: string;
  deviceCount: number;
  /** Macs with any copy older than Fleet's latest, and the rest. Served as a pair, never subtracted here. */
  devicesBehind: number;
  devicesCurrent: number;
}

export interface FleetCatalog {
  /** The `fleet_maintained_apps` flag for this organization. */
  enabled: boolean;
  source: string;
  state: FleetCatalogState | null;
  items: FleetCatalogTitle[];
  total: number;
  page: number;
  pageSize: number;
  /** Titles with at least one Mac, whatever the search or the toggle hid. */
  installedTitles: number;
}
