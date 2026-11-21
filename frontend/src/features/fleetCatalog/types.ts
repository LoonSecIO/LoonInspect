/** `ok` and `unchanged` are answers; the other three are a check that got none (#794). */
export type FleetCatalogOutcome = "ok" | "unchanged" | "refused" | "unreachable" | "unexpected";

/** The version history read's words (#838). `waiting` is leaving GitHub's last requests of the hour
 *  to the daily check and other tools, and carries on by itself. */
export type FleetHistoryOutcome = "ok" | "waiting" | "refused" | "unreachable" | "unexpected";

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
  /** The last version history read, background or a person's (#838). All null before the first. */
  historyCheckedAt: string | null;
  historyOutcome: FleetHistoryOutcome | null;
  /** The server's sentence for `waiting` and the failures. */
  historyDetail: string | null;
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
  /** From the version history (#838): when Fleet's catalog first carried the latest version, and the
   *  version it replaced. Null until the history is read, and where it could not date the latest. */
  inCatalogSince: string | null;
  versionBefore: string | null;
  /** When this instance last read the title's history; null: never. */
  historyReadAt: string | null;
}

export interface FleetVersion {
  version: string;
  /** When Fleet's catalog took the version (its first commit carrying it), not the vendor's release. */
  seenAt: string;
  commitSha: string;
  /** The version it replaced; null at the title's first change. */
  previousVersion: string | null;
}

/** One title's version history as the instance holds it (#838). */
export interface FleetTitleHistory {
  slug: string;
  name: string;
  latestVersion: string;
  historyReadAt: string | null;
  /** The oldest and newest change the reads reached. */
  historySince: string | null;
  historyThrough: string | null;
  /** Whether the oldest is the title's first change in Fleet's history. */
  historyComplete: boolean;
  /** What the last read left undated or could not read. */
  historyDetail: string | null;
  /** Newest first. */
  versions: FleetVersion[];
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
  /** Of those, the titles whose version history the instance has read. */
  installedTitlesWithHistory: number;
}
