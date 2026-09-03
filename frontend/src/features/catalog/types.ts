import type { AppVulnerability } from "@/features/vulnerabilities/types";

export interface CatalogTitleRef {
  id: string;
  name: string;
}

/** One row of the tenant app catalog: a distinct (name, bundle ID, version) the fleet has shown. */
export interface CatalogEntry {
  id: number;
  name: string;
  bundleId: string;
  version: string;
  shortVersion: string | null;
  appHash: string;
  versionHash: string;
  keyTitle: string;
  keyFull: string;
  firstSeenAt: string;
  lastSeenAt: string;
  deviceCount: number;
  jamfTitleIds: string[] | null;
  jamfTitles: CatalogTitleRef[];
  patchState: "latest" | "behind" | "ahead" | "unknown" | null;
  isLatest: boolean | null;
  patchAvailable: boolean | null;
  patchAvailableSince: string | null;
  /** Listed versions newer than the installed one, on the title that dates patchAvailableSince (#68). */
  releasesMissed: number | null;
  thisVersionSeen: boolean | null;
  latestVersion: string | null;
  latestReleasedAt: string | null;
  releasedAt: string | null;
  evaluatedAt: string | null;
  /** LoonInspect's own answer about this exact build — `covered`, `unknown_app` or `off`
   *  (#251). Always present; the shape is what says which of the three it is. */
  vuln: AppVulnerability;
}

export interface CatalogSummary {
  entries: number;
  installed: number;
  matched: number;
  unmatched: number;
}

export interface CatalogListResponse {
  items: CatalogEntry[];
  total: number;
  summary: CatalogSummary;
  /** The corpus generation every `vuln` block on `items` came from. `null` means no corpus
   *  is loaded, which is why every row reads `off` — the page says that in words (#251). */
  corpusAsOf: string | null;
}

export type CatalogJamfFilter = "all" | "matched" | "unmatched";
