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
  /** The platform the row was seen on and judged as (#236); a row that is not `macos`
   *  carries no Jamf answer by construction — not matchable, not merely unmatched. */
  platform: string;
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
  /** What the judgement was made against, for a title attribute (#299). */
  evaluatedSignature: string | null;
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
  /** The page and page size echoed, as every paged list does (#137). */
  page: number;
  pageSize: number;
  /** `null` when the list was scoped to one application (`appHash`, #299): a scoped join
   *  would make the four tenant-wide tiles wrong rather than partial. */
  summary: CatalogSummary | null;
  /** The corpus generation every `vuln` block on `items` came from. `null` means no corpus
   *  is loaded, which is why every row reads `off` — the page says that in words (#251). */
  corpusAsOf: string | null;
}

export type CatalogJamfFilter = "all" | "matched" | "unmatched";

/** `GET /api/catalog/lookup` for one key: the tenant's row if the fleet has shown the app.
 *  Under `appHash` the row stands in for the newest version seen, which is why it carries
 *  no `vuln` (#251); the Devices page reads only the name and version off it (#299). */
export interface CatalogLookup {
  key: string;
  tenant: { name: string; bundleId: string; version: string } | null;
}
