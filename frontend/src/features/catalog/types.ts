import type { AppUpdate, AppVulnerability } from "@/features/vulnerabilities/types";

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
  /** #313 — what the wire has carried since #311. The fold of `basis` across the matches:
   *  true when a title's requirements tested an extension attribute and the judging, which
   *  has no device facts, read it as passing; null on a row judged before the column
   *  existed, and never defaulted to false. */
  eaAssumed: boolean | null;
  /** Which of `jamfTitles` `patchState` / `latestVersion` are about, and which one #68's
   *  sentence is about — routinely different titles on a multi-title app. Stored on every
   *  answered row; a page names a subject only when several titles matched. */
  referenceTitleId: string | null;
  sentenceTitleId: string | null;
  releasedAt: string | null;
  evaluatedAt: string | null;
  /** What the judgement was made against, for a title attribute (#299). */
  evaluatedSignature: string | null;
  /** LoonInspect's own answer about this exact build — `covered`, `unknown_app` or `off`
   *  (#251). Always present; the shape is what says which of the three it is. */
  vuln: AppVulnerability;
  /** What updating this build to `latestVersion` would do to the findings above (#482).
   *  `null` whenever there is nothing to say — not `covered`, no target judged, or this
   *  build already IS the target — and never a zero. */
  vulnUpdate: AppUpdate | null;
  /** *Seen here* (#591): days since the oldest OPEN finding-ledger row on this build — §4d's second clock, this pod's
   *  first observation as against the world's publication date. `null` where the ledger holds no open row, which a
   *  surface prints as a dash and never as 0, and `undefined` on a response whose list does not draw the column. */
  seenHereDays?: number | null;
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
  /** Whether ANY row of this tenant has been judged by the epoch that is answering (#529).
   *  `false` with a corpus loaded is the hour after an epoch moves: every row reads
   *  `unknown_app`, so a list of them is honest only as *not yet judged against*. */
  vulnJudged: boolean;
}

export type CatalogJamfFilter = "all" | "matched" | "unmatched";

/** The stored answer as a filter (#529). `unknown_app` is the ruled spelling (§4b) and is
 *  SERVED: a row judged by an epoch that has moved reads it whatever its counts say.
 *  `patchable` is narrower still (#532): served, carrying findings, and with a target the
 *  epoch holds a row for that closes more than it opens. */
export type CatalogVulnFilter = "all" | "findings" | "kev" | "unknown_app" | "clean" | "patchable";
export type CatalogBand = "critical" | "high" | "medium" | "low";
/** `exposure` is KEV first, then Macs, then findings; `age` is the oldest publication first;
 *  `payoff` is findings closed × Macs carrying the build (#532). */
export type CatalogOrder = "exposure" | "age" | "payoff";

/** `GET /api/catalog/lookup` for one key: the tenant's row if the fleet has shown the app.
 *  Under `appHash` the row stands in for the newest version seen, which is why it carries
 *  no `vuln` (#251); the Devices page reads only the name and version off it (#299). */
export interface CatalogLookup {
  key: string;
  tenant: { name: string; bundleId: string; version: string } | null;
}
