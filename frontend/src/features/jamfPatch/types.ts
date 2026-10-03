import type { AppVulnerability } from "@/features/vulnerabilities/types";

export interface JamfPatchTitle {
  id: string;
  name: string;
  publisher: string | null;
  appName: string | null;
  /** Where `appName` came from (#478): `jamf`, `kill_apps`, `unnamed`, or null on a title
   *  stored before #385's rule existed. Widened to `string` on purpose — a value this
   *  build does not know shows the name and claims nothing (`appNameMarker.ts`). */
  appNameSource: string | null;
  bundleId: string | null;
  currentVersion: string;
  lastModified: string;
  syncedAt: string;
  /** Tenant-scoped: distinct devices with an app matched to this title, and how many are on currentVersion. */
  deviceCount: number;
  devicesOnLatest: number;
  /** Devices whose matched app is behind this title's current version — the honest
   *  laggard count since #314, which excludes devices *ahead* of the catalog. */
  devicesBehind: number;
  /** Distinct devices out of the organization's confirmed patching rule. **Null is not
   *  zero**: nothing judges this title — no rule is confirmed, or it is exempt. */
  devicesOutOfPolicy: number | null;
  /** Which rule judged the title, `exempt`, or null when nothing does. */
  policySource: "default" | "override" | "exempt" | null;
}

/** The closed vocabulary a patching rule is written in (`app.mdm.patch.policy`). A null
 *  limit is not set; either limit exceeded puts a build out of policy. */
export interface PatchRule {
  /** Out of policy once a newer release has been listed for more than this many days. */
  maxDaysBehind: number | null;
  /** Out of policy when more than this many listed releases are newer. */
  maxReleasesBehind: number | null;
  /** The days limit for a build carrying a critical or high finding, in place of
   *  `maxDaysBehind` for that build. Never longer than it. A build the corpus has not
   *  assessed is not severe and is judged by the ordinary limit. */
  maxDaysBehindSevere: number | null;
}

/** One title's own rule, which replaces the organization's for that title. */
export interface PatchRuleOverride extends PatchRule {
  titleId: string;
  /** Null when the catalog no longer lists the title. */
  titleName: string | null;
  exempt: boolean;
}

export interface PatchingRules {
  default: PatchRule | null;
  overrides: PatchRuleOverride[];
  updatedAt: string | null;
  updatedBy: string | null;
}

/** One version of a title against the rule that judges it. */
export interface PolicyVersion {
  state: "within" | "out" | "not_judged";
  reason: "days" | "releases" | null;
  /** When it went out of policy by the days limit; null under the releases limit. */
  since: string | null;
  daysBehind: number | null;
  releasesBehind: number | null;
  /** The days limit this version was judged by: the severe one or the ordinary one. */
  limitDays: number | null;
  /** Whether the build carries a critical or high finding. Null where the corpus has not
   *  assessed it, and wherever the rule has no severe limit. */
  severe: boolean | null;
}

export interface TitlePolicy extends PatchRule {
  source: "default" | "override";
  exempt: boolean;
  /** Whether a corpus answers for this organization, where the rule has a severe limit;
   *  null where it has none. False: the severe limit is judging nothing. */
  severityAnswering: boolean | null;
  /** Listed versions and the unlisted ones a device is on; empty for an exempt title. */
  versions: Record<string, PolicyVersion>;
}

export interface JamfPatchTitleListResponse {
  items: JamfPatchTitle[];
  total: number;
  /** The page and page size echoed, as every paged list does (#137). */
  page: number;
  pageSize: number;
  /** Whether a corpus answers for this organization, where a confirmed rule has a limit for
   *  builds with critical or high findings; null where none does. */
  severityAnswering: boolean | null;
}

/** `GET /api/jamf-patch/coverage` (#109): the posture recorder's own pair counts, live. */
export interface JamfPatchCoverage {
  pairsTotal: number;
  pairsOnLatest: number;
}

export interface JamfPatchSyncResult {
  synced: number;
}

export interface JamfPatchVersion {
  version: string;
  releaseDate?: string;
  [key: string]: unknown;
}

export interface JamfPatchRequirementTest {
  name: string;
  operator: string;
  value: string;
  type: string;
}

export interface JamfPatchRequirementGroup {
  operator: string;
  tests: JamfPatchRequirementTest[];
}

export interface JamfPatchExtensionAttribute {
  key: string;
  displayName?: string | null;
}

export interface JamfPatchTitleDetail extends JamfPatchTitle {
  patches: JamfPatchVersion[];
  requirements: JamfPatchRequirementGroup[];
  extensionAttributes?: JamfPatchExtensionAttribute[] | null;
  /** Installed version → distinct devices, for the apps matched to this title. */
  versionDeviceCounts: Record<string, number>;
  /** Listed version → the corpus's answer for that build. Empty, with `corpusAsOf` null,
   *  when nothing answers for this organization; otherwise every listed version has a key. */
  versionVulns: Record<string, AppVulnerability>;
  corpusAsOf: string | null;
  /** The rule judging this title and each version's verdict; null when nothing judges it. */
  policy: TitlePolicy | null;
}

/** The org's stated patching policy (#116): typed text read beside the evidence, never a
 *  threshold. `statement` is "" when nothing has been stated. `rules` is what a build is
 *  judged against, once someone confirms one; `updatedAt`/`updatedBy` are the statement's. */
export interface PatchingPolicy {
  statement: string;
  updatedAt: string | null;
  updatedBy: string | null;
  rules: PatchingRules;
}
