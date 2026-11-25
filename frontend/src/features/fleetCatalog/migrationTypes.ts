import type { PatchRule, PolicyVersion } from "@/features/jamfPatch/types";

// `GET /fleet-catalog/migration` and its two detail answers (#895–#899), each interface named for the
// OpenAPI schema it mirrors. The server sends every field, and none holds a sentence: the page words
// each code. A null count is "not assessed", never 0.

export type PolicyState = "within" | "out" | "exempt" | "unassessed";
export type ReviewPriority = "review_now" | "plan_update" | "review_identity" | "monitor";
export type PriorityReason = "none_behind" | "unordered" | "identity" | "out_of_policy" | "kev" | "comparable";
export type PolicyUnassessed = "identity" | "no_jamf_title" | "no_rule" | "not_judged";
export type EvidenceAssessment = "off" | "unknown_app" | "partial" | "covered";
export type ImpactUnavailable = "catalog_incomplete" | "no_fleet_title" | "identity_review" | "unordered_target";

/** `MigrationScope`: the Macs the device filter allows (eligible) and keeps (selected). The rest of the
 *  answer counts only the selected Macs. */
export interface MigrationScope {
  eligibleMacs: number;
  selectedMacs: number;
  unknownContactMacs: number;
  unknownInventoryMacs: number;
}

/** `FleetCandidate`: a Fleet title carrying the app's bundle ID. */
export interface FleetCandidate {
  slug: string;
  name: string;
  bundleId: string;
  latestVersion: string;
}

/** `LocalApp`: one installed identity, name and bundle ID. */
export interface MigrationItem {
  appHash: string;
  name: string;
  bundleId: string;
  macs: number;
  versionCount: number;
  match: "exact" | "ambiguous" | "none" | "unknown";
  hasJamfMatch: boolean;
  jamfEvaluated: boolean;
  fleetCandidates: FleetCandidate[];
}

/** `InstalledEvidence`, counting builds. The finding counts are null under `off` and `unknown_app`. */
export interface InstalledEvidence {
  assessment: EvidenceAssessment;
  asOf: string | null;
  assessedBuilds: number;
  unknownBuilds: number;
  affectedBuilds: number | null; highOrCriticalBuilds: number | null; kevBuilds: number | null;
}

/** `FleetBuildAssessmentOut`. The ID lists need `vuln:read`. `policyUnassessed` says why a build reads
 *  `unassessed`; `policyRule` and `policyVerdict`, the Jamf Patch title's, are set for `within` and `out`. */
export interface FleetBuildAssessment {
  name: string;
  version: string;
  deviceCount: number;
  comparison: "exact" | "net_only" | "off" | "unknown_source" | "unknown_target" | "ambiguous";
  addresses: number | null; introduces: number | null; remains: number | null; net: number | null;
  addressedIds: string[] | null; introducedIds: string[] | null; remainingIds: string[] | null;
  installedKev: number | null;
  policyState: PolicyState;
  policySource: "default" | "override" | null;
  policyUnassessed: PolicyUnassessed | null;
  policyTitleId: string | null;
  policyRule: PatchRule | null;
  policyVerdict: PolicyVersion | null;
  policyDueAt: string | null;
}

/** `FleetAssessmentOut`: an app's or a title's builds against a Fleet target. `builds` is empty on the list. */
export interface FleetAssessment {
  targetVersion: string;
  priority: ReviewPriority;
  priorityReason: PriorityReason;
  management: "recurring" | "one_time" | "observe";
  recentVersions: number | null;
  corpusAsOf: string | null;
  oldestGapDays: number | null;
  // Builds, by the comparison against the target and by the patch rule's verdict.
  behindBuilds: number; unorderedBuilds: number; exactBuilds: number; netOnlyBuilds: number; unknownBuilds: number;
  outOfPolicyBuilds: number; withinPolicyBuilds: number; policyExemptBuilds: number; policyUnassessedBuilds: number;
  kevBuilds: number | null; addresses: number | null; introduces: number | null; remains: number | null;
  builds: FleetBuildAssessment[];
}

/** `ReportContext`, which both answers extend. Both records are keyed by `appHash`; `appAssessments`
 *  holds the `exact` apps only. */
interface MigrationEvidence {
  enabled: boolean;
  asOf: string;
  scope: MigrationScope;
  fleetCatalogReady: boolean;
  fleetCatalogReadiness: "unread" | "partial" | "complete";
  jamfCatalogReady: boolean;
  installedEvidence: Record<string, InstalledEvidence>;
  appAssessments: Record<string, FleetAssessment>;
}

/** `MigrationReport`: the list. `fleetDeviceCounts` is keyed by Fleet title slug. */
export interface MigrationPortfolio extends MigrationEvidence {
  fleetDeviceCounts: Record<string, number>;
  items: MigrationItem[];
}

/** `InstalledBuild`. */
export interface InstalledBuild {
  appHash: string;
  versionHash: string;
  version: string;
  shortVersion: string | null;
  macs: number;
}

/** `VersionImpact`: each Mac counted once, as older than the target, at or above it, or unknown. */
export interface MigrationImpact {
  targetVersion: string;
  installedMacs: number;
  olderMacs: number; atOrAboveMacs: number; unknownMacs: number;
}

/** `MigrationDetail`: one app (`item`) or Fleet title (`title`). `impactUnavailable` is set when `impact` is
 *  null; `assessments` holds the title route's one, by slug. #907 types #900's observed upgrades. */
export interface MigrationDetail extends MigrationEvidence {
  item: MigrationItem | null;
  title: FleetCandidate | null;
  items: MigrationItem[];
  builds: InstalledBuild[];
  jamfTitles: { id: string; name: string }[];
  installedMacs: number;
  impact: MigrationImpact | null;
  impactUnavailable: ImpactUnavailable | null;
  assessments: Record<string, FleetAssessment>;
}
