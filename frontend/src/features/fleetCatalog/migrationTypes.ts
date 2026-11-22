/** Tenant-scoped results from /fleet-catalog/migration, evaluated at one inventory cutoff. */
export interface FleetCandidate {
  slug: string;
  bundleId: string;
  name: string;
  latestVersion: string;
}

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

export interface MigrationScope {
  connectionId: number | null;
  clock: "contact" | "inventory";
  days: number | null;
  eligibleMacs: number;
  activeMacs: number;
  staleMacs: number;
  unknownMacs: number;
}

export interface FleetBuildAssessment {
  name: string;
  version: string;
  deviceCount: number;
  comparison: "exact" | "net_only" | "off" | "unknown_source" | "unknown_target" | "ambiguous";
  addressedIds: string[] | null;
  introducedIds: string[] | null;
  remainingIds: string[] | null;
  addresses: number | null;
  introduces: number | null;
  remains: number | null;
  net: number | null;
  installedKev: number | null;
  policyState: "within" | "out" | "exempt" | "unassessed";
  policySource: "default" | "override" | null;
  policyReason: string;
  policyDueAt: string | null;
}

export interface FleetAssessment {
  targetVersion: string;
  oldestGapDays?: number | null;
  management: "recurring" | "one_time" | "observe";
  managementReason: string;
  recentVersions: number | null;
  historyReadAt: string | null;
  historySince: string | null;
  historyThrough: string | null;
  historyComplete: boolean;
  historyDetail: string | null;
  priority: "review_now" | "plan_update" | "review_identity" | "monitor";
  reason: string;
  corpusAsOf: string | null;
  behindBuilds: number;
  unorderedBuilds: number;
  exactBuilds: number;
  netOnlyBuilds: number;
  unknownBuilds: number;
  outOfPolicyBuilds: number;
  withinPolicyBuilds: number;
  policyExemptBuilds: number;
  policyUnassessedBuilds: number;
  kevBuilds: number | null;
  addresses: number | null;
  introduces: number | null;
  remains: number | null;
  builds: FleetBuildAssessment[];
}

export interface InstalledEvidence {
  assessedBuilds: number;
  unknownBuilds: number;
  affectedBuilds: number;
  highOrCriticalBuilds: number;
  kevBuilds: number;
  asOf: string | null;
}

interface MigrationEvidence {
  enabled: boolean;
  asOf: string;
  fleetCatalogReady: boolean;
  fleetCatalogReadiness?: "unread" | "partial" | "complete";
  jamfCatalogReady: boolean;
  scope: MigrationScope;
  assessments: Record<string, FleetAssessment>;
  appAssessments: Record<string, FleetAssessment>;
  installedEvidence: Record<string, InstalledEvidence>;
}

export interface MigrationPortfolio extends MigrationEvidence {
  fleetDeviceCounts: Record<string, number>;
  connections: { id: number; name: string }[];
  items: MigrationItem[];
}

export interface InstalledBuild {
  appHash: string;
  versionHash: string;
  version: string;
  shortVersion: string | null;
  macs: number;
}

export interface MigrationImpact {
  targetVersion: string;
  installedMacs: number;
  olderMacs: number;
  atOrAboveMacs: number;
  unknownMacs: number;
}

export interface MigrationDetail extends MigrationEvidence {
  installedMacs: number;
  observedChanges: {
    windowDays: number;
    versionChanges: number;
    macs: number;
    firstAt: string | null;
    lastAt: string | null;
    adoptionSamples: number;
    medianDaysAfterFleetPublication: number | null;
  };
  builds: InstalledBuild[];
  jamfTitles: { id: string; name: string }[];
  impact: MigrationImpact | null;
  item: MigrationItem | null;
  title: FleetCandidate | null;
  items: MigrationItem[];
}
