export interface JamfPatchTitle {
  id: string;
  name: string;
  publisher: string | null;
  appName: string | null;
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
}

export interface JamfPatchTitleListResponse {
  items: JamfPatchTitle[];
  total: number;
  /** The page and page size echoed, as every paged list does (#137). */
  page: number;
  pageSize: number;
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
}
