export interface JamfPatchTitle {
  id: string;
  name: string;
  publisher: string | null;
  appName: string | null;
  bundleId: string | null;
  currentVersion: string;
  lastModified: string;
  syncedAt: string;
}

export interface JamfPatchTitleListResponse {
  items: JamfPatchTitle[];
  total: number;
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

export interface JamfPatchTitleDetail extends JamfPatchTitle {
  patches: JamfPatchVersion[];
  requirements: JamfPatchRequirementGroup[];
}
