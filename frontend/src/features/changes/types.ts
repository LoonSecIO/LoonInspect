export type ChangeLevel = "high" | "normal" | "low";

export interface DeviceChange {
  id: number;
  mdmConnectionId: number;
  subjectKind: string;
  subjectId: string;
  subjectLabel: string | null;
  serialNumber: string | null;
  udid: string | null;
  spanId: string | null;
  previousSpanId: string | null;
  observedAt: string;
  collectedAt: string;
  trigger: string;
  section: string;
  field: string | null;
  entryKind: string | null;
  entryIdentity: Record<string, unknown> | null;
  entryLabel: string | null;
  change: "changed" | "added" | "removed" | "updated";
  oldValue: Record<string, unknown> | null;
  newValue: Record<string, unknown> | null;
  level: ChangeLevel;
  details: Record<string, unknown> | null;
  policyVersion: string;
}

export interface DeviceChangeListResponse {
  items: DeviceChange[];
  total: number;
  page: number;
  pageSize: number;
}

export interface ChangeFilters {
  q?: string;
  /** The changed thing, not the device: an app name or bundle id, a username, an entry label. */
  artifact?: string;
  /** Exact match. What the Changes page's dropdown means, and what bookmarked URLs carry. */
  level?: ChangeLevel;
  /** This level and above (#107). Mutually exclusive with `level` — the API answers 422
   *  for both, rather than returning the empty intersection as if nothing had happened. */
  minLevel?: ChangeLevel;
  section?: string;
  /** Absolute ISO instant. The feed's anchor, carried into every click-through so a
   *  shared link reproduces the window the sender saw. */
  since?: string;
  connectionId?: number;
  subjectId?: string;
  page?: number;
  pageSize?: number;
}

export interface PolicyField {
  key: string;
  field: string;
  label: string;
  level: ChangeLevel;
  why: string;
  default: boolean;
  enabled: boolean;
  overridden: boolean;
}

export interface PolicyEntryField {
  name: string;
  label: string;
  level: ChangeLevel;
  why: string;
  enabled: boolean;
  overridden: boolean;
}

export interface PolicyEntry {
  kind: string;
  section: string;
  label: string;
  level: ChangeLevel;
  why: string;
  identity: string[];
  added: boolean;
  removed: boolean;
  overridden: boolean;
  fields: PolicyEntryField[];
}

export interface ChangePolicy {
  version: string;
  minimumLevel: ChangeLevel;
  systemAppsIndividually: boolean;
  mutedGroups: string[];
  mutedExtensionAttributes: string[];
  sections: { section: string; fields: PolicyField[] }[];
  entries: PolicyEntry[];
  knownGroups: { id: string; name: string | null }[];
  knownExtensionAttributes: { definitionId: string; name: string | null }[];
  updatedAt: string | null;
}

export interface ChangePolicyUpdate {
  minimumLevel: ChangeLevel;
  fields: Record<string, boolean>;
  entries: Record<string, boolean>;
  systemAppsIndividually: boolean;
  mutedGroups: string[];
  mutedExtensionAttributes: string[];
}
