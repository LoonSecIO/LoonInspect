// Jamf only, deliberately (#79) — this union mirrors the backend's MdmProvider enum,
// which is the seam a second provider plugs into.
export type MdmProviderType = "jamf";
// "loonsecio" still arrives from the server on rows that stored it before the value
// was closed off; it can be displayed but no longer selected (see ConnectionForm).
export type PatchManagementProvider = "none" | "jamf" | "loonsecio";

export interface ProviderCredentialField {
  key: string;
  label: string;
  secret: boolean;
}

export interface ProviderInfo {
  provider: MdmProviderType;
  credentialFields: ProviderCredentialField[];
  /** Jamf's own privilege names, served from app.mdm.jamf.privileges. Rendered
   *  verbatim and never translated — they are what gets typed into Jamf's API Role
   *  editor, which searches on the English strings. */
  requiredPrivileges: string[];
}

export interface MdmConnection {
  id: number;
  name: string;
  provider: MdmProviderType;
  baseUrl: string;
  isActive: boolean;
  patchManagementProvider: PatchManagementProvider;
  loonsecioDataSharingEnabled: boolean;
  credentialFieldsSet: string[];
  hasWebhookSecret: boolean;
  hasLoonsecioLicenseKey: boolean;
  userAgentOverride: string | null;
  sweepPageSize: number | null;
  capabilityDevices: boolean;
  capabilityUsers: boolean;
  capabilityWebhooks: boolean;
  capabilityJamfPro: boolean;
  lastSuccessfulAuthAt: string | null;
  credentialsRotatedAt: string | null;
  credentialsFingerprint: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface MdmConnectionInput {
  name: string;
  provider: MdmProviderType;
  baseUrl: string;
  isActive?: boolean;
  credentials?: Record<string, string>;
  webhookSecret?: string;
  patchManagementProvider?: PatchManagementProvider;
  userAgentOverride?: string;
  sweepPageSize?: number | null;
  capabilityDevices?: boolean;
  capabilityUsers?: boolean;
  capabilityWebhooks?: boolean;
  capabilityJamfPro?: boolean;
}

export interface MdmConnectionTestInput {
  connectionId?: number;
  provider: MdmProviderType;
  baseUrl: string;
  clientId: string;
  clientSecret?: string;
  userAgentOverride?: string;
}

export interface MdmConnectionTestResult {
  success: boolean;
  message: string;
  detail?: string;
}

export type SyncStatusValue = "idle" | "syncing" | "failed";

export interface MdmSyncStatus {
  mdmConnectionId: number;
  provider: MdmProviderType;
  lastSyncAt: string | null;
  status: SyncStatusValue;
  deviceCount: number;
}

export interface MdmSyncTriggerResult {
  connectionId: number;
  /** The run to poll: getRun / getRunLog. */
  jobId: string;
  status: SyncStatusValue;
  /** False when this click joined a sweep that was already running rather than starting
   *  one. Contention is a 202 with the in-flight run's jobID, not a 409 — someone
   *  clicking during a cron sweep wants to see the fleet syncing, and the running
   *  sweep's log answers that better than an error. */
  started: boolean;
}

// --- Runs (#31): the object a pull happens inside ------------------------------------

export type RunStatus = "running" | "succeeded" | "failed";

export interface Run {
  /** The jobID, stamped on every event this run produced. */
  id: string;
  mdmConnectionId: number;
  collectionId: number | null;
  trigger: "sweep" | "manual" | "webhook";
  comparison: "baseline" | "delta";
  lockClass: "device_sweep" | "catalog" | "webhook";
  status: RunStatus;
  windowStart: string;
  windowEnd: string | null;
  startedAt: string;
  finishedAt: string | null;
  heartbeatAt: string;
  deviceCount: number;
  groupCount: number;
  /** Failure accounting (#92): processed + failed = deviceCount (attempted). A run
   *  can be `succeeded` with devicesFailed > 0 — isolated device failures inside the
   *  sweep's tolerance. */
  devicesProcessed: number;
  devicesFailed: number;
  observations: Record<string, number> | null;
  error: string | null;
  actorLabel: string | null;
}

export interface RunLogLine {
  id: number;
  ts: string;
  level: string;
  message: string;
  fields: Record<string, unknown> | null;
}

export interface RunLogResponse {
  run: Run;
  lines: RunLogLine[];
  /** The poller stops on this rather than on an empty page — a sweep mid-fleet can
   *  produce no new lines for a minute and still be running. */
  complete: boolean;
}

// --- Collections (#27): what to collect from a connection, and when -----------------

export type CollectionKind = "device_sweep" | "catalog" | "webhook";
export type CollectionFrequency = "hourly" | "daily" | "weekly" | "every_n_days";

export interface Collection {
  id: number;
  mdmConnectionId: number;
  name: string;
  kind: CollectionKind;
  enabled: boolean;
  sections: string[];
  selector: string | null;
  pageSize: number | null;
  quarantinedExtensionAttributes: string[];
  frequency: CollectionFrequency | null;
  intervalN: number | null;
  atHour: number | null;
  atMinute: number | null;
  weekday: number | null;
  timezone: string | null;
  nextDueAt: string | null;
  lastRunAt: string | null;
  lastRunStatus: string | null;
  lastRunSummary: Record<string, unknown> | null;
  createdAt: string;
  updatedAt: string;
}

export interface CollectionInput {
  name: string;
  kind: CollectionKind;
  enabled?: boolean;
  sections?: string[];
  selector?: string | null;
  pageSize?: number | null;
  quarantinedExtensionAttributes?: string[];
  frequency?: CollectionFrequency | null;
  intervalN?: number | null;
  atHour?: number | null;
  atMinute?: number | null;
  weekday?: number | null;
  timezone?: string | null;
}

export interface SectionInfo {
  name: string;
  jamfSection: string;
  kind: "scalar" | "list";
  entryKind: string | null;
  // One of the five inventory-display sections extension attributes nest under; it is
  // read whenever `extension_attributes` is (#197).
  carriesExtensionAttributes: boolean;
}

export interface CollectionRunResult {
  collectionId: number;
  status: string;
}
