import type { Provider } from "@/features/ai/api";

export type ChangeLevel = "high" | "normal" | "low";

/** `device_changes.change`. A list section's entry is added, removed or updated; a
 *  scalar section's field is changed. `CHANGE_KINDS` in render.ts is the same four, in
 *  the order the page offers them. */
export type ChangeKind = "added" | "removed" | "updated" | "changed";

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
  change: ChangeKind;
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
  /** Exact match on the row's change kind. "List new application installs" is
   *  Applications and `added`; without it that question listed every update too. */
  change?: ChangeKind;
  /** Absolute ISO instant. The feed's anchor, carried into every click-through so a
   *  shared link reproduces the window the sender saw. */
  since?: string;
  connectionId?: number;
  subjectId?: string;
  /** `computer` | `computer_group` | …: without it `subjectId=42` merges computer 42 with
   *  smart group 42, which is why the device page sends all three keys (#300). */
  subjectKind?: string;
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

/** Why the Prompt bar is hidden, checked in this order: the AI flag, the AI-inference
 *  consent, then at least one provider saved in Settings › AI. */
export type PromptHiddenReason = "flag_off" | "consent_off" | "no_provider";

export interface PromptStatus {
  available: boolean;
  reason: PromptHiddenReason | null;
  /** Saved providers, provider and model only — never a URL or a key. */
  providers: { provider: Provider; model: string }[];
}

export interface PromptRequest {
  question: string;
  provider?: Provider | null;
}

/** The page's own filter vocabulary — the URL keys of the Changes page. Null means "any". */
export interface PromptFilters {
  q: string | null;
  artifact: string | null;
  level: ChangeLevel | null;
  section: string | null;
  change: ChangeKind | null;
}

/** One computer the filters match, counted by Postgres — never by the model. */
export interface PromptDevice {
  connectionId: number;
  subjectId: string;
  label: string | null;
  serial: string | null;
  added: number;
  removed: number;
  updated: number;
  changed: number;
}

export interface PromptSummary {
  /** Every matching change row, computers and everything else. */
  total: number;
  devicesTotal: number;
  /** More computers matched than `devices` carries (at most 25). */
  truncated: boolean;
  /** Matching rows on smart groups and definitions rather than computers. */
  otherSubjects: number;
  devices: PromptDevice[];
}

export interface PromptError {
  kind: string;
  message: string;
  status: number | null;
}

/** `error`: the endpoint failed. `unparseable`: it answered, but not with filter settings. */
export type PromptOutcome = "applied" | "error" | "unparseable";

export interface PromptResult {
  outcome: PromptOutcome;
  filters: PromptFilters | null;
  /** The one model-authored string that reaches the page. Plain text, always. */
  unsupported: string | null;
  repairs: string[];
  summary: PromptSummary | null;
  provider: Provider;
  model: string;
  destination: string;
  latencyMs: number;
  error: PromptError | null;
}
