import type { AppVulnerability } from "@/features/vulnerabilities/types";

export interface Device {
  id: number;
  mdmProvider: string;
  mdmConnectionId: number | null;
  externalId: string;
  /** Which Jamf ID space `externalId` names the device in (#233): `macos` today. */
  platform: string;
  serialNumber: string;
  hostname: string;
  lastSeenAt: string | null;
  lastCheckIn: string | null;
  lastInventoryAt: string | null;
  managed: boolean | null;
  supervised: boolean | null;
  osVersion: string | null;
  site: string | null;
  /** Both halves of the same fact (`schemas/devices.py`): the id is what Jamf put on the
   *  device, the name is resolved per request and is null while the catalog has not been
   *  read since the id appeared — never the id in disguise. */
  buildingId: string | null;
  departmentId: string | null;
  building: string | null;
  department: string | null;
}

/** One installed app as `GET /api/devices/{id}` ships it: the row, the Jamf Patch answer
 *  from stored columns, and LoonInspect's own `vuln` block (#300). */
export interface InstalledApp {
  id: number;
  name: string;
  bundleId: string;
  version: string;
  shortVersion: string | null;
  appHash: string;
  versionHash: string;
  isCompliant: boolean | null;
  patchAvailable: boolean | null;
  patchAvailableSince: string | null;
  lastPatchCheckAt: string | null;
  jamfTitleIds: string[] | null;
  patchState: "latest" | "behind" | "ahead" | "unknown" | null;
  thisVersionSeen: boolean | null;
  latestVersion: string | null;
  latestReleasedAt: string | null;
  /** #68: the sentence leads with `patchAvailableSince` and this count, never a day count. */
  releasesMissed: number | null;
  daysSincePatchAvailable: number | null;
  vuln: AppVulnerability;
}

/** An extension attribute as the device last reported it (#197): keyed by Jamf's
 *  definition id, the name a label that can be null, `values` the whole list, `enabled`
 *  the definition's flag carried rather than filtered on. */
export interface ExtensionAttribute {
  definitionId: string;
  name: string | null;
  values: string[];
  source: string;
  enabled: boolean | null;
}

export interface DeviceDetail extends Device {
  apps: InstalledApp[];
  extensionAttributes: ExtensionAttribute[];
  /** The corpus generation every `vuln` block came from; null means no corpus is loaded. */
  corpusAsOf: string | null;
}

export interface DeviceListResponse {
  items: Device[];
  total: number;
  page: number;
  pageSize: number;
}

export type VersionOperator = "eq" | "lt" | "lte" | "gt" | "gte" | "regex";

export interface DeviceFilters {
  q?: string;
  osVersion?: string;
  osVersionOperator?: VersionOperator;
  site?: string;
  building?: string;
  department?: string;
  managed?: boolean;
  supervised?: boolean;
  /** ISO instants; the API's `lastCheckInBefore` / `lastCheckInAfter`. The Overview's
   *  stale-check-in tile is a saved search on the first (#109). */
  lastCheckInBefore?: string;
  lastCheckInAfter?: string;
  /** The carriers of one app, or of one build of it — the application record page's
   *  "→ Devices" links (#299). Carried through paging like every other filter. */
  appHash?: string;
  versionHash?: string;
  page?: number;
  pageSize?: number;
}

/** The observation read (#368): every wire section as the ledger holds it for one Mac,
 *  with its state always present — present, empty, not observed, outside the aperture —
 *  so an absent body is a statement and never a blank. */
export type SectionState = "present" | "empty" | "not_observed" | "outside_aperture";

export interface ObservedEntry {
  kind: string;
  label: string | null;
  body: Record<string, unknown>;
}

export interface SectionObservation {
  name: string;
  wrapper: string;
  state: SectionState;
  body: Record<string, unknown> | null;
  entries: ObservedEntry[];
  entryCount: number;
}

export interface GroupMembership {
  groupId: string;
  name: string | null;
  smart: boolean | null;
  /** Marked rather than dropped when the group has departed (#181). */
  departedAt: string | null;
}

export interface DeviceObservation {
  deviceId: number;
  subjectId: string;
  observed: boolean;
  observedAt: string | null;
  collectedAt: string | null;
  apertureDigest: string | null;
  sections: SectionObservation[];
  groups: GroupMembership[];
}
