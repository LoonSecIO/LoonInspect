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
  building: string | null;
  department: string | null;
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
  page?: number;
  pageSize?: number;
}
