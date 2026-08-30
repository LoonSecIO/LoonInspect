import { apiRequest } from "@/config/api";

export interface UpdateStatusResponse {
  enabled: boolean;
  currentVersion: string;
  /** null is "unknown" (disabled, dev build, or provider unreachable) — render
   *  nothing. false is "checked and current". */
  updateAvailable: boolean | null;
  latestSha: string | null;
  checkedAt: string | null;
}

export function getUpdateStatus(): Promise<UpdateStatusResponse> {
  return apiRequest<UpdateStatusResponse>("/system/update-status");
}

export type SharingTier = "off" | "keys" | "reveal";

export interface DataSharingSettings {
  tier: SharingTier;
  submissionUuid: string;
  excludeGlobs: string[];
  /** COMMUNITY_SHARING=false wins over the stored tier; shown as the lock reason. */
  envDisabled: boolean;
  lastExchangeAt: string | null;
  lastExchangeOutcome: string | null;
  /** The last exchange answered a 413 by dropping its reveals — a degraded "sent". */
  lastExchangeRevealsShed: boolean;
}

export function getDataSharing(): Promise<DataSharingSettings> {
  return apiRequest<DataSharingSettings>("/system/data-sharing");
}

export function updateDataSharing(update: {
  tier?: SharingTier;
  excludeGlobs?: string[];
}): Promise<DataSharingSettings> {
  return apiRequest<DataSharingSettings>("/system/data-sharing", {
    method: "PUT",
    json: update
  });
}

export function resetSubmissionUuid(): Promise<DataSharingSettings> {
  return apiRequest<DataSharingSettings>("/system/data-sharing/reset-uuid", {
    method: "POST"
  });
}

/** The literal next exchange request, built server-side from live data. */
export function previewExchange(): Promise<unknown> {
  return apiRequest<unknown>("/system/data-sharing/preview");
}
