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

export interface VersionResponse {
  version: string;
}

/** The running build. Needs a session but no permission — /auth/status withholds it
 *  from anonymous callers, so this is where a signed-in surface reads it. */
export function getVersion(): Promise<VersionResponse> {
  return apiRequest<VersionResponse>("/system/version");
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
  /** Why the last exchange failed, as the share-log row says it (#408). */
  lastExchangeError: string | null;
  /** AI-inference consent (#112): whether any byte may leave the pod for inference. */
  aiInference: boolean;
}

/** One share-log row, in the NDJSON download's field names (#408). */
export interface ShareLogEntry {
  occurredAt: string;
  tier: string;
  /** scheduled | manual on an exchange row; null on an AI row, which is not one. */
  trigger: string | null;
  endpoint: string;
  /** sent | failed | skipped_env */
  outcome: string;
  payload: unknown;
  revealsShed: boolean;
  revealRequests: unknown[] | null;
  error: string | null;
}

export interface SendExchangeResponse {
  /** The row the exchange wrote: what left, not a preview. */
  exchange: ShareLogEntry;
  /** The settings as they read after it, so Last exchange agrees with the row. */
  settings: DataSharingSettings;
}

export function getDataSharing(): Promise<DataSharingSettings> {
  return apiRequest<DataSharingSettings>("/system/data-sharing");
}

export function updateDataSharing(update: {
  tier?: SharingTier;
  excludeGlobs?: string[];
  aiInference?: boolean;
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

/** Send now (#408): runs the exchange immediately. A failed exchange is still a 200 —
 *  the row says why; a 409 is a refusal before anything was attempted. */
export function sendExchangeNow(): Promise<SendExchangeResponse> {
  return apiRequest<SendExchangeResponse>("/system/data-sharing/send", {
    method: "POST"
  });
}
