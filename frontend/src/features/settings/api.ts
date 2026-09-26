import { apiRequest } from "@/config/api";
import type { FeatureFlag, MfaPolicy } from "@/features/settings/types";

export function listFeatureFlags(): Promise<FeatureFlag[]> {
  return apiRequest<FeatureFlag[]>("/feature-flags");
}

export function updateFeatureFlag(key: string, enabled: boolean): Promise<FeatureFlag> {
  return apiRequest<FeatureFlag>(`/feature-flags/${encodeURIComponent(key)}`, {
    method: "PATCH",
    json: { enabled }
  });
}

/** Who must sign in with a second factor where this session acts (#653); account:read to read, account:write to write. */
export function getMfaPolicy(): Promise<{ mfaRequired: MfaPolicy }> {
  return apiRequest("/settings/mfa-policy");
}

export function putMfaPolicy(mfaRequired: MfaPolicy): Promise<{ mfaRequired: MfaPolicy }> {
  return apiRequest("/settings/mfa-policy", { method: "PUT", json: { mfaRequired } });
}
