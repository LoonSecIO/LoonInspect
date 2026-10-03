import { apiRequest } from "@/config/api";
import type {
  JamfPatchCoverage,
  JamfPatchSyncResult,
  JamfPatchTitleDetail,
  JamfPatchTitleListResponse,
  PatchRule,
  PatchingPolicy
} from "@/features/jamfPatch/types";

// Search/sort/filter happen client-side over the full catalog (a few thousand
// rows at most), so this always pulls everything in one request rather than
// paginating.
const ALL_TITLES_PAGE_SIZE = 5000;

export function listJamfPatchTitles(): Promise<JamfPatchTitleListResponse> {
  const params = new URLSearchParams({ pageSize: String(ALL_TITLES_PAGE_SIZE) });
  return apiRequest<JamfPatchTitleListResponse>(`/jamf-patch/titles?${params.toString()}`);
}

export function getJamfPatchCoverage(): Promise<JamfPatchCoverage> {
  return apiRequest<JamfPatchCoverage>("/jamf-patch/coverage");
}

export function getJamfPatchTitle(titleId: string): Promise<JamfPatchTitleDetail> {
  return apiRequest<JamfPatchTitleDetail>(`/jamf-patch/titles/${encodeURIComponent(titleId)}`);
}

export function syncJamfPatchTitles(): Promise<JamfPatchSyncResult> {
  return apiRequest<JamfPatchSyncResult>("/jamf-patch/sync", { method: "POST" });
}

/** The org's stated patching policy (#116). Reading needs app:read, like the page. */
export function getPatchingPolicy(): Promise<PatchingPolicy> {
  return apiRequest<PatchingPolicy>("/settings/patching-policy");
}

/** State it, or clear it with an empty statement. system:write, audited. */
export function putPatchingPolicy(statement: string): Promise<PatchingPolicy> {
  return apiRequest<PatchingPolicy>("/settings/patching-policy", { method: "PUT", json: { statement } });
}

/** Confirm the organization's rule, or clear it with both limits null. system:write, audited. */
export function putPatchingRule(rule: PatchRule): Promise<PatchingPolicy> {
  return apiRequest<PatchingPolicy>("/settings/patching-policy/rule", { method: "PUT", json: rule });
}

/** Give one title its own rule: limits, or `exempt` alone. system:write, audited. */
export function putPatchingOverride(
  titleId: string,
  override: Partial<PatchRule> & { exempt?: boolean }
): Promise<PatchingPolicy> {
  return apiRequest<PatchingPolicy>(`/settings/patching-policy/overrides/${encodeURIComponent(titleId)}`, {
    method: "PUT",
    json: override
  });
}

/** Remove a title's own rule, so the organization's judges it again. */
export function deletePatchingOverride(titleId: string): Promise<PatchingPolicy> {
  return apiRequest<PatchingPolicy>(`/settings/patching-policy/overrides/${encodeURIComponent(titleId)}`, {
    method: "DELETE"
  });
}
