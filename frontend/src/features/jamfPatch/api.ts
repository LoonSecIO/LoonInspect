import { apiRequest } from "@/config/api";
import type { JamfPatchSyncResult, JamfPatchTitleDetail, JamfPatchTitleListResponse } from "@/features/jamfPatch/types";

export function listJamfPatchTitles(q?: string): Promise<JamfPatchTitleListResponse> {
  const params = new URLSearchParams();
  if (q) params.set("q", q);
  return apiRequest<JamfPatchTitleListResponse>(`/jamf-patch/titles?${params.toString()}`);
}

export function getJamfPatchTitle(titleId: string): Promise<JamfPatchTitleDetail> {
  return apiRequest<JamfPatchTitleDetail>(`/jamf-patch/titles/${encodeURIComponent(titleId)}`);
}

export function syncJamfPatchTitles(): Promise<JamfPatchSyncResult> {
  return apiRequest<JamfPatchSyncResult>("/jamf-patch/sync", { method: "POST" });
}
