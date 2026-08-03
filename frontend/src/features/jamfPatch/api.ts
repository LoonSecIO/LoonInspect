import { apiRequest } from "@/config/api";
import type { JamfPatchSyncResult, JamfPatchTitleDetail, JamfPatchTitleListResponse } from "@/features/jamfPatch/types";

// Search/sort/filter happen client-side over the full catalog (a few thousand
// rows at most), so this always pulls everything in one request rather than
// paginating.
const ALL_TITLES_PAGE_SIZE = 5000;

export function listJamfPatchTitles(): Promise<JamfPatchTitleListResponse> {
  const params = new URLSearchParams({ pageSize: String(ALL_TITLES_PAGE_SIZE) });
  return apiRequest<JamfPatchTitleListResponse>(`/jamf-patch/titles?${params.toString()}`);
}

export function getJamfPatchTitle(titleId: string): Promise<JamfPatchTitleDetail> {
  return apiRequest<JamfPatchTitleDetail>(`/jamf-patch/titles/${encodeURIComponent(titleId)}`);
}

export function syncJamfPatchTitles(): Promise<JamfPatchSyncResult> {
  return apiRequest<JamfPatchSyncResult>("/jamf-patch/sync", { method: "POST" });
}
