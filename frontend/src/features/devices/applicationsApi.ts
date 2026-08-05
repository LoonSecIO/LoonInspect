import { apiRequest } from "@/config/api";

export interface ApplicationVersion {
  /** md5(name:bundleId:version[:shortVersion]) — the LoonSec Global API lookup key. */
  versionHash: string;
  version: string;
  shortVersion: string | null;
  deviceCount: number;
  patchAvailable: boolean | null;
  isCompliant: boolean | null;
}

export interface Application {
  /** md5(name:bundleId) — the application regardless of version. */
  appHash: string;
  name: string;
  bundleId: string;
  deviceCount: number;
  versionCount: number;
  versions: ApplicationVersion[];
}

export interface ApplicationListResponse {
  items: Application[];
  total: number;
}

export function listApplications(params: {
  search?: string;
  limit?: number;
  offset?: number;
} = {}): Promise<ApplicationListResponse> {
  const query = new URLSearchParams();
  if (params.search) query.set("search", params.search);
  if (params.limit !== undefined) query.set("limit", String(params.limit));
  if (params.offset !== undefined) query.set("offset", String(params.offset));

  const suffix = query.toString();
  return apiRequest<ApplicationListResponse>(`/applications${suffix ? `?${suffix}` : ""}`);
}
