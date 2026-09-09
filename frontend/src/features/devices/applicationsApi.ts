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

/** The list envelope every paged endpoint shares (#137): the page's rows, the count
 *  across every page, and the page and page size that produced them, echoed. */
export interface ApplicationListResponse {
  items: Application[];
  total: number;
  page: number;
  pageSize: number;
}

/** `q`, `page` and `pageSize`, like every other list — the endpoint used to take
 *  `search`, `limit` and `offset`, and refuses those names now rather than ignoring
 *  them (#137). `pageSize` is capped at 500 server-side. */
export function listApplications(params: {
  q?: string;
  page?: number;
  pageSize?: number;
} = {}): Promise<ApplicationListResponse> {
  const query = new URLSearchParams();
  if (params.q) query.set("q", params.q);
  if (params.page !== undefined) query.set("page", String(params.page));
  if (params.pageSize !== undefined) query.set("pageSize", String(params.pageSize));

  const suffix = query.toString();
  return apiRequest<ApplicationListResponse>(`/applications${suffix ? `?${suffix}` : ""}`);
}
