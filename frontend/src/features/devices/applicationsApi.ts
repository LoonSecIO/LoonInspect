import { apiRequest } from "@/config/api";

export type RiskSeverity = "critical" | "high" | "medium" | "low";
export type ApplicationScope = { q: string; severities: RiskSeverity[]; hasKev: boolean };
export type ApplicationRisk = { assessment: "off" | "unknown_app" | "partial" | "covered";
  counts: Record<RiskSeverity | "total" | "kev", number> | null; assessedDeviceCount: number;
  devicesWithUnknownBuilds: number; assessedBuildCount: number; unknownBuildCount: number; averagePerAssessedDevice: number | null };

export interface Application {
  /** md5(name:bundleId) — the application regardless of version, and the address of its
   *  record at `/devices/applications/:appHash` (#299). */
  appHash: string;
  name: string;
  bundleId: string;
  deviceCount: number;
  versionCount: number;
  /** #313: the patch answer at this grain — distinct devices whose build matched a Jamf
   *  Patch title at all, and how many of those have a patch available. The first is the
   *  denominator that keeps a zero honest: no title is no answer, not a clean bill. */
  matchedDeviceCount: number;
  patchAvailableDeviceCount: number;
  vulnerabilities?: ApplicationRisk | null;
}

/** The list envelope every paged endpoint shares (#137): the page's rows, the count
 *  across every page, and the page and page size that produced them, echoed. */
export interface ApplicationListResponse {
  items: Application[];
  total: number;
  page: number;
  pageSize: number;
  corpusAsOf: string | null;
  corpusRelease: string | null;
}

/** `q`, `page` and `pageSize`, like every other list — the endpoint used to take
 *  `search`, `limit` and `offset`, and refuses those names now rather than ignoring
 *  them (#137). `pageSize` is capped at 500 server-side. */
export function listApplications(params: {
  q?: string;
  deviceScope?: string;
  severities?: RiskSeverity[];
  hasKev?: boolean;
  page?: number;
  pageSize?: number;
} = {}): Promise<ApplicationListResponse> {
  const query = new URLSearchParams();
  if (params.deviceScope) query.set("deviceScope", params.deviceScope);
  if (params.q) query.set("q", params.q);
  for (const band of params.severities ?? []) query.append("severity", band);
  if (params.hasKev) query.set("hasKev", "true");
  if (params.page !== undefined) query.set("page", String(params.page));
  if (params.pageSize !== undefined) query.set("pageSize", String(params.pageSize));

  const suffix = query.toString();
  return apiRequest<ApplicationListResponse>(`/applications${suffix ? `?${suffix}` : ""}`);
}
