import { apiRequest } from "@/config/api";
import type { DeviceDetail, DeviceFilters, DeviceListResponse } from "@/features/devices/types";

export function listDevices(filters: DeviceFilters): Promise<DeviceListResponse> {
  const params = new URLSearchParams();

  if (filters.q) params.set("q", filters.q);
  if (filters.osVersion) {
    params.set("osVersion", filters.osVersion);
    params.set("osVersionOperator", filters.osVersionOperator ?? "eq");
  }
  if (filters.site) params.set("site", filters.site);
  if (filters.building) params.set("building", filters.building);
  if (filters.department) params.set("department", filters.department);
  if (filters.managed !== undefined) params.set("managed", String(filters.managed));
  if (filters.supervised !== undefined) params.set("supervised", String(filters.supervised));
  if (filters.lastCheckInBefore) params.set("lastCheckInBefore", filters.lastCheckInBefore);
  if (filters.lastCheckInAfter) params.set("lastCheckInAfter", filters.lastCheckInAfter);
  params.set("page", String(filters.page ?? 1));
  params.set("pageSize", String(filters.pageSize ?? 50));

  return apiRequest<DeviceListResponse>(`/devices?${params.toString()}`);
}

/** The device page's one read (#300): the row, every installed app with its Jamf Patch
 *  columns and `vuln` block, every extension attribute, and `corpusAsOf`. */
export function getDevice(id: number): Promise<DeviceDetail> {
  return apiRequest<DeviceDetail>(`/devices/${id}`);
}
