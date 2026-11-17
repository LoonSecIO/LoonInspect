import { apiRequest } from "@/config/api";
import type { FleetCatalog, FleetCatalogState } from "@/features/fleetCatalog/types";

// A few hundred titles at most, so the page reads them in one request and searches and
// sorts what it holds, as the Jamf Patch tab does.
const ALL_TITLES_PAGE_SIZE = 5000;

/** Fleet's titles beside this organization's Macs. Reads what the instance holds; asks GitHub nothing. */
export function getFleetCatalog(installedOnly: boolean): Promise<FleetCatalog> {
  const params = new URLSearchParams({ installedOnly: String(installedOnly), pageSize: String(ALL_TITLES_PAGE_SIZE) });
  return apiRequest<FleetCatalog>(`/fleet-catalog?${params.toString()}`);
}

/** Check Fleet's catalog now. patch:catalog-sync; a refusal is a 409 whose detail is the sentence to show. */
export function refreshFleetCatalog(): Promise<FleetCatalogState> {
  return apiRequest<FleetCatalogState>("/fleet-catalog/refresh", { method: "POST" });
}
