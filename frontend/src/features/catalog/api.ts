import { apiRequest } from "@/config/api";
import type { CatalogJamfFilter, CatalogListResponse, CatalogLookup } from "@/features/catalog/types";

// Search, sort and filter happen client-side over the tenant's catalog (distinct apps, not
// installs — a few thousand rows at most), so this pulls everything in one request.
const ALL_ROWS_PAGE_SIZE = 5000;

export function listCatalog(
  params: { jamf?: CatalogJamfFilter; installedOnly?: boolean; appHash?: string; pageSize?: number } = {}
): Promise<CatalogListResponse> {
  const query = new URLSearchParams({ pageSize: String(params.pageSize ?? ALL_ROWS_PAGE_SIZE) });
  if (params.jamf) query.set("jamf", params.jamf);
  if (params.installedOnly !== undefined) query.set("installedOnly", String(params.installedOnly));
  // One application's rows, with the device counts scoped inside the join and no summary (#299).
  if (params.appHash) query.set("appHash", params.appHash);
  return apiRequest<CatalogListResponse>(`/catalog?${query.toString()}`);
}

/** The name behind a hash, for a chip (#299): by build when `versionHash` is given, else
 *  the app's newest version seen. */
export function lookupCatalog(params: { appHash?: string; versionHash?: string }): Promise<CatalogLookup[]> {
  const query = new URLSearchParams();
  if (params.versionHash) query.set("versionHash", params.versionHash);
  else if (params.appHash) query.set("appHash", params.appHash);
  return apiRequest<CatalogLookup[]>(`/catalog/lookup?${query.toString()}`);
}
