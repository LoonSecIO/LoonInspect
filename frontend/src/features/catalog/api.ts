import { apiRequest } from "@/config/api";
import type { CatalogJamfFilter, CatalogListResponse } from "@/features/catalog/types";

// Search, sort and filter happen client-side over the tenant's catalog (distinct apps, not
// installs — a few thousand rows at most), so this pulls everything in one request.
const ALL_ROWS_PAGE_SIZE = 5000;

export function listCatalog(params: { jamf?: CatalogJamfFilter; installedOnly?: boolean } = {}): Promise<CatalogListResponse> {
  const query = new URLSearchParams({ pageSize: String(ALL_ROWS_PAGE_SIZE) });
  if (params.jamf) query.set("jamf", params.jamf);
  if (params.installedOnly !== undefined) query.set("installedOnly", String(params.installedOnly));
  return apiRequest<CatalogListResponse>(`/catalog?${query.toString()}`);
}
