import { apiRequest } from "@/config/api";
import type { SmartGroupCostResponse } from "@/features/smartGroups/types";

/** The whole ranking in one request. Unpaginated on the server side too: a Jamf tenant
 *  has tens to hundreds of smart groups, and the order is over the whole set. */
export function listSmartGroupCost(): Promise<SmartGroupCostResponse> {
  return apiRequest<SmartGroupCostResponse>("/smart-groups/cost");
}
