import { apiRequest } from "@/config/api";
import type { CreateDestinationInput, Destination, UpdateDestinationInput } from "@/features/destinations/types";

export function listDestinations(): Promise<Destination[]> {
  return apiRequest<Destination[]>("/destinations");
}

export function createDestination(input: CreateDestinationInput): Promise<Destination> {
  return apiRequest<Destination>("/destinations", { method: "POST", json: input });
}

export function updateDestination(id: number, input: UpdateDestinationInput): Promise<Destination> {
  return apiRequest<Destination>(`/destinations/${id}`, { method: "PATCH", json: input });
}

export interface DestinationTestResult {
  ok: boolean;
  detail: string;
}

/** Sends one synthetic event down the real delivery path. Always resolves — a refused
 *  delivery is a successful test that reports a refusal. */
export function testDestination(id: number): Promise<DestinationTestResult> {
  return apiRequest<DestinationTestResult>(`/destinations/${id}/test`, { method: "POST" });
}

export function deleteDestination(id: number): Promise<void> {
  return apiRequest<void>(`/destinations/${id}`, { method: "DELETE" });
}
