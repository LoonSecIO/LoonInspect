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

export function deleteDestination(id: number): Promise<void> {
  return apiRequest<void>(`/destinations/${id}`, { method: "DELETE" });
}
