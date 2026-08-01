import { apiRequest } from "@/config/api";
import type { MdmConnection, MdmConnectionInput } from "@/features/mdm/types";

export function listConnections(): Promise<MdmConnection[]> {
  return apiRequest<MdmConnection[]>("/mdm/connections");
}

export function createConnection(input: MdmConnectionInput): Promise<MdmConnection> {
  return apiRequest<MdmConnection>("/mdm/connections", { method: "POST", json: input });
}

export function updateConnection(
  id: number,
  input: Partial<MdmConnectionInput>
): Promise<MdmConnection> {
  return apiRequest<MdmConnection>(`/mdm/connections/${id}`, { method: "PATCH", json: input });
}

export function deleteConnection(id: number): Promise<void> {
  return apiRequest<void>(`/mdm/connections/${id}`, { method: "DELETE" });
}
