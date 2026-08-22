import { apiRequest } from "@/config/api";
import type {
  Collection,
  CollectionInput,
  CollectionRunResult,
  MdmConnection,
  MdmConnectionInput,
  MdmConnectionTestInput,
  MdmConnectionTestResult,
  MdmSyncStatus,
  MdmSyncTriggerResult,
  ProviderInfo,
  SectionInfo
} from "@/features/mdm/types";

export function listConnections(): Promise<MdmConnection[]> {
  return apiRequest<MdmConnection[]>("/mdm/connections");
}

export function getProviders(): Promise<ProviderInfo[]> {
  return apiRequest<ProviderInfo[]>("/mdm/providers");
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

export function testConnection(input: MdmConnectionTestInput): Promise<MdmConnectionTestResult> {
  return apiRequest<MdmConnectionTestResult>("/mdm/connections/test", { method: "POST", json: input });
}

export function listSyncStatus(): Promise<MdmSyncStatus[]> {
  return apiRequest<MdmSyncStatus[]>("/mdm/status");
}

/** Returns as soon as the pull is queued, not when it finishes — poll listSyncStatus
 *  for progress. */
export function syncConnection(id: number): Promise<MdmSyncTriggerResult> {
  return apiRequest<MdmSyncTriggerResult>(`/mdm/connections/${id}/sync`, { method: "POST" });
}

// --- Collections (#27) ---------------------------------------------------------------

export function listCollections(connectionId: number): Promise<Collection[]> {
  return apiRequest<Collection[]>(`/mdm/connections/${connectionId}/collections`);
}

export function createCollection(connectionId: number, input: CollectionInput): Promise<Collection> {
  return apiRequest<Collection>(`/mdm/connections/${connectionId}/collections`, { method: "POST", json: input });
}

export function updateCollection(id: number, input: Partial<CollectionInput>): Promise<Collection> {
  return apiRequest<Collection>(`/mdm/collections/${id}`, { method: "PATCH", json: input });
}

export function deleteCollection(id: number): Promise<void> {
  return apiRequest<void>(`/mdm/collections/${id}`, { method: "DELETE" });
}

/** 202 as soon as the run is queued; the collection's lastRun* fields carry the outcome. */
export function runCollection(id: number): Promise<CollectionRunResult> {
  return apiRequest<CollectionRunResult>(`/mdm/collections/${id}/run`, { method: "POST" });
}

export function listJamfSections(): Promise<SectionInfo[]> {
  return apiRequest<SectionInfo[]>("/mdm/providers/jamf/sections");
}
