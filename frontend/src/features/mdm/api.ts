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
  Run,
  RunLogResponse,
  RunSummary,
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

/** Returns as soon as the pull is queued, not when it finishes. The result carries the
 *  jobID to poll with getRunLog — and `started: false` when it joined a run that was
 *  already in flight. */
export function syncConnection(id: number): Promise<MdmSyncTriggerResult> {
  return apiRequest<MdmSyncTriggerResult>(`/mdm/connections/${id}/sync`, { method: "POST" });
}

// --- Runs (#31) ----------------------------------------------------------------------

export function listRuns(connectionId?: number, limit = 25): Promise<Run[]> {
  const query = new URLSearchParams({ limit: String(limit) });
  if (connectionId !== undefined) query.set("connectionId", String(connectionId));
  return apiRequest<Run[]>(`/runs?${query.toString()}`);
}

/** The status strip's run facts, one row per connection (#105): which run the stamp
 *  names, how many webhook sweeps have landed since it, and what ran most recently.
 *
 *  Not derivable from `listRuns` — see `RunSummary` and `docs/runs.md` §8. */
export function listRunSummaries(connectionId?: number): Promise<RunSummary[]> {
  const query = new URLSearchParams();
  if (connectionId !== undefined) query.set("connectionId", String(connectionId));
  const suffix = query.toString();
  return apiRequest<RunSummary[]>(`/runs/summary${suffix ? `?${suffix}` : ""}`);
}

/** Engine lines for one run, incrementally. `after` is the last line id already held,
 *  so a poll transfers only what appeared since rather than the whole log each tick. */
export function getRunLog(jobId: string, after = 0): Promise<RunLogResponse> {
  return apiRequest<RunLogResponse>(`/runs/${jobId}/log?after=${after}`);
}

// --- Collections (#27) ---------------------------------------------------------------

export function listCollections(connectionId: number): Promise<Collection[]> {
  return apiRequest<Collection[]>(`/mdm/connections/${connectionId}/collections`);
}

/** Every collection in the tenant, across connections (#106). For callers asking a
 *  question about the pod rather than about one connection — the alternative was a
 *  request per connection on every poll of the front page. */
export function listAllCollections(): Promise<Collection[]> {
  return apiRequest<Collection[]>("/mdm/collections");
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
