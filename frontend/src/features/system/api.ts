import { apiRequest } from "@/config/api";

/** Why the check could not answer (#407) — one of six, never a blank. */
export type UpdateReason = "disabled" | "dev_build" | "unreachable" | "refused" | "no_release" | "unknown_commit";

export interface UpdateStatusResponse {
  enabled: boolean;
  currentVersion: string;
  /** null is "unknown", and `reason` says which: the banner renders nothing, and the
   *  Updates block on Settings › Support names it. false is "checked, and this build
   *  contains the latest published release". */
  updateAvailable: boolean | null;
  /** The commit the latest release's tag points at — a release, no longer main (#407). */
  latestSha: string | null;
  checkedAt: string | null;
  latestTag: string | null;
  /** The release's page on GitHub: "what changed". Only ever an https link. */
  releaseUrl: string | null;
  reason: UpdateReason | null;
}

export function getUpdateStatus(): Promise<UpdateStatusResponse> {
  return apiRequest<UpdateStatusResponse>("/system/update-status");
}

export interface VersionResponse {
  version: string;
}

/** The running build. Needs a session but no permission — /auth/status withholds it
 *  from anonymous callers, so this is where a signed-in surface reads it. */
export function getVersion(): Promise<VersionResponse> {
  return apiRequest<VersionResponse>("/system/version");
}

export type SharingTier = "off" | "keys" | "reveal";

export interface DataSharingSettings {
  tier: SharingTier;
  submissionUuid: string;
  excludeGlobs: string[];
  /** COMMUNITY_SHARING=false wins over the stored tier; shown as the lock reason. */
  envDisabled: boolean;
  lastExchangeAt: string | null;
  lastExchangeOutcome: string | null;
  /** The last exchange answered a 413 by dropping its reveals — a degraded "sent". */
  lastExchangeRevealsShed: boolean;
  /** Why the last exchange failed, as the share-log row says it (#408). */
  lastExchangeError: string | null;
  /** AI-inference consent (#112): whether any byte may leave the pod for inference. */
  aiInference: boolean;
}

/** One share-log row, in the NDJSON download's field names (#408). */
export interface ShareLogEntry {
  occurredAt: string;
  tier: string;
  /** scheduled | manual on an exchange row; null on an AI row, which is not one. */
  trigger: string | null;
  endpoint: string;
  /** sent | failed | skipped_env */
  outcome: string;
  payload: unknown;
  revealsShed: boolean;
  revealRequests: unknown[] | null;
  error: string | null;
}

export interface SendExchangeResponse {
  /** The row the exchange wrote: what left, not a preview. */
  exchange: ShareLogEntry;
  /** The settings as they read after it, so Last exchange agrees with the row. */
  settings: DataSharingSettings;
}

export function getDataSharing(): Promise<DataSharingSettings> {
  return apiRequest<DataSharingSettings>("/system/data-sharing");
}

export function updateDataSharing(update: {
  tier?: SharingTier;
  excludeGlobs?: string[];
  aiInference?: boolean;
}): Promise<DataSharingSettings> {
  return apiRequest<DataSharingSettings>("/system/data-sharing", {
    method: "PUT",
    json: update
  });
}

export function resetSubmissionUuid(): Promise<DataSharingSettings> {
  return apiRequest<DataSharingSettings>("/system/data-sharing/reset-uuid", {
    method: "POST"
  });
}

/** The literal next exchange request, built server-side from live data. */
export function previewExchange(): Promise<unknown> {
  return apiRequest<unknown>("/system/data-sharing/preview");
}

/** Send now (#408): runs the exchange immediately. A failed exchange is still a 200 —
 *  the row says why; a 409 is a refusal before anything was attempted. */
export function sendExchangeNow(): Promise<SendExchangeResponse> {
  return apiRequest<SendExchangeResponse>("/system/data-sharing/send", {
    method: "POST"
  });
}

/** One title no public source on this container knows (#483). `reason` is
 *  `no_public_source` today; an unrecognized value renders untagged, never hidden. */
export interface ExclusionCandidateApp {
  name: string;
  bundleId: string;
  deviceCount: number;
  reason: string;
}

/** Unknown titles under one reverse-DNS prefix. `suggestion` is null where the prefix earns
 *  no glob; `excluded` means a pattern already in the box removes all of them. */
export interface ExclusionCandidateGroup {
  prefix: string;
  suggestion: string | null;
  excluded: boolean;
  appCount: number;
  deviceCount: number;
  apps: ExclusionCandidateApp[];
}

export interface ExclusionGlobCount {
  glob: string;
  /** typed (it is in the box) | suggested (proposed by the page, nothing saved). */
  source: "typed" | "suggested";
  appCount: number;
  deviceCount: number;
  /** Bundle IDs the glob would match but for case — the container's fnmatch is not. */
  caseMisses: string[];
  /** How many more of those the cap left out; 0 when the list above is all of them. */
  moreCaseMisses: number;
}

export interface ExclusionCandidates {
  groups: ExclusionCandidateGroup[];
  moreGroups: number;
  globs: ExclusionGlobCount[];
  /** Patterns in the box past the ceiling, which nothing above counted. */
  moreGlobs: number;
  /** What "unknown" was decided against: both 0 means nothing here can be known yet. */
  catalogTitles: number;
  libraryTitles: number;
}

/** Candidates and glob counts for the box as it stands (#483) — a read, never a write. An
 *  empty draft still sends one empty `glob`, so a cleared box is counted as cleared rather
 *  than falling back to the stored list. */
export function getExclusionCandidates(globs: string[]): Promise<ExclusionCandidates> {
  const query = (globs.length ? globs : [""]).map((g) => `glob=${encodeURIComponent(g)}`).join("&");
  return apiRequest<ExclusionCandidates>(`/system/data-sharing/exclusion-candidates?${query}`);
}

export type ExclusionClassification = "likely_in_house" | "uncertain" | "likely_public";
export type RankingProvider = "apple_fm" | "openai_compatible";
export interface ExclusionRankingStatus {
  available: boolean;
  reason: "flag_off" | "consent_off" | "local_endpoint_required" | null;
  providers: { provider: RankingProvider; model: string; destination: string }[];
}
export interface ExclusionRanking {
  candidates: ExclusionCandidates;
  assessments: { prefix: string; classification: ExclusionClassification }[];
  destination: string;
  model: string;
}
export function getExclusionRankingStatus(): Promise<ExclusionRankingStatus> {
  return apiRequest<ExclusionRankingStatus>("/system/data-sharing/exclusion-ranking");
}
export function rankExclusionCandidates(provider: RankingProvider, globs: string[]): Promise<ExclusionRanking> {
  return apiRequest<ExclusionRanking>("/system/data-sharing/exclusion-ranking", {
    method: "POST", json: { provider, globs }
  });
}
