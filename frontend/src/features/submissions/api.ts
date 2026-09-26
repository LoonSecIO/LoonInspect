import { apiRequest } from "@/config/api";

/** The five submission routes (#623, backend/app/api/submissions.py), each behind SYSTEM_WRITE. Preview and
 *  send are refused while INTELLIGENCE_ACCESS is off; the list, status and withdrawal never are. No answer
 *  carries the case key: this instance mints it on Send and keeps it. */
export const SUBMISSION_PLATFORMS = ["macos", "ios", "ipados", "tvos", "visionos"] as const;
export type SubmissionPlatform = (typeof SUBMISSION_PLATFORMS)[number];
export type SubmissionKind = "coverage" | "correction";

/** A case, and its two one-time acts (a preview ignores both); only a correction names a finding and its release. */
export interface SubmissionIn {
  kind: SubmissionKind; appName: string; bundleId?: string | null; platform: SubmissionPlatform; versions: string[];
  publicUrl?: string | null; text?: string | null; contact?: string | null; finding?: string | null; findingRelease?: string | null;
  permission?: boolean; excludedOverride?: boolean;
}

export interface SubmissionPreviewOut {
  payload: Record<string, unknown>; // exactly what Send puts on the wire, in the contract's names, less the case key
  excludedBy: string | null; // the data-sharing exclusion pattern the bundle identifier matches
}

/** `state` is `pending` until the service acknowledges the case, then the contract's word, or `expired`;
 *  `lastError` is the last act's failure as the one sentence docs/troubleshooting.md §21 quotes. */
export interface SubmissionCaseOut {
  id: string; createdAt: string; kind: SubmissionKind; appName: string; bundleId: string | null; platform: string; versions: string[];
  publicUrl: string | null; text: string | null; contact: string | null; finding: string | null; findingRelease: string | null;
  state: string; receivedAt: string | null; closedAt: string | null; release: string | null; coverage: string | null; note: string | null;
  lastStatusAt: string | null; retryAt: string | null; lastError: string | null; withdrawnAt: string | null;
  excludedOverride: boolean; permissionAt: string | null;
}

/** `enabled`: whether this instance may send a new case (INTELLIGENCE_ACCESS). */
export interface SubmissionCasesOut { enabled: boolean; cases: SubmissionCaseOut[] }

const POST = { method: "POST" } as const;
const act = (id: string, verb: "status" | "withdraw") => `/submissions/${encodeURIComponent(id)}/${verb}`;

export const listSubmissions = () => apiRequest<SubmissionCasesOut>("/submissions");
export const previewSubmission = (body: SubmissionIn) =>
  apiRequest<SubmissionPreviewOut>("/submissions/preview", { ...POST, json: body });
/** 202 with the case as stored. The same fields while a case is open answer that case, never a second one. */
export const sendSubmission = (body: SubmissionIn) => apiRequest<SubmissionCaseOut>("/submissions", { ...POST, json: body });
/** Read once a minute at most: sooner answers 429 with the seconds to wait. */
export const submissionStatus = (id: string) => apiRequest<SubmissionCaseOut>(act(id, "status"), POST);
export const withdrawSubmission = (id: string) => apiRequest<SubmissionCaseOut>(act(id, "withdraw"), POST);
