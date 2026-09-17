import { ApiError, apiRequest } from "@/config/api";
import { env } from "@/config/env";

/** #472's object, as much of it as the page reads; every figure printed is a field here. Contract and vocabulary:
 *  docs/compliance-evidence.md. `days` is absent where it rounds to zero and `fleet` is `{}` where nothing was
 *  counted — absent, never zero (§4). */
export interface Span { seconds: number; days?: number }
export type PartName = "notReported" | "noObservation" | "departed";
export interface Totals { met: Span; unmet: Span; notObserved: Span; window: Span; notObservedParts?: Partial<Record<PartName, Span>> }
export interface ReportWindow { start: string; asOf: string }
export interface EvidenceReport {
  header: {
    method: { statement: string; source: string; connection: { connectionID: number; name: string; provider: string }; catalogue: { version: number; rules: number }; window: ReportWindow };
    notVisible: { controls: string[]; statement: string };
    refusal: string;
    contractVersions: string[];
    clock: { interval: string; statement: string };
  };
  /** The additive key of #536: the sentences, computed once on the server, printed by every rendering. */
  readThisFirst: string[];
  rules: { ruleID: string; title: string }[];
  devices: { deviceID: string; name?: string }[];
  totals: { fleet: Partial<Totals>; byRule: Record<string, Totals>; byDevice: Record<string, Totals> };
}

/** The identity the artefact asserts — **met + unmet + notObserved = window** (§4) — checked on the exact
 *  `seconds` it is asserted on, never on `days`, which round to two places. `null` when it closes and for a bucket
 *  that counted nothing (a `{}` is absent, not a failed sum); both figures otherwise, so the page can print it. */
export function sumFault(total: Partial<Totals>): { sum: number; window: number } | null {
  if (!total.met || !total.unmet || !total.notObserved || !total.window) return null;
  const sum = total.met.seconds + total.unmet.seconds + total.notObserved.seconds;
  return sum === total.window.seconds ? null : { sum, window: total.window.seconds };
}

/** Which of the two failed-read sentences the picker prints. A refusal has its own next check: this route is
 *  gated `audit:read` and the list is `connection:read`, so a hand-built role holding one without the other
 *  reaches the page and is refused the list — 403 here is a real misconfiguration, not a theoretical one. */
export const listFailure = (error: unknown): "denied" | "error" =>
  error instanceof ApiError && error.status === 403 ? "denied" : "error";

/** Both dates blank asks for the endpoint's own default window, never for the epoch. */
function query(connectionID: number, window: ReportWindow): string {
  const asked = new URLSearchParams({ connectionID: String(connectionID) });
  if (window.start) asked.set("start", window.start);
  if (window.asOf) asked.set("asOf", window.asOf);
  return asked.toString();
}

export function getEvidenceReport(connectionID: number, window: ReportWindow): Promise<EvidenceReport> {
  return apiRequest<EvidenceReport>(`/evidence/report?${query(connectionID, window)}`);
}

/** The download, moved here from the Settings › Connections row (#536) and otherwise the same fetch: raw rather
 *  than `apiRequest` because the endpoint answers HTML, and the server names the file. A refusal carries its own
 *  sentence. */
export async function downloadEvidencePage(connectionID: number, window: ReportWindow): Promise<void> {
  const response = await fetch(`${env.apiBaseUrl}/evidence/report.html?${query(connectionID, window)}`, { credentials: "include" });
  if (!response.ok) {
    const refusal: unknown = await response.json().catch(() => null);
    throw new Error(refusal && typeof refusal === "object" && "detail" in refusal ? String(refusal.detail) : "");
  }
  const named = /filename="([^"]+)"/.exec(response.headers.get("content-disposition") ?? "");
  const anchor = document.createElement("a");
  anchor.href = URL.createObjectURL(await response.blob());
  anchor.download = named ? named[1] : "evidence-report.html";
  anchor.click();
  URL.revokeObjectURL(anchor.href);
}
