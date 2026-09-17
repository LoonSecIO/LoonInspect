import { apiRequest } from "@/config/api";
import type { CatalogBand, CatalogOrder, CatalogVulnFilter } from "@/features/catalog/types";
import { askFailureText, type AskSettled } from "@/features/changes/prompt";
import type { PromptRequest, PromptStatus } from "@/features/changes/types";
import type { Translations } from "@/i18n/en";

/**
 * The Vulnerabilities page's AI lever (#534): its wire, its one move on the page, and where the
 * lever's last position is kept — out of the components, so the node-only lane can hold them.
 *
 * Nothing here renders model text: the readback is written from the filters the server
 * whitelisted, and the count is Postgres's. The failure sentences are `t.changes.prompt`'s
 * rather than copies — the two bars fail the same ways, and one set of words is one to keep true.
 */

export type VulnPromptOutcome = "applied" | "proposed" | "invalid" | "error" | "unparseable";

/** The page's four filter keys, as the server whitelists them. `vuln` and `order` are always
 *  set — the page has no *all* state and no unordered list. */
export interface VulnPromptFilters {
  q: string | null;
  vuln: Exclude<CatalogVulnFilter, "all">;
  band: CatalogBand | null;
  order: CatalogOrder;
}

export interface VulnPromptResult {
  outcome: VulnPromptOutcome;
  filters: VulnPromptFilters | null;
  unsupported: string | null;
  repairs: string[];
  widening: string[];
  summary: { total: number } | null;
  provider: string;
  model: string;
  destination: string;
  latencyMs: number;
  error: { kind: string; message: string; status: number | null } | null;
}

/** Whether the lever is drawn at all: the flag, the consent, a saved provider, in that order.
 *  Readable with vuln:read alone, because viewers use the lever and cannot read Settings › AI. */
export function getLeverStatus(): Promise<PromptStatus> {
  return apiRequest<PromptStatus>("/vulnerabilities/prompt");
}

/** The question goes to this server, which sends it — and only it — to the saved provider.
 *  What comes back is filter settings and a count Postgres wrote. */
export function askLever(body: PromptRequest, signal?: AbortSignal): Promise<VulnPromptResult> {
  return apiRequest<VulnPromptResult>("/vulnerabilities/prompt", { method: "POST", json: body, signal });
}

const LEVER_KEY = "looninspect.vulnerabilities.ai";

/** Where this viewer left the lever. A per-viewer convenience and nothing more: a browser
 *  that has never seen it starts **off**, which is what the doctrine's *everything defaults
 *  off* means here, and storage that throws (a private window, blocked site data) is read as
 *  off rather than as a failure. */
export function readLever(): boolean {
  try {
    return window.localStorage.getItem(LEVER_KEY) === "on";
  } catch {
    return false;
  }
}

export function writeLever(on: boolean): void {
  try {
    window.localStorage.setItem(LEVER_KEY, on ? "on" : "off");
  } catch {
    // A viewer whose browser will not keep it still gets the lever; it just starts off again.
  }
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const isText = (value: unknown): value is string => typeof value === "string";
const isTextOrNull = (value: unknown): value is string | null => value === null || typeof value === "string";
const isCount = (value: unknown): value is number => typeof value === "number" && Number.isFinite(value);

const OUTCOMES: readonly VulnPromptOutcome[] = ["applied", "proposed", "invalid", "error", "unparseable"];
/** The page's own vocabulary, one array per key, in the order the readback names them. The
 *  server whitelists the same four; a value outside them is the server answering in a shape
 *  this page cannot read, which is refused here rather than rendered as an unknown chip. */
export const LEVER_STATES: readonly Exclude<CatalogVulnFilter, "all">[] = [
  "findings",
  "kev",
  "unknown_app",
  "clean",
  "patchable"
];
export const LEVER_BANDS: readonly CatalogBand[] = ["critical", "high", "medium", "low"];
export const LEVER_ORDERS: readonly CatalogOrder[] = ["exposure", "age", "payoff"];

function isFilters(value: unknown): value is VulnPromptFilters {
  return (
    isRecord(value) &&
    isTextOrNull(value.q) &&
    LEVER_STATES.includes(value.vuln as VulnPromptFilters["vuln"]) &&
    (value.band === null || LEVER_BANDS.includes(value.band as CatalogBand)) &&
    LEVER_ORDERS.includes(value.order as CatalogOrder)
  );
}

/** Whether a 200's body is the answer `POST /api/vulnerabilities/prompt` promises, checked
 *  before anything reads it: a body that parsed as JSON but is not that — `null`, a proxy's
 *  own JSON, an older or newer shape — would throw on first read and be reported as a
 *  question that never reached the server. */
export function isVulnPromptResult(value: unknown): value is VulnPromptResult {
  return (
    isRecord(value) &&
    OUTCOMES.includes(value.outcome as VulnPromptOutcome) &&
    (value.filters === null || isFilters(value.filters)) &&
    isTextOrNull(value.unsupported) &&
    Array.isArray(value.repairs) &&
    value.repairs.every(isText) &&
    Array.isArray(value.widening) &&
    value.widening.every(isText) &&
    (value.summary === null || (isRecord(value.summary) && isCount(value.summary.total))) &&
    isText(value.provider) &&
    isText(value.model) &&
    isText(value.destination) &&
    isCount(value.latencyMs) &&
    (value.error === null || (isRecord(value.error) && isText(value.error.kind) && isText(value.error.message)))
  );
}

/** What the lever makes of a settled question: an answer to show, or the sentence for why
 *  there is none. Only a rejected request goes through `askFailureText`; a body that arrived
 *  but is not the answer is the server answering in a form this page cannot read. */
export function readLeverReply(
  settled: AskSettled,
  words: Translations["changes"]["prompt"]
): { result: VulnPromptResult } | { refusal: string } {
  if (!settled.ok) return { refusal: askFailureText(settled.error, words) };
  if (!isVulnPromptResult(settled.body)) return { refusal: words.askUnreadable };
  return { result: settled.body };
}

/** The filters an answer moves the page to the moment it lands: an applied one's, and no
 *  other. A proposal waits for its Apply button (ruling 9); an endpoint failure or an answer
 *  that was not filters moves nothing at all. */
export function filtersOnArrival(result: VulnPromptResult): VulnPromptFilters | null {
  return result.outcome === "applied" && result.filters ? result.filters : null;
}

/** The filters the lever applied, as the page's whole URL state — one chip is one whole URL
 *  (`filterTo`), so the lever sets one too, and a filtered list stays a link somebody can send.
 *  `q` is not a URL key on this page; the box holds it. Nor is `age`: the page reads that order
 *  off its own expanded list (`agedList`), so writing it here would make a link that reads back
 *  as *Most exposed* — `payoff` is the one order this URL carries. */
export function leverParams(filters: VulnPromptFilters): URLSearchParams {
  return new URLSearchParams([
    ["vuln", filters.vuln],
    ...(filters.band ? [["band", filters.band]] : []),
    ...(filters.order === "payoff" ? [["order", "payoff"]] : [])
  ]);
}

/**
 * The readback, in the page's own words for its own controls: the chip a filter lights, the
 * band's own label, the heading the order gives the list. Written from the whitelisted
 * filters, never from the model's text.
 */
export function leverReadback(filters: VulnPromptFilters, copy: Translations["vulnerabilities"]): string {
  const states: Record<VulnPromptFilters["vuln"], string> = {
    findings: copy.colFindings,
    kev: copy.filterKev,
    unknown_app: copy.stateUnknownApp,
    clean: copy.stateCoveredClean,
    patchable: copy.filterPatchable
  };
  const bands: Record<CatalogBand, string> = {
    critical: copy.bandCritical,
    high: copy.bandHigh,
    medium: copy.bandMedium,
    low: copy.bandLow
  };
  const orders: Record<CatalogOrder, string> = {
    exposure: copy.mostExposed,
    age: copy.longestExposed,
    payoff: copy.easilyPatchable
  };
  const bits = [states[filters.vuln]];
  if (filters.band) bits.push(bands[filters.band]);
  if (filters.q) bits.push(copy.aiForApp(filters.q));
  bits.push(orders[filters.order]);
  return bits.join(" · ");
}
