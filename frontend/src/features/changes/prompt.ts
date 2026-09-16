import { ApiBodyError, ApiError } from "@/config/api";
import type { Translations } from "@/i18n/en";
import type { Provider } from "@/features/ai/api";
import { CHANGE_KINDS } from "@/features/changes/render";
import type {
  ChangeFilters,
  ChangeKind,
  ChangeLevel,
  PromptDevice,
  PromptError,
  PromptFilters,
  PromptHiddenReason,
  PromptOutcome,
  PromptResult,
  PromptStatus,
  PromptSummary,
  PromptWhen
} from "@/features/changes/types";

/**
 * The Changes Prompt bar's words and its one move on the page, kept out of the
 * components so the node-only test lane can hold them to the contract.
 *
 * Nothing here renders model text. The readback and the response box are written by
 * this code from the filters the server whitelisted and the counts Postgres returned;
 * the one model-authored string, `unsupported`, is passed through to the page as text.
 */

type ChangesStrings = Translations["changes"];
type PromptStrings = ChangesStrings["prompt"];

/** The server keeps the first 500 characters of a question after cleaning it
 *  (`MAX_QUESTION_CHARS` in `backend/app/ai/changes_prompt.py`), so the box stops there
 *  rather than sending a tail that would be dropped without a word. */
export const MAX_QUESTION_CHARS = 500;

const blankToUndefined = <T extends string>(value: T | null | undefined): T | undefined =>
  value === null || value === undefined || value === "" ? undefined : value;

/**
 * The prompt REPLACES the page's filters; it never merges into them. The Changes page
 * merges what it is handed (`nextParams`), so every key it could be carrying is named
 * here — the six the bar speaks, and the four it has no words for (a `minLevel` range from
 * the Overview, a device from the device page) cleared explicitly. Otherwise "which
 * computers installed Wireshark?" asked from a device's own feed would answer for that
 * one device while the readback claimed the fleet. `since` is the bar's as of #443: it
 * carries the start the answer was counted for, and clears a window the page arrived with.
 */
export function filtersFromPrompt(filters: PromptFilters): Partial<ChangeFilters> {
  return {
    q: blankToUndefined(filters.q),
    artifact: blankToUndefined(filters.artifact),
    level: blankToUndefined(filters.level),
    section: blankToUndefined(filters.section),
    change: blankToUndefined(filters.change),
    minLevel: undefined,
    since: blankToUndefined(filters.since),
    connectionId: undefined,
    subjectId: undefined,
    subjectKind: undefined,
    page: 1
  };
}

const COMPARED_KEYS = [
  "q",
  "artifact",
  "level",
  "minLevel",
  "section",
  "change",
  "since",
  "connectionId",
  "subjectId",
  "subjectKind"
] as const satisfies readonly (keyof ChangeFilters)[];

/**
 * Whether the page still shows what the bar applied. The readback and the counts are
 * about those filters; once the operator moves a control or presses Back, they describe
 * a feed that is no longer on screen, and the bar hides them rather than let them read
 * as the current one. The page number is not a filter.
 */
export function stillShowing(applied: Partial<ChangeFilters>, current: ChangeFilters): boolean {
  const norm = (value: string | number | undefined) => (value === "" ? undefined : value);
  return COMPARED_KEYS.every((key) => norm(applied[key]) === norm(current[key]));
}

/**
 * Whether the Changes page's Clear has anything to do, which is when it is enabled: a
 * filter in the URL — the controls' own, and the ones only a link sets (a `since` window,
 * a `minLevel` range, the device chip) — or a page past the first; text in either draft
 * box, applied or not; or a Prompt bar used since the last Clear. Pressed with only the
 * last two, it moves no URL, so it adds no history entry.
 */
export function hasSomethingToClear(
  filters: ChangeFilters,
  drafts: { q: string; artifact: string },
  promptUsed: boolean
): boolean {
  if (promptUsed || drafts.q !== "" || drafts.artifact !== "") return true;
  const set = (value: string | number | undefined) => value !== undefined && value !== "";
  return COMPARED_KEYS.some((key) => set(filters[key])) || (filters.page ?? 1) !== 1;
}

/** Port of the handoff's `describe()`: the filters as a sentence, in the page's own
 *  labels. Order: device, thing, section, level, then the kind of change. `proposed`
 *  words it as what the filters would show, for a proposal nothing has run yet. */
export function readback(
  filters: {
    q?: string | null;
    artifact?: string | null;
    level?: ChangeLevel | null;
    section?: string | null;
    change?: ChangeKind | null;
    since?: string | null;
  },
  strings: ChangesStrings,
  mode: "showing" | "proposed" = "showing"
): string {
  const words = strings.prompt;
  const bits: string[] = [];
  if (filters.q) bits.push(words.readbackDevice(filters.q));
  if (filters.artifact) bits.push(words.readbackArtifact(filters.artifact));
  if (filters.section) bits.push(words.readbackSection(strings.sections[filters.section] ?? filters.section));
  if (filters.level) bits.push(words.readbackLevel(strings.levels[filters.level] ?? filters.level));
  if (filters.change) bits.push(words.readbackChange(words.answerKinds[filters.change] ?? filters.change));
  // Last, and never left out: a start the reader cannot see in a control has to be in words,
  // or the table is narrower than the readback says (#443).
  if (filters.since) bits.push(words.readbackSince(at(filters.since)));
  const [lead, none] =
    mode === "proposed" ? [words.proposalReadbackLead, words.proposalReadbackNone] : [words.readbackLead, words.readbackNone];
  return bits.length > 0 ? `${lead} ${bits.join(", ")}` : none;
}

/**
 * The filters a reply moves the page to the moment it lands: an applied answer's, and no
 * other. A proposal — a correction widened the model's answer, so it would search for
 * more than the model named (ruled 1C, #436) — moves nothing until a person presses its
 * Apply button (`proposedFilters`). An endpoint failure or an answer that was not filters
 * moves nothing at all.
 */
export function filtersOnArrival(result: PromptResult): Partial<ChangeFilters> | null {
  return result.outcome === "applied" && result.filters ? filtersFromPrompt(result.filters) : null;
}

/** The filters a proposal's Apply button moves the page to; null for anything that is not a
 *  proposal. The press is the operator's own, so it replaces whatever the page shows then,
 *  as a hand-set filter would: there is nothing for it to be stale against. */
export function proposedFilters(result: PromptResult): Partial<ChangeFilters> | null {
  return result.outcome === "proposed" && result.filters ? filtersFromPrompt(result.filters) : null;
}

/** A time as the Changes table's own Observed column writes it, so the operator compares
 *  like with like: the browser's format, in the browser's zone. */
function at(iso: string): string {
  return new Date(iso).toLocaleString();
}

/** The viewer's IANA zone, sent with a question so the server can resolve "today" and
 *  "since Monday" to their midnight (#443). Undefined when the browser will not say, which
 *  the server reads as UTC. */
export function viewerZone(): string | undefined {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || undefined;
  } catch {
    return undefined;
  }
}

function deviceLine(device: PromptDevice, words: PromptStrings): string {
  // Serial first: it is the name that survives a rename, and the one an operator pastes
  // into Jamf. A Mac Jamf named after its own serial is not printed twice.
  const names = [...new Set([device.serial, device.label].filter((name): name is string => Boolean(name)))];
  const who = names.length > 0 ? names.join(" — ") : words.answerJamfId(device.subjectId);
  const counts = CHANGE_KINDS.filter((kind) => device[kind] > 0).map((kind) => `${words.answerKinds[kind]} ${device[kind]}`);
  // This Mac's newest, last: the list is ordered by it, so "which was most recent" is read
  // off the order and "when" off the line itself.
  return [who, counts.length > 0 ? counts.join(", ") : null, at(device.lastObservedAt)].filter(Boolean).join(" · ");
}

/**
 * When, and the window it happened in (ruling R1 on #443). The observed time is the Mac's
 * own inventory time, so the box states the observation and not an install: the change
 * happened between the inventory before it and that one. Where the inventory time did not
 * move between the two reads, nothing on the Mac dated it — Jamf's copy changed, or the
 * aperture we read it through did — and our own clock is the only honest bound. Where the
 * earlier observation is no longer stored there is no lower bound, and none is stated.
 */
function whenLines(when: PromptWhen, total: number, words: PromptStrings): string[] {
  const lines = [
    total > 1
      ? words.answerWhenSpan(at(when.oldestObservedAt), at(when.observedAt))
      : words.answerWhenOne(at(when.observedAt)),
  ];
  if (when.deviceTimeMoved && when.previousObservedAt) {
    lines.push(words.answerWindowDevice(at(when.previousObservedAt)));
  } else if (when.previousCollectedAt) {
    lines.push(words.answerWindowOurs(at(when.previousCollectedAt), at(when.collectedAt)));
  }
  return lines;
}

/**
 * The response box, written by code from the server's count — the model never sees a
 * row, so it cannot be the one to say how many matched, nor when. The headline counts
 * computers and their changes; changes on smart groups and definitions are a line of their
 * own, so "2 computers" never silently includes a group. The time follows the headline on
 * every answer that matched something, asked for or not: it is the answer to "when was the
 * last time", and no reading of the question decides whether to state it.
 */
export function answerLines(summary: PromptSummary, strings: ChangesStrings): string[] {
  const words = strings.prompt;
  if (summary.total === 0) return [words.answerNone];
  const lines =
    summary.devicesTotal === 0 && summary.otherSubjects > 0
      ? [words.answerOtherOnly(summary.otherSubjects)]
      : [words.answerHeadline(summary.devicesTotal, summary.total - summary.otherSubjects)];
  if (summary.when) lines.push(...whenLines(summary.when, summary.total, words));
  if (summary.devicesTotal === 0 && summary.otherSubjects > 0) return lines;
  for (const device of summary.devices) lines.push(deviceLine(device, words));
  const unlisted = summary.truncated ? summary.devicesTotal - summary.devices.length : 0;
  if (unlisted > 0) lines.push(words.answerMore(unlisted));
  if (summary.otherSubjects > 0) lines.push(words.answerOther(summary.otherSubjects));
  return lines;
}

export type BannerKind = "error" | "invalid" | "unparseable" | "proposal" | "unsupported" | "readback";

/**
 * Port of the handoff's `showBanner` states. `unsupported` is the important one: the
 * controls answered a narrower question than the one asked, and the banner says so
 * rather than let an incomplete result read as complete. An answer with no filters
 * applied nothing, so it never reaches the readback — that would claim "all changes".
 *
 * `proposal` is a proposed answer not yet applied: the corrections that widened it, what
 * its filters would show, and its Apply button. Once applied (`proposalApplied`), it
 * reads as any answer does, banner and response box.
 *
 * `invalid` is text the model judged not a question about device changes: a greeting, a
 * question about the model, knowledge, writing, or an order to act on a device. Nothing
 * ran, and the server's sentence says why; before this state, such text ran as the whole
 * log. A question asking for all changes is not invalid: it runs, every filter unset.
 */
export function bannerKind(result: PromptResult, proposalApplied = false): BannerKind {
  if (result.outcome === "error") return "error";
  if (result.outcome === "invalid") return "invalid";
  if (result.outcome === "unparseable" || result.filters === null) return "unparseable";
  if (result.outcome === "proposed" && !proposalApplied) return "proposal";
  if (result.unsupported) return "unsupported";
  return "readback";
}

/** The card's name from Settings › AI; an unknown provider shows as its own id. */
export function providerLabel(provider: string, labels: Record<string, string>): string {
  return labels[provider] ?? provider;
}

/** The Prompt bar's Model picker: one option per saved provider, in the order the server
 *  lists them — the first is the default — each named "{card} · {model}". Shown with one
 *  provider saved as much as with three, so what will answer is on screen before asking. */
export function modelOptions(
  providers: PromptStatus["providers"],
  labels: Record<string, string>
): { value: Provider; text: string }[] {
  return providers.map((saved) => ({ value: saved.provider, text: `${providerLabel(saved.provider, labels)} · ${saved.model}` }));
}

/**
 * The sentence under "AI search unavailable" when the request for an answer failed —
 * only ever called with the request's own rejection (`readReply`), so a TypeError here is
 * fetch's and the question never reached the server; that one is told to check that
 * LoonInspect is running. A refusal (409, 422) carries the server's own sentence, shown
 * as written. A status with no reason (a plain-text 500, a proxy's 502 or 504) was
 * answered by something, so it names the status and the app's log instead. A body that
 * could not be read (`ApiBodyError`: cut off mid-stream, or not JSON) was answered too.
 */
export function askFailureText(error: unknown, words: PromptStrings): string {
  if (error instanceof ApiError) return error.detail ?? words.askNoReason(error.status);
  if (error instanceof ApiBodyError) return words.askUnreadable;
  if (error instanceof TypeError) return words.askFailed;
  return words.askUnreadable;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const isText = (value: unknown): value is string => typeof value === "string";
const isTextOrNull = (value: unknown): value is string | null => value === null || typeof value === "string";
const isCount = (value: unknown): value is number => typeof value === "number" && Number.isFinite(value);

const OUTCOMES: readonly PromptOutcome[] = ["applied", "proposed", "invalid", "error", "unparseable"];
const HIDDEN_REASONS: readonly PromptHiddenReason[] = ["flag_off", "consent_off", "no_provider"];
const FILTER_KEYS = ["q", "artifact", "level", "section", "change", "since"] as const satisfies readonly (keyof PromptFilters)[];

function isFilters(value: unknown): value is PromptFilters {
  // Strings only; which ones the page knows is its own business — the URL keeps a level or
  // a kind it cannot read out of the query, and the readback names an unknown one by its key.
  return isRecord(value) && FILTER_KEYS.every((key) => isTextOrNull(value[key]));
}

function isDevice(value: unknown): value is PromptDevice {
  return (
    isRecord(value) &&
    isCount(value.connectionId) &&
    isText(value.subjectId) &&
    isTextOrNull(value.label) &&
    isTextOrNull(value.serial) &&
    isText(value.lastObservedAt) &&
    CHANGE_KINDS.every((kind) => isCount(value[kind]))
  );
}

/** Times are checked as text, not parsed: an unreadable one would render as "Invalid Date",
 *  and a body that is not this shape is the server answering in a form the page cannot read. */
function isWhen(value: unknown): value is PromptWhen {
  return (
    isRecord(value) &&
    isText(value.observedAt) &&
    isText(value.oldestObservedAt) &&
    isText(value.collectedAt) &&
    isTextOrNull(value.previousObservedAt) &&
    isTextOrNull(value.previousCollectedAt) &&
    typeof value.deviceTimeMoved === "boolean"
  );
}

function isSummary(value: unknown): value is PromptSummary {
  return (
    isRecord(value) &&
    isCount(value.total) &&
    isCount(value.devicesTotal) &&
    typeof value.truncated === "boolean" &&
    isCount(value.otherSubjects) &&
    Array.isArray(value.devices) &&
    value.devices.every(isDevice) &&
    (value.when === null || isWhen(value.when))
  );
}

function isPromptError(value: unknown): value is PromptError {
  return isRecord(value) && isText(value.kind) && isText(value.message) && (value.status === null || isCount(value.status));
}

/**
 * Whether a 200's body is the answer `POST /api/changes/prompt` promises, checked before
 * anything reads it. A body that parsed as JSON but is not that — `null`, a proxy's own
 * JSON, an older or newer shape — used to throw a TypeError on first read, which the bar
 * then reported as a question that never reached the server. Every field the bar and its
 * answer box read is checked, so a bad one is refused here rather than crashing the page
 * on render. The provider is a string: an unknown one shows as its own id.
 */
export function isPromptResult(value: unknown): value is PromptResult {
  return (
    isRecord(value) &&
    OUTCOMES.includes(value.outcome as PromptOutcome) &&
    (value.filters === null || isFilters(value.filters)) &&
    isTextOrNull(value.unsupported) &&
    Array.isArray(value.repairs) &&
    value.repairs.every(isText) &&
    Array.isArray(value.widening) &&
    value.widening.every(isText) &&
    (value.summary === null || isSummary(value.summary)) &&
    isText(value.provider) &&
    isText(value.model) &&
    isText(value.destination) &&
    isCount(value.latencyMs) &&
    (value.error === null || isPromptError(value.error))
  );
}

/** Whether a 200's body is the answer `GET /api/changes/prompt` promises. Shared with
 *  Settings › AI, which reads the same status for its line about the bar. */
export function isPromptStatus(value: unknown): value is PromptStatus {
  return (
    isRecord(value) &&
    typeof value.available === "boolean" &&
    (value.reason === null || HIDDEN_REASONS.includes(value.reason as PromptHiddenReason)) &&
    Array.isArray(value.providers) &&
    value.providers.every((saved) => isRecord(saved) && isText(saved.provider) && isText(saved.model))
  );
}

/** A question's request, settled before anything reads what came back: either the
 *  request failed (`error` is its rejection), or a body arrived that is not yet trusted. */
export type AskSettled = { ok: true; body: unknown } | { ok: false; error: unknown };

/**
 * What the bar makes of a settled question: an answer to show, or the sentence for why
 * there is none. Only a rejected request goes through `askFailureText`; a body that
 * arrived but is not the answer is the server answering in a form this page cannot read,
 * whatever reading it would have thrown.
 */
export function readReply(settled: AskSettled, words: PromptStrings): { result: PromptResult } | { refusal: string } {
  if (!settled.ok) return { refusal: askFailureText(settled.error, words) };
  if (!isPromptResult(settled.body)) return { refusal: words.askUnreadable };
  return { result: settled.body };
}

/** Where the browser is: the address bar's path and query, not the router's view of them. */
export interface PageAt {
  pathname: string;
  search: string;
}

/** What to do with a reply: move the filters, drop it unseen, or say it came too late. */
export type ReplyDisposition = "apply" | "drop" | "stale";

/**
 * Whether a reply may still move the page. The answer lands seconds after the question,
 * and applying it navigates, so it must land on the page it was asked from:
 *
 * - aborted, or no longer the latest question: dropped — the bar went away, or a newer
 *   question replaced this one;
 * - a different path: dropped silently — the operator left the page. The router commits a
 *   navigation in a transition, so for a few dozen milliseconds after a sidebar click the
 *   address bar is already on the new page while the Changes page is still mounted; a reply
 *   applied then was resolved against the Changes route and dragged the operator back;
 * - the same path with a different query: stale — the operator moved the filters by hand
 *   while waiting, and the answer would overwrite them. The bar says so instead.
 *
 * `askedAt` and `nowAt` are read from `window.location`, which moves the moment a
 * navigation starts; the router's location is the one that lags.
 */
export function replyDisposition(askedAt: PageAt, nowAt: PageAt, aborted: boolean, isLatest: boolean): ReplyDisposition {
  if (aborted || !isLatest) return "drop";
  if (nowAt.pathname !== askedAt.pathname) return "drop";
  if (nowAt.search !== askedAt.search) return "stale";
  return "apply";
}

/**
 * What went wrong with a read, as a clause for a sentence that goes on to name the next
 * check: the server's own words when it sent any, otherwise what the browser saw — never
 * the browser's error message, which is not the operator's vocabulary. Anything that is
 * neither an ApiError nor fetch's TypeError — a body cut off mid-stream or not JSON
 * (`ApiBodyError`), or one that parsed but is not the shape the read promises (pass
 * `null`) — is an answer that could not be read. Shared with Settings › AI, whose reads of
 * the saved cards and of the bar's state fail the same ways.
 */
export function failureReason(
  error: unknown,
  words: Pick<PromptStrings, "reasonStatus" | "reasonNoAnswer" | "reasonUnreadable">
): string {
  // The server's sentences end in a full stop and the caller's sentence goes on.
  if (error instanceof ApiError) return error.detail ? error.detail.replace(/[\s.]+$/, "") : words.reasonStatus(error.status);
  if (error instanceof ApiBodyError) return words.reasonUnreadable;
  if (error instanceof TypeError) return words.reasonNoAnswer;
  return words.reasonUnreadable;
}
