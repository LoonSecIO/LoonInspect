import { ApiError, apiRequest } from "@/config/api";
import { SLIDER_STOPS, type SliderStop } from "@/features/patchPolicy/replay";
import type { PatchPolicyApp, PatchPolicySourceTrack } from "@/features/support/patchPolicyFeed";

/**
 * Posture › Patch policy's day-walk, as the page reads it (#614): `GET /api/patch-policy/walk` and
 * the few decisions the page makes about its answer. The walk is computed on this instance
 * (`app.core.patch_policy_walk`) and the page recomputes none of it: every number drawn is a field
 * of the answer, and every refusal is the instance's own sentence beside the page's.
 *
 * Three answers, never a fourth: a walk; a refusal (the route's 409, whose `reason` is the word
 * docs/troubleshooting.md §33 walks); or a failed read (no answer, another status, or an answer
 * this build cannot draw), which is not a refusal and says so.
 */

export const WALK_KIND = "patch_policy_walk";
export const WALK_SCHEMA = 1;

export type WalkSource = "public" | "jamf" | "fleet";
/** The toggle's order, and Public first: it is the default (R12). */
export const WALK_SOURCES: readonly WalkSource[] = ["public", "jamf", "fleet"];
export const isWalkSource = (value: string | null): value is WalkSource => WALK_SOURCES.includes(value as WalkSource);

export type WalkYears = 2 | 3;
export const WALK_YEARS: readonly WalkYears[] = [2, 3];
export const isWalkYears = (value: number): value is WalkYears => WALK_YEARS.includes(value as WalkYears);

export interface WalkSeries {
  /** CVEs open on the window's first day from before it, counted apart from `new`. */
  opening: number;
  open: number[];
  new: number[];
  resolved: number[];
  new_by_reason: { became_detectable: number[]; entered_range: number[] };
  resolved_by_reason: { update_installed: number[] };
}

export interface WalkPolicy {
  stop: SliderStop;
  install_delay_days: number | null;
  never_seen: number;
  never_seen_outside_affected_range: number;
  exposed: number;
  exposure_days: number;
  carried_in: number;
  entered_after_start: number;
  pre_window_closed: number;
  exposure_days_carried_in: number;
  exposure_days_entered_after_start: number;
  open_at_window_end: { in_window: number; carried_in: number; entered_after_start: number };
  update_events: number;
  initial_version: string | null;
  final_version: string | null;
  installs: { date: string; version: string | null }[];
  series: WalkSeries;
}

export interface WalkOutcome {
  class: "in_window" | "carried_in" | "entered_after_start" | "pre_window_closed";
  outcome: "exposed" | "never_seen" | "not_open_in_window";
  why?: "fix_installed_first" | "outside_affected_range";
  exposure_days?: number;
  open_at_window_end?: boolean;
  cleared_on?: string | null;
  cleared_by?: string | null;
  intervals?: [string, string][];
  version_at_clock?: string | null;
}

/** How the walk dated one of the CVE's fixes on a line its path visits (ruled 2026-11-25, "count the
 *  next dated version at or above the fix"): one entry per fix LoonSec's data lists, in its order.
 *  `named` is NVD's own fix version where LoonSec's version is not that exact one; `dated_as` and
 *  `on` are the version whose date the walk used, and that date. */
export interface WalkFixDating {
  line: string;
  fix: string | null;
  named: string | null;
  dated_as: string | null;
  on: string | null;
  /** `fix`: the source dates the fix itself; `next_dated`: it dates a later version outside the
   *  CVE's range instead; `undated`: it dates none, and the CVE is walked by its ranges there. */
  how: "fix" | "next_dated" | "undated";
}

export interface WalkCve {
  cve_id: string;
  class: "in_window" | "before_window";
  /** Which clock placed the row: the first day it was detectable where LoonSec knows it, and
   *  NVD's publication date where it does not. */
  clock: "detectable_at" | "published" | null;
  clock_date: string | null;
  published: string | null;
  detectable_at: string | null;
  detectable_not_before?: string | null;
  detectable_censored?: boolean | null;
  detectable_source?: string | null;
  severity: string | null;
  kev_date_added: string | null;
  affected_text?: string | null;
  configurations_changed_after_detectable?: boolean | null;
  /** Absent from an instance older than the ruling: read as none. */
  fix_dated_by?: WalkFixDating[];
  outcomes: Partial<Record<SliderStop, WalkOutcome>>;
}

export interface WalkShortened {
  reason: string;
  date: string;
  /** The instance's own sentence for the cut, in English. */
  sentence: string;
}

export interface WalkLeftOut {
  source: WalkSource;
  reason: string;
  sentence: string;
}

/** The versions a timeline named that a channel LoonSec's data names beside the app's tracks, and
 *  does not walk, lists (`other_channels`): set aside before the walk, never counted as unmatched. */
export interface WalkChannelSetAside {
  channel: string;
  label: string;
  /** The public record LoonSec read the channel's versions from. */
  source: string;
  count: number;
  versions: string[];
}

export interface WalkTimeline {
  source: WalkSource;
  name: string;
  digest: string;
  as_of: string;
  first: string | null;
  last: string | null;
  observations: number;
  matched: number;
  unmatched: string[];
  other_track: number;
  undated: number;
  conflicts: number;
  in_reach: { since: string; until: string; matched: number; unmatched: string[]; share: number };
  ids: string[];
  other_track_versions: string[];
  /** Absent from an instance older than the split by channel: read as none. */
  other_channel?: number;
  other_channels?: WalkChannelSetAside[];
  note: string | null;
}

export interface PatchPolicyWalk {
  kind: typeof WALK_KIND;
  schema: number;
  algorithm: string;
  definitions_version: string;
  input_id: string;
  run_id: string;
  inputs: {
    doc_id: string;
    doc_as_of: string;
    app: string;
    name: string;
    track: string;
    label: string;
    path: { kind: "hold" | "latest"; ceiling_line: string | null; waits_for_promotion: boolean };
    timeline: WalkTimeline;
  };
  window: {
    requested: { years: number; since: string; until: string };
    since: string;
    until: string;
    days: number;
    shortened_by: WalkShortened[];
    aligned?: { sources: WalkSource[]; since: string; until: string; left_out: WalkLeftOut[] };
  };
  counts: {
    cves_in_doc: number;
    in_window: number;
    replayed: number;
    excluded: number;
    before_window: number;
    before_window_excluded: number;
    after_window: number;
    without_clock: number;
    not_detectable: number;
    uncertain_over_1d: number;
    replayed_by_clock: { detectable_at: number; published: number };
    placed_by_clock: { detectable_at: number; published: number };
    /** The `fix_dated_by` entries of the rows `cves` lists, by `how`. Absent from an older instance. */
    fix_dating?: { fix: number; next_dated: number; undated: number };
  };
  exclusions: {
    by_reason: Record<string, number>;
    cves: { cve_id: string; reason: string; clock: string | null; clock_date: string | null; published: string | null; detail: string | null }[];
    before_window_by_reason: Record<string, number>;
  };
  policies: Record<SliderStop, WalkPolicy>;
  cves: WalkCve[];
  cves_page: { page: number; page_size: number; pages: number; total: number };
  intervals_for: SliderStop | null;
  check: { state: "matched" | "unchecked_window"; detail: string };
  definitions: Record<string, string>;
  document_definitions: Record<string, unknown>;
  clocks: Record<string, unknown>;
}

/** The route's 409: `detail` is the instance's sentence, `reason` the word §33 walks. */
export interface WalkRefusal {
  detail: string;
  reason: string;
  source: string | null;
  facts: Record<string, unknown>;
}

export type WalkAnswer =
  | { walk: PatchPolicyWalk; refusal?: undefined; failed?: undefined }
  | { refusal: WalkRefusal; walk?: undefined; failed?: undefined }
  /** No walk and no refusal: `status` is what the instance answered (null for no answer at all),
   *  and `unreadable` names what this build could not draw in an answer that did arrive. */
  | { failed: { status: number | null; unreadable?: string }; walk?: undefined; refusal?: undefined };

export interface WalkRequest {
  app: string;
  track: string;
  source: WalkSource;
  years: WalkYears;
  align: boolean;
  page: number;
}

/** The request, as its query string. No `stop`: the page reads each CVE's outcome under every stop,
 *  which the answer always carries, and draws no day intervals, so a slider move asks for nothing. */
export function walkQuery(request: WalkRequest): string {
  const query = new URLSearchParams({
    app: request.app,
    track: request.track,
    source: request.source,
    years: String(request.years)
  });
  if (request.align) query.set("align", "common");
  if (request.page > 1) query.set("page", String(request.page));
  return query.toString();
}

const isObject = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);

/** What this build cannot draw in an answer, or null when it can. The instance answers in the shape
 *  its own build serves, so this guards a page left open across an update rather than a stranger. */
export function unreadable(body: unknown): string | null {
  if (!isObject(body)) return "not an object";
  if (body.kind !== WALK_KIND) return `kind ${JSON.stringify(body.kind)}`;
  if (body.schema !== WALK_SCHEMA) return `schema ${JSON.stringify(body.schema)}`;
  const window = body.window;
  if (!isObject(window) || typeof window.days !== "number" || typeof window.since !== "string") return "window";
  const policies = body.policies;
  if (!isObject(policies)) return "policies";
  for (const stop of SLIDER_STOPS) {
    const policy = policies[stop];
    const series = isObject(policy) ? policy.series : undefined;
    if (!isObject(series)) return `policies.${stop}.series`;
    for (const key of ["open", "new", "resolved"] as const) {
      const values = series[key];
      if (!Array.isArray(values) || values.length !== window.days) return `policies.${stop}.series.${key}`;
    }
  }
  if (!Array.isArray(body.cves) || !isObject(body.cves_page) || !isObject(body.inputs) || !isObject(body.counts)) return "cves";
  return null;
}

/** A walk's or a refusal's set-aside channels, read tolerantly: a row this build cannot read is skipped. */
export function channelsSetAside(value: unknown): WalkChannelSetAside[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((row): WalkChannelSetAside[] => {
    if (!isObject(row) || typeof row.label !== "string" || typeof row.count !== "number") return [];
    const versions = Array.isArray(row.versions) ? row.versions.filter((each): each is string => typeof each === "string") : [];
    return [{ channel: typeof row.channel === "string" ? row.channel : row.label, label: row.label, source: typeof row.source === "string" ? row.source : "", count: row.count, versions }];
  });
}

const FOUR_PART = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/;

/** Whether a fix LoonSec's data points at is an earlier build of the release NVD names (`named`): both
 *  four-part (Chrome's major.minor.build.patch), the same in their first three parts, the fix's last
 *  part the lower. LoonSec's data lists a fix below NVD's version only where it corrected NVD's bound
 *  to the Mac's own build of that release, read from the vendor's release post (troubleshooting.md §33
 *  step 12); everywhere else its fix is NVD's version or the next one at or above it. The entry
 *  carries no ranks, so this reads the two version strings, and only to choose the words beside the
 *  fix: the walk counts nothing by it, and any other shape of version reads false. */
export function fixBelowNamedBuild(entry: Pick<WalkFixDating, "fix" | "named">): boolean {
  const fix = entry.fix?.match(FOUR_PART);
  const named = entry.named?.match(FOUR_PART);
  if (!fix || !named) return false;
  return fix[1] === named[1] && fix[2] === named[2] && fix[3] === named[3] && Number(fix[4]) < Number(named[4]);
}

/** The refusal in a 409's body, or null when the body is not one. */
function refusalOf(body: unknown): WalkRefusal | null {
  if (!isObject(body) || typeof body.detail !== "string" || typeof body.reason !== "string") return null;
  return {
    detail: body.detail,
    reason: body.reason,
    source: typeof body.source === "string" ? body.source : null,
    facts: isObject(body.facts) ? body.facts : {}
  };
}

/** One walk, by its query string (`walkQuery`). */
export function getPatchPolicyWalk(query: string): Promise<WalkAnswer> {
  return apiRequest<unknown>(`/patch-policy/walk?${query}`).then(
    (body): WalkAnswer => {
      const wrong = unreadable(body);
      return wrong ? { failed: { status: 200, unreadable: wrong } } : { walk: body as PatchPolicyWalk };
    },
    (caught: unknown): WalkAnswer => {
      if (caught instanceof ApiError) {
        const refusal = caught.status === 409 ? refusalOf(caught.body) : null;
        return refusal ? { refusal } : { failed: { status: caught.status } };
      }
      return { failed: { status: null } };
    }
  );
}

// --- what the page decides about /apps ------------------------------------------------------------

/** The app's default track: the one the document marks default, else its first. */
export function defaultTrack(app: Pick<PatchPolicyApp, "tracks">): string | null {
  return (app.tracks.find((track) => track.default) ?? app.tracks.at(0))?.track ?? null;
}

/** One source's answer for one track, as `/apps` gave it; undefined when it gave none. */
export function sourceTrack(app: Pick<PatchPolicyApp, "sources">, source: WalkSource, track: string): PatchPolicySourceTrack | undefined {
  return app.sources[source].tracks.find((entry) => entry.track === track);
}

/** Whether a Jamf patch catalog title that shares the app's bundle id is an ESR title the document
 *  has no track for: the picker folds it under the app's row, so the page says what is not walked. */
export function esrFoldedIn(app: Pick<PatchPolicyApp, "bundleIds" | "tracks">, titles: readonly { name: string; bundleId: string | null }[]): boolean {
  if (app.tracks.some((track) => track.channel === "esr" || track.edition === "esr")) return false;
  const mine = new Set(app.bundleIds.map((id) => id.toLowerCase()));
  return titles.some((title) => title.bundleId !== null && mine.has(title.bundleId.toLowerCase()) && /\besr\b/i.test(title.name));
}

// --- what the graph reads -------------------------------------------------------------------------

/** The day `offset` days after `since` (a `YYYY-MM-DD` day, read as UTC). */
export function dayAfter(since: string, offset: number): string {
  const day = new Date(`${since}T00:00:00Z`);
  day.setUTCDate(day.getUTCDate() + offset);
  return day.toISOString().slice(0, 10);
}

export interface SeriesDay {
  offset: number;
  date: string;
  open: number;
  new: number;
  becameDetectable: number;
  enteredRange: number;
  resolved: number;
  /** The version installed that day, when the device installed one. */
  installed: string | null;
}

/** One day of a stop's series, with what the device installed on it. */
export function seriesDay(policy: WalkPolicy, since: string, offset: number): SeriesDay {
  const { series } = policy;
  const date = dayAfter(since, offset);
  return {
    offset,
    date,
    open: series.open[offset] ?? 0,
    new: series.new[offset] ?? 0,
    becameDetectable: series.new_by_reason?.became_detectable?.[offset] ?? 0,
    enteredRange: series.new_by_reason?.entered_range?.[offset] ?? 0,
    resolved: series.resolved[offset] ?? 0,
    installed: policy.installs.find((install) => install.date === date)?.version ?? null
  };
}

/** The days the count moved (something opened or was resolved), and the first day, which the count
 *  opens on: the graph's table view. */
export function movedDays(policy: WalkPolicy, since: string): SeriesDay[] {
  const { series } = policy;
  const days: SeriesDay[] = [];
  for (let offset = 0; offset < series.open.length; offset += 1) {
    if (offset === 0 || series.new[offset] > 0 || series.resolved[offset] > 0) days.push(seriesDay(policy, since, offset));
  }
  return days;
}

export interface SeriesSummary {
  first: number;
  last: number;
  peak: number;
  peakDate: string;
  /** Opened after the first day; the first day's count is `first`. */
  opened: number;
  resolved: number;
}

/** What the graph's accessible name says: where the count starts and ends, its peak, and how many
 *  opened and were resolved over the window. */
export function summarise(policy: WalkPolicy, since: string): SeriesSummary {
  const { open } = policy.series;
  let peakAt = 0;
  open.forEach((value, offset) => {
    if (value > open[peakAt]) peakAt = offset;
  });
  const sum = (values: number[]) => values.reduce((total, value) => total + value, 0);
  return {
    first: open[0] ?? 0,
    last: open.at(-1) ?? 0,
    peak: open[peakAt] ?? 0,
    peakDate: dayAfter(since, peakAt),
    opened: sum(policy.series.new.slice(1)),
    resolved: sum(policy.series.resolved)
  };
}

/** A y-axis that ends on a clean number at or above `max`, with its ticks: 0 and up to four more. */
export function yTicks(max: number): number[] {
  if (max <= 0) return [0, 1];
  const rough = max / 4;
  const magnitude = 10 ** Math.floor(Math.log10(rough));
  const step = [1, 2, 5, 10].map((each) => each * magnitude).find((each) => each >= rough) ?? 10 * magnitude;
  const whole = Math.max(1, Math.ceil(step));
  const top = Math.ceil(max / whole) * whole;
  const ticks: number[] = [];
  for (let value = 0; value <= top; value += whole) ticks.push(value);
  return ticks;
}

/** The first day of each year inside the window, as offsets: the x-axis's ticks between its ends. */
export function yearTicks(since: string, days: number): { offset: number; year: string }[] {
  const ticks: { offset: number; year: string }[] = [];
  const first = Number(since.slice(0, 4));
  for (let year = first + 1; ; year += 1) {
    const offset = Math.round((Date.parse(`${year}-01-01T00:00:00Z`) - Date.parse(`${since}T00:00:00Z`)) / 86_400_000);
    if (offset >= days) break;
    if (offset > 0) ticks.push({ offset, year: String(year) });
  }
  return ticks;
}
