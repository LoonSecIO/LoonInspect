/**
 * The patch-policy replay file as this page reads it (#614, first slice): its shape, the check that
 * refuses a file the page must not draw, and the lookups the views share. Pure, and free of the app:
 * no fetch, no router, no locale, so the same module can serve the page wherever it is lifted to.
 *
 * LoonVD computes every number (`docs/PATCH-POLICY-REPLAY.md` in LoonVD-Internal); nothing here
 * recomputes one. The contract is additive-only: unknown keys are ignored, and a file of another
 * `kind`, `schema` or CVE clock, or one whose own totals disagree, is refused whole rather than drawn
 * in part.
 *
 * Schema 3 is the replay of the eight stops, each labelled by the days it waits (ruled 2026-11-27,
 * "0 = same day"): a stop of N days installs each release N days after the date its timeline gives
 * it, and every day row says so in its own `install_delay_days`, which must be the number in its stop
 * id. Like schema 2 it names its own release dates: `timeline` says where they come from and what a
 * date means, and each release and fix carries `release_date` on that timeline.
 *
 * Schema 2 counts the old way: its N-day row waits N - 1 days (the file's own `definitions.install`
 * says the install date is the release date + (D - 1) days), so drawn under this page's stops every
 * number would sit one day early. It is refused whole, in words, and never relabelled here: LoonSec
 * writes the replays, and this page computes nothing in them. Schema 1 has no `timeline` block, the
 * part of the file this page reads to name and link where its release dates come from, so this page
 * refuses it rather than print dates without naming and linking their source.
 *
 * `cve_clock` names the clock every CVE is placed on. This page states one clock, NVD's publication
 * date, in its own words, so a file on any other clock is refused rather than drawn under words that
 * would misstate it.
 */

import { POLICY_DEFINITION_IDS } from "@/features/patchPolicy/definitions";

export const REPLAY_KIND = "patch_policy_replay";
export const REPLAY_SCHEMA = 3;
/** The schema that counts the old way, an N-day row being N - 1 days waited: refused in its own words. */
export const REPLAY_OLD_COUNT_SCHEMA = 2;
/** The one CVE clock the page's words state: each CVE counts from the day NVD published it. */
export const REPLAY_CVE_CLOCK = "published";

/** The slider's stops, in order: the day policies, each labelled by the days it waits, then Never. */
export const SLIDER_STOPS = ["0d", "1d", "3d", "7d", "14d", "30d", "60d", "never"] as const;
export type SliderStop = (typeof SLIDER_STOPS)[number];
/** The day policies, which wait the days their id names; `never` installs nothing. */
export type DayStop = Exclude<SliderStop, "never">;
export const DAY_STOPS = SLIDER_STOPS.filter((stop): stop is DayStop => stop !== "never");
/** The days a day stop waits after the date a release is given: the number in its id. */
export const stopDays = (stop: DayStop): number => Number.parseInt(stop, 10);

/** The file's `critical_or_kev` row, superseded by the built-in policy definitions (ruled
 *  2026-11-28, #954): computed in the file, never on the slider and never quoted. LoonSec replaces it
 *  with rows on the ruled definitions when it writes the files again. A file reads with it, without it,
 *  or with rows keyed by a definition id instead, and the page draws and quotes none of them: it prints
 *  this row's definition apart, in the file's words, and none of its numbers. */
export const SUPERSEDED_POLICY = "critical_or_kev";

export interface PolicyTotals {
  /** On a day row, the days it waits after a release's date: the number in its stop id (schema 3). */
  install_delay_days?: number | null;
  never_seen: number;
  never_seen_outside_affected_range: number;
  exposed: number;
  exposure_days: number;
  open_at_window_end: number;
  update_events: number;
  initial_version: string;
  final_version: string;
  installs: { date: string; version: string }[];
}

/** One of NVD's statements of which versions a CVE affects, as the file carries it: a range with its
 *  bounds, or one exact version. The page prints it and never evaluates it. */
export interface AffectedStatement {
  kind?: string;
  version?: string;
  bounds?: Record<string, unknown>;
}

export interface LedgerFix {
  /** The release line the fix is on: `"4.4"`, or `""` for an app replayed as one line. */
  branch?: string;
  fixed_version?: string | null;
  /** The fixed release's date on the file's own `timeline`. */
  release_date?: string | null;
  /** The statement this fix closes. A CVE carries one fix per statement, so a CVE NVD states several
   *  ranges for can carry several fixes on one line: an app replayed as one line puts them all there. */
  affected?: AffectedStatement;
}

/** Where the file's release dates come from, in the file's own words. The page prints `name` and
 *  `clock` as they stand and names no source the file does not. */
export interface ReplayTimeline {
  source?: string;
  name: string;
  url?: string;
  fetched_at: string;
  sha256?: string;
  /** What one of its dates means: the day a build was first served, a tag's date, and so on. */
  clock: string;
  /** The edition the table keeps, where the product has more than one (Mozilla's `release`, beside
   *  its ESR): the page then says which one is replayed. */
  edition?: string;
}

/** One cut the file made to its window, in its own words: the day it now ends, why, and a sentence. */
export interface WindowCut {
  date?: string;
  reason?: string;
  sentence?: string;
}

export interface LedgerOutcome {
  outcome: string;
  /** On `never_seen`: `fix_installed_first` or `outside_affected_range`. */
  why?: string;
  cleared_by?: string | null;
  cleared_on?: string | null;
  exposure_days?: number;
  open_at_window_end?: boolean;
}

export interface LedgerRow {
  cve_id: string;
  published?: string;
  /** NVD's status for the record when the file was made (`Analyzed`, `Awaiting Analysis`, `Deferred`, …). */
  status?: string | null;
  severity?: string | null;
  fixes?: LedgerFix[];
  exclusion?: string | null;
  /** Absent on an excluded CVE, which no policy was replayed against. */
  outcomes?: Record<string, LedgerOutcome>;
}

export interface ExcludedCve {
  cve_id: string;
  published?: string;
  reason?: string;
  detail?: string | null;
}

export interface PatchPolicyReplay {
  kind: typeof REPLAY_KIND;
  schema: typeof REPLAY_SCHEMA;
  run_id: string;
  /** `until` is the window's last day. Where the file cut it short, `requested_until` is the day it
   *  was asked to reach and `shortened_by` says why; the page prints both and computes neither. */
  window: { since: string; until: string; requested_until?: string; shortened_by?: WindowCut[] };
  definitions: Record<string, string>;
  /** The clock every CVE is placed on, by its key in `clocks`. The page reads only `published`. */
  cve_clock: typeof REPLAY_CVE_CLOCK;
  /** `published` defines the CVE clock the page states: each CVE counts from NVD's publication date. */
  clocks: Record<string, string> & { published: string };
  timeline: ReplayTimeline;
  counts: { cves_in_window: number; cves_replayed: number; cves_excluded: number };
  exclusions: { by_reason: Record<string, number>; cves: ExcludedCve[] };
  policies: Record<SliderStop, PolicyTotals> & Record<string, PolicyTotals | undefined>;
  branch_choice: {
    /** The release line the device is held to; `null` for an app replayed as one line, whose
     *  fixes all name the line `""` and which has no other line to choose. */
    held_at_branch: string | null;
    cves_where_the_choice_changes_the_answer?: { by_policy?: Record<string, number> };
  };
  /** Present where the vendor promotes a major to stable on a day of its own (Chrome): `skip` is the
   *  device that waits for that day. */
  early_stable_choice?: { device?: string; promotion_table_behind_timeline?: boolean };
  product?: { bundle_ids?: string[] };
  ledger: LedgerRow[];
}

/** Why a file was not drawn. `detail` is in the file's own key names, so it reads the same in every
 *  language and can be pasted into a report as it stands. */
export type Refusal =
  | { why: "unreadable" }
  | { why: "kind"; found: string }
  | { why: "schema"; found: string }
  /** Schema 2: its N-day row is N - 1 days waited, so it cannot be drawn under labels that mean days waited. */
  | { why: "old_count" }
  /** A day row that does not state the days it waits as its stop id's number; `found` as the file has it. */
  | { why: "delay"; stop: DayStop; found: string }
  | { why: "clock"; found: string }
  | { why: "missing"; key: string }
  | { why: "totals"; detail: string };

export type ReadResult = { replay: PatchPolicyReplay; refusal?: undefined } | { refusal: Refusal; replay?: undefined };

type Json = Record<string, unknown>;
const isRecord = (value: unknown): value is Json => typeof value === "object" && value !== null && !Array.isArray(value);
const isCount = (value: unknown): value is number => typeof value === "number" && Number.isInteger(value) && value >= 0;
const isText = (value: unknown): value is string => typeof value === "string" && value !== "";
const shown = (value: unknown) => (value === undefined ? "absent" : JSON.stringify(value));

const POLICY_COUNTS = ["never_seen", "never_seen_outside_affected_range", "exposed", "exposure_days", "open_at_window_end", "update_events"] as const;

/** The first key the page draws that the file lacks or mistypes, as a dotted path; `null` when all are there. */
function firstMissing(file: Json): string | null {
  if (!isText(file.run_id)) return "run_id";
  if (!isRecord(file.window) || !isText(file.window.since)) return "window.since";
  if (!isText(file.window.until)) return "window.until";
  if (!isRecord(file.definitions)) return "definitions";
  if (!isRecord(file.clocks) || !isText(file.clocks.published)) return "clocks.published";
  // The page names the source of every date it prints, and says what a date means, from these.
  if (!isRecord(file.timeline) || !isText(file.timeline.name)) return "timeline.name";
  if (!isText(file.timeline.clock)) return "timeline.clock";
  if (!isText(file.timeline.fetched_at)) return "timeline.fetched_at";
  // Present on every replay, and `null` only for one release line: the page reads null as that.
  if (!isRecord(file.branch_choice) || !(file.branch_choice.held_at_branch === null || isText(file.branch_choice.held_at_branch))) {
    return "branch_choice.held_at_branch";
  }
  if (!isRecord(file.counts)) return "counts";
  for (const key of ["cves_in_window", "cves_replayed", "cves_excluded"]) if (!isCount(file.counts[key])) return `counts.${key}`;
  if (!isRecord(file.policies)) return "policies";
  for (const stop of SLIDER_STOPS) {
    const policy = file.policies[stop];
    if (!isRecord(policy)) return `policies.${stop}`;
    for (const key of POLICY_COUNTS) if (!isCount(policy[key])) return `policies.${stop}.${key}`;
    for (const key of ["initial_version", "final_version"]) if (!isText(policy[key])) return `policies.${stop}.${key}`;
    if (!Array.isArray(policy.installs)) return `policies.${stop}.installs`;
  }
  if (!isRecord(file.exclusions) || !isRecord(file.exclusions.by_reason)) return "exclusions.by_reason";
  if (!Object.values(file.exclusions.by_reason).every(isCount)) return "exclusions.by_reason";
  if (!Array.isArray(file.exclusions.cves) || !file.exclusions.cves.every((row) => isRecord(row) && isText(row.cve_id))) return "exclusions.cves";
  if (!Array.isArray(file.ledger) || !file.ledger.every((row) => isRecord(row) && isText(row.cve_id))) return "ledger";
  return null;
}

/** The first day row that does not wait the days its stop id names, with what it states instead;
 *  `null` when every one does. A schema-3 file states each row's delay, so the page never infers
 *  the count from a label: a row that waits otherwise, or does not say, is not drawn under it. */
function firstWrongDelay(file: Json): { stop: DayStop; found: string } | null {
  const policies = file.policies as Json;
  for (const stop of DAY_STOPS) {
    const stated = (policies[stop] as Json).install_delay_days;
    if (stated !== stopDays(stop)) return { stop, found: shown(stated) };
  }
  return null;
}

/** The first of the file's own totals that does not agree with another, in its own key names; `null`
 *  when they all close. Checked, never repaired: the page prints these numbers side by side, so a
 *  headline over a table that counts differently would be two answers on one screen. */
function firstDisagreement(replay: PatchPolicyReplay): string | null {
  const { cves_in_window: inWindow, cves_replayed: replayed, cves_excluded: excluded } = replay.counts;
  if (replayed + excluded !== inWindow) {
    return `counts: cves_replayed ${replayed} + cves_excluded ${excluded} ≠ cves_in_window ${inWindow}`;
  }
  const byReason = Object.values(replay.exclusions.by_reason).reduce((sum, count) => sum + count, 0);
  if (byReason !== excluded) return `exclusions.by_reason sums to ${byReason} ≠ counts.cves_excluded ${excluded}`;
  if (replay.exclusions.cves.length !== excluded) {
    return `exclusions.cves lists ${replay.exclusions.cves.length} ≠ counts.cves_excluded ${excluded}`;
  }
  // The superseded row, and a row keyed by a definition id, are held to the same sum when the file
  // carries them, though none of them is drawn: the file's own totals agree, or it is not drawn at all.
  for (const key of [...SLIDER_STOPS, SUPERSEDED_POLICY, ...POLICY_DEFINITION_IDS]) {
    const policy = replay.policies[key];
    if (!policy || !isCount(policy.never_seen) || !isCount(policy.exposed)) continue;
    if (policy.never_seen + policy.exposed !== replayed) {
      return `policies.${key}: never_seen ${policy.never_seen} + exposed ${policy.exposed} ≠ counts.cves_replayed ${replayed}`;
    }
    if (policy.never_seen_outside_affected_range > policy.never_seen) {
      return `policies.${key}: never_seen_outside_affected_range ${policy.never_seen_outside_affected_range} > never_seen ${policy.never_seen}`;
    }
  }
  if (replay.ledger.length !== inWindow) return `ledger lists ${replay.ledger.length} ≠ counts.cves_in_window ${inWindow}`;
  const rows = replayedRows(replay);
  if (rows.length !== replayed) return `ledger rows without an exclusion: ${rows.length} ≠ counts.cves_replayed ${replayed}`;
  for (const stop of SLIDER_STOPS) {
    const policy = replay.policies[stop];
    const outcomes = rows.map((row) => row.outcomes?.[stop]);
    const tallies: [string, number, number][] = [
      ["never_seen", outcomes.filter((outcome) => outcome?.outcome === "never_seen").length, policy.never_seen],
      ["exposed", outcomes.filter((outcome) => outcome?.outcome === "exposed").length, policy.exposed],
      [
        "never_seen_outside_affected_range",
        outcomes.filter((outcome) => outcome?.outcome === "never_seen" && outcome.why === "outside_affected_range").length,
        policy.never_seen_outside_affected_range
      ]
    ];
    for (const [key, listed, stated] of tallies) {
      if (listed !== stated) return `ledger under ${stop}: ${key} ${listed} ≠ policies.${stop}.${key} ${stated}`;
    }
  }
  return null;
}

/** Read one replay file: the replay, or the reason it is refused. Never a partial answer. */
export function readReplay(raw: unknown): ReadResult {
  if (!isRecord(raw)) return { refusal: { why: "unreadable" } };
  if (raw.kind !== REPLAY_KIND) return { refusal: { why: "kind", found: shown(raw.kind) } };
  // The old count has its own words: its rows would be drawn a day early under these stops.
  if (raw.schema === REPLAY_OLD_COUNT_SCHEMA) return { refusal: { why: "old_count" } };
  if (raw.schema !== REPLAY_SCHEMA) return { refusal: { why: "schema", found: shown(raw.schema) } };
  // Before any other key: the page's words state this clock, so a file on another one is not drawn.
  if (raw.cve_clock === undefined) return { refusal: { why: "missing", key: "cve_clock" } };
  if (raw.cve_clock !== REPLAY_CVE_CLOCK) return { refusal: { why: "clock", found: shown(raw.cve_clock) } };
  const key = firstMissing(raw);
  if (key) return { refusal: { why: "missing", key } };
  const delay = firstWrongDelay(raw);
  if (delay) return { refusal: { why: "delay", ...delay } };
  const replay = raw as unknown as PatchPolicyReplay;
  const detail = firstDisagreement(replay);
  return detail ? { refusal: { why: "totals", detail } } : { replay };
}

/** The CVEs the policies were replayed against: the ledger less its excluded rows. */
export function replayedRows(replay: PatchPolicyReplay): LedgerRow[] {
  return replay.ledger.filter((row) => !row.exclusion);
}

/** A fix that names its fixed version, which is the only kind the Fix column prints. */
export type NamedFix = LedgerFix & { fixed_version: string };

/** Every fix on the release line the device is held to, which are the ones its installs can reach,
 *  oldest release first. A held line of `null` is the one line of an app replayed as one, whose fixes
 *  all name the line `""`. There is one fix per statement NVD makes about the CVE, so a line can carry
 *  several: a Mozilla CVE NVD states for the ESR lines and the release channel alike has one fix per
 *  range, and which of them the device's versions fall in is LoonVD's judgement, not this page's. So
 *  every one is returned, never the first. Empty where the CVE names no fix on that line: those are
 *  the rows that were never in range. */
export function heldFixes(row: LedgerRow, line: string | null): NamedFix[] {
  const held = line ?? "";
  const fixes = (Array.isArray(row.fixes) ? row.fixes : []).filter(
    (fix): fix is NamedFix => isRecord(fix) && (fix.branch ?? "") === held && isText(fix.fixed_version)
  );
  // By the date the file gives, so the list reads in order; an undated fix goes last, and a tie keeps
  // the file's order (the sort is stable).
  const order = (fix: LedgerFix) => (isText(fix.release_date) ? `0${fix.release_date}` : "1");
  return fixes.sort((a, b) => (order(a) < order(b) ? -1 : order(a) > order(b) ? 1 : 0));
}

/** One bound of an affected range, as the page words it: the version, and whether it is included. */
export interface AffectedBound {
  version: string;
  including: boolean;
}

/** A statement the page can word: one exact version, or a range with a start, an end, or both. */
export type AffectedRange = { exact: string } | { start?: AffectedBound; end?: AffectedBound };

/** A fix's statement in the shape the page words, read defensively: `null` for one it cannot word
 *  (absent, unbounded, or a kind it does not know), which then prints without a range. */
export function affectedBounds(fix: LedgerFix): AffectedRange | null {
  const affected = fix.affected;
  if (!isRecord(affected)) return null;
  if (affected.kind === "exact") return isText(affected.version) ? { exact: affected.version } : null;
  if (affected.kind !== "range" || !isRecord(affected.bounds)) return null;
  const { bounds } = affected;
  const bound = (including: string, excluding: string): AffectedBound | undefined => {
    const [kept, left] = [bounds[including], bounds[excluding]];
    return isText(kept) ? { version: kept, including: true } : isText(left) ? { version: left, including: false } : undefined;
  };
  const start = bound("versionStartIncluding", "versionStartExcluding");
  const end = bound("versionEndIncluding", "versionEndExcluding");
  return start || end ? { ...(start && { start }), ...(end && { end }) } : null;
}

/** Where the file cut its window short: the last day it was asked to reach, when that is not the day
 *  it ends, and each reason it gives, in its own words. `null` when the window runs as asked. Read
 *  defensively, because the check does not ask for either key: a window that was never cut has none. */
export function windowCut(replay: PatchPolicyReplay): { requested: string | null; reasons: string[] } | null {
  const { until, requested_until: requested, shortened_by: cuts } = replay.window;
  const reasons = (Array.isArray(cuts) ? cuts : [])
    .map((cut: unknown) => (!isRecord(cut) ? null : isText(cut.sentence) ? cut.sentence : isText(cut.reason) ? cut.reason : null))
    .filter((reason): reason is string => reason !== null);
  const asked = isText(requested) && requested !== until ? requested : null;
  return asked !== null || reasons.length > 0 ? { requested: asked, reasons } : null;
}

export const isSliderStop = (value: string | null): value is SliderStop => SLIDER_STOPS.includes(value as SliderStop);
