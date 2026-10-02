/**
 * The patch-policy replay file as this page reads it (#614, first slice): its shape, the check that
 * refuses a file the page must not draw, and the lookups the views share. Pure, and free of the app:
 * no fetch, no router, no locale, so the same module can serve the page wherever it is lifted to.
 *
 * LoonVD computes every number (`docs/PATCH-POLICY-REPLAY.md` in LoonVD-Internal); nothing here
 * recomputes one. The contract is additive-only: unknown keys are ignored, and a file of another `kind`
 * or `schema`, or one whose own totals disagree, is refused whole rather than drawn in part.
 */

export const REPLAY_KIND = "patch_policy_replay";
export const REPLAY_SCHEMA = 1;

/** The slider's stops, in order: the day policies, then Never. */
export const SLIDER_STOPS = ["1d", "7d", "14d", "30d", "60d", "never"] as const;
export type SliderStop = (typeof SLIDER_STOPS)[number];

/** Tabled by Kyle, 2026-10-02: computed in the file, never on the slider and never quoted. The page
 *  prints its definition, which says so, and none of its numbers. */
export const TABLED_POLICY = "critical_or_kev";

export interface PolicyTotals {
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

export interface LedgerFix {
  branch?: string;
  fixed_version?: string | null;
  release_date_reported_by_jamf?: string | null;
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
  window: { since: string; until: string };
  definitions: Record<string, string>;
  clocks: Record<string, string>;
  evidence: { catalog_fetched_at: string; catalog_snapshot_id?: string };
  counts: { cves_in_window: number; cves_replayed: number; cves_excluded: number };
  exclusions: { by_reason: Record<string, number>; cves: ExcludedCve[] };
  policies: Record<SliderStop, PolicyTotals> & Record<string, PolicyTotals | undefined>;
  branch_choice?: {
    held_at_branch?: string;
    cves_where_the_choice_changes_the_answer?: { by_policy?: Record<string, number> };
  };
  product?: { bundle_ids?: string[] };
  ledger: LedgerRow[];
}

/** Why a file was not drawn. `detail` is in the file's own key names, so it reads the same in every
 *  language and can be pasted into a report as it stands. */
export type Refusal =
  | { why: "unreadable" }
  | { why: "kind"; found: string }
  | { why: "schema"; found: string }
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
  if (!isRecord(file.clocks)) return "clocks";
  if (!isRecord(file.evidence) || !isText(file.evidence.catalog_fetched_at)) return "evidence.catalog_fetched_at";
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
  // The tabled policy is held to the same sum when the file carries it, though none of it is drawn.
  for (const key of [...SLIDER_STOPS, TABLED_POLICY]) {
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
  if (raw.schema !== REPLAY_SCHEMA) return { refusal: { why: "schema", found: shown(raw.schema) } };
  const key = firstMissing(raw);
  if (key) return { refusal: { why: "missing", key } };
  const replay = raw as unknown as PatchPolicyReplay;
  const detail = firstDisagreement(replay);
  return detail ? { refusal: { why: "totals", detail } } : { replay };
}

/** The CVEs the policies were replayed against: the ledger less its excluded rows. */
export function replayedRows(replay: PatchPolicyReplay): LedgerRow[] {
  return replay.ledger.filter((row) => !row.exclusion);
}

/** The fix on the release line the device is held to, which is the one its installs can reach.
 *  `null` where the CVE names no fix on that line: those are the rows that were never in range. */
export function heldFix(row: LedgerRow, branch: string | undefined): LedgerFix | null {
  return row.fixes?.find((fix) => fix.branch === branch) ?? null;
}

export const isSliderStop = (value: string | null): value is SliderStop => SLIDER_STOPS.includes(value as SliderStop);
