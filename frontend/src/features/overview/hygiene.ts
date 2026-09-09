import type { Run } from "@/features/mdm/types";

/**
 * The hygiene tiles' definitions and the recent-runs line (#109).
 *
 * Pure on purpose, like `heroRun.ts`: every threshold here is a code constant by ruling
 * (never a slider), every tile IS a saved search, and the one derived number above the
 * runs table has to be honest about the window it was counted in. Pinned by
 * `hygiene.test.ts` in the frontend test lane (#285).
 */

/** A Mac that has not checked in for this long is the first hygiene tile. */
export const STALE_CHECK_IN_DAYS = 7;

/** The `lastCheckInBefore` instant the stale tile searches on, as an absolute ISO string
 *  — the same reason `sinceAnchor.ts` gives: a relative window would mean something
 *  different every time the saved search was opened. Whole minutes, so the tile and the
 *  link it carries agree byte for byte within a render. */
export function staleCheckInBefore(now: Date): string {
  const cutoff = new Date(now.getTime() - STALE_CHECK_IN_DAYS * 86_400_000);
  cutoff.setUTCSeconds(0, 0);
  return cutoff.toISOString();
}

/** `on / total` as a whole percentage, or null when there is nothing to divide by — a
 *  tile that says "0%" of nothing has manufactured a number. */
export function coveragePercent(onLatest: number, total: number): number | null {
  if (total <= 0) return null;
  return Math.round((onLatest / total) * 100);
}

export interface WebhookRunsToday {
  count: number;
  /** True when the list reached back past the start of today, so the count is the
   *  whole day's; false when it did not — the list was capped — and the count is a
   *  floor. */
  complete: boolean;
}

/** Webhook runs started today (UTC), counted over the runs in hand. Honest about the
 *  cap: `/api/runs` answers newest-first up to a page size, so if the oldest run in the
 *  list still started today the day extends past what was fetched. */
export function webhookRunsToday(runs: readonly Run[], now: Date): WebhookRunsToday {
  const dayStart = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  const started = runs.map((run) => Date.parse(run.startedAt)).filter((ms) => Number.isFinite(ms));
  const count = runs.filter(
    (run) => run.trigger === "webhook" && Date.parse(run.startedAt) >= dayStart
  ).length;
  const oldest = started.length ? Math.min(...started) : null;
  return { count, complete: oldest === null || oldest < dayStart };
}

/** The runs table shows this many. */
export const RECENT_RUNS_LIMIT = 10;

/** Newest first, capped — the order `/api/runs` answers in, made explicit so a caller
 *  that hands rows in another order still gets the table the issue describes. */
export function recentRuns(runs: readonly Run[], limit = RECENT_RUNS_LIMIT): Run[] {
  return [...runs].sort((a, b) => Date.parse(b.startedAt) - Date.parse(a.startedAt)).slice(0, limit);
}
