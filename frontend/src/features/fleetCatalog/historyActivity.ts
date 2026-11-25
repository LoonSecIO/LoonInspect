import type { FleetTitleHistory } from "@/features/fleetCatalog/types";

export const DAY = 86_400_000;
export const WEEK = 7 * DAY;
/** The cadence chart's window: 13 weekly bars, 91 days. */
export const WEEKS = 13;

export interface HistoryActivity {
  /** Dated versions in each week of the window, oldest week first. */
  bins: number[];
  /** The median gap between consecutive dated versions over the whole history, in days to one
   *  decimal. Null unless the history is whole and dates at least two versions. */
  median: number | null;
  /** The window in UTC milliseconds: the midnight that opens its first day, and the one that closes the read's day. */
  start: number;
  end: number;
  /** The sum of the bins, so the headline counts exactly the versions the bars draw. */
  total: number;
  /** Read back to the title's first change, with nothing left undated: a history without gaps. */
  whole: boolean;
}

/**
 * A title's version history as a cadence (#901), for the chart over its detail layout: the
 * versions Fleet's catalog dated in each of the 13 weeks to the day the history was read, and
 * the median gap between them over the whole history.
 *
 * Commit dates are instants, so the weeks are UTC days ending on the UTC day of
 * `historyReadAt`: the same history draws the same bars wherever it is read. Null when there is
 * nothing to draw, the history unread or without a dated version.
 */
export function historyActivity(history: FleetTitleHistory): HistoryActivity | null {
  if (history.historyReadAt === null || history.versions.length === 0) return null;
  const read = new Date(history.historyReadAt);
  const end = Date.UTC(read.getUTCFullYear(), read.getUTCMonth(), read.getUTCDate() + 1);
  const start = end - WEEKS * WEEK;
  const bins = new Array<number>(WEEKS).fill(0);
  const dates = history.versions.map((row) => Date.parse(row.seenAt)).sort((a, b) => a - b);
  for (const at of dates) if (at >= start && at < end) bins[Math.floor((at - start) / WEEK)] += 1;
  const whole = history.historyComplete && !history.historyDetail;
  const gaps = dates.slice(1).map((at, i) => (at - dates[i]) / DAY).sort((a, b) => a - b);
  const middle = (gaps[Math.floor((gaps.length - 1) / 2)] + gaps[Math.floor(gaps.length / 2)]) / 2;
  return {
    bins,
    median: whole && gaps.length > 0 ? Math.round(middle * 10) / 10 : null,
    start,
    end,
    total: bins.reduce((sum, count) => sum + count, 0),
    whole
  };
}
