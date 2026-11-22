import type { FleetTitleHistory } from "./types";
import { fleetDetailCopy } from "./fleetDetailCopy";
import { useLocale } from "@/i18n/LocaleContext";

const DAY = 86_400_000;
const WEEK = 7 * DAY;
const WEEKS = 13;

/** Commit dates are instants. Use UTC days and the actual read time for a reproducible window. */
function historyActivity(history: FleetTitleHistory) {
  if (!history.historyReadAt) return null;
  const read = new Date(history.historyReadAt);
  const end = Date.UTC(read.getUTCFullYear(), read.getUTCMonth(), read.getUTCDate() + 1);
  const start = end - WEEKS * WEEK;
  const bins: number[] = Array(WEEKS).fill(0);
  const dates = history.versions.map(row => Date.parse(row.seenAt)).sort((a, b) => a - b);
  for (const at of dates) {
    if (at >= start && at < end) bins[Math.floor((at - start) / WEEK)]++;
  }
  const gaps = dates.slice(1).map((at, i) => (at - dates[i]) / DAY).sort((a, b) => a - b);
  let median: number | null = null;
  if (gaps.length && history.historyComplete && !history.historyDetail) {
    median = Math.round((gaps[Math.floor((gaps.length - 1) / 2)] + gaps[Math.floor(gaps.length / 2)]) * 5) / 10;
  }
  return { bins, median, start, end, total: dates.filter(at => at >= end - 90 * DAY && at < end).length };
}

export function FleetHistoryActivity({ history }: { history: FleetTitleHistory }) {
  const { locale } = useLocale();
  const c = fleetDetailCopy[locale];
  const data = historyActivity(history);
  if (!data || !history.versions.length) return null;
  const max = Math.max(1, ...data.bins);
  const date = (ms: number) => new Date(ms).toLocaleDateString(locale, { day: "numeric", month: "short", timeZone: "UTC" });
  return (
    <section className="rounded-md border bg-muted/20 p-4">
      <h4 className="font-medium">{c.cadence}</h4>
      <div className="mt-2 flex flex-wrap gap-x-6 gap-y-2">
        <p><strong className="tabular-nums">{data.total}</strong> <span className="text-muted-foreground">{c.recent}</span></p>
        {data.median !== null && <p><strong>{c.dayUnit(data.median)}</strong> <span className="text-muted-foreground">{c.daysBetween}</span></p>}
      </div>
      <div className="mt-4 grid h-12 items-end gap-1" style={{ gridTemplateColumns: `repeat(${WEEKS}, minmax(0, 1fr))` }} aria-hidden="true">
        {data.bins.map((n, i) => (
          <div key={i} className={n ? "rounded-t-sm bg-[#2a78d6] dark:bg-[#3987e5]" : "bg-border"}
            style={{ height: n ? `${(100 * n) / max}%` : "1px" }}
            title={`${date(data.start + i * WEEK)} – ${date(data.start + (i + 1) * WEEK - DAY)} · ${n}`} />
        ))}
      </div>
      <div className="mt-1 flex justify-between text-xs text-muted-foreground"><span>{date(data.start)}</span><span>{date(data.end - DAY)} UTC</span></div>
      {(!history.historyComplete || !!history.historyDetail) && <p className="mt-2 text-xs text-muted-foreground">{c.partial}</p>}
    </section>
  );
}
