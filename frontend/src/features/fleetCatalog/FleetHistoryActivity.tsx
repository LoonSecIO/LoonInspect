import { DAY, historyActivity, WEEK, WEEKS } from "@/features/fleetCatalog/historyActivity";
import type { FleetTitleHistory } from "@/features/fleetCatalog/types";
import { useLocale } from "@/i18n/LocaleContext";

// One measure, one hue: categorical slot 1, as VersionDevicesChart's bars.
const BAR = "bg-[#2a78d6] dark:bg-[#3987e5]";

/**
 * The cadence chart at the top of a title's version history in its detail layout (#901): the
 * versions Fleet's catalog dated in each of the 13 weeks to the day the history was read, and,
 * for a history without gaps, the median gap between dated versions over all of it. The bars are
 * one image whose label gives the count and the window; the table under the chart lists each
 * version. A history with gaps says so, and the read's status under the chart says why. Nothing
 * while the history is unread or dates no version.
 */
export function FleetHistoryActivity({ history }: { history: FleetTitleHistory }) {
  const { t, locale } = useLocale();
  const activity = historyActivity(history);
  if (activity === null) return null;
  const words = t.fleetCatalog;
  const max = Math.max(1, ...activity.bins);
  const day = (ms: number, options: Intl.DateTimeFormatOptions = {}) =>
    new Date(ms).toLocaleDateString(locale, { day: "numeric", month: "short", timeZone: "UTC", ...options });
  const count = activity.total.toLocaleString(locale);
  return (
    <section className="rounded-md border bg-muted/20 p-4">
      <h4 className="font-medium">{words.cadenceTitle}</h4>
      <div className="mt-2 flex flex-wrap gap-x-6 gap-y-2">
        <p>
          <strong className="tabular-nums">{count}</strong>{" "}
          <span className="text-muted-foreground">{words.cadenceRecent(WEEKS)}</span>
        </p>
        {activity.median !== null && (
          <p>
            <strong className="tabular-nums">
              {words.cadenceDays(activity.median.toLocaleString(locale), activity.median === 1)}
            </strong>{" "}
            <span className="text-muted-foreground">{words.cadenceMedianGap}</span>
          </p>
        )}
      </div>
      <div
        role="img"
        aria-label={words.cadenceChartLabel(count, WEEKS, day(activity.end - DAY))}
        className="mt-4 grid h-12 items-end gap-1"
        style={{ gridTemplateColumns: `repeat(${WEEKS}, minmax(0, 1fr))` }}
      >
        {activity.bins.map((n, week) => (
          <div
            key={week}
            className={n > 0 ? `rounded-t-sm ${BAR}` : "bg-border"}
            style={{ height: n > 0 ? `${(100 * n) / max}%` : "1px" }}
            title={`${day(activity.start + week * WEEK)} – ${day(activity.start + (week + 1) * WEEK - DAY)} · ${n.toLocaleString(locale)}`}
          />
        ))}
      </div>
      <div aria-hidden="true" className="mt-1 flex justify-between text-xs text-muted-foreground">
        <span>{day(activity.start)}</span>
        <span>{day(activity.end - DAY, { timeZoneName: "short" })}</span>
      </div>
      {!activity.whole && <p className="mt-2 text-muted-foreground">{words.cadenceGaps}</p>}
    </section>
  );
}
