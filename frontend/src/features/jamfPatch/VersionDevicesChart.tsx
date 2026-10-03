import { policySentence } from "@/features/jamfPatch/policyRules";
import type { PolicyVersion } from "@/features/jamfPatch/types";
import type { VersionRow } from "@/features/jamfPatch/versionRows";
import { useLocale } from "@/i18n/LocaleContext";

// One measure, one hue: categorical slot 1 of the dataviz palette, stepped per mode as
// ReleaseCalendar's ramp is. Identity is the row's own label, never the colour — a version
// Jamf does not list says so in words beside its name.
const BAR = "bg-[#2a78d6] dark:bg-[#3987e5]";
// Where a patching rule judges the title, the bar also carries the version's verdict: the
// status palette's critical for out of policy, a neutral for a version the rule cannot
// judge. Never colour alone — the row says "out of policy" in words beside the version.
const BAR_OUT = "bg-[#d03b3b]";
const BAR_NOT_JUDGED = "bg-muted-foreground/40";

// Past this many rows the chart scrolls inside its card rather than pushing the table off
// the page: with the box unticked a title lists every version Jamf has ever recorded.
const SCROLL_AFTER = 14;

function barClass(verdict: PolicyVersion | undefined): string {
  if (verdict?.state === "out") return BAR_OUT;
  if (verdict?.state === "not_judged") return BAR_NOT_JUDGED;
  return BAR;
}

/**
 * Devices by version: one horizontal bar per version, its length the number of Macs whose
 * matched app is on it, the count printed at the tip.
 *
 * Horizontal because the categories are version strings and there can be dozens. The rows
 * are the page's own (`versionRows`), already filtered by its checkbox, so the chart and the
 * table under it never disagree about which versions are showing. The table is this chart's
 * table view; the `aria-label` says so.
 */
export function VersionDevicesChart({
  rows,
  totalDevices,
  policy
}: {
  rows: VersionRow[];
  totalDevices: number;
  /** The rule judging the title and each version's verdict, or null where nothing judges it
   *  (no rule, or exempt): then every bar is a plain count and there is no legend. */
  policy: {
    versions: Record<string, PolicyVersion>;
    maxReleasesBehind: number | null;
    maxDaysBehindSevere: number | null;
  } | null;
}) {
  const { t } = useLocale();
  const copy = t.jamfPatch.detail;
  const rules = t.jamfPatch.rules;
  const max = rows.reduce((most, row) => Math.max(most, row.devices), 0);

  if (rows.length === 0 || max === 0) {
    return <p className="text-sm text-muted-foreground">{copy.chartEmpty}</p>;
  }

  const verdicts = rows.map((row) => policy?.versions[row.version]);
  const shows = (state: PolicyVersion["state"]) => verdicts.some((verdict) => verdict?.state === state);

  return (
    <div className="space-y-2">
      {policy && (
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
          <span className="inline-flex items-center gap-1.5">
            <span className={`h-2.5 w-2.5 rounded-sm ${BAR}`} />
            {rules.legendWithin}
          </span>
          {shows("out") && (
            <span className="inline-flex items-center gap-1.5">
              <span className={`h-2.5 w-2.5 rounded-sm ${BAR_OUT}`} />
              {rules.legendOut}
            </span>
          )}
          {shows("not_judged") && (
            <span className="inline-flex items-center gap-1.5">
              <span className={`h-2.5 w-2.5 rounded-sm ${BAR_NOT_JUDGED}`} />
              {rules.legendNotJudged}
            </span>
          )}
        </div>
      )}
    <div
      role="img"
      aria-label={copy.chartAriaLabel(rows.length, totalDevices)}
      className={`grid grid-cols-[max-content_minmax(0,1fr)] items-center gap-x-3 gap-y-1.5 text-sm ${
        rows.length > SCROLL_AFTER ? "max-h-[26rem] overflow-y-auto pr-2" : ""
      }`}
    >
      {rows.map((row, index) => (
        <div key={`${row.listed ? "listed" : "unlisted"}:${row.version}`} className="group contents">
          <div className="max-w-[16rem] truncate text-right tabular-nums">
            <span className="font-medium">{row.version || "—"}</span>
            {row.latest && <span className="ml-1.5 text-xs text-muted-foreground">{copy.chartCurrent}</span>}
            {!row.listed && <span className="ml-1.5 text-xs text-muted-foreground">{copy.chartUnlisted}</span>}
            {verdicts[index]?.state === "out" && <span className="ml-1.5 text-xs font-medium">{rules.chartOut}</span>}
          </div>
          <div className="relative flex items-center gap-2 rounded-sm group-hover:bg-accent/50">
            {/* Square at the baseline, 4px rounded at the data end; a 2px floor so one Mac
                beside five hundred is still a mark. No bar at all for zero. */}
            {row.devices > 0 && (
              <div
                className={`h-4 shrink-0 rounded-r ${barClass(verdicts[index])}`}
                style={{ width: `max(2px, ${(row.devices / max) * 88}%)` }}
              />
            )}
            <span className={`tabular-nums ${row.devices === 0 ? "text-muted-foreground" : ""}`}>{row.devices}</span>
            <div
              className={`pointer-events-none absolute left-0 z-10 hidden whitespace-nowrap rounded-md border bg-popover px-2 py-1 text-xs text-popover-foreground shadow-md group-hover:block ${
                // The first row has nothing above it inside the scroll box to open into.
                index === 0 ? "top-full mt-1" : "bottom-full mb-1"
              }`}
            >
              {copy.chartTooltip(
                row.version,
                row.devices,
                row.releaseDate ? new Date(row.releaseDate).toLocaleDateString() : null,
                row.listed
              )}
              {policy && verdicts[index] ? ` · ${policySentence(verdicts[index], policy, t)}` : ""}
            </div>
          </div>
        </div>
      ))}
    </div>
    </div>
  );
}
