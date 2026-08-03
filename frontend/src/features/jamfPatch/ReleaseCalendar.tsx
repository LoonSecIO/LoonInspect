import { useMemo } from "react";
import type { JamfPatchVersion } from "@/features/jamfPatch/types";
import { useLocale } from "@/i18n/LocaleContext";

const WEEKS = 53;
const DAY_MS = 24 * 60 * 60 * 1000;

// Sequential blue ramp (mode-agnostic hex, per the dataviz palette): light mode
// reads low->high as light->dark, dark mode flips anchor so low->high reads
// dark->light against the dark surface. True zero uses the muted surface
// token rather than the ramp, matching GitHub's own convention.
const CELL_CLASSES: Record<0 | 1 | 2 | 3 | 4, string> = {
  0: "bg-muted",
  1: "bg-[#cde2fb] dark:bg-[#184f95]",
  2: "bg-[#86b6ef] dark:bg-[#256abf]",
  3: "bg-[#3987e5] dark:bg-[#5598e7]",
  4: "bg-[#1c5cab] dark:bg-[#b7d3f6]"
};

interface DayCell {
  date: Date;
  isoDate: string;
  count: number;
  bucket: 0 | 1 | 2 | 3 | 4;
}

function isoDate(date: Date): string {
  return date.toISOString().slice(0, 10);
}

function bucketFor(count: number, max: number): 0 | 1 | 2 | 3 | 4 {
  if (count === 0) return 0;
  if (max <= 1) return 4;
  const ratio = count / max;
  if (ratio <= 0.25) return 1;
  if (ratio <= 0.5) return 2;
  if (ratio <= 0.75) return 3;
  return 4;
}

function buildWeeks(countsByDay: Map<string, number>): DayCell[][] {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const endOfWeek = new Date(today.getTime() + (6 - today.getDay()) * DAY_MS);
  const totalDays = WEEKS * 7;
  const start = new Date(endOfWeek.getTime() - (totalDays - 1) * DAY_MS);

  const max = Math.max(0, ...countsByDay.values());
  const days: DayCell[] = [];
  for (let i = 0; i < totalDays; i++) {
    const date = new Date(start.getTime() + i * DAY_MS);
    const key = isoDate(date);
    const count = countsByDay.get(key) ?? 0;
    days.push({ date, isoDate: key, count, bucket: bucketFor(count, max) });
  }

  const weeks: DayCell[][] = [];
  for (let i = 0; i < days.length; i += 7) {
    weeks.push(days.slice(i, i + 7));
  }
  return weeks;
}

export function ReleaseCalendar({ patches }: { patches: JamfPatchVersion[] }) {
  const { t } = useLocale();

  const countsByDay = useMemo(() => {
    const counts = new Map<string, number>();
    for (const patch of patches) {
      if (!patch.releaseDate) continue;
      const parsed = new Date(patch.releaseDate);
      if (Number.isNaN(parsed.getTime())) continue;
      const key = isoDate(parsed);
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    return counts;
  }, [patches]);

  const weeks = useMemo(() => buildWeeks(countsByDay), [countsByDay]);

  const totalReleases = useMemo(() => {
    let sum = 0;
    for (const count of countsByDay.values()) sum += count;
    return sum;
  }, [countsByDay]);

  const monthLabels = useMemo(() => {
    let lastMonth = -1;
    return weeks.map((week) => {
      const firstDay = week[0].date;
      const month = firstDay.getMonth();
      if (month !== lastMonth) {
        lastMonth = month;
        return firstDay.toLocaleDateString(undefined, { month: "short" });
      }
      return "";
    });
  }, [weeks]);

  function cellLabel(day: DayCell): string {
    const dateLabel = day.date.toLocaleDateString(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric"
    });
    return day.count === 0
      ? t.jamfPatch.detail.calendarNoReleases(dateLabel)
      : t.jamfPatch.detail.calendarReleases(day.count, dateLabel);
  }

  return (
    <div className="space-y-2">
      <div className="overflow-x-auto">
        <div
          className="inline-flex flex-col gap-1"
          role="img"
          aria-label={t.jamfPatch.detail.calendarAriaLabel(totalReleases)}
        >
          <div className="flex h-4 gap-1 pl-6 text-xs text-muted-foreground">
            {weeks.map((week, index) => (
              <div key={week[0].isoDate} className="relative w-[11px] shrink-0">
                {monthLabels[index] && (
                  <span className="absolute left-0 top-0 whitespace-nowrap">{monthLabels[index]}</span>
                )}
              </div>
            ))}
          </div>
          <div className="flex gap-1">
            <div className="flex w-6 shrink-0 flex-col justify-between gap-1 pr-1 text-right text-xs text-muted-foreground">
              <span />
              <span>{t.jamfPatch.detail.calendarMon}</span>
              <span />
              <span>{t.jamfPatch.detail.calendarWed}</span>
              <span />
              <span>{t.jamfPatch.detail.calendarFri}</span>
              <span />
            </div>
            {weeks.map((week) => (
              <div key={week[0].isoDate} className="flex flex-col gap-1">
                {week.map((day, dayIndex) => (
                  <div key={day.isoDate} className="group relative">
                    <div className={`h-[11px] w-[11px] rounded-sm ${CELL_CLASSES[day.bucket]}`} />
                    <div
                      className={`pointer-events-none absolute left-1/2 z-10 hidden -translate-x-1/2 whitespace-nowrap rounded-md border bg-popover px-2 py-1 text-xs text-popover-foreground shadow-md group-hover:block ${
                        // The top (Sunday) row only has the 16px month-label row above it inside
                        // the scroll container's clip box — not enough headroom for an upward
                        // tooltip, so it opens downward instead. Every other row has a full cell
                        // row of clearance above it and is safe opening upward.
                        dayIndex === 0 ? "top-full mt-1" : "bottom-full mb-1"
                      }`}
                    >
                      {cellLabel(day)}
                    </div>
                  </div>
                ))}
              </div>
            ))}
          </div>
        </div>
      </div>
      <div className="flex items-center justify-end gap-1 text-xs text-muted-foreground">
        <span>{t.jamfPatch.detail.calendarLess}</span>
        {([0, 1, 2, 3, 4] as const).map((bucket) => (
          <div key={bucket} className={`h-[11px] w-[11px] rounded-sm ${CELL_CLASSES[bucket]}`} />
        ))}
        <span>{t.jamfPatch.detail.calendarMore}</span>
      </div>
    </div>
  );
}
