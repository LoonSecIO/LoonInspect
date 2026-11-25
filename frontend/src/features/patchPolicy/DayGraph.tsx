import { useId, useState, type KeyboardEvent, type PointerEvent } from "react";
import { movedDays, seriesDay, summarise, yTicks, yearTicks, type WalkPolicy } from "@/features/patchPolicy/walk";
import type { WalkCopy } from "@/features/patchPolicy/walkCopy";

// The dataviz palette's first three categorical slots (as VersionDevicesChart's slot 1), each stepped
// for its mode and checked as a set for colour-vision deficiency on 2026-11-24 (worst adjacent pair
// ΔE 9.2 on the light surface, 9.4 on the dark; 8 is the target). Open is the measure; opened
// and resolved are events, told apart by direction as well as hue: opened marks rise from the
// strip's midline, resolved marks fall. Aqua sits under 3:1 on the light surface, so the legend
// names every mark and the table under the graph carries every value.
const OPEN_LINE = "stroke-[#2a78d6] dark:stroke-[#3987e5]";
const OPEN_WASH = "fill-[#2a78d6]/10 dark:fill-[#3987e5]/10";
const OPEN_DOT = "bg-[#2a78d6] dark:bg-[#3987e5]";
const NEW_MARK = "stroke-[#eb6834] dark:stroke-[#d95926]";
const NEW_KEY = "bg-[#eb6834] dark:bg-[#d95926]";
const RESOLVED_MARK = "stroke-[#1baf7a] dark:stroke-[#199e70]";
const RESOLVED_KEY = "bg-[#1baf7a] dark:bg-[#199e70]";

const PLOT_HEIGHT = 100;
const STRIP_HEIGHT = 40;
const STRIP_MID = STRIP_HEIGHT / 2;
/** How far the keyboard moves on Page Up and Page Down. */
const PAGE_DAYS = 30;

/**
 * One stop's day graph (#614): CVEs open on each day of the window, with the days CVEs opened and
 * the days an install resolved them marked in a strip under it, on one day axis. Every value is a
 * field of the walk's per-day series; the graph computes only where to draw it.
 *
 * The marks are SVG stretched to the card's width (one unit per day), drawn with strokes that do
 * not scale, so a two-year window and a phone both keep 2px lines; every word is HTML laid over it.
 * A crosshair snaps to the day under the pointer or the keyboard and reads that day out, and the
 * table under the graph lists every day the count moved, so nothing is behind a hover.
 */
export function DayGraph({ policy, since, until, stopName, words, num }: { policy: WalkPolicy; since: string; until: string; stopName: string; words: WalkCopy; num: (value: number) => string }) {
  const { open, new: opened, resolved } = policy.series;
  const days = open.length;
  const [at, setAt] = useState<number | null>(null);
  const readout = useId();
  const ticks = yTicks(Math.max(0, ...open));
  const top = ticks.at(-1) ?? 1;
  const summary = summarise(policy, since);
  const busiest = Math.max(1, ...opened, ...resolved);
  const y = (value: number) => PLOT_HEIGHT - (value / top) * PLOT_HEIGHT;
  const tickHeight = (count: number) => 4 + ((STRIP_MID - 6) * count) / busiest;

  // A step line: each day holds its count across its own width.
  let line = `M0 ${y(open[0] ?? 0)}`;
  for (let offset = 0; offset < days; offset += 1) line += ` V${y(open[offset])} H${offset + 1}`;
  const area = `${line} V${PLOT_HEIGHT} H0 Z`;
  const day = at === null ? null : seriesDay(policy, since, at);
  const left = (offset: number) => `${((offset + 0.5) / days) * 100}%`;
  const years = yearTicks(since, days).filter((tick) => tick.offset / days > 0.08 && tick.offset / days < 0.92);
  const empty = summary.peak === 0 && summary.resolved === 0;

  const point = (event: PointerEvent<HTMLDivElement>) => {
    const box = event.currentTarget.getBoundingClientRect();
    if (box.width <= 0) return;
    setAt(Math.min(days - 1, Math.max(0, Math.floor(((event.clientX - box.left) / box.width) * days))));
  };
  const key = (event: KeyboardEvent<HTMLDivElement>) => {
    const from = at ?? days - 1;
    const moves: Record<string, number> = { ArrowLeft: from - 1, ArrowRight: from + 1, PageUp: from - PAGE_DAYS, PageDown: from + PAGE_DAYS, Home: 0, End: days - 1 };
    if (!(event.key in moves)) return;
    event.preventDefault();
    setAt(Math.min(days - 1, Math.max(0, moves[event.key])));
  };

  const tip = day && (
    <>
      <span className="block font-medium tabular-nums">{day.date}</span>
      <span className="block">
        <b className="tabular-nums">{num(day.open)}</b> {words.openWord}
      </span>
      <span className="block text-muted-foreground">{words.tipNew(day.new, day.becameDetectable, day.enteredRange)}</span>
      <span className="block text-muted-foreground">{words.tipResolved(day.resolved)}</span>
      {day.installed && <span className="block text-muted-foreground">{words.tipInstalled(day.installed)}</span>}
    </>
  );

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
        <span className="inline-flex items-center gap-1.5"><span className={`h-0.5 w-4 rounded-full ${OPEN_DOT}`} />{words.legendOpen}</span>
        <span className="inline-flex items-center gap-1.5"><span className={`h-3 w-0.5 rounded-full ${NEW_KEY}`} />{words.legendNew}</span>
        <span className="inline-flex items-center gap-1.5"><span className={`h-3 w-0.5 rounded-full ${RESOLVED_KEY}`} />{words.legendResolved}</span>
      </div>
      {empty && <p className="text-sm text-muted-foreground">{words.graphEmpty(stopName)}</p>}
      <div className="grid grid-cols-[2.5rem_minmax(0,1fr)] gap-x-2">
        <div className="relative h-44 text-right text-xs tabular-nums text-muted-foreground" aria-hidden="true">
          {ticks.map((tick) => (
            <span key={tick} className="absolute right-0 -translate-y-1/2" style={{ top: `${(y(tick) / PLOT_HEIGHT) * 100}%` }}>{num(tick)}</span>
          ))}
        </div>
        <div className="relative min-w-0">
          <div className="relative">
            <svg
              role="img"
              aria-label={words.graphSummary(stopName, since, until, summary.first, summary.last, summary.peak, summary.peakDate, summary.opened, summary.resolved)}
              viewBox={`0 0 ${days} ${PLOT_HEIGHT}`}
              preserveAspectRatio="none"
              className="block h-44 w-full overflow-visible"
            >
              {ticks.map((tick) => (
                <line key={tick} x1={0} x2={days} y1={y(tick)} y2={y(tick)} className="stroke-border" strokeWidth={1} vectorEffect="non-scaling-stroke" />
              ))}
              <path d={area} className={OPEN_WASH} stroke="none" />
              <path d={line} className={OPEN_LINE} fill="none" strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" vectorEffect="non-scaling-stroke" />
            </svg>
            {/* The end of the line, marked and labelled: the one value a reader most often wants without hovering. */}
            <span className={`pointer-events-none absolute right-0 h-2 w-2 -translate-y-1/2 translate-x-1/2 rounded-full ring-2 ring-card ${OPEN_DOT}`} style={{ top: `${(y(summary.last) / PLOT_HEIGHT) * 100}%` }} />
            <span aria-hidden="true" className="pointer-events-none absolute right-2 -translate-y-full pb-0.5 text-xs font-medium tabular-nums" style={{ top: `${(y(summary.last) / PLOT_HEIGHT) * 100}%` }}>
              {num(summary.last)}
            </span>
          </div>
          <svg aria-hidden="true" viewBox={`0 0 ${days} ${STRIP_HEIGHT}`} preserveAspectRatio="none" className="mt-1 block h-8 w-full">
            <line x1={0} x2={days} y1={STRIP_MID} y2={STRIP_MID} className="stroke-border" strokeWidth={1} vectorEffect="non-scaling-stroke" />
            {opened.map((count, offset) =>
              count > 0 ? <line key={`n${offset}`} x1={offset + 0.5} x2={offset + 0.5} y1={STRIP_MID - 1} y2={STRIP_MID - tickHeight(count)} className={NEW_MARK} strokeWidth={2} strokeLinecap="round" vectorEffect="non-scaling-stroke" /> : null
            )}
            {resolved.map((count, offset) =>
              count > 0 ? <line key={`r${offset}`} x1={offset + 0.5} x2={offset + 0.5} y1={STRIP_MID + 1} y2={STRIP_MID + tickHeight(count)} className={RESOLVED_MARK} strokeWidth={2} strokeLinecap="round" vectorEffect="non-scaling-stroke" /> : null
            )}
          </svg>
          {/* The hit target is the whole plot and strip: a reader aims at a day, never at a 2px line. */}
          <div
            tabIndex={0}
            role="group"
            aria-label={words.graphKeys}
            aria-describedby={readout}
            className="absolute inset-0 cursor-crosshair rounded-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            onPointerMove={point}
            onPointerLeave={() => setAt(null)}
            onKeyDown={key}
            onFocus={() => setAt((current) => current ?? days - 1)}
            onBlur={() => setAt(null)}
          >
            {day && (
              <>
                <span className="pointer-events-none absolute inset-y-0 w-px bg-foreground/40" style={{ left: left(day.offset) }} />
                <span
                  className={`pointer-events-none absolute top-1 z-10 whitespace-nowrap rounded-md border bg-popover px-2 py-1 text-xs text-popover-foreground shadow-md ${day.offset / days > 0.6 ? "-translate-x-full -ml-2" : "ml-2"}`}
                  style={{ left: left(day.offset) }}
                >
                  {tip}
                </span>
              </>
            )}
          </div>
          <div className="relative mt-1 h-4 text-xs tabular-nums text-muted-foreground" aria-hidden="true">
            <span className="absolute left-0">{since}</span>
            {years.map((tick) => (
              <span key={tick.year} className="absolute -translate-x-1/2" style={{ left: `${(tick.offset / days) * 100}%` }}>{tick.year}</span>
            ))}
            <span className="absolute right-0">{until}</span>
          </div>
        </div>
      </div>
      <p id={readout} className="sr-only" aria-live="polite">
        {day ? `${day.date}: ${words.tipOpen(day.open)}, ${words.tipNew(day.new, day.becameDetectable, day.enteredRange)}, ${words.tipResolved(day.resolved)}${day.installed ? `, ${words.tipInstalled(day.installed)}` : ""}` : ""}
      </p>
      <details className="text-sm">
        <summary className="cursor-pointer text-muted-foreground">{words.graphTable}</summary>
        <div className="mt-1 max-h-72 overflow-auto rounded-lg border bg-card">
          <table className="w-full min-w-[30rem] text-sm">
            <thead className="sticky top-0 border-b bg-card text-left text-muted-foreground">
              <tr>
                {[words.colDay, words.colOpen, words.colOpened, words.colResolved, words.colInstalled].map((label) => <th key={label} className="px-3 py-1.5 font-medium">{label}</th>)}
              </tr>
            </thead>
            <tbody>
              {movedDays(policy, since).map((moved) => (
                <tr key={moved.offset} className="border-b last:border-0">
                  <td className="whitespace-nowrap px-3 py-1.5 tabular-nums">{moved.date}</td>
                  <td className="px-3 py-1.5 tabular-nums">{num(moved.open)}</td>
                  <td className="px-3 py-1.5 tabular-nums">{num(moved.new)}</td>
                  <td className="px-3 py-1.5 tabular-nums">{num(moved.resolved)}</td>
                  <td className="px-3 py-1.5 font-mono text-xs">{moved.installed ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </div>
  );
}
