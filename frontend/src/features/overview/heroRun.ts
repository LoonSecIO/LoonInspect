import type { Run } from "@/features/mdm/types";

/**
 * The hero reclaim rule, ruled in #104: **first sync and manual or scheduled full syncs
 * only.**
 *
 * A full sync of the fleet is the `device_sweep` lock class — a catalog refresh reads
 * metadata, not devices, and has no business taking the page over. Of the three triggers
 * (`sweep` = the scheduler, `manual` = someone pressed Sync now, `webhook` = Jamf told us
 * about one device), the first two are the fleet arriving and the third is a single
 * record landing. A webhook sweep firing every few minutes would otherwise seize the
 * hero from whatever the operator was reading; its place is a chip in the status strip
 * (#105), so this predicate declines the hero rather than rendering nothing.
 */
export function takesTheHero(run: Run): boolean {
  return run.lockClass === "device_sweep" && run.trigger !== "webhook";
}

/** The run whose first completion the settled line describes: the one that had nothing
 *  to diff against. There is one per connection and lock class, so on a pod with several
 *  connections the newest wins — `listRuns` returns newest-first. */
export function findBaselineRun(runs: Run[]): Run | null {
  return runs.find((run) => takesTheHero(run) && run.comparison === "baseline" && run.status === "succeeded") ?? null;
}

/** The run in flight that the hero should show, if any. */
export function findRunningHeroRun(runs: Run[]): Run | null {
  return runs.find((run) => takesTheHero(run) && run.status === "running") ?? null;
}

/** `2026-08-29 14:03 UTC` — UTC by ruling, because the run stamp an operator pastes into
 *  Splunk is UTC and a local rendering here would not match what they search. */
export function formatUtc(iso: string): string {
  const stamp = new Date(iso);
  if (Number.isNaN(stamp.getTime())) return iso;
  const pad = (value: number) => String(value).padStart(2, "0");
  return (
    `${stamp.getUTCFullYear()}-${pad(stamp.getUTCMonth() + 1)}-${pad(stamp.getUTCDate())} ` +
    `${pad(stamp.getUTCHours())}:${pad(stamp.getUTCMinutes())} UTC`
  );
}

/** `14:32 UTC` — the time-only half of `formatUtc`, for the all-clear attestation on
 *  `/` (#106), whose one computed line names the clock and not the date. UTC for the
 *  same reason the full stamp is: it is the clock the operator's Splunk search runs on. */
export function formatUtcClock(iso: string): string {
  const stamp = new Date(iso);
  if (Number.isNaN(stamp.getTime())) return iso;
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${pad(stamp.getUTCHours())}:${pad(stamp.getUTCMinutes())} UTC`;
}

/** Elapsed wall time as `38s`, `4m 12s`, `1h 07m`. Untranslated on purpose: h/m/s read
 *  the same in both shipped languages, and a clock is not prose. */
export function formatDuration(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000));
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = total % 60;
  const pad = (value: number) => String(value).padStart(2, "0");
  if (hours > 0) return `${hours}h ${pad(minutes)}m`;
  if (minutes > 0) return `${minutes}m ${pad(seconds)}s`;
  return `${seconds}s`;
}

/** How long a run took, from its own timestamps. */
export function runDuration(run: Run, now = Date.now()): string {
  const started = new Date(run.startedAt).getTime();
  const ended = run.finishedAt ? new Date(run.finishedAt).getTime() : now;
  return formatDuration(ended - started);
}
