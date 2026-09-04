import type {
  Collection,
  MdmConnection,
  MdmSyncStatus,
  Run,
  RunSummary,
  SyncStatusValue
} from "@/features/mdm/types";
import { formatUtc } from "@/features/overview/heroRun";

/**
 * The status strip's join and its formatters (#105) — one thin line per connection, the
 * first thing on a settled Overview.
 *
 * Pure on purpose, for the reason `heroRun.ts` and `sinceAnchor.ts` are: everything here
 * is a decision that can be wrong in a way a screenshot will not reveal — which schedule
 * counts as "the next sweep", what a cadence means in hours, whether a missing row is a
 * zero or an absence. None of it needs React to be checked. It has no test today because
 * the frontend has no test runner at all — that is
 * [#285](https://github.com/LoonSecIO/LoonInspect/issues/285), and this module is now the
 * largest uncovered surface on the front door, so it is what that issue should aim at
 * after `sinceAnchor.ts`.
 *
 * The strip states facts and **never turns red**. Thresholds — overdue sweeps, stale
 * inventory, a failed run — are Needs Attention rows (#106), which is why
 * `ConnectionStatus` carries the raw material for those judgements (`schedules`,
 * `latestRun`, `inventoryAsOf`) and makes none of them itself.
 */

/** The hostname of a connection's base URL. The Connections page prints the whole URL
 *  because that is the field an admin typed; the strip prints only the host, because on
 *  a two-Jamf pod the host is the thing that tells the lines apart and the scheme and
 *  path never do. Falls back to the raw string rather than throwing — a stored value
 *  that will not parse is still worth showing. */
export function hostOf(baseUrl: string): string {
  try {
    return new URL(baseUrl).hostname;
  } catch {
    return baseUrl;
  }
}

/**
 * A collection's configured cadence, in hours. `null` means it has no cadence at all:
 * event-driven (a webhook collection) or unscheduled.
 *
 * Exported because #106's inventory-STALE threshold is **twice the collection's own
 * configured cadence** (Kyle, 2026-09-04) — daily becomes 48h, hourly becomes 2h. That
 * ruling is per collection, not per pod, which is why `ConnectionStatus` exposes every
 * schedule rather than one folded number: a connection with an hourly sweep and a weekly
 * one has two different ideas of "late", and folding them would pick the wrong one.
 */
export function cadenceHours(collection: Collection): number | null {
  switch (collection.frequency) {
    case "hourly":
      return 1;
    case "daily":
      return 24;
    case "weekly":
      return 168;
    case "every_n_days":
      // The backend requires n >= 2 for this frequency; 2 is the same default
      // `app.core.scheduling.next_due` falls back to, so the two agree on a row whose
      // interval somehow went missing.
      return 24 * (collection.intervalN ?? 2);
    default:
      return null;
  }
}

export type AgeUnit = "now" | "minutes" | "hours" | "days";

/** How long ago something was, coarsely. */
export interface CoarseAge {
  unit: AgeUnit;
  value: number;
}

/**
 * The relative half of the stamp: `2026-08-29 14:32 UTC (2h ago)`.
 *
 * Returns the shape rather than the words, because German puts the relation in front
 * ("vor 2 Std.") and a component that appended a translated " ago" to a number would
 * produce "2 Std. vor". The locale file owns the sentence; this owns the arithmetic.
 *
 * Coarse deliberately — one significant unit. The absolute UTC beside it is the precise
 * value, and a strip that said "2 hours 14 minutes ago" would spend the line's width on
 * a number nobody acts on.
 */
export function coarseAge(iso: string, now: Date): CoarseAge | null {
  const then = Date.parse(iso);
  if (!Number.isFinite(then)) return null;
  // Clamped at zero: a pod whose clock is behind its database briefly produces a future
  // stamp, and "in -1 minutes" is a bug report where "just now" is the truth.
  const seconds = Math.max(0, (now.getTime() - then) / 1000);
  if (seconds < 60) return { unit: "now", value: 0 };
  if (seconds < 3600) return { unit: "minutes", value: Math.floor(seconds / 60) };
  if (seconds < 86_400) return { unit: "hours", value: Math.floor(seconds / 3600) };
  return { unit: "days", value: Math.floor(seconds / 86_400) };
}

/** A bare `HH:MM UTC` clock where that cannot be misread, the full `formatUtc` stamp
 *  where it could.
 *
 *  **The tense is a parameter because the strip has two of them, and the ambiguity is
 *  not symmetric.** `next sweep 02:00` is a promise about the future; `Splunk OK 08:35`
 *  is a report about the past. A bare clock is safe in opposite directions for the two,
 *  so one shared rule was wrong for one of them whichever way it was written:
 *
 *  - `upcoming` — short only for an instant in the next 24 hours. A *past* instant here
 *    is the anomaly the reader most needs to see: a dead scheduler rendered
 *    `next sweep 02:00 UTC` for a sweep that was due this morning and never ran, turning
 *    a failure into a promise.
 *  - `past` — short only for an instant earlier the same UTC day. `Splunk OK 08:35 UTC`
 *    at 09:00 is the healthy reading and the template this issue specifies; but a last
 *    delivery at 22:40 *yesterday* rendered `Splunk OK 22:40 UTC`, which at 09:00 reads
 *    as thirteen hours from now — a dead pipe rendered as a healthy one.
 *
 *  Both bugs came from one symmetric `|due - now| < 24h` window, which accepted the past
 *  as readily as the future. There is deliberately no default: a caller that has not
 *  said which direction it means cannot be given a safe answer. */
export function formatDue(iso: string, now: Date, tense: "upcoming" | "past"): string {
  const due = Date.parse(iso);
  if (!Number.isFinite(due)) return iso;
  const ahead = due - now.getTime();
  const sameUtcDay = new Date(due).toISOString().slice(0, 10) === now.toISOString().slice(0, 10);
  const unambiguous = tense === "upcoming" ? ahead >= 0 && ahead < 86_400_000 : ahead < 0 && sameUtcDay;
  if (!unambiguous) return formatUtc(iso);
  const stamp = new Date(due);
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${pad(stamp.getUTCHours())}:${pad(stamp.getUTCMinutes())} UTC`;
}

/** `8f3a…c1` — enough of a jobID to recognise, never enough to search with. The full
 *  value travels in the element's `title` and its clipboard copy, because the entire
 *  point of a stamp is that it gets pasted into Splunk. */
export function shortRunId(id: string): string {
  if (id.length <= 8) return id;
  return `${id.slice(0, 4)}…${id.slice(-2)}`;
}

/** One collection on a connection, reduced to what a status judgement needs. */
export interface SweepSchedule {
  collectionId: number;
  name: string;
  kind: Collection["kind"];
  enabled: boolean;
  /** UTC ISO, straight from the row. Never re-derived client-side: `next_due_at` is
   *  materialised by `app.core.scheduling` from a timezone the browser does not have,
   *  and a second implementation here would disagree with the tick twice a year. */
  nextDueAt: string | null;
  cadenceHours: number | null;
  lastRunAt: string | null;
  lastRunStatus: string | null;
}

/**
 * Everything the strip prints about one connection, and everything #106 needs to decide
 * whether any of it warrants a row. Built once by `OverviewPage` and handed to both, so
 * the count in a Needs Attention row and the line above it cannot disagree.
 */
export interface ConnectionStatus {
  connectionId: number;
  name: string;
  host: string;
  isActive: boolean;
  /** `null` means there is no `MdmSyncState` row yet — the connection has never swept.
   *  Not zero: an unswept pod has not measured zero devices, it has not measured
   *  anything, and "0 devices" is a measurement claim. */
  deviceCount: number | null;
  /** The instant the device numbers describe. The pinned run's `finishedAt` when there
   *  is one, so the line cannot contradict its own stamp; `lastSyncAt` only as the
   *  fallback for a pod whose runs have aged past 30-day retention. */
  inventoryAsOf: string | null;
  syncStatus: SyncStatusValue | null;
  fullSweep: Run | null;
  webhookSweepsSince: number;
  latestRun: Run | null;
  /** Soonest `nextDueAt` across enabled device-sweep schedules. */
  nextDueAt: string | null;
  /** Which schedule that was — the row #106 deep-links to. */
  nextDueCollectionId: number | null;
  schedules: SweepSchedule[];
}

export interface ConnectionStatusInput {
  connections: MdmConnection[];
  syncStatuses: MdmSyncStatus[];
  runSummaries: RunSummary[];
  /** Keyed by connection id. A connection whose collections could not be fetched is
   *  absent rather than empty — the strip then says nothing about its schedule instead
   *  of claiming there is none. */
  collectionsByConnection: Map<number, Collection[]>;
}

/**
 * The join: connections × sync state × run summaries × collections.
 *
 * Driven by `connections`, because that is the list the operator created and the strip
 * prints a line for each of them — including one added five minutes ago that has no sync
 * state, no runs and no collections yet.
 */
export function buildConnectionStatuses(input: ConnectionStatusInput): ConnectionStatus[] {
  const statusById = new Map(input.syncStatuses.map((status) => [status.mdmConnectionId, status]));
  const summaryById = new Map(input.runSummaries.map((summary) => [summary.mdmConnectionId, summary]));

  return input.connections.map((connection) => {
    const syncState = statusById.get(connection.id) ?? null;
    const summary = summaryById.get(connection.id) ?? null;
    const collections = input.collectionsByConnection.get(connection.id) ?? [];

    const schedules: SweepSchedule[] = collections.map((collection) => ({
      collectionId: collection.id,
      name: collection.name,
      kind: collection.kind,
      enabled: collection.enabled,
      nextDueAt: collection.nextDueAt,
      cadenceHours: cadenceHours(collection),
      lastRunAt: collection.lastRunAt,
      lastRunStatus: collection.lastRunStatus
    }));

    // **Device sweeps only.** The issue's source list says "min(next_due_at) across
    // enabled collections", which would let an hourly catalog refresh be announced as
    // "next sweep 01:00" — a metadata read reported as the fleet being re-measured. A
    // catalog refresh is not a sweep, so it cannot answer the question this segment asks.
    const sweeps = schedules.filter(
      (schedule) => schedule.kind === "device_sweep" && schedule.enabled && schedule.nextDueAt !== null
    );
    const next = sweeps.reduce<SweepSchedule | null>((soonest, schedule) => {
      if (soonest === null) return schedule;
      return Date.parse(schedule.nextDueAt!) < Date.parse(soonest.nextDueAt!) ? schedule : soonest;
    }, null);

    const fullSweep = summary?.lastFullSweep ?? null;

    return {
      connectionId: connection.id,
      name: connection.name,
      host: hostOf(connection.baseUrl),
      isActive: connection.isActive,
      // Gated on EVIDENCE, not on the row's existence. `set_sync_status` creates the
      // MdmSyncState row on the failure path too (`app/mdm/service.py`), and
      // `device_count` defaults to 0 — so a connection whose very first sweep dies on
      // bad credentials had a row saying zero, and the strip reported a three-thousand
      // Mac tenant as `0 devices · no full sweep yet`. `lastSyncAt` is the only field
      // that means a sweep actually finished, so the count is trusted only alongside it.
      // Assumption 5 of this PR always said `null` must render "no inventory yet" and
      // never "0 devices"; this is the gate that makes that true.
      deviceCount: syncState?.lastSyncAt ? syncState.deviceCount : null,
      // The pinned run first. `MdmSyncState.deviceCount` is a projection written once at
      // the end of each sweep (docs/runs.md §9), so pairing it with that sweep's own
      // finish time is the one reading where "N devices, inventory as of X" is
      // internally true. `lastSyncAt` is the fallback, not the source — if a later
      // change re-sources the count from a fresher endpoint "because it is fresher", the
      // as-of claim breaks silently and nothing here will say so.
      inventoryAsOf: fullSweep?.finishedAt ?? syncState?.lastSyncAt ?? null,
      syncStatus: syncState?.status ?? null,
      fullSweep,
      webhookSweepsSince: summary?.webhookSweepsSince ?? 0,
      latestRun: summary?.latestRun ?? null,
      nextDueAt: next?.nextDueAt ?? null,
      nextDueCollectionId: next?.collectionId ?? null,
      schedules
    };
  });
}
