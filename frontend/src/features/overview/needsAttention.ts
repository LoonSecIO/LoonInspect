import type { ChangeLevel } from "@/features/changes/types";
import type { Destination } from "@/features/destinations/types";
import type { Collection, MdmConnection, Run } from "@/features/mdm/types";
import type { UpdateStatusResponse } from "@/features/system/api";

/**
 * **Needs attention** — the action list on `/` (#106), and the only surface on which a
 * dead Splunk pipe reliably shows up today.
 *
 * Pure on purpose, for the reason `heroRun.ts` and `sinceAnchor.ts` are: every line here
 * is a decision that can be wrong in a way a screenshot will not reveal. Nothing in this
 * module fetches, renders, or translates. It has no test today because the frontend has
 * no test runner at all — that is
 * [#285](https://github.com/LoonSecIO/LoonInspect/issues/285), and this file should be
 * near the front of the queue: it now encodes two founder rulings and five predicates.
 *
 * ## Two rules this module exists to keep
 *
 * **Needs Attention has exactly one composition, and no other surface mirrors or
 * recomposes it.** There is one function that decides what needs attention, and every
 * surface that shows any part of the answer reads its output rather than asking the
 * questions again. The sidebar's count badge is its only off-page rendering. A second
 * implementation — a tile that counts failures, a header dot with its own thresholds —
 * would be two products disagreeing about whether a customer's pod is healthy, on the
 * same screen, and no amount of care keeps two copies of five predicates in step.
 *
 * **The dated all-clear line is template-only, forever.** "Nothing needs your attention
 * · checked 14:32 UTC" is not a status message; it is the product attesting, with a
 * timestamp, that it looked and found nothing. Every word of it is a template filled
 * from the same checks that would have produced rows. No model ever writes it, softens
 * it, or summarises it — a generated all-clear is a claim about a fleet whose evidence
 * is a sampled distribution, and this is the one sentence in the product a customer may
 * paste into an audit.
 *
 * The mechanism that keeps the second rule true is `degraded`: a check that *could not
 * run* must never read as a check that came back clean, so an input that errored is
 * reported, withholds the line, and is rendered as its own row. An input the session
 * lacks permission for is a different thing — `denied`, silent, and it does **not**
 * withhold the line, because an operator without `destination:read` is not the person
 * who fixes destinations and would otherwise never see a green line again. Getting these
 * two backwards is the single highest-consequence mistake available in this file.
 *
 * ## The alerts socket
 *
 * #101's NEW-app latch lands here as another row type with no redesign: add its member
 * to `AttentionKind`, add one `Fetched<>` field to `AttentionInputs`, push rows inside
 * `composeAttention`, add one string to both locales. No component changes.
 */

/** What a row can be about. `#101` appends `"new_app"`; nothing else in this file is
 *  additive, so that is the whole extension point. */
export type AttentionKind =
  | "run_failed"
  | "destination_failing"
  | "collection_overdue"
  | "inventory_stale"
  | "update_available";

/**
 * One input, and what happened when the session asked for it.
 *
 * Three states, not two, and the third is the point. `denied` means this session has no
 * permission to run the check — a fact about the operator, not about the fleet, so it is
 * silent. `error` means the check *should* have run and did not, which is the one thing
 * an all-clear must never be printed over.
 */
export type Fetched<T> = { ok: true; value: T } | { ok: false; reason: "denied" | "error" };

export interface AttentionRow {
  /** `${kind}:${subjectId}` — stable across polls, so React keys and any future
   *  per-row dismissal survive a refresh that reorders the list. */
  id: string;
  kind: AttentionKind;
  /** The closed `LEVELS` vocabulary from `backend/app/changes/policy.py`. Reused rather
   *  than minting a `severity`: the product already has one word for how much a thing
   *  matters, and a second would have to be mapped to the first forever. */
  level: ChangeLevel;
  /** The name of the thing — a collection, a destination. Never a built sentence: the
   *  panel interpolates it into a translated string, so a sentence assembled here would
   *  be an English sentence in the German UI. */
  subject: string | null;
  /** Where the subject lives, when that is not obvious — the connection's name on a pod
   *  with more than one. "Full device sweep" is the same name on every connection. */
  context: string | null;
  href: string | null;
  /** The instant the row is about. Orders rows within a level; null sorts last. */
  at: string | null;
}

export interface AttentionInputs {
  now: Date;
  runs: Fetched<Run[]>;
  collections: Fetched<Collection[]>;
  /** Names only, and deliberately not a check of its own: it answers *which* connection
   *  a row is about, never *whether* there is a row. So a connections request that
   *  errored costs a row its context and does not withhold the all-clear line — nothing
   *  about the fleet went unexamined. */
  connections: Fetched<MdmConnection[]>;
  destinations: Fetched<Destination[]>;
  update: Fetched<UpdateStatusResponse>;
}

export interface AttentionResult {
  rows: AttentionRow[];
  /** Rows the cap hid. Reported rather than swallowed — a pod with four connections and
   *  a dead tick can produce more than five real rows, and a cap that silently ate them
   *  would be a worse lie than a long list. */
  dropped: number;
  /** Checks that errored. Rendered as rows, and they withhold the all-clear line. */
  degraded: AttentionKind[];
  checkedAt: string;
}

/**
 * How late a collection may be before the tick is presumed dead.
 *
 * An hour, ruled with the issue. `next_due_at` is advanced **at claim**, not at
 * completion, so a row that is still past due means the scheduler never picked the
 * collection up — a dead tick or a dead worker — rather than a sweep running long. The
 * grace absorbs a minute tick that was busy, a container restart, and a sweep that
 * claimed late; an hour of nothing having been claimed is not any of those.
 */
export const OVERDUE_GRACE_MS = 3_600_000;

/** At most five. The list justifies the front door by being short enough to act on;
 *  a scrollable one is a dashboard, which "/" deliberately is not (#104). */
export const MAX_ROWS = 5;

/** `LEVELS` order from the backend's change policy: high, normal, low. */
const LEVEL_ORDER: ChangeLevel[] = ["high", "normal", "low"];

/**
 * What each kind is worth, and why.
 *
 * `high` is reserved for **a claim the product is currently making that is false**:
 * evidence is not reaching the SIEM (`destination_failing`), or the numbers on these
 * pages no longer describe the fleet (`inventory_stale`). `normal` is a mechanism that
 * failed — a run broke, a tick did not fire — which is a symptom of a disease that may
 * not have set in yet. `low` is an improvement available, not a thing that is wrong.
 */
const LEVEL_OF: Record<AttentionKind, ChangeLevel> = {
  destination_failing: "high",
  inventory_stale: "high",
  run_failed: "normal",
  collection_overdue: "normal",
  update_available: "low"
};

/** Which input answers which check. Used to turn an errored input into `degraded`
 *  entries, so the mapping lives in one place rather than in five catch blocks. */
const CHECKS_BY_INPUT: Record<"runs" | "collections" | "destinations" | "update", AttentionKind[]> = {
  runs: ["run_failed"],
  collections: ["collection_overdue", "inventory_stale"],
  destinations: ["destination_failing"],
  update: ["update_available"]
};

function millis(iso: string | null | undefined): number | null {
  if (!iso) return null;
  const parsed = Date.parse(iso);
  return Number.isFinite(parsed) ? parsed : null;
}

function valueOrNull<T>(fetched: Fetched<T>): T | null {
  return fetched.ok ? fetched.value : null;
}

/**
 * The list, from stored latest-fields only.
 *
 * Every predicate below reads a column that is already written down — a run's status, a
 * destination's last failure, a collection's next due and last success. Nothing here
 * counts, aggregates, or re-derives: this panel polls, and a front page that recomputed
 * the state of the fleet on every tick would be the most expensive query in the product
 * (Kyle's cache-don't-calculate rule).
 */
export function composeAttention(inputs: AttentionInputs): AttentionResult {
  const { now } = inputs;
  const nowMs = now.getTime();
  const rows: AttentionRow[] = [];

  const connections = valueOrNull(inputs.connections) ?? [];
  const nameOfConnection = new Map(connections.map((connection) => [connection.id, connection.name]));
  const collections = valueOrNull(inputs.collections) ?? [];

  // --- Inventory stale: the numbers on these pages no longer describe the fleet ------
  //
  // Twice the collection's own configured cadence, ruled 2026-09-04 and computed by the
  // backend (`stale_after`), never here: the multiple and the cadence table are a ruling,
  // and a ruling encoded in two languages is a ruling that will eventually disagree with
  // itself. A null `staleAfterSeconds` is "makes no staleness claim" — a webhook
  // collection with no cadence to double — and renders nothing.
  //
  // `lastSuccessAt`, not `lastRunAt`: the latter is the attempt's *start* and is written
  // on failures too, so a collection that has been failing for a week would read as
  // having run a minute ago. This is the trap the backend column was added to close.
  const staleCollectionIds = new Set<number>();
  for (const collection of collections) {
    if (collection.kind !== "device_sweep" || !collection.enabled) continue;
    if (collection.staleAfterSeconds === null) continue;
    const window = collection.staleAfterSeconds * 1000;
    const lastSuccess = millis(collection.lastSuccessAt);
    // A collection that has never succeeded is measured from its own creation, so a pod
    // that is four minutes old does not open on a wall of red before its first sweep has
    // had a chance to finish.
    const since = lastSuccess ?? millis(collection.createdAt);
    if (since === null || nowMs - since <= window) continue;
    staleCollectionIds.add(collection.id);
    rows.push({
      id: `inventory_stale:${collection.id}`,
      kind: "inventory_stale",
      level: LEVEL_OF.inventory_stale,
      subject: collection.name,
      context: nameOfConnection.get(collection.mdmConnectionId) ?? null,
      href: "/settings/connections",
      at: lastSuccess === null ? null : collection.lastSuccessAt
    });
  }

  // --- Collection overdue: nothing ever claimed it ----------------------------------
  //
  // Worth being precise about what this catches, because the English is misleading:
  // `next_due_at` advances at claim time, so an overdue row means the collection was
  // never picked up. A sweep that is running long is *not* here, and should not be — it
  // is being watched by the hero.
  for (const collection of collections) {
    if (!collection.enabled || collection.nextDueAt === null) continue;
    const due = millis(collection.nextDueAt);
    if (due === null || nowMs <= due + OVERDUE_GRACE_MS) continue;
    rows.push({
      id: `collection_overdue:${collection.id}`,
      kind: "collection_overdue",
      level: LEVEL_OF.collection_overdue,
      subject: collection.name,
      context: nameOfConnection.get(collection.mdmConnectionId) ?? null,
      href: "/settings/connections",
      at: collection.nextDueAt
    });
  }

  // --- Run failed: the newest run of each connection and lock class ------------------
  //
  // Per lock class, not per connection: a catalog refresh and a device sweep are
  // separate mutexes and fail for separate reasons, so "the connection's latest run"
  // would let a succeeding catalog hide a failing sweep. `listRuns` returns newest
  // first, so the first row seen for a pair is the newest one.
  const runs = valueOrNull(inputs.runs) ?? [];
  const seenLocks = new Set<string>();
  for (const run of runs) {
    const lock = `${run.mdmConnectionId}:${run.lockClass}`;
    if (seenLocks.has(lock)) continue;
    seenLocks.add(lock);
    if (run.status !== "failed") continue;
    // A stale collection already says something strictly worse about the same
    // collection — "it has not succeeded in twice its cadence" contains "its last run
    // failed". Two rows for one problem would eat the cap and tell the operator nothing
    // the first row did not.
    if (run.collectionId !== null && staleCollectionIds.has(run.collectionId)) continue;
    rows.push({
      id: `run_failed:${run.id}`,
      kind: "run_failed",
      level: LEVEL_OF.run_failed,
      subject: collections.find((row) => row.id === run.collectionId)?.name ?? null,
      context: nameOfConnection.get(run.mdmConnectionId) ?? null,
      href: "/settings/connections",
      at: run.finishedAt ?? run.startedAt
    });
  }

  // --- Destination failing: evidence is not reaching the SIEM ------------------------
  //
  // The last failure is more recent than the last success, or there has never been a
  // success. Disabled destinations are excluded: an operator who turned one off is not
  // being told about it every time they open the front page.
  for (const destination of valueOrNull(inputs.destinations) ?? []) {
    if (!destination.enabled || destination.lastFailureAt === null) continue;
    const failed = millis(destination.lastFailureAt);
    const succeeded = millis(destination.lastSuccessAt);
    if (failed === null) continue;
    if (succeeded !== null && succeeded >= failed) continue;
    rows.push({
      id: `destination_failing:${destination.id}`,
      kind: "destination_failing",
      level: LEVEL_OF.destination_failing,
      subject: destination.name,
      context: null,
      href: "/settings/destinations",
      at: destination.lastFailureAt
    });
  }

  // --- Update available --------------------------------------------------------------
  //
  // `true` only. `null` is "unknown" — the check is disabled, this is a dev build, or
  // GitHub was unreachable — and unknown must be indistinguishable from current (#43),
  // which is the rule `UpdateBanner` already follows. `href` is null because there is no
  // page to send anyone to; the banner carries the command.
  const update = valueOrNull(inputs.update);
  if (update?.updateAvailable === true) {
    rows.push({
      id: `update_available:${update.latestSha ?? "unknown"}`,
      kind: "update_available",
      level: LEVEL_OF.update_available,
      subject: update.latestSha?.slice(0, 7) ?? null,
      context: null,
      href: null,
      at: update.checkedAt
    });
  }

  // Level first, then **oldest first** within a level: a destination that has been
  // refusing deliveries for three days outranks one that failed five minutes ago, which
  // may still be a blip. A row with no instant has no age and sorts last.
  rows.sort((a, b) => {
    const byLevel = LEVEL_ORDER.indexOf(a.level) - LEVEL_ORDER.indexOf(b.level);
    if (byLevel !== 0) return byLevel;
    const aAt = millis(a.at);
    const bAt = millis(b.at);
    if (aAt === null) return bAt === null ? 0 : 1;
    if (bAt === null) return -1;
    return aAt - bAt;
  });

  const degraded: AttentionKind[] = [];
  for (const [key, kinds] of Object.entries(CHECKS_BY_INPUT) as [
    keyof typeof CHECKS_BY_INPUT,
    AttentionKind[]
  ][]) {
    const fetched = inputs[key];
    // `denied` is deliberately absent: a permission the session does not hold is not a
    // check that failed, and must not withhold the all-clear line.
    if (!fetched.ok && fetched.reason === "error") degraded.push(...kinds);
  }

  return {
    rows: rows.slice(0, MAX_ROWS),
    dropped: Math.max(0, rows.length - MAX_ROWS),
    degraded,
    checkedAt: now.toISOString()
  };
}

/**
 * Whether the dated all-clear may be printed.
 *
 * A function rather than an inline `&&` in the panel, because it is the attestation's
 * gate: the one predicate in this feature that has to be greppable, and the one that
 * must not be re-typed anywhere. Every check that could run came back clean, and no
 * check that should have run failed to.
 *
 * Takes the two fields it reads rather than a whole `AttentionResult`, so the panel can
 * ask it about the store's slices without the store having to hold a result object it
 * would otherwise never use.
 */
export function isAllClear(result: Pick<AttentionResult, "rows" | "degraded">): boolean {
  return result.rows.length === 0 && result.degraded.length === 0;
}
