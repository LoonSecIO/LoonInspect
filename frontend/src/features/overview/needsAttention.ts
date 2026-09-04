import type { AlertListResponse } from "@/features/alerts/types";
import type { ChangeLevel } from "@/features/changes/types";
import type { Destination } from "@/features/destinations/types";
import type { CollectionSummary, MdmConnection } from "@/features/mdm/types";
import type { UpdateStatusResponse } from "@/features/system/api";

/**
 * **Needs attention** — the action list on `/` (#106), and the only surface on which a
 * dead Splunk pipe reliably shows up today.
 *
 * Pure on purpose, for the reason `heroRun.ts` and `sinceAnchor.ts` are: every line here
 * is a decision that can be wrong in a way a screenshot will not reveal. Nothing in this
 * module fetches, renders, or translates. It has no test today because the frontend has
 * no test runner at all — that is
 * [#285](https://github.com/LoonSecIO/LoonInspect/issues/285), and **this is the module
 * #285 should aim at first**: it now encodes six predicates, two collapses and five
 * founder rulings, and `composeAttention` and `isAllClear` are both pure functions of
 * plain data — a test runner can drive them the moment one exists, with no DOM, no
 * fetch and no store. Four separate claims about this comparator have been refuted by
 * *executing* it, which is the argument for the runner in one sentence.
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
 * That rationale is about a *partial* denial, and it stops being true at the end of its
 * own range. When **every** input resolves `denied`, silence over all of them leaves
 * `rows` and `degraded` both empty, which is indistinguishable from a clean fleet — and
 * `/` is not role-gated, so such a session opened the front page and was handed
 * *"Nothing needs your attention · checked 08:14 UTC"*: a dated attestation about a
 * fleet on which zero checks had executed. `blind` is that whole-range case, and it is
 * not a sixth `denied` row — it is the panel saying which question it is not in a
 * position to answer. Failure must never read as emptiness (#150), and saying what the
 * product cannot see is the doctrine (#251), not a gap to paper over.
 *
 * **What #101 changed about who reaches it, stated because the old note said otherwise.**
 * `blind` was written for `Role.viewer`, which holds `_INVENTORY_READ` and nothing else
 * (`backend/app/core/permissions.py`) and therefore had every one of the four checks
 * denied. The alerts check is gated on `device:read` + `app:read` — which a Viewer
 * *holds* — so a Viewer now resolves one check of four and is no longer blind. Executed,
 * not assumed: a Viewer with no open latch composes `blind=false, rows=0, degraded=0`,
 * and `isAllClear` therefore prints the dated line over three checks that were refused.
 *
 * That is the partial-denial branch of the same ruling, applied consistently — a Viewer
 * genuinely did examine something, and the ruling is explicit that a partial denial is
 * silent and does not withhold the line. But it means no *role* reaches `blind` today;
 * it is now reached only by a principal denied all four, such as an API token scoped
 * away from inventory read. Whether the all-clear should still be printable when the
 * only check that ran is about apps rather than the pipeline is a question for a ruling,
 * not for this file to decide on its own.
 *
 * ## Stored latest-fields, and why there is no page of runs here
 *
 * Every predicate reads a column that is already written down. That is Kyle's
 * cache-don't-calculate rule, and on the failed-run check it is also the difference
 * between a working panel and a blind one.
 *
 * `ingest_webhook` mints **one Run row per allowlisted Jamf event**
 * (`backend/app/mdm/service.py`; `ComputerInventoryCompleted` is on the allowlist in
 * `backend/app/mdm/jamf/client.py`). At three thousand Macs with daily recon that is
 * ~125 rows an hour, `GET /runs` orders by `started_at DESC` and takes no lock-class
 * filter — so a 03:00 sweep that failed is off any page the browser would ask for by
 * about 03:25, and by 08:00 the operator reads *"Nothing needs your attention · checked
 * 08:14 UTC"* over a dead sweep. The fetch succeeded, so nothing is `degraded`; nothing
 * on screen discloses that a window ever existed. A permanently failing **catalog**
 * collection produces no row from any of the five checks, ever.
 *
 * So the failed-run row is composed from `collection.lastRunStatus` / `lastRunAt`
 * instead: latest-fields on the tenant-wide collections list this panel already fetches,
 * bounded by nothing, one per collection rather than one per event, and written **only**
 * by `run_collection` — the webhook path never touches them, so the flood cannot reach
 * this check by construction rather than by a bigger `limit`.
 *
 * `/api/runs/summary` (#105) was the other candidate and was rejected here. Its
 * `latestRun` is the newest run of **any** lock class per *connection*, so a webhook run
 * that succeeded a minute ago hides the device sweep that failed at 03:00 — the exact
 * hiding the old per-lock-class loop existed to prevent — and a failing catalog
 * collection is invisible to it for the same reason. It is the right shape for the
 * strip's question ("what ran last here?") and the wrong shape for this one ("is
 * anything broken?").
 *
 * ## The alerts socket
 *
 * Filled by #101 exactly as it was cut: `"new_app"` joined `AttentionKind`, one
 * `Fetched<>` field joined `AttentionInputs`, one block pushes rows inside
 * `composeAttention`, one string per locale. No component changed.
 *
 * `new_app` is the first row here that is about the **fleet** rather than the pipeline,
 * and it is the only one whose level this file does not decide: an alert row carries a
 * stored `level` from `app.alerts.service.KIND_LEVELS`, and re-grading it here would be a
 * second opinion on one fact. It is also the only source that can have more rows than the
 * API returned — a tool pushed to two thousand Macs opens two thousand latches — which is
 * why its input carries a `total` and `dropped` counts the remainder rather than
 * pretending the page was the whole answer.
 *
 * It is also the only kind that is *ranked* rather than merely levelled, and the two
 * facts are the same fact: unbounded rows that never close would otherwise take the whole
 * five-row budget from the checks this panel exists for. `RANK_WITHIN_LEVEL` carries the
 * ruling and the reasoning.
 */

/** What a row can be about. `new_app` is #101's, and arrived as one more member — which
 *  is the whole extension point this union exists to be. */
export type AttentionKind =
  | "run_failed"
  | "destination_failing"
  | "collection_overdue"
  | "inventory_stale"
  | "update_available"
  | "new_app";

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
   *  be an English sentence in the German UI. Null on a collapsed row, which stands for
   *  several things and can name none of them. */
  subject: string | null;
  /** Where the subject lives, when that is not obvious — the connection's name on a pod
   *  with more than one. "Full device sweep" is the same name on every connection. */
  context: string | null;
  href: string | null;
  /** The instant the row is about — when the run failed, when the collection was due,
   *  when the destination last refused. Rendered as an age beside the row and used to
   *  order rows within a level; null sorts last and renders nothing. */
  at: string | null;
  /** How many things this row stands for. `1` is the ordinary row that names its
   *  subject. Above 1 the row is a **collapse** — the overdue check and the stale check
   *  each produce one, for the same reason: their subjects fail together by construction
   *  — and the panel gives it a sentence of its own rather than gluing a number onto a
   *  singular verb. */
  count: number;
}

export interface AttentionInputs {
  now: Date;
  /** Three of the five checks read this one list: a collection row carries its own
   *  schedule, its own last outcome and its own last success. */
  collections: Fetched<CollectionSummary[]>;
  /** Names only, and deliberately not a check of its own: it answers *which* connection
   *  a row is about, never *whether* there is a row. So a connections request that
   *  errored costs a row its context and does not withhold the all-clear line — nothing
   *  about the fleet went unexamined. */
  connections: Fetched<MdmConnection[]>;
  destinations: Fetched<Destination[]>;
  update: Fetched<UpdateStatusResponse>;
  /** Open alert latches (#101). The whole response rather than its items, because the
   *  page is bounded and one fleet-wide install opens a latch per device — `total` is
   *  what lets `dropped` say how many rows are really behind the cap. */
  alerts: Fetched<AlertListResponse>;
}

export interface AttentionResult {
  rows: AttentionRow[];
  /** Rows the cap hid, plus open latches the bounded page never fetched. Reported rather
   *  than swallowed — a pod with four connections and a dead tick can produce more than
   *  five real rows, one new tool pushed fleet-wide produces thousands, and a cap that
   *  silently ate them would be a worse lie than a long list. */
  dropped: number;
  /** Checks that errored. Rendered as rows, and they withhold the all-clear line. */
  degraded: AttentionKind[];
  /**
   * **Not one check could run.** Every input in `CHECKS_BY_INPUT` came back `denied`, so
   * nothing about this fleet was examined and the panel has no finding of any kind —
   * clean or otherwise — to report.
   *
   * A separate field from `degraded` because it is a different sentence to a different
   * person. A degraded check is a fault the operator can chase; this is a session
   * without the permissions the panel is built on, and telling a viewer that "recent
   * runs could not be checked" five times over would read as five faults in the product.
   * It withholds the all-clear (`isAllClear`) — that is the whole point — and it is
   * deliberately *not* counted into `total`: the sidebar badge counts things that need
   * attention, and a role boundary is not one of them.
   *
   * `false` the moment any single check resolves, including a partial denial, which is
   * the case the silent-`denied` ruling was actually made about.
   */
  blind: boolean;
  /**
   * Everything the panel would render: rows before the cap, plus the degraded rows.
   *
   * This is the number the sidebar badge shows, and it is computed here because the
   * badge is the list's only off-page rendering (Kyle's A9 ruling) and must not
   * under-deliver on it. `rows.length` is the wrong count twice over — it is
   * post-`slice`, so nine problems would render "5", and it excludes `degraded`, so a
   * pod where all five checks error would render no badge at all.
   */
  total: number;
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
 * pages no longer describe the fleet (`inventory_stale`, `run_failed`). `normal` is a
 * mechanism that failed — a tick did not fire — which is a symptom of a disease that may
 * not have set in yet. `low` is an improvement available, not a thing that is wrong.
 *
 * **`run_failed` is `high`, and moved there by ruling** (Kyle, 2026-09-04). It was filed
 * as mechanism, and that was the inconsistency: a sweep that failed means the fleet was
 * **not read**, so the numbers on these pages describe a fleet as it was before the
 * failure — the identical condition `inventory_stale` is `high` for, arriving by a faster
 * route. `inventory_stale` is that state noticed late; `run_failed` is the same state
 * noticed immediately. Filing the two at different levels said the delay was the thing
 * that mattered.
 *
 * The consequence the ruling was made for: `RANK_WITHIN_LEVEL` gives `new_app` rank 1 and
 * every other kind rank 0, so with `run_failed` in the same band a failed run now
 * outranks new-app noise **unconditionally**, through the mechanism already built. A
 * cross-level rank was rejected — a `normal` row sorting above a `high` one would make
 * the level vocabulary mean nothing, and a level is only for the promise that a red row
 * outranks a grey one.
 *
 * `new_app` is deliberately absent, and the `Exclude` says so out loud rather than
 * leaving a reader to notice. Its level is *stored* — graded once in the backend by
 * `app.alerts.service.KIND_LEVELS` (`high`, founder-ruled 2026-08-29) and carried on the
 * row — so deciding it again here would be two gradings of one fact that agree right up
 * until the day they do not.
 */
const LEVEL_OF: Record<Exclude<AttentionKind, "new_app">, ChangeLevel> = {
  destination_failing: "high",
  inventory_stale: "high",
  run_failed: "high",
  collection_overdue: "normal",
  update_available: "low"
};

/**
 * The tie-break **inside** a level. Lower sorts first; everything is 0 but `new_app`.
 *
 * Ruled by Kyle on 2026-09-04, and it exists because the ordinary tie-break — oldest
 * first — is exactly wrong for a latch that never closes. `new_app` is `high`, and that
 * ruling stands. But an open latch closes only when the app is uninstalled, which for a
 * Jamf-deployed app never happens, so latches accumulate and their age only ever grows.
 * A destination carries `lastFailureAt`, refreshed on every retry, so a *currently dead*
 * Splunk pipe is always the **newest** thing in the band. Age-only, five open latches
 * older than the last delivery attempt push "Deliveries are failing" off a five-row list
 * permanently — on the panel whose whole job is to be the one place a dead pipe shows up.
 *
 * The same rank is what makes `run_failed` beat a wall of latches now that it is `high`
 * (see `LEVEL_OF`): one table, two starvations closed, no exception list.
 *
 * Rejected: demoting `new_app` to `normal`, which would have made a genuinely high signal
 * quiet on every surface that reads the level rather than only inside a five-row budget;
 * and capping latches at N inside the composition, which would have made the panel lie
 * about how many there are instead of ordering them honestly.
 *
 * The comparator is `Record<AttentionKind, …>` rather than a `kind === "new_app"` test so
 * that a kind added to the union has to state its rank rather than inherit one silently.
 */
const RANK_WITHIN_LEVEL: Record<AttentionKind, number> = {
  destination_failing: 0,
  inventory_stale: 0,
  run_failed: 0,
  collection_overdue: 0,
  update_available: 0,
  new_app: 1
};

/** Which input answers which check. Used to turn an errored input into `degraded`
 *  entries, so the mapping lives in one place rather than in four catch blocks. The
 *  collections list answers three of the six: one request, three blind spots when it
 *  fails, and the panel says all three rather than one vague line. */
const CHECKS_BY_INPUT: Record<
  "collections" | "destinations" | "update" | "alerts",
  AttentionKind[]
> = {
  collections: ["run_failed", "collection_overdue", "inventory_stale"],
  destinations: ["destination_failing"],
  update: ["update_available"],
  alerts: ["new_app"]
};

/** A collection row is only worth a *failed* row. `skipped` is the rate floor doing its
 *  job, `ok` is fine, and null is a collection that has never been attempted. */
const RUN_FAILED = "failed";

function millis(iso: string | null | undefined): number | null {
  if (!iso) return null;
  const parsed = Date.parse(iso);
  return Number.isFinite(parsed) ? parsed : null;
}

function valueOrNull<T>(fetched: Fetched<T>): T | null {
  return fetched.ok ? fetched.value : null;
}

/** The ordinary row: one thing, named. */
function one(row: Omit<AttentionRow, "count">): AttentionRow {
  return { ...row, count: 1 };
}

/**
 * The list, from stored latest-fields only.
 *
 * Every predicate below reads a column that is already written down — a collection's
 * last outcome, last success and next due; a destination's last failure. Nothing here
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
  const stale: CollectionSummary[] = [];
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
    stale.push(collection);
  }

  // One row for the outage, not one row per collection — the same collapse the overdue
  // check makes below, ruled onto this check on 2026-09-04 for the same reason.
  //
  // These failures are correlated **by construction**: one credential, one network path
  // and one scheduler serve every collection on a connection, so a rotated token or a
  // firewall rule puts all of them past their window inside one cadence. Five rows naming
  // five collections were always five renderings of one fact, and they spent the whole
  // five-row cap saying it — which is how a *currently failing* `destination_failing` row
  // (always the newest thing in the `high` band, because `last_failure_at` is rewritten on
  // every delivery retry) got starved off the panel entirely. Executed, not argued: the
  // proof harness in this PR drives five stale collections against one fresh destination.
  //
  // Not a re-rank. Giving `destination_failing` a rank of its own would have fixed this
  // one instance and left the shape intact — the next `high` kind with correlated
  // failures starves it again, and `RANK_WITHIN_LEVEL` becomes a list of exceptions
  // maintained by whoever last got bitten.
  //
  // Oldest last-success, because the ranking within a level is oldest-first and the
  // outage is as old as the longest silence in it. A collection that has *never*
  // succeeded contributes no instant — same as it does on its own row, where creation is
  // not a success and must not be rendered as one — so a collapse of only such
  // collections carries `at: null` and sorts last, exactly as the single row would.
  if (stale.length > 1) {
    const oldestSuccess = stale.reduce<string | null>((earliest, collection) => {
      const at = millis(collection.lastSuccessAt);
      if (at === null) return earliest;
      const best = millis(earliest);
      return best === null || at < best ? collection.lastSuccessAt : earliest;
    }, null);
    rows.push({
      // Not keyed on the members, for the reason the overdue collapse is not: collections
      // cross their windows one after another and a churning key would remount the row.
      id: "inventory_stale:all",
      kind: "inventory_stale",
      level: LEVEL_OF.inventory_stale,
      subject: null,
      context: null,
      href: "/settings/connections",
      at: oldestSuccess,
      count: stale.length
    });
  } else if (stale.length === 1) {
    const collection = stale[0];
    rows.push(
      one({
        id: `inventory_stale:${collection.id}`,
        kind: "inventory_stale",
        level: LEVEL_OF.inventory_stale,
        subject: collection.name,
        context: nameOfConnection.get(collection.mdmConnectionId) ?? null,
        href: "/settings/connections",
        at: millis(collection.lastSuccessAt) === null ? null : collection.lastSuccessAt
      })
    );
  }

  // --- Collection overdue: nothing ever claimed it ----------------------------------
  //
  // Worth being precise about what this catches, because the English is misleading:
  // `next_due_at` advances at claim time, so an overdue row means the collection was
  // never picked up. A sweep that is running long is *not* here, and should not be — it
  // is being watched by the hero.
  const overdue: CollectionSummary[] = [];
  for (const collection of collections) {
    if (!collection.enabled || collection.nextDueAt === null) continue;
    const due = millis(collection.nextDueAt);
    if (due === null || nowMs <= due + OVERDUE_GRACE_MS) continue;
    overdue.push(collection);
  }

  // One row for the storm, not one row per collection.
  //
  // `claim_due` walks every due collection in a single pass and advances `next_due_at`
  // before any work starts, so one dead minute tick puts *every* enabled collection past
  // the grace inside the same hour. Rendered one-per-collection that is five identical
  // `normal` rows naming five collections, eating the whole cap, and nothing on screen
  // naming the one thing that is actually broken. (The honest reading of the collapsed
  // sentence is "nothing claimed them" — a long-running sweep holding its connection's
  // lock can also keep a second sweep on that connection from being claimed — but the
  // scheduler is far and away the likeliest cause and is the right place to send someone
  // looking.)
  //
  // Oldest due instant, because the ranking within a level is oldest-first and the storm
  // is as old as the first thing it swallowed.
  if (overdue.length > 1) {
    const oldest = overdue.reduce((earliest, collection) =>
      (millis(collection.nextDueAt) ?? Infinity) < (millis(earliest.nextDueAt) ?? Infinity) ? collection : earliest
    );
    rows.push({
      // Not keyed on the members: the set changes as collections come due one after
      // another, and a key that churned would remount the row on every poll.
      id: "collection_overdue:all",
      kind: "collection_overdue",
      level: LEVEL_OF.collection_overdue,
      subject: null,
      context: null,
      href: "/settings/connections",
      at: oldest.nextDueAt,
      count: overdue.length
    });
  } else if (overdue.length === 1) {
    const collection = overdue[0];
    rows.push(
      one({
        id: `collection_overdue:${collection.id}`,
        kind: "collection_overdue",
        level: LEVEL_OF.collection_overdue,
        subject: collection.name,
        context: nameOfConnection.get(collection.mdmConnectionId) ?? null,
        href: "/settings/connections",
        at: collection.nextDueAt
      })
    );
  }

  // --- Run failed: the collection's own last outcome ---------------------------------
  //
  // Per collection, from the row's stored `lastRunStatus`. See the module docstring for
  // why this is not a page of `/api/runs`: the webhook path mints a run per Jamf event
  // and would push a failed 03:00 sweep off any window the browser can ask for within
  // half an hour, while never touching these columns.
  //
  // Enabled only, matching every other check: an operator who turned a collection off is
  // not asked about the run it failed before they did.
  for (const collection of collections) {
    if (!collection.enabled || collection.lastRunStatus !== RUN_FAILED) continue;
    // A stale collection already says something strictly worse about the same
    // collection — "it has not succeeded in twice its cadence" contains "its last run
    // failed". Two rows for one problem would eat the cap and tell the operator nothing
    // the first row did not.
    if (staleCollectionIds.has(collection.id)) continue;
    rows.push(
      one({
        id: `run_failed:${collection.id}`,
        kind: "run_failed",
        level: LEVEL_OF.run_failed,
        subject: collection.name,
        context: nameOfConnection.get(collection.mdmConnectionId) ?? null,
        href: "/settings/connections",
        at: collection.lastRunAt
      })
    );
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
    rows.push(
      one({
        id: `destination_failing:${destination.id}`,
        kind: "destination_failing",
        level: LEVEL_OF.destination_failing,
        subject: destination.name,
        context: null,
        href: "/settings/destinations",
        at: destination.lastFailureAt
      })
    );
  }

  // --- Update available --------------------------------------------------------------
  //
  // `true` only. `null` is "unknown" — the check is disabled, this is a dev build, or
  // GitHub was unreachable — and unknown must be indistinguishable from current (#43),
  // which is the rule `UpdateBanner` already follows. `href` is null because there is no
  // page to send anyone to; the banner carries the command.
  const update = valueOrNull(inputs.update);
  if (update?.updateAvailable === true) {
    rows.push(
      one({
        id: `update_available:${update.latestSha ?? "unknown"}`,
        kind: "update_available",
        level: LEVEL_OF.update_available,
        subject: update.latestSha?.slice(0, 7) ?? null,
        context: null,
        href: null,
        at: update.checkedAt
      })
    );
  }

  // --- New app: something is installed that was not there last time -------------------
  //
  // The latch is derived and closes itself (`docs/alerts.md`): a row is here because the
  // app is on that Mac *now* and was absent from that Mac's previous inventory, and it
  // disappears when the app does. There is nothing to acknowledge, which is why the panel
  // offers no way to — and why this count is safe to read as a fact about the fleet.
  //
  // `level` comes off the row rather than out of `LEVEL_OF`; see that table's note, and
  // `RANK_WITHIN_LEVEL` for why being `high` does not let these rows eat the cap.
  //
  // The link is the change that recorded the install, on a page that already reads both
  // of these from the URL — no new route, and no alerts page, which #101 ruled out for v0.
  // **Both** parameters, because the row names a Mac: `artifact` alone lands on every
  // install of that app across the fleet, with the one device the row is about nowhere on
  // screen, so the operator arrives at a page that has thrown away half of what they
  // clicked. `q` is the device search (`backend/app/api/changes.py`) and matches the
  // hostname — the same `general.name` that `Device.hostname` and `subject_label` are both
  // written from, so the two agree by construction rather than by luck. It is an ILIKE
  // substring, so a hostname contained in another hostname widens the result; widening a
  // fleet-wide page toward the right device is strictly better than not narrowing at all.
  const alerts = valueOrNull(inputs.alerts);
  for (const alert of alerts?.items ?? []) {
    const artifact = encodeURIComponent(alert.appName);
    const device = encodeURIComponent(alert.deviceLabel);
    rows.push(
      one({
        id: `new_app:${alert.id}`,
        kind: "new_app",
        level: alert.level,
        subject: alert.appName,
        context: alert.deviceLabel,
        href: `/devices/changes?artifact=${artifact}&q=${device}`,
        at: alert.openedAt
      })
    );
  }
  // Latches the bounded page never asked for. Counted into `dropped` rather than dropped
  // on the floor: one new tool pushed to two thousand Macs is two thousand open latches,
  // and a panel that showed five while implying five was all of them would be the same
  // lie the cap exists to avoid telling.
  const unfetchedAlerts = alerts ? Math.max(0, alerts.total - alerts.items.length) : 0;

  // Level first, then the kind's rank within that level, then **oldest first**: a
  // destination that has been refusing deliveries for three days outranks one that failed
  // five minutes ago, which may still be a blip. A row with no instant has no age and
  // sorts last.
  //
  // The rank sits *between* level and age, not after it, because it exists precisely to
  // beat age: see `RANK_WITHIN_LEVEL` for the two starvations it was ruled to stop. Levels
  // still sort in whole blocks, so the coloured stripes down the left of the panel never
  // read as unsorted.
  rows.sort((a, b) => {
    const byLevel = LEVEL_ORDER.indexOf(a.level) - LEVEL_ORDER.indexOf(b.level);
    if (byLevel !== 0) return byLevel;
    const byRank = RANK_WITHIN_LEVEL[a.kind] - RANK_WITHIN_LEVEL[b.kind];
    if (byRank !== 0) return byRank;
    const aAt = millis(a.at);
    const bAt = millis(b.at);
    if (aAt === null) return bAt === null ? 0 : 1;
    if (bAt === null) return -1;
    return aAt - bAt;
  });

  const degraded: AttentionKind[] = [];
  // Counted over the same registry that produces `degraded`, which is why #101's alerts
  // input joined both by adding one line to `CHECKS_BY_INPUT` and nothing else.
  // `connections` is correctly outside it: it answers *which* connection a row is about,
  // never *whether* there is a row, so a session that could read every check but not the
  // connection names is not blind — its rows would just lose their context.
  let checksAsked = 0;
  let checksDenied = 0;
  for (const [key, kinds] of Object.entries(CHECKS_BY_INPUT) as [
    keyof typeof CHECKS_BY_INPUT,
    AttentionKind[]
  ][]) {
    const fetched = inputs[key];
    checksAsked += 1;
    // `denied` is deliberately absent from `degraded`: a permission the session does not
    // hold is not a check that failed, and a *partial* denial must not withhold the
    // all-clear line. All of them denied is the other end of that range — see `blind`.
    if (!fetched.ok && fetched.reason === "error") degraded.push(...kinds);
    if (!fetched.ok && fetched.reason === "denied") checksDenied += 1;
  }

  return {
    rows: rows.slice(0, MAX_ROWS),
    dropped: Math.max(0, rows.length - MAX_ROWS) + unfetchedAlerts,
    degraded,
    blind: checksDenied === checksAsked,
    total: rows.length + degraded.length,
    checkedAt: now.toISOString()
  };
}

/**
 * Whether the dated all-clear may be printed.
 *
 * A function rather than an inline `&&` in the panel, because it is the attestation's
 * gate: the one predicate in this feature that has to be greppable, and the one that
 * must not be re-typed anywhere. Every check that could run came back clean, no check
 * that should have run failed to — and at least one check ran at all.
 *
 * That last clause is `blind`, and it is here rather than in the panel for the same
 * reason the other two are: an emptiness that means "nothing was examined" is the one
 * state this sentence must never be printed over, and a condition the panel re-typed
 * would be a second implementation of the attestation rule.
 *
 * Takes the fields it reads rather than a whole `AttentionResult`, so the panel can ask
 * it about the store's slices without the store having to hold a result object it would
 * otherwise never use.
 */
export function isAllClear(result: Pick<AttentionResult, "rows" | "degraded" | "blind">): boolean {
  return !result.blind && result.rows.length === 0 && result.degraded.length === 0;
}
