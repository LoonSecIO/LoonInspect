import { useEffect } from "react";
import { AlertTriangle, CheckCircle2, HelpCircle, Lock } from "lucide-react";
import { Link } from "react-router";
import { useAttentionStore } from "@/features/overview/attentionStore";
import { coarseAge } from "@/features/overview/connectionStatus";
import { formatUtc, formatUtcClock } from "@/features/overview/heroRun";
import { isAllClear, type AttentionRow } from "@/features/overview/needsAttention";
import { useLocale } from "@/i18n/LocaleContext";
import { cn } from "@/lib/utils";
import type { Translations } from "@/i18n/en";

/** How often the panel re-runs its checks. Slower than the run watcher above it: none of
 *  these facts change on a fifteen-second scale, and this is five requests. */
const REFRESH_INTERVAL_MS = 60000;

/** The stripe. The three levels are the change policy's, so the colours are the ones the
 *  rest of the product already uses for high / normal / low. */
const STRIPE: Record<string, string> = {
  high: "bg-destructive",
  normal: "bg-amber-500",
  low: "bg-muted-foreground/40"
};

/** `2h ago`, in the reader's language.
 *
 *  Borrowed from the status strip's vocabulary (#105) rather than given a second set of
 *  four strings here. The two surfaces sit inches apart on the same page and both answer
 *  "how long ago"; two vocabularies would drift into "2h ago" above "2 hours ago", which
 *  reads as two different measurements of the same thing. */
function ageOf(t: Translations, iso: string, now: Date): string | null {
  const age = coarseAge(iso, now);
  if (age === null) return null;
  if (age.unit === "now") return t.overview.strip.agoNow;
  if (age.unit === "minutes") return t.overview.strip.agoMinutes(age.value);
  if (age.unit === "hours") return t.overview.strip.agoHours(age.value);
  return t.overview.strip.agoDays(age.value);
}

/**
 * The verb the row leads with.
 *
 * A collapsed row (`count > 1`) gets a sentence of its own rather than the singular verb
 * with a number appended. Two checks can collapse — overdue and stale — and each names
 * the shared cause its subjects failed for rather than counting the subjects: nothing
 * claimed them, or nothing has read them. So this is two explicit branches rather than a
 * general "plural form of every kind" mechanism the other four kinds would never use;
 * a kind whose members fail independently has nothing to collapse *to*.
 */
function headlineFor(t: Translations, row: AttentionRow): string {
  if (row.count > 1) {
    if (row.kind === "collection_overdue") return t.overview.attention.schedulerStalled(row.count);
    if (row.kind === "inventory_stale") return t.overview.attention.inventoryStalled(row.count);
  }
  return t.overview.attention.kinds[row.kind];
}

function Row({ row, now }: { row: AttentionRow; now: Date }) {
  const { t } = useLocale();
  const age = row.at === null ? null : ageOf(t, row.at, now);
  const body = (
    <>
      <span aria-hidden="true" className={cn("h-8 w-1 shrink-0 rounded-full", STRIPE[row.level])} />
      <span className="font-medium text-card-foreground">{headlineFor(t, row)}</span>
      {/* The name is interpolated, never concatenated into the sentence above: a
          sentence assembled here would be an English sentence in the German UI. */}
      {row.subject && <span className="text-muted-foreground">{row.subject}</span>}
      {row.context && <span className="text-xs text-muted-foreground">· {row.context}</span>}
      {/* WHEN. Composed for every row and, until this commit, rendered for none — so
          `Sync failed · Full device sweep · Production Jamf` read the same whether it
          happened five minutes or three weeks ago, inches under a header saying
          "checked 14:32 UTC". The predictable read of that pair is that it failed at
          14:32, which is a *wrong* timestamp and worse than none. It also made the
          oldest-first-within-level ranking unreconstructable: age is the priority
          signal, so hiding it hides why the list is in the order it is in.

          Coarse in the line, exact in `title` and `dateTime` — the same split the
          all-clear line makes below, and the strip already makes for the run id. */}
      {row.at !== null && age !== null && (
        <time dateTime={row.at} title={formatUtc(row.at)} className="text-xs text-muted-foreground">
          · {age}
        </time>
      )}
    </>
  );

  // A row with nowhere to go is still a row. `update_available` has no page in the
  // product — the banner carries the command — and a dead link would be worse than none.
  return (
    <li>
      {row.href ? (
        <Link to={row.href} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-5 py-3 text-sm hover:bg-accent">
          {body}
        </Link>
      ) : (
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 px-5 py-3 text-sm">{body}</div>
      )}
    </li>
  );
}

/**
 * **Needs attention** (#106) — the action list that justifies the front door.
 *
 * Every decision this panel shows is made in `needsAttention.ts` and loaded by
 * `attentionStore.ts`; this file chooses colours and words and nothing else. That split
 * is the ruling, not a preference: the composition has exactly one implementation, and
 * the sidebar's badge reads the same store rather than counting rows of its own.
 *
 * The empty state is the reason the panel exists at all. "Nothing needs your attention ·
 * checked 14:32 UTC" is a dated attestation the product makes about a customer's fleet,
 * so it is withheld the moment a check could not run (`degraded`), and it is
 * template-only forever — no AI prose ever writes this line (docs/v-never.md).
 *
 * There are therefore **four** states here, not three, and the fourth is the one this
 * panel was quietly getting wrong: nothing checked yet (no claim), nothing the session
 * is allowed to check (`blind` — a role statement, no clock), something found (rows),
 * nothing found (the attestation). Only the last of those is dated, because it is the
 * only one making a claim about the fleet.
 *
 * **The clock is visible; the full instant rides the element** (Kyle, 2026-09-04, on
 * #106). The line keeps `checked HH:MM UTC` because the panel is read at a glance and a
 * full stamp costs the sentence its shape, but the whole attestation is wrapped in a
 * `<time dateTime>` carrying the exact instant, with the human-readable stamp in
 * `title` — present in the DOM, available on hover, and carried into a rich-text paste.
 * A screenshot still captures only the clock; that is a larger call about the copy and
 * was explicitly not made here.
 *
 * The `<time>` wraps the *sentence* rather than a span around the clock inside it. The
 * alternative was splitting `allClear` into a prefix and a clock so the element could
 * sit between them, and that was rejected for the reason every string in this feature is
 * a whole template: German word order is not English word order, and a sentence
 * assembled from fragments in a component is an English sentence wherever it is read.
 *
 * Named `NeedsAttentionPanel` rather than `NeedsAttention` for a boring reason worth
 * writing down so nobody "tidies" it back: the composition already owns
 * `needsAttention.ts`, and on a case-insensitive filesystem `NeedsAttention.tsx` beside
 * it is the same path — TypeScript refuses the pair outright. The composition keeps the
 * plain name, because it is the module #101 imports.
 */
export function NeedsAttentionPanel() {
  const { t } = useLocale();
  const ta = t.overview.attention;
  const rows = useAttentionStore((state) => state.rows);
  const dropped = useAttentionStore((state) => state.dropped);
  const degraded = useAttentionStore((state) => state.degraded);
  const blind = useAttentionStore((state) => state.blind);
  const checkedAt = useAttentionStore((state) => state.checkedAt);
  const loadAttention = useAttentionStore((state) => state.loadAttention);

  useEffect(() => {
    void loadAttention();
    const tick = () => {
      if (document.hidden) return;
      void loadAttention();
    };
    const handle = window.setInterval(tick, REFRESH_INTERVAL_MS);
    return () => window.clearInterval(handle);
  }, [loadAttention]);

  // Nothing is claimed before the first check returns. An all-clear dated to a check
  // that has not happened would be the exact failure this panel is built to avoid.
  if (checkedAt === null) {
    return (
      <section className="rounded-lg border bg-card px-5 py-4 text-sm text-muted-foreground shadow-sm">
        {ta.loading}
      </section>
    );
  }

  // Every age on this panel is measured from one instant — the check the header names —
  // so two rows that are the same age can never render as different ones.
  const now = new Date(checkedAt);

  // Nothing was examined, so nothing is attested.
  //
  // Every check this session can make came back denied, so the composition produced no
  // rows and no degraded entries. That emptiness used to reach the green line — a dated
  // all-clear about a fleet on which zero checks had run, handed to the session least
  // able to notice it was hollow. Failure must never read as emptiness (#150).
  //
  // Written for `Role.viewer`, which had all four checks denied. Since #101 a Viewer
  // holds the alerts check (`device:read` + `app:read`) and so is no longer blind — see
  // the note in `needsAttention.ts`. The state is still live for a principal denied all
  // four, and for any future role that is.
  //
  // No timestamp on this state, deliberately. A clock here would date *something*, and
  // the only honest thing to date is a check, of which there were none. It is also not
  // rendered as five denied rows: this is one fact about the session, not five faults in
  // the product, and naming the missing access is the actionable half — it is what the
  // reader repeats to whoever administers their account.
  if (blind) {
    return (
      <section className="rounded-lg border bg-card px-5 py-4 text-sm shadow-sm">
        <p className="flex items-start gap-3 text-card-foreground">
          <Lock aria-hidden="true" className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
          <span>
            <span className="font-medium">{ta.blindTitle}</span>{" "}
            <span className="text-muted-foreground">{ta.blindBody}</span>
          </span>
        </p>
      </section>
    );
  }

  // The gate lives in the composition, not here. A panel that re-typed the condition
  // would be the second implementation of the attestation rule. `blind` is one of its
  // three clauses, so the branch above is a redundancy the gate does not depend on: if
  // this component's order were ever changed, `isAllClear` would still refuse the line.
  if (isAllClear({ rows, degraded, blind })) {
    return (
      <section className="flex items-center gap-3 rounded-lg border bg-card px-5 py-4 text-sm shadow-sm">
        <CheckCircle2 aria-hidden="true" className="h-4 w-4 shrink-0 text-emerald-600" />
        <p className="text-card-foreground">
          <time dateTime={checkedAt} title={formatUtc(checkedAt)}>
            {ta.allClear(formatUtcClock(checkedAt))}
          </time>
        </p>
      </section>
    );
  }

  return (
    <section className="rounded-lg border bg-card shadow-sm">
      <header className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 border-b px-5 py-4">
        <h2 className="flex items-center gap-2 font-semibold text-card-foreground">
          <AlertTriangle aria-hidden="true" className="h-4 w-4 text-amber-500" />
          {ta.title}
        </h2>
        {/* Same split as the all-clear: the header says when the *check* ran, and each
            row says when its own fact happened, so the two can never be read as one. */}
        <time dateTime={checkedAt} title={formatUtc(checkedAt)} className="text-sm text-muted-foreground">
          {ta.checked(formatUtcClock(checkedAt))}
        </time>
      </header>

      <ul className="divide-y">
        {rows.map((row) => (
          <Row key={row.id} row={row} now={now} />
        ))}
        {/* A check that could not run is a row, never silence (#150's rule). It says
            which check, because "something went wrong" is not actionable. */}
        {degraded.map((kind) => (
          <li key={`degraded:${kind}`} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-5 py-3 text-sm">
            <HelpCircle aria-hidden="true" className="h-4 w-4 shrink-0 text-muted-foreground" />
            <span className="text-muted-foreground">{ta.couldNotCheck(ta.checkNames[kind])}</span>
          </li>
        ))}
      </ul>

      {dropped > 0 && (
        // The cap hid real rows and says so. A short list that quietly truncated would
        // be worse than a long one.
        <footer className="border-t px-5 py-3 text-sm text-muted-foreground">{ta.andMore(dropped)}</footer>
      )}
    </section>
  );
}
