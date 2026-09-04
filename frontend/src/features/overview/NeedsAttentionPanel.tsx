import { useEffect } from "react";
import { AlertTriangle, CheckCircle2, HelpCircle } from "lucide-react";
import { Link } from "react-router";
import { useAttentionStore } from "@/features/overview/attentionStore";
import { formatUtcClock } from "@/features/overview/heroRun";
import { isAllClear, type AttentionKind, type AttentionRow } from "@/features/overview/needsAttention";
import { useLocale } from "@/i18n/LocaleContext";
import { cn } from "@/lib/utils";
import type { Translations } from "@/i18n/en";

/** How often the panel re-runs its checks. Slower than the run watcher above it: none of
 *  these facts change on a fifteen-second scale, and this is six requests. */
const REFRESH_INTERVAL_MS = 60000;

/** The stripe. The three levels are the change policy's, so the colours are the ones the
 *  rest of the product already uses for high / normal / low. */
const STRIPE: Record<string, string> = {
  high: "bg-destructive",
  normal: "bg-amber-500",
  low: "bg-muted-foreground/40"
};

function sentenceFor(t: Translations, kind: AttentionKind): string {
  return t.overview.attention.kinds[kind];
}

function Row({ row }: { row: AttentionRow }) {
  const { t } = useLocale();
  const body = (
    <>
      <span aria-hidden="true" className={cn("h-8 w-1 shrink-0 rounded-full", STRIPE[row.level])} />
      <span className="font-medium text-card-foreground">{sentenceFor(t, row.kind)}</span>
      {/* The name is interpolated, never concatenated into the sentence above: a
          sentence assembled here would be an English sentence in the German UI. */}
      {row.subject && <span className="text-muted-foreground">{row.subject}</span>}
      {row.context && <span className="text-xs text-muted-foreground">· {row.context}</span>}
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

  // The gate lives in the composition, not here. A panel that re-typed the condition
  // would be the second implementation of the attestation rule.
  if (isAllClear({ rows, degraded })) {
    return (
      <section className="flex items-center gap-3 rounded-lg border bg-card px-5 py-4 text-sm shadow-sm">
        <CheckCircle2 aria-hidden="true" className="h-4 w-4 shrink-0 text-emerald-600" />
        <p className="text-card-foreground">{ta.allClear(formatUtcClock(checkedAt))}</p>
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
        <p className="text-sm text-muted-foreground">{ta.checked(formatUtcClock(checkedAt))}</p>
      </header>

      <ul className="divide-y">
        {rows.map((row) => (
          <Row key={row.id} row={row} />
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
