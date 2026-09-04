import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router";
import { listChanges } from "@/features/changes/api";
import { diffLines, whatOf } from "@/features/changes/render";
import type { DeviceChange } from "@/features/changes/types";
import { formatUtc } from "@/features/overview/heroRun";
import { changesHref, readLastVisit, resolveAnchor, summarise, writeLastVisit } from "@/features/overview/sinceAnchor";
import { useLocale } from "@/i18n/LocaleContext";

/** Enough rows to fill the panel, and enough beyond it that the header's device count is
 *  exact on any ordinary day. The feed shows ten; it asks for more so `summarise` counts
 *  distinct devices over the window rather than over what happens to be visible. */
const FETCH_SIZE = 100;
const VISIBLE_ROWS = 10;

/** What the feed shows: notable and above. `low` is the noise the change policy already
 *  defaults off, and a front page that reprinted it would bury the reason to look. */
const FEED_MIN_LEVEL = "normal" as const;

/**
 * "Since you last looked" — the centerpiece feed on `/` (#107).
 *
 * The anchor is per-browser (`localStorage`, 24 hours for anyone without one), but it is
 * resolved to an **absolute instant** the moment the panel loads: printed in the header
 * and baked into every click-through, so a screenshot in a ticket or a link pasted into
 * Slack reproduces exactly the window the sender was looking at. A relative `since=24h`
 * would mean something different for every person who opened it.
 *
 * **The stamp is written on unmount, not on load.** Writing it on load would move the
 * anchor to *now* while the operator was still reading the panel, so a refresh would show
 * an empty feed and the changes they had not finished reading would be gone for good.
 */
export function ChangesFeed({ baselineAt }: { baselineAt: string | null }) {
  const { t } = useLocale();
  const tf = t.overview.feed;

  /** The thing that changed. Shared with the Changes table so the two cannot drift. */
  function describe(row: DeviceChange): string {
    const what = whatOf(
      row,
      // No labels: the feed does not read the change policy, so a field appears under its
      // own name. Worth a raw `cfBundleVersion` on a glance surface rather than a second
      // request on "/" for cosmetics — the Changes page fetches them and shows the label.
      {},
      {
        section: (name) => t.changes.sections[name] ?? name,
        entryKind: (kind) => t.changes.entryKinds[kind] ?? kind
      }
    );
    return what.identity ? `${what.head} · ${what.identity}` : what.head;
  }

  /** What moved, on one line — the panel gives each row exactly one. */
  function summariseChange(row: DeviceChange): string {
    return diffLines(row)
      .map((line) => {
        const value = line.pair ? `${line.from ?? "—"} → ${line.to ?? "—"}` : (line.from ?? line.to ?? "");
        return line.label ? `${line.label} ${value}` : value;
      })
      .join(" · ");
  }

  // Resolved once per mount. Recomputing it on every render would slide the window under
  // the reader, and it is the value every click-through URL is built from.
  const anchor = useMemo(() => resolveAnchor(readLastVisit(), new Date()), []);
  const [rows, setRows] = useState<DeviceChange[] | null>(null);
  const [total, setTotal] = useState(0);
  const [failed, setFailed] = useState(false);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      // The visit is stamped as the operator leaves, so "since you last looked" means the
      // last time they finished looking.
      writeLastVisit(new Date());
    };
  }, []);

  const load = useCallback(async () => {
    try {
      const response = await listChanges({ since: anchor, minLevel: FEED_MIN_LEVEL, pageSize: FETCH_SIZE });
      if (!mounted.current) return;
      setRows(response.items);
      setTotal(response.total);
      setFailed(false);
    } catch {
      // #150's rule: failure must never read as emptiness. A feed that could not load
      // says so, rather than showing the same panel a quiet fleet shows.
      if (mounted.current) setFailed(true);
    }
  }, [anchor]);

  useEffect(() => {
    void load();
  }, [load]);

  if (failed) {
    return (
      <section className="rounded-lg border bg-card px-5 py-4 text-sm shadow-sm">
        <h2 className="font-semibold text-card-foreground">{tf.title}</h2>
        <p className="mt-1 text-destructive">{tf.loadError}</p>
      </section>
    );
  }

  if (rows === null) {
    return (
      <section className="rounded-lg border bg-card px-5 py-4 text-sm text-muted-foreground shadow-sm">
        {tf.loading}
      </section>
    );
  }

  const summary = summarise(rows, total);
  const href = changesHref(anchor, FEED_MIN_LEVEL);

  return (
    <section className="rounded-lg border bg-card shadow-sm">
      <header className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 border-b px-5 py-4">
        <h2 className="font-semibold text-card-foreground">{tf.title}</h2>
        <p className="text-sm text-muted-foreground">
          {/* The anchor is printed, not implied — the header and the link say the same
              absolute instant, which is what makes a screenshot reproducible. */}
          {tf.summary(summary.total, summary.devices, formatUtc(anchor), summary.notable)}
        </p>
      </header>

      {summary.rows.length === 0 ? (
        <p className="px-5 py-4 text-sm text-muted-foreground">
          {/* Never a fake zero. On day one the fleet has a baseline and nothing to
              compare it against yet, which is a different sentence from "nothing
              changed" — and the operator is owed the difference. */}
          {baselineAt ? tf.emptyAfterBaseline : tf.emptyQuiet}
        </p>
      ) : (
        <ul className="divide-y">
          {summary.rows.slice(0, VISIBLE_ROWS).map((row) => (
            <li key={row.id}>
              <Link to={href} className="flex flex-wrap items-baseline gap-x-3 gap-y-1 px-5 py-3 text-sm hover:bg-accent">
                <span className="font-medium text-card-foreground">{row.subjectLabel ?? row.subjectId}</span>
                <span className="text-muted-foreground">{describe(row)}</span>
                {/* The fields that moved, not the entries they moved inside. This line
                    printed two whole JSON bodies with no truncation at all, so one app
                    update could take the full width of the panel and still not show the
                    version — the reason #307 exists, at its loudest. */}
                <span className="font-mono text-xs text-muted-foreground">{summariseChange(row)}</span>
                <span className="rounded-full border px-2 py-0.5 text-xs text-muted-foreground">{row.trigger}</span>
                <span className="ml-auto whitespace-nowrap text-xs text-muted-foreground">{formatUtc(row.observedAt)}</span>
              </Link>
            </li>
          ))}
        </ul>
      )}

      <footer className="border-t px-5 py-3">
        <Link to={href} className="text-sm font-medium underline underline-offset-4">
          {tf.seeAll}
        </Link>
      </footer>
    </section>
  );
}
