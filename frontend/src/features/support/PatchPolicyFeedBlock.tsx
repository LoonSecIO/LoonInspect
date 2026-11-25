import { useEffect, useState } from "react";
import { describeFeed, getPatchPolicyApps, type PatchPolicyFeed } from "@/features/support/patchPolicyFeed";
import { useLocale } from "@/i18n/LocaleContext";

type Loaded = { state: "ready"; feed: PatchPolicyFeed } | { state: "failed" } | null;

/** The states that are not an answer: the sentence is drawn in the warning colour for these. */
const FAILED = new Set(["not_published", "algorithm_unknown", "download_failed", "invalid"]);

/**
 * Settings › Support › **LoonSec patch-policy data** (#614): the one sentence that says whether
 * LoonSec's patch-policy document has arrived on this instance, how old the copy held is, and what
 * the last attempt to receive one found — the line docs/troubleshooting.md §32 starts from. Then
 * the copy's id and when it arrived, and when and where the last attempt looked.
 *
 * Rendered for readers who hold APP_READ, the route's permission. It reads one route and posts
 * nothing; receiving the document is the data-sharing exchange's work, not this page's.
 */
export function PatchPolicyFeedBlock() {
  const { t } = useLocale();
  const words = t.support.patchPolicyFeed;
  const [loaded, setLoaded] = useState<Loaded>(null);

  useEffect(() => {
    let cancelled = false;
    getPatchPolicyApps()
      .then((answer) => {
        if (!cancelled) setLoaded({ state: "ready", feed: answer.feed });
      })
      .catch(() => {
        if (!cancelled) setLoaded({ state: "failed" });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const feed = loaded?.state === "ready" ? loaded.feed : null;
  const when = (value: string | null) => (value ? new Date(value).toLocaleString() : "—");

  return (
    <div className="space-y-3 rounded-lg border bg-card p-4">
      <h2 className="text-lg font-semibold">{words.heading}</h2>
      <p className="max-w-3xl text-sm text-muted-foreground">{words.help}</p>
      {loaded === null && <p className="text-sm text-muted-foreground">{words.loading}</p>}
      {loaded?.state === "failed" && <p className="text-sm text-destructive">{words.errorLoading}</p>}
      {feed && (
        <>
          <p className={`max-w-3xl text-sm ${FAILED.has(feed.state) ? "text-amber-700 dark:text-amber-400" : ""}`}>
            {describeFeed(feed, words)}
          </p>
          {feed.docId && feed.fetchedAt && (
            <p className="break-all font-mono text-xs text-muted-foreground">
              {words.held(feed.docId.slice(0, 12), when(feed.fetchedAt))}
            </p>
          )}
          {feed.attemptedAt && (
            <p className="text-xs text-muted-foreground">
              {words.attempted(when(feed.attemptedAt), feed.source === "file" ? words.fromFile : words.fromExchange)}
            </p>
          )}
        </>
      )}
    </div>
  );
}
