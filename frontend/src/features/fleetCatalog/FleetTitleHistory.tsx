import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { ApiError } from "@/config/api";
import { getTitleHistory, readTitleHistory } from "@/features/fleetCatalog/api";
import type { FleetTitleHistory as History } from "@/features/fleetCatalog/types";
import { useLocale } from "@/i18n/LocaleContext";

const COMMIT_URL = "https://github.com/fleetdm/fleet/commit/";

function day(value: string | null): string {
  return value === null ? "" : new Date(value).toLocaleDateString();
}

/**
 * One title's version history, opened from its row on the Fleet catalog tab (#838): each version
 * Fleet's catalog carried, the day it took it (linked to the commit), and the version it replaced.
 *
 * Opening it reads what the instance holds and asks GitHub nothing. Read history is the one
 * control that does, for an account that may sync a catalog: the whole history, now, for any
 * title, installed here or not. A refusal shows the server's sentence: the reserve, a read
 * already running, or what GitHub did.
 */
export function FleetTitleHistory({
  slug,
  canRead,
  onRead
}: {
  slug: string;
  canRead: boolean;
  /** After a read that landed, so the page reads its list again: the row's date and the progress line moved. */
  onRead?: () => void;
}) {
  const { t } = useLocale();
  const [history, setHistory] = useState<History | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reading, setReading] = useState(false);
  const [readError, setReadError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    getTitleHistory(slug)
      .then((answer) => {
        if (live) setHistory(answer);
      })
      .catch((caught: unknown) => {
        if (live) setError(caught instanceof ApiError && caught.detail ? caught.detail : t.fleetCatalog.historyErrorLoading);
      });
    return () => {
      live = false;
    };
  }, [slug, t]);

  function handleRead() {
    setReading(true);
    setReadError(null);
    readTitleHistory(slug)
      .then((answer) => {
        setHistory(answer);
        onRead?.();
      })
      .catch((caught: unknown) =>
        setReadError(caught instanceof ApiError && caught.detail ? caught.detail : t.fleetCatalog.historyReadError)
      )
      .finally(() => setReading(false));
  }

  if (error !== null)
    return (
      <p role="alert" className="text-sm text-destructive">
        {error}
      </p>
    );
  if (history === null) return <p className="text-sm text-muted-foreground">{t.fleetCatalog.loading}</p>;

  const read = history.historyReadAt !== null;
  // Status, then the button under it, at most max-w-2xl wide: the panel is as wide as the
  // catalog table, which scrolls sideways in a narrow window, and a button at the panel's right
  // edge sat in the part scrolled out of view.
  return (
    <div className="max-w-2xl space-y-3 text-sm" data-testid={`fleet-history-${slug}`}>
      <div className="space-y-1" aria-live="polite">
        <p>
          {!read
            ? t.fleetCatalog.historyNotRead
            : history.historySince === null
              ? t.fleetCatalog.historyReadNothing(day(history.historyReadAt))
              : history.historyComplete
                ? t.fleetCatalog.historyReadWhole(day(history.historyReadAt), day(history.historySince))
                : t.fleetCatalog.historyReadFrom(day(history.historyReadAt), day(history.historySince))}
        </p>
        {history.historyDetail && <p className="text-muted-foreground">{history.historyDetail}</p>}
        <p className="text-xs text-muted-foreground">{t.fleetCatalog.historyDatesNote}</p>
      </div>
      {canRead && (
        <Button size="sm" variant="outline" onClick={handleRead} disabled={reading}>
          {reading ? t.fleetCatalog.historyReading : read ? t.fleetCatalog.historyReadAgain : t.fleetCatalog.historyRead}
        </Button>
      )}
      {readError && (
        <p role="alert" className="text-destructive">
          {readError}
        </p>
      )}
      {read && history.versions.length === 0 && <p className="text-muted-foreground">{t.fleetCatalog.historyNoVersions}</p>}
      {history.versions.length > 0 && (
        <table className="w-full max-w-xl">
          <thead className="text-left text-muted-foreground">
            <tr>
              <th className="py-1 pr-4 font-medium">{t.fleetCatalog.historyVersion}</th>
              <th className="py-1 pr-4 font-medium">{t.fleetCatalog.historyInCatalog}</th>
              <th className="py-1 font-medium">{t.fleetCatalog.historyReplaced}</th>
            </tr>
          </thead>
          <tbody>
            {history.versions.map((version) => (
              <tr key={version.version}>
                <td className="py-1 pr-4 tabular-nums">{version.version}</td>
                <td className="py-1 pr-4">
                  <a
                    className="underline"
                    href={`${COMMIT_URL}${version.commitSha}`}
                    target="_blank"
                    rel="noreferrer noopener"
                    aria-label={t.fleetCatalog.historyCommitLabel(day(version.seenAt), version.commitSha.slice(0, 8))}
                  >
                    {day(version.seenAt)}
                  </a>
                </td>
                <td className="py-1 tabular-nums text-muted-foreground">
                  {version.previousVersion ?? t.fleetCatalog.historyReplacedNone}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
