import { useEffect, useState, type ReactElement } from "react";
import { Button } from "@/components/ui/button";
import { ExternalLink } from "@/components/ui/external-link";
import { ApiError } from "@/config/api";
import { getTitleHistory, readTitleHistory } from "@/features/fleetCatalog/api";
import { manifestUrl } from "@/features/fleetCatalog/catalogView";
import { FleetHistoryActivity } from "@/features/fleetCatalog/FleetHistoryActivity";
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
 *
 * The tab passes neither `detail` nor `onSelectVersion` (#901), so its panel is drawn as before them.
 */
export function FleetTitleHistory({
  slug,
  canRead,
  onRead,
  detail = false,
  onSelectVersion
}: {
  slug: string;
  canRead: boolean;
  /** After a read that landed, so the page reads its list again: the row's date and the progress line moved. */
  onRead?: () => void;
  /** An app's own page: the cadence chart on top, the page's width, a version search and each row's manifest. */
  detail?: boolean;
  /** A Compare button on each row, handing the caller that row's version. */
  onSelectVersion?: (version: string) => void;
}) {
  const { t } = useLocale();
  const [query, setQuery] = useState("");
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
  const needle = query.trim().toLowerCase();
  const matches = history.versions.filter((version) => version.version.toLowerCase().includes(needle));
  // In the detail layout the panel is a section of its own page and takes the page's width, and
  // its table, up to five columns, scrolls inside it instead of widening the page. `relative`
  // keeps the sr-only headers and names in the scroll box: positioned against the page, one in
  // a column scrolled out of view widened the page on a phone.
  const wrap = (table: ReactElement) => (detail ? <div className="relative overflow-x-auto">{table}</div> : table);
  // Status, then the button under it, at most max-w-2xl wide: the panel is as wide as the
  // catalog table, which scrolls sideways in a narrow window, and a button at the panel's right
  // edge sat in the part scrolled out of view.
  return (
    <div className={detail ? "space-y-3 text-sm" : "max-w-2xl space-y-3 text-sm"} data-testid={`fleet-history-${slug}`}>
      {detail && <FleetHistoryActivity history={history} />}
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
      {detail && history.versions.length > 0 && (
        <label className="block font-medium">
          {t.fleetCatalog.historySearch}
          <input
            type="search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            className="mt-1 block w-full max-w-sm rounded-md border border-input bg-background px-3 py-2 font-normal focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          />
        </label>
      )}
      {history.versions.length > 0 && matches.length === 0 && (
        <p className="text-muted-foreground">{t.fleetCatalog.historySearchNone}</p>
      )}
      {matches.length > 0 && wrap(
        <table className={detail ? "w-full" : "w-full max-w-xl"}>
          <thead className="text-left text-muted-foreground">
            <tr>
              <th className="py-1 pr-4 font-medium">{t.fleetCatalog.historyVersion}</th>
              <th className="py-1 pr-4 font-medium">{t.fleetCatalog.historyInCatalog}</th>
              <th className="py-1 font-medium">{t.fleetCatalog.historyReplaced}</th>
              {detail && (
                <th className="py-1 pl-4 font-medium">
                  <span className="sr-only">{t.fleetCatalog.historyManifest}</span>
                </th>
              )}
              {onSelectVersion && (
                <th className="py-1 pl-4 font-medium">
                  <span className="sr-only">{t.fleetCatalog.historyTargetColumn}</span>
                </th>
              )}
            </tr>
          </thead>
          <tbody>
            {matches.map((version) => (
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
                {detail && (
                  <td className="whitespace-nowrap py-1 pl-4">
                    <ExternalLink href={manifestUrl(slug, version.commitSha)}>
                      <span aria-hidden="true">{t.fleetCatalog.historyManifest}</span>
                      <span className="sr-only">{t.fleetCatalog.historyManifestLabel(version.version)}</span>
                    </ExternalLink>
                  </td>
                )}
                {onSelectVersion && (
                  <td className="py-1 pl-4">
                    <Button size="sm" variant="outline" onClick={() => onSelectVersion(version.version)}>
                      {t.fleetCatalog.historyCompare(version.version)}
                    </Button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
