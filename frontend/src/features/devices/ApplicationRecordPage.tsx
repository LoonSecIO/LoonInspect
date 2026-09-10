import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router";
import { listCatalog } from "@/features/catalog/api";
import { PATCH_STATE_COLORS } from "@/features/catalog/patchState";
import type { CatalogEntry, CatalogListResponse } from "@/features/catalog/types";
import { getJamfPatchTitle } from "@/features/jamfPatch/api";
import type { JamfPatchTitleDetail } from "@/features/jamfPatch/types";
import { AssessmentCell, CorpusBanner } from "@/features/vulnerabilities/AppAssessment";
import { useLocale } from "@/i18n/LocaleContext";
import type { Translations } from "@/i18n/en";

/** Every row of one app: distinct builds, not installs, so a page is the whole record. */
const RECORD_PAGE_SIZE = 500;

type Result<T> = { state: "ready"; value: T } | { state: "failed" };

function formatDay(value: string | null): string {
  return value ? new Date(value).toLocaleDateString() : "—";
}

function formatInstant(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "—";
}

/**
 * One application's record (#299): `/devices/applications/:appHash`, keyed by
 * `app_hash = md5(name:bundle_id)` and never by bundle ID, because two apps sharing a
 * bundle ID under different names are two records.
 *
 * The order of the page is the argument: identity, then one answer sentence from the rows
 * in hand, then the corpus's edge, then the version spread — one row per carried build at
 * `key_full` grain, which is the only grain an assessment may legally ride — then the two
 * edge blocks that are never rows inside the spread. Carriers are a link, not a table:
 * the Devices page is built, URL-stated and paginated, and inherits every filter it has.
 */
export function ApplicationRecordPage() {
  const { t } = useLocale();
  const tr = t.applications.record;
  const { appHash } = useParams<{ appHash: string }>();

  const [loaded, setLoaded] = useState<{ key: string; result: Result<CatalogListResponse> } | null>(null);
  const [titles, setTitles] = useState<{ key: string; items: JamfPatchTitleDetail[] } | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!appHash) return;
    let cancelled = false;
    listCatalog({ appHash, installedOnly: false, pageSize: RECORD_PAGE_SIZE })
      .then((response) => {
        if (!cancelled) setLoaded({ key: appHash, result: { state: "ready", value: response } });
      })
      .catch(() => {
        if (!cancelled) setLoaded({ key: appHash, result: { state: "failed" } });
      });
    return () => {
      cancelled = true;
    };
  }, [appHash]);

  const current = loaded && loaded.key === appHash ? loaded.result : null;
  const rows = useMemo(() => (current?.state === "ready" ? current.value.items : []), [current]);
  const titleIds = useMemo(() => [...new Set(rows.flatMap((row) => row.jamfTitleIds ?? []))].sort(), [rows]);
  const titlesKey = titleIds.join(",");

  // Jamf's side of the record: each matched title's listed versions, read from the title
  // endpoint that already ships. A title that fails to load is left out rather than
  // failing the page; the block says how many it read.
  useEffect(() => {
    if (!titlesKey) return;
    let cancelled = false;
    Promise.allSettled(titlesKey.split(",").map((id) => getJamfPatchTitle(id))).then((settled) => {
      if (cancelled) return;
      const items = settled.flatMap((result) => (result.status === "fulfilled" ? [result.value] : []));
      setTitles({ key: titlesKey, items });
    });
    return () => {
      cancelled = true;
    };
  }, [titlesKey]);

  if (!appHash) return null;
  if (current === null) return <p className="text-sm text-muted-foreground">{tr.loading}</p>;
  if (current.state === "failed" || rows.length === 0) {
    return (
      <section className="space-y-3">
        <p className={`text-sm ${current.state === "failed" ? "text-destructive" : "text-muted-foreground"}`}>
          {current.state === "failed" ? tr.errorLoading : tr.notFound}
        </p>
        <Link to="/devices/applications" className="text-sm underline underline-offset-4">
          {tr.back}
        </Link>
      </section>
    );
  }

  const identity = rows[0];
  // The server's order — devices descending — is the spread's order (#299 §5).
  const carried = rows.filter((row) => row.deviceCount > 0);
  const remembered = rows.filter((row) => row.deviceCount === 0);
  const installs = carried.reduce((sum, row) => sum + row.deviceCount, 0);
  const patchable = carried.filter((row) => row.patchAvailable === true).length;
  const lastReported = carried.map((row) => row.lastSeenAt).sort().at(-1) ?? null;
  const carriedVersions = new Set(rows.map((row) => row.version));
  const jamfTitles = titles && titles.key === titlesKey ? titles.items : null;
  const unlisted = (jamfTitles ?? []).flatMap((title) =>
    title.patches.filter((patch) => !carriedVersions.has(patch.version)).map((patch) => ({ title, patch }))
  );

  function copyBundleId() {
    void navigator.clipboard?.writeText(identity.bundleId).then(() => setCopied(true));
  }

  return (
    <section className="space-y-6">
      <div>
        <p className="text-sm font-medium text-muted-foreground">
          <Link to="/devices/applications" className="hover:underline">
            {tr.back}
          </Link>
        </p>
        <h2 className="text-2xl font-bold tracking-tight">{identity.name}</h2>
        <p className="mt-1 flex flex-wrap items-center gap-2 text-sm">
          <span className="font-mono text-muted-foreground">{identity.bundleId}</span>
          <button type="button" className="rounded border px-2 py-0.5 text-xs hover:bg-accent/40" onClick={copyBundleId}>
            {copied ? tr.copied : tr.copy}
          </button>
        </p>
        {/* Demoted to a labelled lookup key: the record's address, not an identity Jamf knows. */}
        <p className="mt-1 text-xs text-muted-foreground" title={tr.lookupKeyHint}>
          {tr.lookupKey}: <span className="font-mono">{identity.appHash}</span>
        </p>
      </div>

      <p className="text-sm">
        {carried.length === 0 ? tr.answerNone : tr.answer(carried.length, installs, patchable, formatInstant(lastReported))}
        {carried.length > 0 && (
          <>
            {" · "}
            <Link to={`/devices?appHash=${appHash}`} className="underline decoration-dotted underline-offset-4 hover:decoration-solid">
              {tr.allCarriers}
            </Link>
          </>
        )}
      </p>

      <CorpusBanner corpusAsOf={current.value.corpusAsOf} t={t} />

      <section className="space-y-2">
        <h3 className="text-lg font-semibold">{tr.spreadHeading}</h3>
        <div className="overflow-x-auto rounded-lg border bg-card">
          <table className="w-full text-sm">
            <thead className="border-b bg-muted/30 text-left text-muted-foreground">
              <tr>
                <th className="px-4 py-2 font-medium">{tr.colVersion}</th>
                <th className="px-4 py-2 font-medium">{tr.colDevices}</th>
                <th className="px-4 py-2 font-medium">{tr.colPatch}</th>
                <th className="px-4 py-2 font-medium">{tr.colLatest}</th>
                <th className="px-4 py-2 font-medium">{tr.colVuln}</th>
                <th className="px-4 py-2 font-medium">{tr.colFirstSeen}</th>
                <th className="px-4 py-2 font-medium">{tr.colLastSeen}</th>
                <th className="px-4 py-2 font-medium">{tr.colJudged}</th>
                <th className="px-4 py-2 font-medium">{tr.colCarriers}</th>
              </tr>
            </thead>
            <tbody>
              {carried.length === 0 && (
                <tr>
                  <td className="px-4 py-4 text-muted-foreground" colSpan={9}>
                    {tr.answerNone}
                  </td>
                </tr>
              )}
              {carried.map((row) => (
                <tr key={row.id} className="border-b align-top last:border-0">
                  <td className="px-4 py-2 tabular-nums">
                    {row.version}
                    {row.shortVersion && row.shortVersion !== row.version ? (
                      <span className="text-muted-foreground"> ({row.shortVersion})</span>
                    ) : null}
                  </td>
                  <td className="px-4 py-2 tabular-nums">{row.deviceCount}</td>
                  <td className="px-4 py-2">
                    <PatchCell row={row} t={t} />
                  </td>
                  <td className="px-4 py-2 tabular-nums">{row.latestVersion ?? "—"}</td>
                  <td className="px-4 py-2">
                    {/* Legal here and only here: each row is one build at key_full grain. */}
                    <AssessmentCell vuln={row.vuln} t={t} />
                  </td>
                  <td className="px-4 py-2">{formatDay(row.firstSeenAt)}</td>
                  <td className="px-4 py-2">{formatDay(row.lastSeenAt)}</td>
                  <td className="px-4 py-2 text-muted-foreground" title={row.evaluatedSignature ?? undefined}>
                    {row.evaluatedAt ? formatInstant(row.evaluatedAt) : tr.notJudged}
                  </td>
                  <td className="px-4 py-2">
                    <Link
                      to={`/devices?appHash=${appHash}&versionHash=${row.versionHash}`}
                      className="whitespace-nowrap underline decoration-dotted underline-offset-4 hover:decoration-solid"
                    >
                      {tr.carriers}
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Two edge blocks, never rows inside the spread: what the catalog remembers with no
          carrier (no zero printed), and what Jamf lists that nobody here runs (no Devices
          column at all, so the zero has nowhere to be printed). */}
      {remembered.length > 0 && (
        <section className="rounded-lg border bg-card p-4 text-sm">
          <p className="font-medium">{tr.rememberedHeading}</p>
          <ul className="mt-1 space-y-0.5 text-muted-foreground">
            {remembered.map((row) => (
              <li key={row.id} className="tabular-nums">
                {tr.rememberedRow(row.version, formatDay(row.lastSeenAt))}
              </li>
            ))}
          </ul>
        </section>
      )}

      <section className="rounded-lg border bg-card p-4 text-sm">
        <p className="font-medium">{tr.unlistedHeading}</p>
        {titleIds.length === 0 ? (
          <p className="mt-1 text-muted-foreground">{tr.unlistedNone}</p>
        ) : jamfTitles === null ? (
          <p className="mt-1 text-muted-foreground">{tr.unlistedTitleLoading}</p>
        ) : unlisted.length === 0 ? (
          <p className="mt-1 text-muted-foreground">{tr.unlistedAllCarried(jamfTitles.length)}</p>
        ) : (
          <table className="mt-2 text-sm">
            <thead className="text-left text-xs text-muted-foreground">
              <tr>
                <th className="pr-6 font-medium">{tr.colVersion}</th>
                <th className="pr-6 font-medium">{tr.colTitle}</th>
                <th className="font-medium">{tr.colReleased}</th>
              </tr>
            </thead>
            <tbody>
              {unlisted.map(({ title, patch }) => (
                <tr key={`${title.id}:${patch.version}`}>
                  <td className="pr-6 tabular-nums">{patch.version}</td>
                  <td className="pr-6">
                    <Link to={`/devices/applications/jamf-patch/${title.id}`} className="hover:underline">
                      {title.name}
                    </Link>
                  </td>
                  <td className="text-muted-foreground">{patch.releaseDate ? formatDay(patch.releaseDate) : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </section>
  );
}

/** #68's sentence from stored columns: `patchAvailableSince` and `releasesMissed`, never a
 *  day count. */
function PatchCell({ row, t }: { row: CatalogEntry; t: Translations }) {
  if (!row.patchState) return <span className="text-muted-foreground">—</span>;
  const stateLabels: Record<string, string> = {
    latest: t.catalog.stateLatest,
    behind: t.catalog.stateBehind,
    ahead: t.catalog.stateAhead,
    unknown: t.catalog.stateUnknown
  };
  return (
    <div className="space-y-0.5">
      <span className="inline-flex items-center gap-1.5">
        <span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: PATCH_STATE_COLORS[row.patchState] }} />
        {stateLabels[row.patchState] ?? row.patchState}
      </span>
      {row.patchAvailable && (
        <span className="block text-xs text-muted-foreground">
          {t.catalog.behindSince(formatDay(row.patchAvailableSince), row.releasesMissed)}
        </span>
      )}
    </div>
  );
}
