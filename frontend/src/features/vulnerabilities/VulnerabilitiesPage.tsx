import { useEffect, useState } from "react";
import { Link } from "react-router";
import { ApiError } from "@/config/api";
import { listCatalog } from "@/features/catalog/api";
import { LatestCell, PatchAnswerCell } from "@/features/catalog/PatchAnswerCell";
import type { CatalogEntry, CatalogListResponse } from "@/features/catalog/types";
import { AssessmentCell, CorpusBanner } from "@/features/vulnerabilities/AppAssessment";
import { useLocale } from "@/i18n/LocaleContext";
import type { Translations } from "@/i18n/en";

/**
 * Posture › Vulnerabilities — the fleet ranking the Catalog tab cannot show (#529).
 *
 * The Catalog sorts its vulnerability column client-side over the page in hand; this list is
 * filtered and ordered by the server over every build the tenant has. One row is one BUILD
 * and never one CVE: that is the grain the container holds and the grain a Mac admin acts
 * on, since you push an app update.
 *
 * Three states before a row is drawn, in this order: nothing answers (the `409` — the banner
 * and its *why* block alone, because an empty table under a filter reads as *nothing found*,
 * §4a); loaded but nothing judged against it yet (`vulnJudged` false — one sentence, no
 * list); judged. Not here, each with its own issue and none stubbed: Easily patchable (#532),
 * the chips, Longest exposed and By the numbers (#538).
 */

const TOP = 10;
const PAGE = 50;
/** One request per pause, not one per keystroke: the search is a server read. */
const TYPING_MS = 300;

type Load = "loading" | "ready" | "silent" | "failed";

/** The four bands as small counts, reachable only inside the `covered` narrowing — there is
 *  no branch here in which an unassessed build contributes a zero (§4a). */
function Bands({ entry, t }: { entry: CatalogEntry; t: Translations }) {
  if (entry.vuln.assessment !== "covered" || entry.vuln.counts.total === 0) return null;
  const { severity } = entry.vuln.counts;
  const copy = t.vulnerabilities;
  const named: [string, number][] = [
    [copy.bandCritical, severity.critical],
    [copy.bandHigh, severity.high],
    [copy.bandMedium, severity.medium],
    [copy.bandLow, severity.low]
  ];
  const shown = named.filter(([, count]) => count > 0).map(([label, count]) => `${label} ${count}`);
  return <span className="block text-xs text-muted-foreground">{shown.join(" · ")}</span>;
}

export function VulnerabilitiesPage() {
  const { t } = useLocale();
  const copy = t.vulnerabilities;
  // A plain text box over the catalog's own `q` (name, bundle id, version). An id-shaped
  // query is routed to the by-id page by #533 and the AI lever is #534 — said here rather
  // than drawn as a control with nothing behind it.
  const [term, setTerm] = useState("");
  const [expanded, setExpanded] = useState(false);
  const [page, setPage] = useState(1);
  const [answer, setAnswer] = useState<CatalogListResponse | null>(null);
  const [load, setLoad] = useState<Load>("loading");

  useEffect(() => {
    let cancelled = false;
    const timer = setTimeout(() => {
      setLoad("loading");
      listCatalog({
        vuln: "findings",
        order: "exposure",
        q: term.trim() || undefined,
        page: expanded ? page : 1,
        pageSize: expanded ? PAGE : TOP
      })
        .then((response) => {
          if (cancelled) return;
          setAnswer(response);
          setLoad("ready");
        })
        .catch((error: unknown) => {
          // The 409 is a STATE, never an error message: nothing is answering for this
          // organization, which the banner below says in words and names both causes for.
          if (!cancelled) setLoad(error instanceof ApiError && error.status === 409 ? "silent" : "failed");
        });
    }, TYPING_MS);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [term, expanded, page]);

  const judged = load === "ready" && answer !== null && answer.vulnJudged;
  const rows = judged ? (answer?.items ?? []) : [];
  const total = answer?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / PAGE));

  return (
    <section className="space-y-4">
      <p className="text-xs uppercase tracking-wide text-muted-foreground">{copy.eyebrow}</p>
      <h1 className="text-2xl font-semibold">{copy.pageTitle}</h1>
      <p className="text-sm text-muted-foreground">{copy.pageDescription}</p>

      {/* One date governs the page; `silent` has none to give. */}
      <CorpusBanner corpusAsOf={load === "silent" ? null : (answer?.corpusAsOf ?? null)} t={t} />

      {load === "failed" && <p className="text-sm text-destructive">{copy.errorLoading}</p>}
      {load === "ready" && answer !== null && !answer.vulnJudged && (
        <p className="text-sm text-muted-foreground">{copy.notYetJudged}</p>
      )}

      {judged && (
        <>
          <input
            className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            placeholder={copy.searchPlaceholder}
            value={term}
            onChange={(event) => {
              setTerm(event.target.value);
              setPage(1);
            }}
          />

          <div className="flex items-baseline justify-between">
            <h2 className="text-lg font-medium">{copy.mostExposed}</h2>
            {!expanded && total > rows.length && (
              <button type="button" className="text-sm underline underline-offset-4" onClick={() => setExpanded(true)}>
                {copy.seeAll(total)}
              </button>
            )}
          </div>
          <p className="text-sm text-muted-foreground">{copy.mostExposedHint}</p>

          <div className="overflow-x-auto rounded-lg border bg-card">
            <table className="w-full text-sm">
              <thead className="border-b bg-muted/30 text-left text-muted-foreground">
                <tr>
                  {[copy.colBuild, copy.colFindings, copy.colKev, copy.colMacs, copy.colOldest, copy.colFix].map(
                    (label) => (
                      <th key={label} className="px-4 py-2 font-medium">
                        {label}
                      </th>
                    )
                  )}
                </tr>
              </thead>
              <tbody>
                {rows.length === 0 && (
                  <tr>
                    <td className="px-4 py-4 text-muted-foreground" colSpan={6}>
                      {term ? copy.noMatches : copy.noFindings}
                    </td>
                  </tr>
                )}
                {rows.map((entry) => (
                  <tr key={entry.id} className="border-b align-top last:border-0">
                    <td className="px-4 py-2">
                      <Link to={`/devices/applications/${encodeURIComponent(entry.appHash)}`} className="font-medium hover:underline">
                        {entry.name} {entry.version}
                      </Link>
                      <span className="block font-mono text-xs text-muted-foreground">{entry.bundleId}</span>
                    </td>
                    <td className="px-4 py-2">
                      {/* The ONE rendering of the three states here, handed the row so #482's
                          update line prints beside the count it is about. */}
                      <AssessmentCell vuln={entry.vuln} row={entry} t={t} />
                      <Bands entry={entry} t={t} />
                    </td>
                    <td className="px-4 py-2 tabular-nums">
                      {entry.vuln.assessment === "covered" && entry.vuln.counts.kev > 0 ? entry.vuln.counts.kev : "—"}
                    </td>
                    <td className="px-4 py-2 tabular-nums">
                      <Link to={`/devices?versionHash=${entry.versionHash}`} className="hover:underline">
                        {entry.deviceCount}
                      </Link>
                    </td>
                    <td className="px-4 py-2 tabular-nums">
                      {entry.vuln.assessment === "covered" && entry.vuln.daysOldestPublished.total !== null
                        ? copy.days(entry.vuln.daysOldestPublished.total)
                        : "—"}
                    </td>
                    <td className="px-4 py-2">
                      <LatestCell answer={entry} t={t} />
                      <PatchAnswerCell answer={entry} t={t} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {expanded && (
            <div className="flex items-center gap-3 text-sm">
              <button
                type="button"
                className="rounded-md border px-3 py-1 disabled:opacity-50"
                disabled={page <= 1}
                onClick={() => setPage((current) => current - 1)}
              >
                {copy.previous}
              </button>
              <span className="text-muted-foreground">{copy.pageOf(page, pages)}</span>
              <button
                type="button"
                className="rounded-md border px-3 py-1 disabled:opacity-50"
                disabled={page >= pages}
                onClick={() => setPage((current) => current + 1)}
              >
                {copy.next}
              </button>
            </div>
          )}
        </>
      )}
    </section>
  );
}
