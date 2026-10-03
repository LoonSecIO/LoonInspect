import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router";
import { ChevronDown, ChevronRight } from "lucide-react";
import { AppNameLine } from "@/features/jamfPatch/AppNameLine";
import { getJamfPatchTitle } from "@/features/jamfPatch/api";
import type { JamfPatchTitleDetail, PolicyVersion } from "@/features/jamfPatch/types";
import { ReleaseCalendar } from "@/features/jamfPatch/ReleaseCalendar";
import { RequirementsSection } from "@/features/jamfPatch/RequirementsSection";
import { RequirementsTestPanel } from "@/features/jamfPatch/RequirementsTestPanel";
import { TitlePolicyCard } from "@/features/jamfPatch/TitlePolicyCard";
import { policySentence } from "@/features/jamfPatch/policyRules";
import { VersionDevicesChart } from "@/features/jamfPatch/VersionDevicesChart";
import { filterVersionRows, hideEmptyByDefault, versionRows } from "@/features/jamfPatch/versionRows";
import { AssessmentCell } from "@/features/vulnerabilities/AppAssessment";
import { formatCorpusDate } from "@/features/vulnerabilities/types";
import { useLocale } from "@/i18n/LocaleContext";

/** One version's verdict in the table: the status dot with its words, never the dot alone. */
function PolicyCell({
  verdict,
  sentence
}: {
  verdict: PolicyVersion | undefined;
  sentence: (verdict: PolicyVersion) => string;
}) {
  if (!verdict) return <span className="text-muted-foreground">—</span>;
  return (
    <span className={`inline-flex items-start gap-1.5 ${verdict.state === "not_judged" ? "text-muted-foreground" : ""}`}>
      {verdict.state === "out" && <span className="mt-1.5 h-2 w-2 shrink-0 rounded-full bg-[#d03b3b]" />}
      {sentence(verdict)}
    </span>
  );
}

export function JamfPatchDetailPage() {
  const { t } = useLocale();
  const { titleId } = useParams<{ titleId: string }>();

  const [title, setTitle] = useState<JamfPatchTitleDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [versionsExpanded, setVersionsExpanded] = useState(false);
  // "Hide versions with 0 devices". Null until the reader touches the box, so each title
  // opens on its own default (`hideEmptyByDefault`) rather than on the last title's choice.
  const [hideEmptyChoice, setHideEmptyChoice] = useState<boolean | null>(null);
  // Bumped when this title's patching rule changes: every verdict on the page is the API's,
  // so a changed rule is a re-read, without the page falling back to "Loading".
  const [revision, setRevision] = useState(0);

  // A different title is a different question, and the page has to say it is asking
  // rather than leave the last title's facts standing under the new name. Adjusted here,
  // during the render that changed the id, rather than from the effect below — React's
  // own "adjusting state when a prop changes". From an effect it lands a render late.
  // Keyed on everything the effect re-runs for, the locale beside the id: a guard on less
  // is a re-fetch that clears nothing, and here a stale failure line does not merely sit
  // above the answer, it replaces it — the title block below is gated on `!error`.
  const [asked, setAsked] = useState({ titleId, t });
  if (asked.titleId !== titleId || asked.t !== t) {
    setAsked({ titleId, t });
    setLoading(true);
    setError(null);
    if (asked.titleId !== titleId) setHideEmptyChoice(null);
  }

  useEffect(() => {
    if (!titleId) return;

    let cancelled = false;

    getJamfPatchTitle(titleId)
      .then((response) => {
        if (!cancelled) setTitle(response);
      })
      .catch(() => {
        if (!cancelled) setError(t.jamfPatch.detail.errorLoading);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [titleId, t, revision]);

  // The chart and the table read one list through one filter, so they cannot disagree
  // about which versions are showing.
  const rows = useMemo(() => (title ? versionRows(title) : []), [title]);
  const hideEmpty = hideEmptyChoice ?? hideEmptyByDefault(rows);
  const shown = useMemo(() => filterVersionRows(rows, hideEmpty), [rows, hideEmpty]);
  const listedShown = shown.visible.filter((row) => row.listed);
  const listedTotal = rows.filter((row) => row.listed).length;
  const unlistedDevices = rows.filter((row) => !row.listed).reduce((sum, row) => sum + row.devices, 0);
  // The Vulnerability column exists only where a corpus answers for this organization. With
  // none there is no column of "not assessed" — one sentence under the table says so (#298).
  const corpusAsOf = title?.corpusAsOf ?? null;
  // And the Policy column only where a rule judges this title: no rule, or an exempt title,
  // is said once in the policy card rather than as a column of "not judged".
  const judged = title?.policy && !title.policy.exempt ? title.policy : null;
  const columns = 3 + (corpusAsOf === null ? 0 : 1) + (judged === null ? 0 : 1);

  return (
    <section className="space-y-6">
      <div>
        <Link to="/devices/applications/jamf-patch" className="text-sm text-muted-foreground hover:underline">
          {t.jamfPatch.detail.back}
        </Link>
      </div>

      {loading && <p className="text-sm text-muted-foreground">{t.jamfPatch.detail.loading}</p>}
      {!loading && error && <p className="text-sm text-destructive">{error}</p>}
      {!loading && !error && !title && <p className="text-sm text-muted-foreground">{t.jamfPatch.detail.notFound}</p>}

      {!loading && !error && title && (
        <>
          <div>
            <p className="text-sm font-medium text-muted-foreground">{t.jamfPatch.eyebrow}</p>
            <h1 className="text-3xl font-bold tracking-tight">{title.name}</h1>
            <p className="mt-1 text-sm text-muted-foreground">
              {title.publisher ?? "—"} · {title.bundleId ?? "—"} · {t.jamfPatch.tableCurrentVersion}:{" "}
              {title.currentVersion}
            </p>
            {/* The same marker the row carried, where the row sent the reader (#478). */}
            <AppNameLine title={title} t={t} className="mt-1 block text-sm text-muted-foreground" />
            <p className="mt-1 text-sm text-muted-foreground">
              {t.jamfPatch.detail.deviceSummary(title.deviceCount, title.devicesOnLatest)}
            </p>
          </div>

          <TitlePolicyCard title={title} onChanged={() => setRevision((current) => current + 1)} />

          {/* The versions come before the catalog's own detail: which versions the fleet is on,
              and which of them the policy and the corpus have something to say about, is what
              the page is opened for. */}
          <div className="space-y-3 rounded-lg border bg-card p-4">
            <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-2">
              <h2 className="text-lg font-semibold">
                {t.jamfPatch.detail.versionsHeading} ({listedTotal})
              </h2>
              <label className="flex items-center gap-2 text-sm" title={t.jamfPatch.detail.hideEmptyHint}>
                <input type="checkbox" checked={hideEmpty} onChange={(e) => setHideEmptyChoice(e.target.checked)} />
                {t.jamfPatch.detail.hideEmpty}
              </label>
            </div>

            <div className="space-y-2">
              <h3 className="text-sm font-medium">{t.jamfPatch.detail.chartTitle}</h3>
              <VersionDevicesChart rows={shown.visible} totalDevices={title.deviceCount} policy={judged} />
            </div>

            <button
              type="button"
              onClick={() => setVersionsExpanded((current) => !current)}
              className="flex w-full items-center gap-2 text-left"
              aria-expanded={versionsExpanded}
            >
              {versionsExpanded ? (
                <ChevronDown className="h-4 w-4 shrink-0 text-muted-foreground" />
              ) : (
                <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground" />
              )}
              <h3 className="text-sm font-medium">{t.jamfPatch.detail.versionsTitle}</h3>
            </button>

            {versionsExpanded && (
              <>
                <div className="overflow-x-auto rounded-lg border bg-card">
                  <table className="w-full text-sm">
                    <thead className="border-b bg-muted/30 text-left text-muted-foreground">
                      <tr>
                        <th className="px-4 py-2 font-medium">{t.jamfPatch.detail.tableVersion}</th>
                        <th className="px-4 py-2 font-medium">{t.jamfPatch.detail.tableReleaseDate}</th>
                        <th className="px-4 py-2 font-medium">{t.jamfPatch.detail.tableDeviceCount}</th>
                        {judged !== null && <th className="px-4 py-2 font-medium">{t.jamfPatch.rules.tablePolicy}</th>}
                        {/* Back, and real this time. #298 deleted a stub that rendered dashes
                            and said a column could not be built at this grain; since #385 a
                            title carries the app name a Mac reports, so every listed version
                            has the content key the corpus is compiled on. Each cell is that
                            build's own answer — never the title's, never the fleet's. */}
                        {corpusAsOf !== null && (
                          <th className="px-4 py-2 font-medium">{t.jamfPatch.detail.tableVulnerability}</th>
                        )}
                      </tr>
                    </thead>
                    <tbody>
                      {listedTotal === 0 && (
                        <tr>
                          <td className="px-4 py-4 text-muted-foreground" colSpan={columns}>
                            {t.jamfPatch.detail.empty}
                          </td>
                        </tr>
                      )}
                      {listedTotal > 0 && listedShown.length === 0 && (
                        <tr>
                          <td className="px-4 py-4 text-muted-foreground" colSpan={columns}>
                            {t.jamfPatch.detail.emptyAllHidden(listedTotal)}
                          </td>
                        </tr>
                      )}
                      {listedShown.map((row) => (
                        <tr key={row.version} className="border-b align-top last:border-0">
                          <td className="px-4 py-2 font-medium">{row.version}</td>
                          <td className="px-4 py-2">
                            {row.releaseDate ? new Date(row.releaseDate).toLocaleDateString() : "—"}
                          </td>
                          <td className="px-4 py-2 tabular-nums">{row.devices}</td>
                          {judged !== null && (
                            <td className="px-4 py-2">
                              <PolicyCell verdict={judged.versions[row.version]} sentence={(verdict) => policySentence(verdict, judged, t)} />
                            </td>
                          )}
                          {corpusAsOf !== null && (
                            <td className="px-4 py-2">
                              {/* A version the answer does not name reads outside the corpus,
                                  dated — never a blank a reader could take for clean. */}
                              <AssessmentCell
                                vuln={title.versionVulns[row.version] ?? { assessment: "unknown_app", corpusAsOf }}
                                t={t}
                              />
                            </td>
                          )}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                <p className="text-sm text-muted-foreground">
                  {t.jamfPatch.detail.versionsShown(listedShown.length, listedTotal)}
                  {listedTotal - listedShown.length > 0 &&
                    ` · ${t.jamfPatch.detail.hiddenWithoutDevices(listedTotal - listedShown.length)}`}
                </p>
                <p className="text-sm text-muted-foreground">
                  {corpusAsOf === null
                    ? t.jamfPatch.detail.vulnerabilityOff
                    : t.jamfPatch.detail.vulnerabilityGrain(formatCorpusDate(corpusAsOf))}
                </p>
              </>
            )}
            {unlistedDevices > 0 && (
              <p className="text-sm text-muted-foreground">{t.jamfPatch.detail.unlistedVersions(unlistedDevices)}</p>
            )}
          </div>

          <div className="space-y-3 rounded-lg border bg-card p-4">
            <h2 className="text-lg font-semibold">{t.jamfPatch.detail.calendarTitle}</h2>
            <p className="text-sm text-muted-foreground">{t.jamfPatch.detail.calendarDescription}</p>
            <ReleaseCalendar patches={title.patches} />
          </div>

          <div className="space-y-3 rounded-lg border bg-card p-4">
            <h2 className="text-lg font-semibold">{t.jamfPatch.detail.requirementsTitle}</h2>
            <p className="text-sm text-muted-foreground">{t.jamfPatch.detail.requirementsDescription}</p>
            <RequirementsSection groups={title.requirements} />
          </div>

          <div className="space-y-3 rounded-lg border bg-card p-4">
            <h2 className="text-lg font-semibold">{t.jamfPatch.detail.testTitle}</h2>
            <p className="text-sm text-muted-foreground">{t.jamfPatch.detail.testDescription}</p>
            <RequirementsTestPanel requirements={title.requirements} />
          </div>

        </>
      )}
    </section>
  );
}
