import { useEffect, useState } from "react";
import { Link } from "react-router";
import { Button } from "@/components/ui/button";
import { ApiError } from "@/config/api";
import { installedAppsPath } from "@/features/catalog/patchPlanNavigation";
import { getFleetDetail } from "@/features/fleetCatalog/api";
import type { FleetAssessment, FleetBuildAssessment, MigrationDetail } from "@/features/fleetCatalog/migrationTypes";
import { policySentence } from "@/features/jamfPatch/policyRules";
import { findingIdIn, findingPath } from "@/features/vulnerabilities/findingId";
import { useLocale } from "@/i18n/LocaleContext";

const card = "space-y-3 rounded-xl border bg-card p-5 text-sm", label = "text-xs text-muted-foreground";
const link = "font-medium text-primary underline decoration-primary/40 underline-offset-4 hover:decoration-primary";

/** One target's answer: the page's own for Fleet's latest, else the reply for the version a history row's Compare chose. */
type TargetAnswer = Pick<MigrationDetail, "impact" | "impactUnavailable"> & { assessment?: FleetAssessment };

/** What the target changes on one build, worded for every #897 `comparison`. An exact count opens its IDs, which the server sends
 *  only for `vuln:read` (`include_ids`), so each it sends links to its own page. A null count reads "—", never 0. */
function Findings({ build }: { build: FleetBuildAssessment }) {
  const { t, locale } = useLocale();
  const words = t.fleetDetail, n = (value: number | null) => value === null ? "—" : value.toLocaleString(locale);
  const groups = [[words.addressed, build.addressedIds], [words.introduced, build.introducedIds], [words.remaining, build.remainingIds]] as const;
  switch (build.comparison) {
    case "exact": return <>{words.exactDelta(n(build.addresses), n(build.introduces), n(build.remains))}
      {groups.some(([, ids]) => ids?.length) && <details className="mt-1"><summary className="cursor-pointer font-medium">{words.proof}</summary>
        <dl className="max-h-56 space-y-2 overflow-y-auto py-2">{groups.map(([name, ids]) => ids?.length ? <div key={name}><dt className={label}>{name}</dt>
          <dd className="flex flex-wrap gap-x-3 gap-y-1 font-mono text-xs">{ids.map(id => findingIdIn(id)
            ? <Link key={id} className={link} to={findingPath(id)}>{id}</Link> : <span key={id}>{id}</span>)}</dd></div> : null)}</dl></details>}</>;
    case "net_only": return build.net === null ? "—" : <>{words.netDelta(build.net, n(Math.abs(build.net)))}<small className={`block ${label}`}>{words.capped}</small></>;
    case "ambiguous": return words.ambiguousBuild;
    default: return words[build.comparison];
  }
}

/** A build's patch-rule verdict in the Jamf Patch title page's words, picked by code (no sentence comes from the server), its rule
 *  linked to that page, and its due date: never under the releases limit, where the days limit's date can still be ahead (#914). */
function PolicyCell({ build }: { build: FleetBuildAssessment }) {
  const { t, locale } = useLocale();
  const words = t.fleetDetail, rules = t.jamfPatch.rules, { policyVerdict: verdict, policyRule: rule, policyTitleId: title } = build;
  const unjudged = { identity: words.policyIdentity, no_jamf_title: words.policyNoTitle, no_rule: rules.titleNone, not_judged: rules.verdictNotJudged };
  return <><p>{verdict && rule ? policySentence(verdict, rule, t, locale) : build.policyState === "exempt" ? rules.titleExempt : unjudged[build.policyUnassessed ?? "not_judged"]}</p>
    {build.policySource && title && <Link className={`block text-xs ${link}`} to={`${installedAppsPath}/jamf-patch/${encodeURIComponent(title)}`}>
      {build.policySource === "override" ? words.overrideRule : words.defaultRule}</Link>}
    {build.policyDueAt && verdict?.reason !== "releases" && <small className="block">{words.due(new Date(build.policyDueAt).toLocaleDateString(locale))}</small>}</>;
}

/** **Vulnerability and policy evidence**: the patch-rule counts over every installed build, then one row per build older than the
 *  target. Outside the panel it carries the page's #899 reason, since the panel says its own once. A build whose version cannot
 *  be ordered against the target is counted under the table, never dropped. */
export function BuildEvidence({ assessment, reason }: { assessment?: FleetAssessment; reason?: string | null }) {
  const { t, locale } = useLocale();
  const words = t.fleetDetail, n = (value: number) => value.toLocaleString(locale);
  const builds = assessment?.builds ?? [], unordered = assessment?.unorderedBuilds ?? 0, named = new Set(builds.map(build => build.name)).size > 1;
  return <section className={card}><h3 className="text-lg font-semibold">{words.findings}</h3><p className={label}>{words.scanner}</p>
    {reason && <p>{reason}</p>}
    {assessment && <>
      <h4 className="font-medium">{words.allPolicy}</h4>
      <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">{([[t.jamfPatch.rules.legendWithin, assessment.withinPolicyBuilds], [t.jamfPatch.rules.legendOut, assessment.outOfPolicyBuilds],
        [words.exempt, assessment.policyExemptBuilds], [words.unassessed, assessment.policyUnassessedBuilds]] as const).map(([name, value]) =>
        <div key={name}><dt className={label}>{name}</dt><dd className="font-semibold tabular-nums">{n(value)}</dd></div>)}</dl>
      <p className="text-muted-foreground">{assessment.corpusAsOf ? t.vulnerabilities.corpusHeading(new Date(assessment.corpusAsOf).toLocaleDateString(locale, { timeZone: "UTC" }))
        : t.vulnerabilities.corpusHeadingNone} · {words.findingScope}</p>
      {builds.length > 0 && <div className="overflow-x-auto"><table className="w-full text-left"><thead className={`border-b ${label}`}><tr>
        {[words.version, words.count, words.risk, t.fleetPlanning.columns.policy].map(name => <th key={name} scope="col" className="p-2">{name}</th>)}</tr></thead>
        <tbody>{builds.map((build, index) => <tr key={`${build.name}:${build.version}:${index}`} className="border-b align-top last:border-0">
          <td className="break-all p-2"><strong>{build.version}</strong>{named && <small className={`block ${label}`}>{build.name}</small>}</td>
          <td className="p-2 tabular-nums">{n(build.deviceCount)}</td>
          <td className="p-2"><Findings build={build} />{build.installedKev !== null && build.installedKev > 0 && <small className="block font-medium">{words.kev(n(build.installedKev))}</small>}</td>
          <td className="p-2"><PolicyCell build={build} /></td></tr>)}</tbody></table></div>}
      {unordered > 0 ? <p className="text-muted-foreground">{words.unordered(n(unordered), unordered === 1, assessment.targetVersion)}</p>
        : !builds.length && <p className="text-muted-foreground">{words.noOlder}</p>}
    </>}
  </section>;
}

/** **Compare a target version**: the selected Macs against one Fleet version, then that version's evidence. Keyed by target, so one
 *  target's rows never label the next. Fleet's latest is the page's own answer (`initial`, `latestAssessment`), with no request; an
 *  earlier version asks #899's route on the page's device filter, aborted when the target changes or the page goes. A refusal shows
 *  its sentence as sent, and the flag's 409 main's, as the page's own read does. */
export function FleetTargetComparison({ kind, id, slug, scope, version, latest, initial, latestAssessment, onReset }: { kind: "apps" | "titles"; id: string;
  slug: string; scope: string; version: string; latest: string; initial: TargetAnswer; latestAssessment?: FleetAssessment; onReset: () => void }) {
  const { t, locale } = useLocale();
  const words = t.fleetDetail, n = (value: number) => value.toLocaleString(locale);
  const [fetched, setFetched] = useState<TargetAnswer | null>(null);
  const [failed, setFailed] = useState<{ status: number; detail: string | null } | null>(null);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    if (version === latest) return;
    const controller = new AbortController();
    getFleetDetail(kind, id, scope, version, controller.signal)
      .then(reply => { if (!controller.signal.aborted) setFetched({ ...reply, assessment: kind === "apps" ? reply.appAssessments[id] : reply.assessments[slug] }); })
      .catch((caught: unknown) => { if (!controller.signal.aborted) setFailed(caught instanceof ApiError ? caught : { status: 0, detail: null }); });
    return () => controller.abort();
  }, [kind, id, slug, scope, version, latest, attempt]);
  const answer = version === latest ? { ...initial, assessment: latestAssessment } : fetched, impact = answer?.impact;
  return <>
    <section className={card}>
      <div className="flex flex-wrap items-center justify-between gap-2"><h3 className="text-lg font-semibold">{words.impact}</h3>
        <span className="break-all rounded-md border bg-muted px-2 py-1 font-mono">{words.target} {version}</span></div>
      {version !== latest && <Button size="sm" variant="outline" onClick={onReset}>{words.resetTarget}</Button>}
      {failed ? <div role="alert" className="space-y-2"><p className="font-medium">{words.impactError}</p><p>{failed.status === 409 ? t.fleetCatalog.emptyFlagOff : failed.detail ?? words.impactNoReason}</p>
        <Button size="sm" variant="outline" onClick={() => { setFailed(null); setAttempt(k => k + 1); }}>{words.retry}</Button></div>
        : !answer ? <p role="status" className="text-muted-foreground">{words.fetchImpact}</p>
        : impact ? <dl className="grid grid-cols-2 gap-3 border-t pt-3 sm:grid-cols-4">{([[words.installedScope, impact.installedMacs], [words.older, impact.olderMacs],
          [words.atOrAbove, impact.atOrAboveMacs], [words.unknown, impact.unknownMacs]] as const).map(([name, value]) =>
          <div key={name}><dt className={label}>{name}</dt><dd className="text-2xl font-semibold tabular-nums">{n(value)}</dd></div>)}</dl>
        : answer.impactUnavailable && <p>{words.impactUnavailable(answer.impactUnavailable, version)}</p>}
      <p className={label}>{words.chooseFromHistory}{version !== latest && ` ${words.pinCheck}`}</p>
    </section>
    {answer?.assessment && <BuildEvidence assessment={answer.assessment} />}
  </>;
}
