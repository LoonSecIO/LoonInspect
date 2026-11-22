import { useEffect, useState } from "react";
import { Link } from "react-router";
import { findingIdIn, findingPath } from "@/features/vulnerabilities/findingId";
import { useHasPermission } from "@/features/auth/store";
import { PERMISSIONS } from "@/features/auth/types";
import { getFleetDetail } from "./detailApi";
import { fleetDetailCopy, type FleetDetailCopy } from "./fleetDetailCopy";
import type { FleetAssessment, FleetBuildAssessment, MigrationDetail } from "./migrationTypes";
import { useLocale } from "@/i18n/LocaleContext";
import { ApiError } from "@/config/api";
import { Button } from "@/components/ui/button";

function Findings({ build, copy, canOpen }: { build: FleetBuildAssessment; copy: FleetDetailCopy; canOpen: boolean }) {
  if (build.comparison === "exact" && build.addresses !== null && build.introduces !== null && build.remains !== null) {
    const groups = [[copy.addressed, build.addressedIds], [copy.introduced, build.introducedIds], [copy.remaining, build.remainingIds]] as const;
    return <><span>{copy.exactDelta(build.addresses, build.introduces, build.remains)}</span>
      {groups.some(([, ids]) => ids?.length) && <details className="mt-1">
        <summary className="cursor-pointer text-sm font-medium">{copy.proof}</summary>
        <dl className="max-h-56 space-y-2 overflow-y-auto py-2">{groups.map(([label, ids]) => ids && ids.length > 0 && (
          <div key={label}><dt className="text-xs font-medium">{label}</dt>
            <dd className="flex flex-wrap gap-x-3 gap-y-1">{ids.map(id => canOpen && findingIdIn(id)
              ? <Link key={id} className="font-mono text-xs text-primary underline" to={findingPath(id)}>{id}</Link>
              : <span key={id} className="font-mono text-xs">{id}</span>)}</dd>
          </div>
        ))}</dl>
      </details>}
    </>;
  }
  if (build.comparison === "net_only" && build.net !== null) {
    return <><span>{copy.netDelta(build.net)}</span><small className="block text-muted-foreground">{copy.capped}</small></>;
  }
  if (build.comparison === "ambiguous") return <span>{copy.ambiguousBuild}</span>;
  if (build.comparison === "off" || build.comparison === "unknown_source" || build.comparison === "unknown_target") {
    return <span>{copy[build.comparison]}</span>;
  }
  return <span>{copy.noEvidence}</span>;
}

export function BuildEvidence({ assessment }: { assessment?: FleetAssessment }) {
  const { locale } = useLocale();
  const c = fleetDetailCopy[locale];
  const canOpen = useHasPermission(PERMISSIONS.VULN_READ);
  return (
    <section className="space-y-3 rounded-xl border bg-card p-5">
      <h3 className="text-lg font-semibold">{c.findings}</h3>
      <p className="text-xs text-muted-foreground">{c.scanner}</p>
      {!assessment ? <p className="text-sm text-muted-foreground">{c.noEvidence}</p> : <>
        <div className="space-y-2"><h4 className="text-sm font-medium">{c.allPolicy}</h4>
          <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">{([
            [c.within, assessment.withinPolicyBuilds], [c.out, assessment.outOfPolicyBuilds],
            [c.exempt, assessment.policyExemptBuilds], [c.unassessed, assessment.policyUnassessedBuilds]
          ] as const).map(([label, value]) => <div key={label}><dt className="text-xs text-muted-foreground">{label}</dt><dd className="font-semibold tabular-nums">{value}</dd></div>)}</dl>
        </div>
        <p className="text-sm text-muted-foreground">{assessment.corpusAsOf
          ? `${c.corpus} ${assessment.corpusAsOf} · ${c.findingScope}` : c.corpusOff}</p>
        {assessment.builds.length ? <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="border-b text-xs text-muted-foreground"><tr>
              <th scope="col" className="p-2">{c.version}</th><th scope="col" className="p-2">{c.count}</th>
              <th scope="col" className="p-2">{c.risk}</th><th scope="col" className="p-2">{c.policy}</th>
            </tr></thead>
            <tbody>{assessment.builds.map((build, index) => <tr key={`${build.name}:${build.version}:${index}`} className="border-b align-top last:border-0">
              <td className="p-2"><strong>{build.version}</strong><small className="block text-muted-foreground">{build.name}</small></td>
              <td className="p-2 tabular-nums">{build.deviceCount}</td>
              <td className="p-2"><Findings build={build} copy={c} canOpen={canOpen}/>
                {build.installedKev !== null && build.installedKev > 0 && <small className="block font-medium">{c.kev(build.installedKev)}</small>}
              </td>
              <td className="p-2"><span className="font-medium">{c[build.policyState]}</span>
                {build.policySource && <small className="block text-muted-foreground">{build.policySource === "override" ? c.overrideRule : c.defaultRule}</small>}
                <small className="block text-muted-foreground">{build.policyReason}</small>
                {build.policyDueAt && <small className="block">{c.due} {new Date(build.policyDueAt).toLocaleDateString(locale)}</small>}
              </td>
            </tr>)}</tbody>
          </table>
        </div> : <p className="text-sm text-muted-foreground">{assessment.behindBuilds || assessment.unorderedBuilds ? c.noEvidence : c.noOlder}</p>}
      </>}
    </section>
  );
}

interface ComparisonProps {
  kind: "apps" | "titles";
  id: string;
  slug: string;
  scope: string;
  version: string;
  latest: string;
  initial: MigrationDetail;
  onReset: () => void;
}

/** This component is keyed by target and scope so the last target's results never label the next one. */
export function FleetTargetComparison({ kind, id, slug, scope, version, latest, initial, onReset }: ComparisonProps) {
  const { locale } = useLocale();
  const c = fleetDetailCopy[locale];
  const [historical, setHistorical] = useState<MigrationDetail | null>(null);
  const reply = version === latest ? initial : historical;
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    if (version === latest) return;
    let active = true;
    getFleetDetail(kind, id, scope, version).then(value => {
      if (active) setHistorical(value);
    }).catch((cause: unknown) => {
      if (active) setError(cause instanceof ApiError && cause.detail ? cause.detail : c.impactError);
    });
    return () => { active = false; };
  }, [kind, id, scope, version, latest, attempt, c]);
  const assessment = kind === "apps" ? reply?.appAssessments[id] : reply?.assessments[slug];
  const impact = reply?.impact;
  return (
    <div className="space-y-4">
      <section className="space-y-3 rounded-xl border bg-card p-5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="text-lg font-semibold">{c.impact}</h3>
          <span className="rounded-md border bg-muted px-2 py-1 font-mono text-sm">{c.target} {version}</span>
        </div>
        {version !== latest && <Button variant="outline" size="sm" onClick={onReset}>{c.resetTarget}</Button>}
        {error ? <div role="alert" className="space-y-2 text-sm text-destructive"><p>{error}</p><Button variant="outline" size="sm" onClick={() => { setError(null); setAttempt(n => n + 1); }}>{c.retry}</Button></div>
          : !reply ? <p role="status" className="text-sm text-muted-foreground">{c.fetchImpact}</p>
          : !impact ? <p className="text-sm text-muted-foreground">{c.noImpact}</p>
          : <dl className="grid grid-cols-2 gap-3 border-t pt-3 sm:grid-cols-4">
              {([[c.installedScope, impact.installedMacs], [c.older, impact.olderMacs], [c.atOrAbove, impact.atOrAboveMacs], [c.unknown, impact.unknownMacs]] as const).map(([label, value]) => (
                <div key={label}><dt className="text-xs text-muted-foreground">{label}</dt><dd className="text-2xl font-semibold tabular-nums">{value}</dd></div>
              ))}
            </dl>}
        <p className="text-xs text-muted-foreground">{c.chooseFromHistory} {version !== latest && (
          locale === "de" ? "Prüfen Sie vor einer Versionsbindung die Verfügbarkeit unter Fleet → Actions → Versions."
            : "Before pinning this version, check its availability under Fleet → Actions → Versions."
        )}</p>
      </section>
      {reply && <BuildEvidence assessment={assessment?.targetVersion === version ? assessment : undefined}/>}
    </div>
  );
}
