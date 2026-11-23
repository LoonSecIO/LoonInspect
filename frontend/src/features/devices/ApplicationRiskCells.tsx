import type { Application } from "./applicationsApi";

const colors = { critical: "bg-red-600", high: "bg-orange-500", medium: "bg-amber-400", low: "bg-sky-500" };
const bands = ["critical", "high", "medium", "low"] as const;
export function ApplicationRiskCells({ app }: { app: Application }) {
  const risk = app.vulnerabilities;
  if (!risk || risk.counts === null) return <>
    <td className="px-4 py-3 text-muted-foreground">{!risk || risk.assessment === "off" ? "Not assessed" : "Unknown"}</td>
    <td className="px-4 py-3 text-right text-muted-foreground">—</td>
    <td className="px-4 py-3 text-right text-muted-foreground">—</td>
  </>;
  return <>
    <td className="px-4 py-3"><div className="flex flex-wrap gap-1.5">
      {bands.filter(band => risk.counts![band] > 0).map(band => <span key={band} className="inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-xs" title={`${risk.counts![band].toLocaleString()} ${band} findings`}>
        <span className={`h-1.5 w-1.5 rounded-full ${colors[band]}`} />{band} {risk.counts![band].toLocaleString()}
      </span>)}
      {risk.counts.kev > 0 && <span className="rounded border border-red-300 px-1.5 py-0.5 text-xs font-medium text-red-700 dark:text-red-300">KEV {risk.counts.kev.toLocaleString()}</span>}
      {risk.counts.total === 0 && <span className="text-muted-foreground">No known findings</span>}
    </div><p className="mt-1 text-xs text-muted-foreground">{risk.assessedDeviceCount.toLocaleString()}/{app.deviceCount.toLocaleString()} devices assessed{risk.assessment === "partial" ? " · partial coverage" : ""}</p></td>
    <td className="px-4 py-3 text-right font-medium tabular-nums">{risk.counts.total.toLocaleString()}</td>
    <td className="px-4 py-3 text-right tabular-nums" title="Known findings divided by distinct devices with at least one assessed build. Unassessed builds contribute no zeroes.">
      {risk.averagePerAssessedDevice?.toLocaleString(undefined, { maximumFractionDigits: 2, minimumFractionDigits: 1 }) ?? "—"}
    </td>
  </>;
}
