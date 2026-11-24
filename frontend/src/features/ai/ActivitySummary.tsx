import { count, coverage, duration, stamp, type ActivityMetrics, type ActivityReport } from "./activity";

function Measured({ value, reports, attempts, timing = false }: { value: number | null; reports: number; attempts: number; timing?: boolean }) {
  return <><span>{timing ? duration(value) : count(value)}</span><span className="block text-xs text-muted-foreground">{coverage(reports, attempts)}</span></>;
}
export function ActivitySummary({ report: r, select }: { report: ActivityReport; select: (key: string, value: string) => void }) {
  const m = r.totals;
  const measuredFrom = r.detailedSince === null ? null : Date.parse(r.detailedSince);
  const workMeasured = measuredFrom !== null && measuredFrom < Date.parse(r.end) + 86_400_000;
  const partialWork = workMeasured && (measuredFrom! > Date.parse(r.start) || r.coverage.legacyAttempts > 0 || !!r.coverage.recordingDegradedSince);
  const cards: { label: string; value: number | null; reports?: number; timing?: boolean }[] = [
    { label: "Inference attempts", value: m.attempts }, { label: "Provider dispatches", value: m.dispatches, reports: m.dispatchReports },
    { label: "Useful results", value: m.usefulResults, reports: m.usefulReports }, { label: "Failed attempts", value: m.failed },
    { label: "Average request time", value: m.avgRequestMs, reports: m.requestReports, timing: true },
    { label: "Average local wait", value: m.avgWaitMs, reports: m.waitReports, timing: true },
  ];
  const maxDay = Math.max(1, ...r.trend.map(day => day.attempts));
  const outcomeLabel = (id: string) => r.facets.outcomes.find(item => item.id === id)?.label ?? id.replaceAll("_", " ");
  const cell = (row: ActivityMetrics, key: "input" | "output" | "cache") => <Measured value={key === "input" ? row.inputTokens : key === "output" ? row.outputTokens : row.cachedTokens}
    reports={key === "input" ? row.inputReports : key === "output" ? row.outputReports : row.cacheReports} attempts={row.attempts} />;
  return <div className="space-y-5">
    {!r.aiEnabled && <p className="rounded-lg border p-3 text-sm">AI inference is disabled. Retained historical measurements remain readable.</p>}
    {r.state === "unavailable" && <p role="alert" className="rounded-lg border p-3 text-sm">Measurement is incomplete. Recorded calls are shown below, but missing writes mean these totals cannot establish usage or health. Check application diagnostics.</p>}
    {r.state === "usage_disabled" ? <p role="status">Usage measurement is disabled. Counts are unavailable; check AI settings.</p> : <>
      <dl className="grid grid-cols-2 gap-3 lg:grid-cols-3 xl:grid-cols-6">{cards.map(card => <div key={card.label} className="rounded-lg border bg-card p-4">
        <dt className="text-sm text-muted-foreground">{card.label}</dt><dd className="mt-2 text-2xl font-semibold tabular-nums">{card.timing ? duration(card.value) : count(card.value)}</dd>
        {card.reports !== undefined && <p className="mt-1 text-xs text-muted-foreground">{coverage(card.reports, m.attempts)}</p>}</div>)}</dl>
      <p className="text-xs text-muted-foreground">An attempt can fail while waiting before dispatch. Dispatch means handed to the HTTP transport; it does not confirm receipt by the provider. Useful results were accepted by the requesting feature; a provider answer alone is not proof of useful work. Missing measurements are unknown, not zero.</p>
      {r.state === "no_calls" && <p role="status" className="rounded-lg border p-4">No inference attempts were recorded in this period. {r.configuredServices.length ? "Check the range or use a configured AI feature." : "No AI service is configured; open Provider setup to configure one."}</p>}
      {r.state === "no_matches" && <p role="status" className="rounded-lg border p-4">No attempts match these filters. Clear a filter or choose another period.</p>}
      {(r.state === "ready" || (r.state === "unavailable" && m.attempts > 0)) && <>
        <section className="space-y-3"><h3 className="font-semibold">Which services handled the calls?</h3>
          <div className="overflow-x-auto rounded-lg border"><table className="w-full text-left text-sm"><thead className="bg-muted/50"><tr>
            {["Service at call time", "Attempts / share", "Useful results", "Input tokens", "Output tokens", "Average request"].map(label => <th className="p-3" key={label} scope="col">{label}</th>)}
          </tr></thead><tbody>{r.services.map(service => <tr className="border-t" key={service.serviceId}>
            <th className="p-3 font-normal" scope="row"><button className="text-left font-medium underline underline-offset-4" onClick={() => select("service", service.serviceId)}>{service.serviceLabel}</button>
              <span className="block text-xs text-muted-foreground">{service.serviceKind.replaceAll("_", " ")}</span></th>
            <td className="p-3 tabular-nums">{count(service.attempts)} · {m.attempts ? (service.attempts / m.attempts * 100).toFixed(1) : "0"}%</td>
            <td className="p-3"><Measured value={service.usefulResults} reports={service.usefulReports} attempts={service.attempts} /></td>
            <td className="p-3">{cell(service, "input")}</td><td className="p-3">{cell(service, "output")}</td>
            <td className="p-3"><Measured value={service.avgRequestMs} reports={service.requestReports} attempts={service.attempts} timing /></td>
          </tr>)}</tbody></table></div>
        </section>
        <div className="grid gap-5 lg:grid-cols-2">
          <section className="rounded-lg border p-4"><h3 className="font-semibold">What is it doing?</h3><ul className="mt-3 space-y-2">{r.purposes.map(purpose => <li key={purpose.feature}>
            <button className="flex w-full items-center justify-between gap-3 rounded px-2 py-2 text-left text-sm hover:bg-muted" onClick={() => select("purpose", purpose.feature)}>
              <span className="underline underline-offset-4">{purpose.label}</span><span className="font-semibold tabular-nums">{count(purpose.attempts)} attempts</span>
            </button></li>)}</ul></section>
          <section className="rounded-lg border p-4"><h3 className="font-semibold">Calls over time</h3><p className="mt-1 text-xs text-muted-foreground">Finalized inference attempts by UTC day · select a day to inspect.</p>
            <div className="mt-3 flex h-32 items-stretch gap-0.5" role="group" aria-label="Daily inference attempts">{r.trend.map(day => <button key={day.day}
              className="group flex min-w-0 flex-1 flex-col justify-end rounded-sm hover:bg-muted focus-visible:outline-2 focus-visible:outline-primary"
              aria-label={`${day.day}: ${count(day.attempts)} attempts`} title={`${day.day}: ${count(day.attempts)} attempts`}
              onClick={() => select("day", day.day)}><span aria-hidden="true" className="w-full rounded-t-sm bg-primary/75 group-hover:bg-primary"
                style={{ height: `${day.attempts / maxDay * 100}%`, minHeight: day.attempts ? 3 : 0 }} /></button>)}</div>
            <div className="mt-2 flex justify-between text-xs text-muted-foreground"><span>{r.start}</span><span>{count(m.attempts)} total</span><span>{r.end}</span></div>
          </section>
        </div>
      </>}
      <details className="rounded-lg border p-4"><summary className="cursor-pointer font-medium">Work, timing, token coverage and model details</summary>
        {!workMeasured ? <p className="my-3 text-sm">Logical work was not measured in this period. Arrivals, completions, cache hits and skips are unknown; daily attempt totals cannot reconstruct them.</p> : <>
          <p className="my-3 text-sm">Measured logical work: {count(r.work.arrivals)} arrivals · {count(r.work.completed)} useful completions · {count(r.work.failed)} failures · {count(r.work.cached)} cache hits · {count(r.work.skipped)} skipped · {count(r.work.expired)} expired · {count(r.work.retries)} retries · {count(r.work.fallbacks)} fallbacks. These are work events, not additional inference calls. A cache hit does not dispatch inference.</p>
          <p className="mb-3 text-xs text-muted-foreground">Arrivals use arrival time; terminal outcomes use completion time. A job may arrive before this period and finish inside it.</p>
          {partialWork && <p className="mb-3 text-xs text-muted-foreground">Work counts cover only recorded lifecycle events. Measurement began {stamp(r.detailedSince)}; legacy records and recording gaps cannot establish missing work.</p>}
        </>}
        <p className="my-3 text-sm">Attempts: {count(m.answered)} answered · {count(m.unusable)} unusable · {count(m.waitingTimeouts)} waiting timeouts · {count(m.retries)} retries · {count(m.fallbacks)} fallbacks.</p>
        <dl className="my-4 grid grid-cols-2 gap-4 lg:grid-cols-4">{[
          ["Average total elapsed", m.avgTotalMs, m.totalReports, true], ["Average provider-reported execution", m.avgProviderMs, m.providerReports, true],
          ["Input tokens", m.inputTokens, m.inputReports, false], ["Output tokens", m.outputTokens, m.outputReports, false],
          ["Cached tokens", m.cachedTokens, m.cacheReports, false],
        ].map(([label, value, reports, timing]) => <div key={String(label)}><dt className="text-sm font-medium">{label}</dt><dd className="mt-1 text-sm">
          <Measured value={value as number | null} reports={reports as number} attempts={m.attempts} timing={timing as boolean} /></dd></div>)}</dl>
        <p className="mb-3 text-xs text-muted-foreground">Durations are averages of measured attempts, with separate coverage. Provider execution is reported by the provider. Tokens are reported usage, not a billing estimate.</p>
        <div className="overflow-x-auto"><table className="w-full text-left text-xs"><thead><tr>{["Service / purpose", "Requested → reported model", "Outcome", "Attempts", "Dispatched", "Useful", "Input / output / cached tokens", "Average wait / request / total"].map(label => <th scope="col" className="p-2" key={label}>{label}</th>)}</tr></thead>
          <tbody>{r.groups.map((group, index) => <tr className="border-t" key={index}>
            <td className="p-2">{group.serviceLabel}<br />{group.purpose}{group.legacy && <span className="block">Legacy measurement</span>}</td>
            <td className="p-2 break-all">{group.requested || "Unknown"} → {group.reported || "Unknown"}</td>
            <td className="p-2">{outcomeLabel(group.outcome)}</td><td className="p-2">{count(group.attempts)}</td>
            <td className="p-2"><Measured value={group.dispatches} reports={group.dispatchReports} attempts={group.attempts} /></td>
            <td className="p-2"><Measured value={group.usefulResults} reports={group.usefulReports} attempts={group.attempts} /></td>
            <td className="space-y-1 p-2"><div>Input: {cell(group, "input")}</div><div>Output: {cell(group, "output")}</div><div>Cached: {cell(group, "cache")}</div></td>
            <td className="space-y-1 p-2"><div>Wait: <Measured value={group.avgWaitMs} reports={group.waitReports} attempts={group.attempts} timing /></div>
              <div>Request: <Measured value={group.avgRequestMs} reports={group.requestReports} attempts={group.attempts} timing /></div>
              <div>Total: <Measured value={group.avgTotalMs} reports={group.totalReports} attempts={group.attempts} timing /></div></td>
          </tr>)}</tbody></table></div>
      </details>
    </>}
    <div className="space-y-1 text-xs text-muted-foreground">
      <p>History as of {stamp(r.asOf)} · first retained daily measurement {r.firstMeasured ?? "Not yet measured"} · {r.retentionDays} days retained.</p>
      <p>Detailed measurement began {stamp(r.detailedSince)}. {count(r.coverage.legacyAttempts)} legacy attempts; {count(r.coverage.detailedAttempts)} detailed attempts. Historical service labels stay as recorded; a provider configuration change does not rewrite them.</p>
      {!!r.coverage.missing.length && <p>Coverage limits: {r.coverage.missing.join(" ")}</p>}
      {r.coverage.recordingDegradedSince && <p role="alert">Recording has been incomplete since {stamp(r.coverage.recordingDegradedSince)}. Totals may omit calls; check application diagnostics.</p>}
    </div>
  </div>;
}
