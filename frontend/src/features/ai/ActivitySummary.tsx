import { useLocale } from "@/i18n/LocaleContext";
import { formats, type ActivityMetrics, type ActivityReport } from "./activity";

function Measured({ value, reports, attempts, timing = false }: { value: number | null; reports: number; attempts: number; timing?: boolean }) {
  const { count, coverage, duration } = formats(useLocale().t.aiActivity);
  return <><span>{timing ? duration(value) : count(value)}</span><span className="block text-xs text-muted-foreground">{coverage(reports, attempts)}</span></>;
}
export function ActivitySummary({ report: r, select }: { report: ActivityReport; select: (key: string, value: string) => void }) {
  const c = useLocale().t.aiActivity, s = c.summary;
  const { count, coverage, duration, stamp } = formats(c);
  const m = r.totals;
  const measuredFrom = r.detailedSince === null ? null : Date.parse(r.detailedSince);
  const workMeasured = measuredFrom !== null && measuredFrom < Date.parse(r.end) + 86_400_000;
  const partialWork = workMeasured && (measuredFrom! > Date.parse(r.start) || r.coverage.legacyAttempts > 0 || !!r.coverage.recordingDegradedSince);
  const cards: { label: string; value: number | null; reports?: number; timing?: boolean }[] = [
    { label: s.attempts, value: m.attempts }, { label: s.dispatches, value: m.dispatches, reports: m.dispatchReports },
    { label: s.useful, value: m.usefulResults, reports: m.usefulReports }, { label: s.failed, value: m.failed },
    { label: s.avgRequest, value: m.avgRequestMs, reports: m.requestReports, timing: true },
    { label: s.avgWait, value: m.avgWaitMs, reports: m.waitReports, timing: true },
  ];
  const maxDay = Math.max(1, ...r.trend.map(day => day.attempts));
  const outcomeLabel = (id: string) => r.facets.outcomes.find(item => item.id === id)?.label ?? id.replaceAll("_", " ");
  const cell = (row: ActivityMetrics, key: "input" | "output" | "cache") => <Measured value={key === "input" ? row.inputTokens : key === "output" ? row.outputTokens : row.cachedTokens}
    reports={key === "input" ? row.inputReports : key === "output" ? row.outputReports : row.cacheReports} attempts={row.attempts} />;
  return <div className="space-y-5">
    {!r.aiEnabled && <p className="rounded-lg border p-3 text-sm">{s.aiDisabled}</p>}
    {r.state === "unavailable" && <p role="alert" className="rounded-lg border p-3 text-sm">{s.incomplete}</p>}
    {r.state === "usage_disabled" ? <p role="status">{s.usageDisabled}</p> : <>
      <dl className="grid grid-cols-2 gap-3 lg:grid-cols-3 xl:grid-cols-6">{cards.map(card => <div key={card.label} className="rounded-lg border bg-card p-4">
        <dt className="text-sm text-muted-foreground">{card.label}</dt><dd className="mt-2 text-2xl font-semibold tabular-nums">{card.timing ? duration(card.value) : count(card.value)}</dd>
        {card.reports !== undefined && <p className="mt-1 text-xs text-muted-foreground">{coverage(card.reports, m.attempts)}</p>}</div>)}</dl>
      <p className="text-xs text-muted-foreground">{s.dispatchNote}</p>
      {r.state === "no_calls" && <p role="status" className="rounded-lg border p-4">{s.noCalls} {r.configuredServices.length ? s.noCallsConfigured : s.noCallsUnconfigured}</p>}
      {r.state === "no_matches" && <p role="status" className="rounded-lg border p-4">{s.noMatches}</p>}
      {(r.state === "ready" || (r.state === "unavailable" && m.attempts > 0)) && <>
        <section className="space-y-3"><h3 className="font-semibold">{s.servicesTitle}</h3>
          <div className="overflow-x-auto rounded-lg border"><table className="w-full text-left text-sm"><thead className="bg-muted/50"><tr>
            {s.serviceColumns.map(label => <th className="p-3" key={label} scope="col">{label}</th>)}
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
          <section className="rounded-lg border p-4"><h3 className="font-semibold">{s.purposesTitle}</h3><ul className="mt-3 space-y-2">{r.purposes.map(purpose => <li key={purpose.feature}>
            <button className="flex w-full items-center justify-between gap-3 rounded px-2 py-2 text-left text-sm hover:bg-muted" onClick={() => select("purpose", purpose.feature)}>
              <span className="underline underline-offset-4">{purpose.label}</span><span className="font-semibold tabular-nums">{s.attemptCount(count(purpose.attempts))}</span>
            </button></li>)}</ul></section>
          <section className="rounded-lg border p-4"><h3 className="font-semibold">{s.trendTitle}</h3><p className="mt-1 text-xs text-muted-foreground">{s.trendHelp}</p>
            <div className="mt-3 flex h-32 items-stretch gap-0.5" role="group" aria-label={s.trendGroup}>{r.trend.map(day => <button key={day.day}
              className="group flex min-w-0 flex-1 flex-col justify-end rounded-sm hover:bg-muted focus-visible:outline-2 focus-visible:outline-primary"
              aria-label={s.day(day.day, count(day.attempts))} title={s.day(day.day, count(day.attempts))}
              onClick={() => select("day", day.day)}><span aria-hidden="true" className="w-full rounded-t-sm bg-primary/75 group-hover:bg-primary"
                style={{ height: `${day.attempts / maxDay * 100}%`, minHeight: day.attempts ? 3 : 0 }} /></button>)}</div>
            <div className="mt-2 flex justify-between text-xs text-muted-foreground"><span>{r.start}</span><span>{s.total(count(m.attempts))}</span><span>{r.end}</span></div>
          </section>
        </div>
      </>}
      <details className="rounded-lg border p-4"><summary className="cursor-pointer font-medium">{s.details}</summary>
        {!workMeasured ? <p className="my-3 text-sm">{s.workUnmeasured}</p> : <>
          <p className="my-3 text-sm">{s.work({ arrivals: count(r.work.arrivals), completed: count(r.work.completed), failed: count(r.work.failed), cached: count(r.work.cached),
            skipped: count(r.work.skipped), expired: count(r.work.expired), retries: count(r.work.retries), fallbacks: count(r.work.fallbacks) })}</p>
          <p className="mb-3 text-xs text-muted-foreground">{s.workTimes}</p>
          {partialWork && <p className="mb-3 text-xs text-muted-foreground">{s.partialWork(stamp(r.detailedSince))}</p>}
        </>}
        <p className="my-3 text-sm">{s.attemptsLine({ answered: count(m.answered), unusable: count(m.unusable), waitingTimeouts: count(m.waitingTimeouts), retries: count(m.retries), fallbacks: count(m.fallbacks) })}</p>
        <dl className="my-4 grid grid-cols-2 gap-4 lg:grid-cols-4">{[
          [s.avgTotal, m.avgTotalMs, m.totalReports, true], [s.avgProvider, m.avgProviderMs, m.providerReports, true],
          [s.inputTokens, m.inputTokens, m.inputReports, false], [s.outputTokens, m.outputTokens, m.outputReports, false],
          [s.cachedTokens, m.cachedTokens, m.cacheReports, false],
        ].map(([label, value, reports, timing]) => <div key={String(label)}><dt className="text-sm font-medium">{label}</dt><dd className="mt-1 text-sm">
          <Measured value={value as number | null} reports={reports as number} attempts={m.attempts} timing={timing as boolean} /></dd></div>)}</dl>
        <p className="mb-3 text-xs text-muted-foreground">{s.durationsNote}</p>
        <div className="overflow-x-auto"><table className="w-full text-left text-xs"><thead><tr>{s.groupColumns.map(label => <th scope="col" className="p-2" key={label}>{label}</th>)}</tr></thead>
          <tbody>{r.groups.map((group, index) => <tr className="border-t" key={index}>
            <td className="p-2">{group.serviceLabel}<br />{group.purpose}{group.legacy && <span className="block">{s.legacy}</span>}</td>
            <td className="p-2 break-all">{group.requested || c.unknown} → {group.reported || c.unknown}</td>
            <td className="p-2">{outcomeLabel(group.outcome)}</td><td className="p-2">{count(group.attempts)}</td>
            <td className="p-2"><Measured value={group.dispatches} reports={group.dispatchReports} attempts={group.attempts} /></td>
            <td className="p-2"><Measured value={group.usefulResults} reports={group.usefulReports} attempts={group.attempts} /></td>
            <td className="space-y-1 p-2"><div>{s.input} {cell(group, "input")}</div><div>{s.output} {cell(group, "output")}</div><div>{s.cached} {cell(group, "cache")}</div></td>
            <td className="space-y-1 p-2"><div>{s.wait} <Measured value={group.avgWaitMs} reports={group.waitReports} attempts={group.attempts} timing /></div>
              <div>{s.request} <Measured value={group.avgRequestMs} reports={group.requestReports} attempts={group.attempts} timing /></div>
              <div>{s.totalTime} <Measured value={group.avgTotalMs} reports={group.totalReports} attempts={group.attempts} timing /></div></td>
          </tr>)}</tbody></table></div>
      </details>
    </>}
    <div className="space-y-1 text-xs text-muted-foreground">
      <p>{s.historyAsOf(stamp(r.asOf), r.firstMeasured ?? c.notMeasured, r.retentionDays)}</p>
      <p>{s.detailed(stamp(r.detailedSince), count(r.coverage.legacyAttempts), count(r.coverage.detailedAttempts))}</p>
      {!!r.coverage.missing.length && <p>{s.coverageLimits} {r.coverage.missing.join(" ")}</p>}
      {r.coverage.recordingDegradedSince && <p role="alert">{s.recordingIncomplete(stamp(r.coverage.recordingDegradedSince))}</p>}
    </div>
  </div>;
}
