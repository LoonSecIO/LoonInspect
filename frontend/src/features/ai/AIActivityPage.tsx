import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { Button } from "@/components/ui/button";
import { useLocale } from "@/i18n/LocaleContext";
import { ActivitySummary } from "./ActivitySummary";
import { LiveActivityPanel } from "./LiveActivityPanel";
import { activityQuery, filterKeys, getActivity, rangeError, readFailure, utcDay, type ActivityReport } from "./activity";

function Filter({ label, value, options, onChange }: {
  label: string; value: string; options: { id: string; label: string }[]; onChange: (value: string) => void;
}) {
  const h = useLocale().t.aiActivity.history;
  return <label className="grid gap-1 text-sm"><span>{label}</span><select className="min-w-0 rounded-md border bg-background px-2 py-2"
    value={value} onChange={event => onChange(event.target.value)}>
    <option value="">{h.all}</option>{value && !options.some(option => option.id === value) && <option value={value}>{h.outside(value)}</option>}
    {options.map(option => <option value={option.id} key={option.id}>{option.label}</option>)}
  </select></label>;
}

export function AIActivityPage() {
  const c = useLocale().t.aiActivity, h = c.history;
  const [params, setParams] = useSearchParams();
  const query = activityQuery(params);
  const queryString = query.toString();
  const start = query.get("start")!, end = query.get("end")!;
  const invalid = rangeError(start, end, c);
  const [refresh, setRefresh] = useState(0);
  const key = `${queryString}:${refresh}`;
  const [reading, setReading] = useState<{ key: string; data?: ActivityReport; error?: { reason: unknown } }>({ key });
  if (reading.key !== key) setReading({ key });
  useEffect(() => {
    if (invalid) return;
    const controller = new AbortController();
    getActivity(queryString, controller.signal).then(data => {
      if (!controller.signal.aborted) setReading({ key, data });
    }).catch(error => {
      if (!controller.signal.aborted) setReading({ key, error: { reason: error } });
    });
    return () => controller.abort();
  }, [queryString, key, invalid]);
  function select(name: string, value: string) {
    const next = new URLSearchParams(query);
    if (name === "day") { next.set("start", value); next.set("end", value); }
    else if (value) next.set(name, value); else next.delete(name);
    setParams(next);
  }
  function period(days: number) {
    const next = new URLSearchParams(query); next.set("start", utcDay(1 - days)); next.set("end", utcDay()); setParams(next);
  }
  const report = reading.key === key ? reading.data : undefined;
  return <div className="space-y-6">
    <header className="flex flex-wrap items-start justify-between gap-3"><div><h1 className="text-3xl font-bold tracking-tight">{c.title}</h1>
      <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{c.intro}</p></div>
      <Link to="/settings/ai" className="text-sm font-medium underline underline-offset-4">{c.providerSetup}</Link></header>
    <LiveActivityPanel />
    <section aria-labelledby="ai-history-title" className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3"><div><h2 id="ai-history-title" className="text-lg font-semibold">{h.title}</h2>
        <p className="text-sm text-muted-foreground">{h.intro}</p></div>
        <Button variant="outline" size="sm" disabled={!!invalid} onClick={() => setRefresh(value => value + 1)}>{h.refresh}</Button></div>
      <div className="space-y-3 rounded-lg border bg-card p-4">
        <div className="flex flex-wrap items-end gap-3">
          <div className="flex gap-1" role="group" aria-label={h.period}>{[7, 30, 90].map(days => <Button size="sm" key={days}
            variant={start === utcDay(1 - days) && end === utcDay() ? "default" : "outline"} onClick={() => period(days)}>{h.days(days)}</Button>)}</div>
          <label className="grid gap-1 text-sm">{h.from}<input className="rounded-md border bg-background px-2 py-1.5" type="date" value={start} max={end}
            onChange={event => select("start", event.target.value)} /></label>
          <label className="grid gap-1 text-sm">{h.through}<input className="rounded-md border bg-background px-2 py-1.5" type="date" value={end} min={start} max={utcDay()}
            onChange={event => select("end", event.target.value)} /></label>
          {filterKeys.some(name => query.has(name)) && <Button size="sm" variant="ghost" onClick={() => {
            const next = new URLSearchParams(query); filterKeys.forEach(name => next.delete(name)); setParams(next);
          }}>{h.clearFilters}</Button>}
        </div>
        <details open={filterKeys.some(name => query.has(name))}><summary className="cursor-pointer text-sm font-medium">{h.filters}</summary>
        <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <Filter label={h.service} value={query.get("service") ?? ""} options={(report?.facets.services ?? []).map(service => ({ id: service.serviceId, label: service.serviceLabel }))} onChange={value => select("service", value)} />
          <Filter label={h.purpose} value={query.get("purpose") ?? ""} options={(report?.facets.purposes ?? []).map(p => ({ id: p.id, label: c.purposeLabel(p.label) }))} onChange={value => select("purpose", value)} />
          <Filter label={h.model} value={query.get("model") ?? ""} options={(report?.facets.models ?? []).map(model => ({ id: model, label: model }))} onChange={value => select("model", value)} />
          <Filter label={h.outcome} value={query.get("outcome") ?? ""} options={report?.facets.outcomes ?? []} onChange={value => select("outcome", value)} />
        </div>
        <details open={!!query.get("provider")} className="text-sm"><summary className="cursor-pointer text-muted-foreground">{h.protocolFilter}</summary>
          <div className="mt-2 max-w-sm"><Filter label={h.protocol} value={query.get("provider") ?? ""} options={[
            { id: "apple_fm", label: h.protocols.apple_fm }, { id: "openai_compatible", label: h.protocols.openai_compatible }, { id: "anthropic", label: h.protocols.anthropic },
          ]} onChange={value => select("provider", value)} /></div><p className="mt-2 text-xs text-muted-foreground">{h.protocolHelp}</p>
        </details>
        </details>
      </div>
      {invalid ? <p role="alert" className="text-sm text-destructive">{invalid}</p>
        : reading.key === key && reading.error ? <p role="alert" className="text-sm text-destructive">{readFailure(reading.error.reason, false, c)}</p>
        : report ? <ActivitySummary report={report} select={select} /> : <p role="status" className="text-sm text-muted-foreground">{h.reading}</p>}
    </section>
  </div>;
}
