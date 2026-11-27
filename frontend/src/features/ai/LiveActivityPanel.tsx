import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { useLocale } from "@/i18n/LocaleContext";
import { formats, getLiveActivity, readFailure, type LiveActivity } from "./activity";

const POLL_MS = 15_000;
const STALE_MS = 45_000;

export function LiveActivityPanel() {
  const c = useLocale().t.aiActivity;
  const { age, count, stamp } = formats(c);
  const [reading, setReading] = useState<{ data?: LiveActivity; error?: { reason: unknown }; receivedAt?: number }>({});
  const [refresh, setRefresh] = useState(0);
  const [clock, setClock] = useState(Date.now);
  const [visible, setVisible] = useState(() => document.visibilityState !== "hidden");
  useEffect(() => {
    const update = () => { setVisible(document.visibilityState !== "hidden"); setClock(Date.now()); };
    document.addEventListener("visibilitychange", update);
    const timer = window.setInterval(() => { if (document.visibilityState !== "hidden") setClock(Date.now()); }, 1000);
    return () => { document.removeEventListener("visibilitychange", update); window.clearInterval(timer); };
  }, []);
  useEffect(() => {
    if (!visible) return;
    const controller = new AbortController();
    let pending = false;
    function load() {
      if (pending) return;
      pending = true;
      getLiveActivity(controller.signal).then(data => {
        if (!controller.signal.aborted) setReading({ data, receivedAt: Date.now() });
      }).catch(error => {
        if (!controller.signal.aborted) setReading(previous => ({ ...previous, error: { reason: error } }));
      }).finally(() => { pending = false; });
    }
    load();
    const timer = window.setInterval(load, POLL_MS);
    return () => { controller.abort(); window.clearInterval(timer); };
  }, [refresh, visible]);
  const data = reading.data;
  // Age on the browser's clock alone: the server's asOf comes from another clock, and any
  // skew between the two would otherwise read as age.
  const stale = !!data && reading.receivedAt !== undefined && clock - reading.receivedAt >= STALE_MS;
  const error = reading.error && readFailure(reading.error.reason, true, c);
  const unavailable = !!error || stale;
  const health = unavailable ? c.live.unavailable : data?.label ?? c.live.reading;
  const healthy = !unavailable && (data?.state === "keeping_up" || data?.state === "idle");
  const incomplete = !data?.windowComplete || !!data.coverage.recordingDegradedSince;
  return <section aria-labelledby="live-workload-title" className="space-y-4 rounded-xl border bg-card p-5">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div><h2 id="live-workload-title" className="text-lg font-semibold">{c.live.title}</h2>
        <p className="text-sm text-muted-foreground">{c.live.intro}</p></div>
      <Button variant="outline" size="sm" onClick={() => setRefresh(value => value + 1)}>{c.live.refresh}</Button>
    </div>
    <div className={`rounded-lg border p-3 ${healthy ? "border-emerald-600/30 bg-emerald-500/5" : "bg-muted/30"}`}>
      <p role="status" className="font-semibold">{health}</p>
      {error ? <p role="alert" className="mt-1 text-sm">{error}</p>
        : stale ? <p role="alert" className="mt-1 text-sm">{c.live.stale}</p>
        : data && <><p className="mt-1 text-sm">{data.message}</p>{data.nextCheck && <p className="mt-1 text-sm">{c.live.nextCheck} {data.nextCheck}</p>}</>}
      <p className="mt-2 text-xs text-muted-foreground">{data ? `${unavailable ? c.live.lastReading : c.live.asOf}: ${stamp(data.asOf)}` : c.live.noReading} · {visible ? c.live.polling : c.live.paused}</p>
    </div>
    {data && !unavailable && data.state !== "unavailable" && data.usageEnabled && <>
      <dl className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        {[[c.live.waiting, count(data.waiting)], [c.live.running, count(data.running)], [c.live.oldestWait, data.waiting === 0 ? c.live.noneWaiting : age(data.oldestWaitingSeconds)],
          [c.live.arriving(data.windowSeconds / 60), count(data.arrivals)], [c.live.completions(data.windowSeconds / 60), count(data.usefulCompletions)]].map(([label, value]) => <div key={label}>
          <dt className="text-sm text-muted-foreground">{label}</dt><dd className="text-2xl font-semibold tabular-nums">{value}</dd></div>)}
      </dl>
      <details className="text-sm"><summary className="cursor-pointer font-medium">{c.live.evidence}</summary>
      <p className="mt-2 text-muted-foreground">{c.live.window(stamp(data.windowStart), stamp(data.asOf), incomplete)}</p>
      <p className="text-sm">{c.live.failures(count(data.failed), count(data.rateLimited), count(data.timeouts), count(data.waitingTimeouts), count(data.expired))}</p>
        <p className="mt-2">{data.rule}</p>
        <ul className="my-2 list-disc space-y-1 pl-5">
          <li>{c.live.inventory(count(data.inventory.waiting), count(data.inventory.running), age(data.inventory.oldestWaitingSeconds), !data.inventory.enabled)}</li>
          <li>{c.live.interactive(count(data.interactive.waiting), count(data.interactive.running), age(data.interactive.oldestWaitingSeconds))}</li>
          <li>{c.live.patch(count(data.patchInvestigations.running), age(data.patchInvestigations.oldestRunningSeconds))}</li>
        </ul>
        <p>{c.live.detailedSince(stamp(data.coverage.detailedSince))}</p>
      </details>
      {!!data.coverage.missing.length && <p className="text-sm">{c.live.coverageLimits} {data.coverage.missing.join(" ")}</p>}
      {data.coverage.recordingDegradedSince && <p role="alert" className="text-sm">{c.live.recordingIncomplete(stamp(data.coverage.recordingDegradedSince))}</p>}
    </>}
  </section>;
}
