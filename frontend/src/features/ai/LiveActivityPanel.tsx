import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { age, count, getLiveActivity, readFailure, stamp, type LiveActivity } from "./activity";

const POLL_MS = 15_000;
const STALE_MS = 45_000;

export function LiveActivityPanel() {
  const [reading, setReading] = useState<{ data?: LiveActivity; error?: string; receivedAt?: number }>({});
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
        if (!controller.signal.aborted) setReading(previous => ({ ...previous, error: readFailure(error, true) }));
      }).finally(() => { pending = false; });
    }
    load();
    const timer = window.setInterval(load, POLL_MS);
    return () => { controller.abort(); window.clearInterval(timer); };
  }, [refresh, visible]);
  const data = reading.data;
  const stale = !!data && clock - Math.min(reading.receivedAt ?? 0, Date.parse(data.asOf)) >= STALE_MS;
  const unavailable = !!reading.error || stale;
  const health = unavailable ? "Measurement unavailable" : data?.label ?? "Reading workload…";
  const healthy = !unavailable && (data?.state === "keeping_up" || data?.state === "idle");
  const incomplete = !data?.windowComplete || !!data.coverage.recordingDegradedSince;
  return <section aria-labelledby="live-workload-title" className="space-y-4 rounded-xl border bg-card p-5">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div><h2 id="live-workload-title" className="text-lg font-semibold">Live workload</h2>
        <p className="text-sm text-muted-foreground">Current work across all services · independent of the history filters below.</p></div>
      <Button variant="outline" size="sm" onClick={() => setRefresh(value => value + 1)}>Refresh live workload</Button>
    </div>
    <div className={`rounded-lg border p-3 ${healthy ? "border-emerald-600/30 bg-emerald-500/5" : "bg-muted/30"}`}>
      <p role="status" className="font-semibold">{health}</p>
      {reading.error ? <p role="alert" className="mt-1 text-sm">{reading.error}</p>
        : stale ? <p role="alert" className="mt-1 text-sm">The last reading is at least 45 seconds old. Refresh to check the workload; its previous health verdict is no longer current.</p>
        : data && <><p className="mt-1 text-sm">{data.message}</p>{data.nextCheck && <p className="mt-1 text-sm">Next check: {data.nextCheck}</p>}</>}
      <p className="mt-2 text-xs text-muted-foreground">{data ? `${unavailable ? "Last successful reading" : "As of"}: ${stamp(data.asOf)}` : "No successful reading yet."} · {visible ? "Refreshes every 15 seconds" : "Refresh paused while this tab is hidden"}</p>
    </div>
    {data && !unavailable && data.state !== "unavailable" && data.usageEnabled && <>
      <dl className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        {[["Waiting", count(data.waiting)], ["Running", count(data.running)], ["Oldest wait", data.waiting === 0 ? "None waiting" : age(data.oldestWaitingSeconds)],
          [`Work arriving (${data.windowSeconds / 60} min)`, count(data.arrivals)], [`Useful completions (${data.windowSeconds / 60} min)`, count(data.usefulCompletions)]].map(([label, value]) => <div key={label}>
          <dt className="text-sm text-muted-foreground">{label}</dt><dd className="text-2xl font-semibold tabular-nums">{value}</dd></div>)}
      </dl>
      <details className="text-sm"><summary className="cursor-pointer font-medium">Recent failures, status evidence and coverage</summary>
      <p className="mt-2 text-muted-foreground">Arrivals and completions: {stamp(data.windowStart)}–{stamp(data.asOf)}{incomplete ? " · incomplete measurement window" : ""}. Waiting and running are current counts.</p>
      <p className="text-sm">Recent failures: {count(data.failed)} · Rate limits: {count(data.rateLimited)} · Request timeouts: {count(data.timeouts)} · Waiting timeouts: {count(data.waitingTimeouts)} · Expired: {count(data.expired)}</p>
        <p className="mt-2">{data.rule}</p>
        <ul className="my-2 list-disc space-y-1 pl-5">
          <li>Inventory summaries: {count(data.inventory.waiting)} waiting, {count(data.inventory.running)} running, oldest wait {age(data.inventory.oldestWaitingSeconds)}{!data.inventory.enabled && " · disabled"}.</li>
          <li>Interactive requests: {count(data.interactive.waiting)} waiting, {count(data.interactive.running)} running, oldest wait {age(data.interactive.oldestWaitingSeconds)}.</li>
          <li>Patch investigations: {count(data.patchInvestigations.running)} active, oldest {age(data.patchInvestigations.oldestRunningSeconds)} · partial coverage of source research before inference.</li>
        </ul>
        <p>Detailed measurement began: {stamp(data.coverage.detailedSince)}. Other applications using these providers are outside LoonInspect’s visibility.</p>
      </details>
      {!!data.coverage.missing.length && <p className="text-sm">Coverage limits: {data.coverage.missing.join(" ")}</p>}
      {data.coverage.recordingDegradedSince && <p role="alert" className="text-sm">Recording has been incomplete since {stamp(data.coverage.recordingDegradedSince)}. These counts may omit work; check the application diagnostics.</p>}
    </>}
  </section>;
}
