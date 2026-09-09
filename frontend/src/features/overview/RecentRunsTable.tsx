import { useState } from "react";
import { RunLogPanel } from "@/features/mdm/RunLogPanel";
import type { Run } from "@/features/mdm/types";
import { formatUtcClock, runDuration } from "@/features/overview/heroRun";
import { recentRuns, webhookRunsToday } from "@/features/overview/hygiene";
import { useLocale } from "@/i18n/LocaleContext";

/**
 * The recent-runs table, below the fold (#109): the last ten runs the page already holds
 * (the Overview fetches a page of runs for its hero and baseline; this reads the same
 * rows, so it costs no request). Trigger, status, window, devices, duration, actor; a
 * row click opens the existing run-log panel beneath it.
 *
 * The one derived line above it — webhook sweeps today — is the only webhook-liveness
 * signal in the product, and it is honest about its window: counted over the rows in
 * hand, and marked a floor when they never reached back past midnight.
 */
export function RecentRunsTable({ runs }: { runs: Run[] }) {
  const { t } = useLocale();
  const tr = t.overview.recentRuns;
  const [openId, setOpenId] = useState<string | null>(null);
  const rows = recentRuns(runs);
  const webhooks = webhookRunsToday(runs, new Date());

  const triggerLabel: Record<Run["trigger"], string> = {
    sweep: tr.triggerSweep,
    manual: tr.triggerManual,
    webhook: tr.triggerWebhook
  };
  const statusLabel: Record<Run["status"], string> = {
    running: tr.statusRunning,
    succeeded: tr.statusSucceeded,
    failed: tr.statusFailed
  };

  return (
    <section className="rounded-lg border bg-card text-sm shadow-sm">
      <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1 px-5 py-4">
        <h2 className="font-semibold text-card-foreground">{tr.title}</h2>
        <p className="text-xs text-muted-foreground">
          {webhooks.complete ? tr.webhooksToday(webhooks.count) : tr.webhooksTodayAtLeast(webhooks.count, runs.length)}
        </p>
      </div>
      {rows.length === 0 ? (
        <p className="px-5 pb-4 text-muted-foreground">{tr.empty}</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-muted/40 text-left text-xs text-muted-foreground">
              <tr>
                <th className="px-4 py-2 font-medium">{tr.colTrigger}</th>
                <th className="px-4 py-2 font-medium">{tr.colStatus}</th>
                <th className="px-4 py-2 font-medium">{tr.colWindow}</th>
                <th className="px-4 py-2 font-medium">{tr.colDevices}</th>
                <th className="px-4 py-2 font-medium">{tr.colDuration}</th>
                <th className="px-4 py-2 font-medium">{tr.colActor}</th>
              </tr>
            </thead>
            <tbody>
              {rows.flatMap((run) => {
                const open = openId === run.id;
                const row = (
                  <tr
                    key={run.id}
                    className="cursor-pointer border-t hover:bg-accent/40"
                    onClick={() => setOpenId(open ? null : run.id)}
                    aria-expanded={open}
                  >
                    <td className="px-4 py-2">
                      <span className="rounded bg-muted px-1.5 py-0.5 text-xs">{triggerLabel[run.trigger]}</span>
                    </td>
                    <td className={`px-4 py-2 ${run.status === "failed" ? "text-destructive" : ""}`}>
                      {statusLabel[run.status]}
                    </td>
                    <td className="whitespace-nowrap px-4 py-2 text-muted-foreground">
                      {formatUtcClock(run.windowStart)}
                      {run.windowEnd ? ` – ${formatUtcClock(run.windowEnd)}` : ""}
                    </td>
                    <td className="px-4 py-2">{run.deviceCount}</td>
                    <td className="px-4 py-2 text-muted-foreground">{runDuration(run)}</td>
                    <td className="px-4 py-2 text-muted-foreground">{run.actorLabel ?? "—"}</td>
                  </tr>
                );
                if (!open) return [row];
                return [
                  row,
                  <tr key={`${run.id}-log`} className="border-t bg-muted/20">
                    <td className="px-4 py-3" colSpan={6}>
                      <RunLogPanel jobId={run.id} joined={true} />
                    </td>
                  </tr>
                ];
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
