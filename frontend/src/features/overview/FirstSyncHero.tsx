import { useEffect, useRef, useState } from "react";
import { Link } from "react-router";
import { RefreshCw } from "lucide-react";
import type { Run } from "@/features/mdm/types";
import { useRunLog } from "@/features/mdm/useRunLog";
import { formatDuration } from "@/features/overview/heroRun";
import { useLocale } from "@/i18n/LocaleContext";

/** The elapsed clock. Its own second-by-second state so a re-render for the clock does
 *  not cost anything but the clock — the log and the counters re-render on their own
 *  schedule, which is whenever the poll returns something new. */
function Elapsed({ startedAt, live }: { startedAt: string; live: boolean }) {
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    if (!live) return;
    const handle = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(handle);
  }, [live]);

  return <>{formatDuration(now - new Date(startedAt).getTime())}</>;
}

function Counter({ label, value }: { label: string; value: number }) {
  return (
    <div>
      <p className="text-xs uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className="font-mono text-2xl tabular-nums">{value.toLocaleString()}</p>
    </div>
  );
}

/**
 * The hero while a full sync is in flight (#104): elapsed time, the counters ticking,
 * and the engine talking.
 *
 * It watches through `useRunLog`, the same poller the connections panel uses — one
 * request every couple of seconds carries the run and the new lines together, so the
 * counters, the log and the moment it ends all come from one answer.
 *
 * `run` seeds the panel from the listing that found it, so the header is right on the
 * first paint rather than a second later when the first poll lands.
 */
export function FirstSyncHero({ run: seed, onFinished }: {
  run: Run;
  onFinished: (run: Run) => void;
}) {
  const { t } = useLocale();
  const { run: polled, lines } = useRunLog(seed.id, onFinished);
  const run = polled ?? seed;
  const logRef = useRef<HTMLDivElement>(null);

  const running = run.status === "running";
  const failed = run.status === "failed";

  // The interesting line is always the last one. Without this the box shows the start
  // of a forty-minute log for the whole forty minutes.
  useEffect(() => {
    const box = logRef.current;
    if (box) box.scrollTop = box.scrollHeight;
  }, [lines]);

  return (
    <section className="space-y-4 rounded-lg border bg-card p-6 text-card-foreground shadow-sm">
      <div className="flex flex-wrap items-center gap-3">
        {running && <RefreshCw aria-hidden className="h-5 w-5 animate-spin text-primary" />}
        <h1 className="text-2xl font-bold tracking-tight">
          {failed
            ? t.overview.syncFailedTitle
            : run.comparison === "baseline"
              ? t.overview.firstSyncTitle
              : t.overview.syncTitle}
        </h1>
      </div>

      <div className="flex flex-wrap gap-x-12 gap-y-4">
        <div>
          <p className="text-xs uppercase tracking-wide text-muted-foreground">{t.overview.elapsedLabel}</p>
          <p className="font-mono text-2xl tabular-nums">
            <Elapsed startedAt={run.startedAt} live={running} />
          </p>
        </div>
        <Counter label={t.overview.devicesLabel} value={run.deviceCount} />
        <Counter label={t.overview.groupsLabel} value={run.groupCount} />
      </div>

      <div className="space-y-1">
        <p className="text-xs uppercase tracking-wide text-muted-foreground">{t.overview.engineLog}</p>
        <div
          ref={logRef}
          className="h-40 overflow-y-auto rounded border bg-background p-2 font-mono text-[11px] leading-relaxed"
        >
          {lines.length === 0 && <p className="text-muted-foreground">{t.settings.runLogEmpty}</p>}
          {lines.map((line) => (
            <p key={line.id} className={line.level === "error" ? "text-destructive" : undefined}>
              <span className="text-muted-foreground">{new Date(line.ts).toLocaleTimeString()} </span>
              {line.message}
            </p>
          ))}
        </div>
      </div>

      {failed && (
        <div className="space-y-2">
          {run.error && <p className="text-sm text-destructive">{run.error}</p>}
          <Link to="/settings/connections" className="text-sm font-medium underline underline-offset-4">
            {t.overview.openConnection}
          </Link>
        </div>
      )}

      <p className="font-mono text-[10px] text-muted-foreground">
        {t.settings.runJobId}: {run.id}
      </p>
    </section>
  );
}
