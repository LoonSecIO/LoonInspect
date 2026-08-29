import { useCallback, useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { getRunLog } from "@/features/mdm/api";
import type { Run, RunLogLine } from "@/features/mdm/types";
import { useLocale } from "@/i18n/LocaleContext";

/**
 * Run-now's "processing" state and the engine log behind it (#31).
 *
 * Polls one jobID. Three things about the polling are deliberate:
 *
 * - **It stops on the run's terminal status, not on an empty page.** A sweep mid-fleet
 *   can go a minute without producing a line and is very much alive; treating quiet as
 *   done would blank the panel in the middle of the pull.
 * - **It stops while the tab is hidden.** Background tabs polling a database every two
 *   seconds for a forty-minute sweep is load nobody asked for, and the browser throttles
 *   the timer unpredictably anyway. `visibilitychange` resumes it, and the cursor means
 *   resuming costs one request for everything missed rather than a re-fetch.
 * - **It asks for lines `after` the last id it holds.** The alternative re-sends the
 *   whole log on every tick for the length of the run.
 */
export function RunLogPanel({ jobId, joined, onFinished }: {
  jobId: string;
  joined: boolean;
  onFinished?: (run: Run) => void;
}) {
  const { t } = useLocale();
  const [run, setRun] = useState<Run | null>(null);
  const [lines, setLines] = useState<RunLogLine[]>([]);
  const [expanded, setExpanded] = useState(false);
  // Refs, not state: the poll callback reads them without being torn down and rebuilt
  // (and the interval restarted) on every line that arrives.
  const cursor = useRef(0);
  const finishedNotified = useRef(false);

  const poll = useCallback(async () => {
    try {
      const page = await getRunLog(jobId, cursor.current);
      setRun(page.run);
      if (page.lines.length > 0) {
        cursor.current = page.lines[page.lines.length - 1].id;
        setLines((held) => [...held, ...page.lines]);
      }
      if (page.complete && !finishedNotified.current) {
        finishedNotified.current = true;
        onFinished?.(page.run);
      }
      return page.complete;
    } catch {
      // A failed poll is not a failed run. Keep the last known state on screen and try
      // again on the next tick rather than replacing the log with an error.
      return false;
    }
  }, [jobId, onFinished]);

  useEffect(() => {
    cursor.current = 0;
    finishedNotified.current = false;
    setLines([]);
    setRun(null);
  }, [jobId]);

  useEffect(() => {
    let cancelled = false;
    let handle: number | undefined;

    const tick = async () => {
      if (cancelled || document.hidden) return;
      const complete = await poll();
      if (complete && handle !== undefined) {
        window.clearInterval(handle);
        handle = undefined;
      }
    };

    const start = () => {
      if (handle !== undefined || finishedNotified.current) return;
      void tick();
      handle = window.setInterval(() => void tick(), 2000);
    };

    const onVisibility = () => {
      if (document.hidden) {
        if (handle !== undefined) {
          window.clearInterval(handle);
          handle = undefined;
        }
      } else {
        start();
      }
    };

    start();
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      cancelled = true;
      if (handle !== undefined) window.clearInterval(handle);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [poll]);

  const running = run === null || run.status === "running";
  const label = running
    ? t.settings.runProcessing
    : run.status === "succeeded"
      ? t.settings.runSucceeded
      : t.settings.runFailed;

  return (
    <div className="rounded-md border bg-muted/20 px-3 py-2 text-xs">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <span className={running ? "text-primary" : run.status === "failed" ? "text-destructive" : "text-muted-foreground"}>
          {label}
        </span>
        {run && !running && (
          <span className="text-muted-foreground">
            {t.settings.runSummary(run.deviceCount, run.groupCount)}
          </span>
        )}
        {run && !running && run.devicesFailed > 0 && (
          <span className="text-muted-foreground">
            {t.settings.runDevicesFailed(run.devicesFailed)}
          </span>
        )}
        {joined && <span className="text-muted-foreground">{t.settings.runJoined}</span>}
        <Button variant="ghost" size="sm" className="ml-auto h-6 px-2" onClick={() => setExpanded((open) => !open)}>
          {expanded ? t.settings.runHideDetails : t.settings.runMoreDetails}
        </Button>
      </div>

      {expanded && (
        <div className="mt-2 space-y-1">
          <p className="font-mono text-[10px] text-muted-foreground">
            {t.settings.runJobId}: {jobId}
          </p>
          <div className="max-h-48 overflow-y-auto rounded border bg-background p-2 font-mono text-[11px]">
            {lines.length === 0 && <p className="text-muted-foreground">{t.settings.runLogEmpty}</p>}
            {lines.map((line) => (
              <p key={line.id} className={line.level === "error" ? "text-destructive" : undefined}>
                <span className="text-muted-foreground">{new Date(line.ts).toLocaleTimeString()} </span>
                {line.message}
                {line.fields && Object.keys(line.fields).length > 0 && (
                  <span className="text-muted-foreground">
                    {" "}
                    {Object.entries(line.fields)
                      .filter(([, value]) => value !== null && value !== undefined)
                      .map(([key, value]) => `${key}=${typeof value === "object" ? JSON.stringify(value) : String(value)}`)
                      .join(" ")}
                  </span>
                )}
              </p>
            ))}
          </div>
          {run?.error && <p className="text-destructive">{run.error}</p>}
        </div>
      )}
    </div>
  );
}
