import { useState } from "react";
import { Button } from "@/components/ui/button";
import { useRunLog } from "@/features/mdm/useRunLog";
import type { Run } from "@/features/mdm/types";
import { useLocale } from "@/i18n/LocaleContext";

/**
 * Run-now's "processing" state and the engine log behind it (#31).
 *
 * The polling lives in `useRunLog` — this component is one of its two presentations
 * (the overview hero is the other). What it shows is unchanged: a status word, the
 * counts once the run settles, and the engine lines behind a details toggle.
 */
export function RunLogPanel({ jobId, joined, onFinished }: {
  jobId: string;
  joined: boolean;
  onFinished?: (run: Run) => void;
}) {
  const { t } = useLocale();
  const { run, lines } = useRunLog(jobId, onFinished);
  const [expanded, setExpanded] = useState(false);

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
