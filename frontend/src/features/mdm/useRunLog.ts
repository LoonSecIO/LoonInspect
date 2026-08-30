import { useCallback, useEffect, useRef, useState } from "react";
import { getRunLog } from "@/features/mdm/api";
import type { Run, RunLogLine } from "@/features/mdm/types";

/**
 * One poller for one jobID, and the only one in the app (#31, #104).
 *
 * Lifted out of RunLogPanel when the overview hero needed the same live run — two
 * pollers would have meant two sets of the behaviour below, drifting apart. The panel
 * and the hero render the same `{ run, lines }` differently; neither owns the polling.
 *
 * Four things about the polling are deliberate:
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
 * - **`onFinished` is held in a ref.** Callers write it inline, so a caller re-render
 *   would otherwise rebuild the poll callback, tear the interval down and start a fresh
 *   one — an extra request per parent render, for no change in what is being watched.
 *
 * The run rides along with every page of lines on purpose (see the endpoint's
 * docstring): terminal state and line count come from one answer and cannot disagree,
 * which is also what lets the hero tick `deviceCount` without a second request.
 */
export function useRunLog(
  jobId: string,
  onFinished?: (run: Run) => void
): { run: Run | null; lines: RunLogLine[] } {
  const [run, setRun] = useState<Run | null>(null);
  const [lines, setLines] = useState<RunLogLine[]>([]);
  // Refs, not state: the poll callback reads them without being torn down and rebuilt
  // (and the interval restarted) on every line that arrives.
  const cursor = useRef(0);
  const finishedNotified = useRef(false);
  const finishedHandler = useRef(onFinished);
  useEffect(() => {
    finishedHandler.current = onFinished;
  });

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
        finishedHandler.current?.(page.run);
      }
      return page.complete;
    } catch {
      // A failed poll is not a failed run. Keep the last known state on screen and try
      // again on the next tick rather than replacing the log with an error.
      return false;
    }
  }, [jobId]);

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

  return { run, lines };
}
