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
 * Five things about the polling are deliberate:
 *
 * - **It stops on the run's terminal status, not on an empty page, and only once it has
 *   read the log to the end.** A sweep mid-fleet can go a minute without producing a line
 *   and is very much alive; treating quiet as done would blank the panel in the middle of
 *   the pull. Every page of a finished run says complete and a page stops at 500 lines,
 *   so it asks again at once until a page brings nothing new.
 * - **It stops while the tab is hidden.** Background tabs polling a database every two
 *   seconds for a forty-minute sweep is load nobody asked for, and the browser throttles
 *   the timer unpredictably anyway. `visibilitychange` resumes it, and the cursor means
 *   resuming asks only for what was missed rather than re-fetching.
 * - **It asks for lines `after` the last id it holds.** The alternative re-sends the
 *   whole log on every tick for the length of the run.
 * - **One poll is out at a time, and only for the job on screen.** The interval does not
 *   wait for an answer: a server slower than two seconds would be asked twice from one
 *   cursor and both answers appended. An answer that lands after the panel was pointed at
 *   another job is dropped, not written into that job's lines, cursor and finish.
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

  // `cancelled` is true once the effect that sent this poll has been torn down: the panel
  // was pointed at another job or closed, and the answer is dropped whole.
  const poll = useCallback(async (cancelled: () => boolean) => {
    try {
      for (;;) {
        const page = await getRunLog(jobId, cursor.current);
        if (cancelled()) return true;
        setRun(page.run);
        if (page.lines.length > 0) {
          cursor.current = page.lines[page.lines.length - 1].id;
          setLines((held) => [...held, ...page.lines]);
        }
        if (page.complete && !finishedNotified.current) {
          finishedNotified.current = true;
          finishedHandler.current?.(page.run);
        }
        // Finished, but a page stops at 500 lines: ask again until one brings nothing new.
        if (!page.complete || page.lines.length === 0) return page.complete;
      }
    } catch {
      // A failed poll is not a failed run. Keep the last known state on screen and try
      // again on the next tick rather than replacing the log with an error.
      return false;
    }
  }, [jobId]);

  // Pointed at a different job, the hook starts from nothing: the lines and the run it
  // holds belong to the job just left. Cleared here, during the render that changed
  // `jobId`, rather than from an effect — an effect clears them a render late, and the
  // panel paints one frame of the previous run's log under the new run's heading.
  const [watching, setWatching] = useState(jobId);
  if (watching !== jobId) {
    setWatching(jobId);
    setLines([]);
    setRun(null);
  }

  useEffect(() => {
    let cancelled = false;
    let polling = false;
    let done = false; // the run has ended and its log is read: nothing starts it again
    let handle: number | undefined;
    // The cursor and the finished latch belong to the job being polled, and `poll`
    // changes with `jobId` — so this runs exactly when the job does.
    cursor.current = 0;
    finishedNotified.current = false;

    const tick = async () => {
      if (cancelled || document.hidden || polling) return;
      polling = true;
      done = await poll(() => cancelled);
      polling = false;
      if (done && handle !== undefined) {
        window.clearInterval(handle);
        handle = undefined;
      }
    };

    const start = () => {
      if (handle !== undefined || done) return;
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
