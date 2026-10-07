import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { getRunLog } from "@/features/mdm/api";
import type { Run, RunLogLine, RunLogResponse } from "@/features/mdm/types";

/** How long a poll may stay out before it is given up and the next tick asks again. */
const POLL_TIMEOUT_MS = 30_000;

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
 *   so it asks again at once until a page brings nothing new, then allows one grace tick
 *   for closing lines written after the terminal status.
 * - **It stops while the tab is hidden.** Background tabs polling a database every two
 *   seconds for a forty-minute sweep is load nobody asked for, and the browser throttles
 *   the timer unpredictably anyway. `visibilitychange` resumes it, and the cursor means
 *   resuming asks only for what was missed rather than re-fetching.
 * - **It asks for lines `after` the last id it holds.** The alternative re-sends the
 *   whole log on every tick for the length of the run.
 * - **One poll is out at a time, and only for the job on screen.** The interval does not
 *   wait for an answer: a server slower than two seconds would be asked twice from one
 *   cursor and both answers appended. A poll still out after 30 seconds is given up, so a
 *   request that never answers cannot hold the panel still. An answer that lands after
 *   the panel was pointed at another job is dropped, not written into that job's lines,
 *   cursor and finish.
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
  const emptyComplete = useRef(false);
  const finishedHandler = useRef(onFinished);
  useEffect(() => {
    finishedHandler.current = onFinished;
  });

  // The job on screen, set as React commits the render that switched it. The effect below
  // is torn down later: unless a click caused the switch, React lets the browser paint it
  // and runs the old effect's cleanup in a later task, and Run now and Re-emit switch after
  // an await, not in the click. An answer landing in between would otherwise be written
  // into the new job.
  const onScreen = useRef(jobId);
  useLayoutEffect(() => {
    onScreen.current = jobId;
  }, [jobId]);

  // An answer is dropped whole once the panel has left its job, or once the effect that
  // sent it has been torn down (`cancelled`): the panel was closed, or StrictMode's
  // development double mount threw that effect away.
  const poll = useCallback(async (cancelled: () => boolean, read: (after: number) => Promise<RunLogResponse>) => {
    try {
      for (;;) {
        if (cancelled() || onScreen.current !== jobId) return true;
        if (document.hidden) return false;
        const page = await read(cursor.current);
        if (cancelled() || onScreen.current !== jobId) return true;
        setRun(page.run);
        const fresh = page.lines.filter((line) => line.id > cursor.current);
        if (fresh.length > 0) {
          emptyComplete.current = false;
          cursor.current = Math.max(...fresh.map((line) => line.id));
          setLines((held) => [...held, ...fresh]);
        }
        if (page.complete && !finishedNotified.current) {
          finishedNotified.current = true;
          finishedHandler.current?.(page.run);
        }
        // Finished, but a page stops at 500 lines: ask again until one brings nothing new.
        if (!page.complete) {
          emptyComplete.current = false;
          return false;
        }
        if (fresh.length === 0) {
          const drained = emptyComplete.current;
          emptyComplete.current = true;
          return drained;
        }
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
    let inFlight: AbortController | undefined;
    let requestTimer: number | undefined;
    const read = async (after: number) => {
      inFlight = new AbortController();
      requestTimer = window.setTimeout(() => inFlight?.abort(), POLL_TIMEOUT_MS);
      try {
        return await getRunLog(jobId, after, inFlight.signal);
      } finally {
        window.clearTimeout(requestTimer);
        requestTimer = undefined;
        inFlight = undefined;
      }
    };
    // The cursor and the finished latch belong to the job being polled, and `poll`
    // changes with `jobId` — so this runs exactly when the job does.
    cursor.current = 0;
    finishedNotified.current = false;
    emptyComplete.current = false;

    const tick = async () => {
      if (cancelled || document.hidden || polling) return;
      polling = true;
      done = await poll(() => cancelled, read);
      polling = false;
      if (done && handle !== undefined) {
        window.clearInterval(handle);
        handle = undefined;
      }
    };

    const start = () => {
      if (document.hidden || handle !== undefined || done) return;
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
      inFlight?.abort();
      window.clearTimeout(requestTimer);
      if (handle !== undefined) window.clearInterval(handle);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [jobId, poll]);

  return { run, lines };
}
