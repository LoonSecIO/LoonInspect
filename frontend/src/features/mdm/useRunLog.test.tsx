// @vitest-environment jsdom
/** The run-now poller's contract (#31, #104), driven through RunLogPanel with a stubbed fetch and a fake clock. Its rules
 *  break without a visible sign, so each has a test: stop on a terminal status once the log is read to its end, and never
 *  on a quiet page; stand down while the tab is hidden and come back with one request from the held cursor; ask only
 *  after the last line id held; keep the log through a failed poll; call onFinished once; keep one poll out at a time;
 *  drop a late answer for a job the panel has left. The one file in this lane with a DOM (jsdom, opted in on line 1):
 *  effects and `visibilitychange` are what is under test, and server rendering runs neither. */

import { StrictMode, useEffect, useState } from "react";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from "vitest";
import { RunLogPanel } from "@/features/mdm/RunLogPanel";
import type { Run, RunLogResponse } from "@/features/mdm/types";
import { en } from "@/i18n/en";

vi.mock("@/i18n/LocaleContext", async () => {
  const { en: t } = await import("@/i18n/en");
  return { useLocale: () => ({ t, locale: "en" }) };
});

const JOB = "6f1d2c3b-31a0-4c1e-9d2f-0b5e3a524a5e";
const NEXT = "0b9e7c41-2d5a-4f36-8e1b-7a3c6d2f9e05"; // the job Run now or Re-emit points the panel at next
const RUN: Run = {
  id: JOB, mdmConnectionId: 1, collectionId: null, trigger: "manual", comparison: "delta", lockClass: "device_sweep",
  status: "running", windowStart: "2026-10-06T09:00:00Z", windowEnd: null, startedAt: "2026-10-06T09:00:00Z",
  finishedAt: null, heartbeatAt: "2026-10-06T09:00:00Z", deviceCount: 1200, groupCount: 14, devicesProcessed: 1200,
  devicesFailed: 0, observations: null, error: null, actorLabel: null
};

/** One answer of GET /runs/{jobId}/log: these line ids, and the run in `status` — complete once it is no longer
 *  running, as backend/app/api/runs.py decides it. */
const page = (ids: number[], status: Run["status"] = "running", job = JOB): RunLogResponse => ({
  run: { ...RUN, id: job, status },
  lines: ids.map((id) => ({ id, ts: "2026-10-06T09:00:00Z", level: "info", message: `line ${id}`, fields: null })),
  complete: status !== "running"
});

// What the stubbed fetch answers, in order: a page, a page that answers when the test says, a 502, no answer, or
// silence until the poller gives the request up.
type Answer = RunLogResponse | Promise<RunLogResponse> | 502 | "unreachable" | "silent";
const answers: Answer[] = [];
const fetchStub = vi.fn<typeof fetch>(async (_url, init) => {
  const next = answers.shift();
  if (next === undefined || next === "unreachable") throw new TypeError("Failed to fetch");
  if (next === "silent") {
    const signal = init?.signal;
    return new Promise<Response>((_answer, fail) => signal?.addEventListener("abort", () => fail(signal.reason)));
  }
  if (next === 502) return { ok: false, status: 502, json: async () => ({ detail: "Bad Gateway" }) } as Response;
  // A bare answer rather than a Response: its body is one promise, so a poll settles inside the act that fired it.
  const body = await next;
  return { ok: true, status: 200, json: async () => body } as Response;
});
const asked = () => fetchStub.mock.calls.map(([url]) => String(url));
const after = (id: number, job = JOB) => `/api/runs/${job}/log?after=${id}`;
const finished = vi.fn();
let hidden = false;

/** Moves the poller's clock; every poll that fires settles into the render before this returns. */
const advance = (ms: number) => act(() => vi.advanceTimersByTimeAsync(ms));
/** The browser sends the tab to the background or brings it back; whatever that starts settles. */
const tab = (state: "hidden" | "visible") => act(async () => {
  hidden = state === "hidden";
  document.dispatchEvent(new Event("visibilitychange"));
  await vi.advanceTimersByTimeAsync(0);
});
/** The engine lines on screen, by message. */
const shown = () => screen.queryAllByText(/^line \d+$/).map((line) => line.lastChild?.textContent);
const labelled = (label: string) => screen.queryByText(label) !== null;
const panel = () => <RunLogPanel jobId={JOB} joined={false} onFinished={(run) => finished(run)} />;

/** The panel as Run now mounts it, its log opened, the first poll answered (or still out, if its answer is). */
async function mount() {
  const view = render(panel());
  fireEvent.click(screen.getByText(en.settings.runMoreDetails));
  await advance(0);
  return view;
}

let complaints: MockInstance<typeof console.error>;
beforeEach(() => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval"] });
  vi.stubGlobal("fetch", fetchStub);
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  complaints = vi.spyOn(console, "error");
  hidden = false;
  Object.defineProperty(document, "hidden", { configurable: true, get: () => hidden });
});
afterEach(() => {
  cleanup();
  const said = complaints.mock.calls.map(([first]) => String(first));
  Reflect.deleteProperty(document, "hidden");
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.useRealTimers();
  fetchStub.mockClear();
  finished.mockClear();
  answers.length = 0;
  // A render update outside act, or two lines under one key, is a console error: either means the test proved less.
  expect(said).toEqual([]);
});

describe("the run-now poller (useRunLog, through RunLogPanel)", () => {
  it("keeps polling through quiet pages: no new lines twice, then lines again, and on", async () => {
    answers.push(page([1, 2]), page([]), page([]), page([3]), page([]));
    await mount();
    await advance(4 * 2000);
    expect(asked()).toEqual([after(0), after(2), after(2), after(2), after(3)]);
    expect(shown()).toEqual(["line 1", "line 2", "line 3"]);
    expect([labelled(en.settings.runProcessing), finished.mock.calls.length, vi.getTimerCount()]).toEqual([true, 0, 1]);
  });

  it("stops on the run's terminal status once its log is read, and the tab coming back does not start it again", async () => {
    // Every page of a finished run says complete, so the page that brought its last lines is followed by an empty one.
    answers.push(page([1]), page([2, 3], "succeeded"), page([], "succeeded"));
    await mount();
    await advance(2000);
    expect([asked(), vi.getTimerCount()]).toEqual([[after(0), after(1), after(3)], 0]);
    await advance(60_000);
    await tab("hidden");
    await tab("visible");
    expect(asked()).toHaveLength(3);
    expect(shown()).toEqual(["line 1", "line 2", "line 3"]);
    expect(labelled(en.settings.runSucceeded)).toBe(true);
  });

  it("stands down while the tab is hidden, and comes back with one request from the held cursor", async () => {
    answers.push(page([1, 2, 3]));
    await mount();
    expect(vi.getTimerCount()).toBe(1);
    await tab("hidden");
    expect(vi.getTimerCount()).toBe(0);
    await advance(10 * 60_000);
    expect(asked()).toEqual([after(0)]);

    // Everything the run wrote while the tab was away arrives in the one answer.
    answers.push(page([4, 5, 6, 7]), page([8]));
    await tab("visible");
    expect(asked()).toEqual([after(0), after(3)]);
    expect(shown()).toEqual(["line 1", "line 2", "line 3", "line 4", "line 5", "line 6", "line 7"]);
    await advance(2000);
    expect([asked().at(-1), vi.getTimerCount()]).toEqual([after(7), 1]);
  });

  it("keeps the lines it has through failed polls, and asks again from the same place", async () => {
    answers.push(page([1, 2]), 502, "unreachable", page([3]));
    await mount();
    await advance(2 * 2000);
    expect(shown()).toEqual(["line 1", "line 2"]);
    expect(labelled(en.settings.runProcessing)).toBe(true);
    await advance(2000);
    expect(asked()).toEqual([after(0), after(2), after(2), after(2)]);
    expect(shown()).toEqual(["line 1", "line 2", "line 3"]);
  });

  it("calls onFinished once: not for a poll still out, a parent re-render, or the tab coming back", async () => {
    let answerFirst!: (body: RunLogResponse) => void;
    // The first answer is held past the next tick. The two after it are traps: a poller that asks again while it is
    // out, or starts again after finishing, is answered "finished" once more.
    const held = new Promise<RunLogResponse>((resolve) => (answerFirst = resolve));
    answers.push(held, page([], "succeeded"), page([], "succeeded"));
    const view = await mount();
    await advance(2000);
    answerFirst(page([], "succeeded"));
    await advance(0);
    const polls = asked().length;
    view.rerender(panel()); // a new inline onFinished, as a parent's re-render writes it
    await tab("hidden");
    await tab("visible");
    await advance(60_000);
    expect(asked()).toHaveLength(polls);
    expect(finished).toHaveBeenCalledTimes(1);
    expect(finished).toHaveBeenCalledWith(expect.objectContaining({ id: JOB, status: "succeeded" }));
  });

  it("asks for the lines after the last id it holds, never from the top", async () => {
    // Line ids are one sequence across every run (run_log.id), so a run's lines neither start at 1 nor run contiguous.
    answers.push(page([907, 912, 940]), page([941]), page([]), page([958, 1003]), page([]));
    await mount();
    await advance(4 * 2000);
    expect(asked()).toEqual([after(0), after(940), after(941), after(941), after(1003)]);
    expect(shown()).toEqual(["line 907", "line 912", "line 940", "line 941", "line 958", "line 1003"]);
  });

  it("keeps one poll out at a time: a slow answer is waited for, not asked for again from the same place", async () => {
    let answerFirst!: (body: RunLogResponse) => void;
    answers.push(new Promise<RunLogResponse>((resolve) => (answerFirst = resolve)), page([3]));
    await mount();
    await advance(3 * 2000); // the server takes longer than three ticks to answer the first poll
    expect(asked()).toEqual([after(0)]);
    answerFirst(page([1, 2]));
    await advance(2000);
    expect(asked()).toEqual([after(0), after(2)]);
    expect(shown()).toEqual(["line 1", "line 2", "line 3"]);
  });

  it("gives a poll up after 30 seconds without an answer, and asks again from the same place", async () => {
    // A request that never answers: a server stuck mid-request, or a connection a sleeping laptop left half open.
    answers.push(page([1, 2]), "silent", page([3], "succeeded"), page([], "succeeded"));
    await mount();
    await advance(2000 + 29_999); // the poll sent at 2 s is still out, and no other has gone
    expect(asked()).toEqual([after(0), after(2)]);
    await advance(1 + 2000); // given up at 32 s, and asked again by the next tick at the latest
    expect(asked()).toEqual([after(0), after(2), after(2), after(3)]);
    expect([shown(), labelled(en.settings.runSucceeded), vi.getTimerCount()])
      .toEqual([["line 1", "line 2", "line 3"], true, 0]);
  });

  it("drops an answer still out when the panel is pointed at another job", async () => {
    // Run now or Re-emit points the panel at a new job, and a re-emit runs beside a sweep, so their line ids interleave.
    let answerLate!: (body: RunLogResponse) => void;
    answers.push(
      new Promise<RunLogResponse>((resolve) => (answerLate = resolve)),
      page([1001, 1002], "running", NEXT), page([1003], "running", NEXT), page([], "succeeded", NEXT)
    );
    const view = await mount();
    view.rerender(<RunLogPanel jobId={NEXT} joined={false} onFinished={(run) => finished(run)} />);
    await advance(0);
    answerLate(page([1500], "succeeded")); // the job just left: a line written after the new job's, and its finish
    await advance(0);
    expect(labelled(en.settings.runProcessing)).toBe(true); // the heading is still the new job's, running
    await advance(2 * 2000);
    expect(asked()).toEqual([after(0), after(0, NEXT), after(1002, NEXT), after(1003, NEXT)]);
    expect(shown()).toEqual(["line 1001", "line 1002", "line 1003"]);
    expect(finished.mock.calls).toEqual([[expect.objectContaining({ id: NEXT, status: "succeeded" })]]);
  });

  it("drops the left job's answer landing between the switch's commit and its effect's teardown", async () => {
    // Run now and Re-emit switch the job after an await, not in a click, so React paints the switch and tears the left
    // job's effect down in a later task. act runs both at once, so this test switches outside it, on real timers, and
    // the left job's answer (its last line, and its finish) lands the moment the new job id is on screen.
    vi.useRealTimers();
    let answerLeft!: (body: RunLogResponse) => void;
    let answerNext!: (body: RunLogResponse) => void;
    // The left job's poll, still out, then an answer for a poller that reads on past it.
    answers.push(new Promise<RunLogResponse>((resolve) => (answerLeft = resolve)), page([], "failed"));
    const toNext = vi.fn<typeof fetch>(async () => {
      const body = await new Promise<RunLogResponse>((resolve) => (answerNext = resolve));
      return { ok: true, status: 200, json: async () => body } as Response;
    });
    const route: typeof fetch = (url, init) => (String(url).includes(NEXT) ? toNext : fetchStub)(url, init);
    vi.stubGlobal("fetch", route);
    let point!: (jobId: string) => void;
    function Connection({ expose }: { expose: (point: (jobId: string) => void) => void }) {
      const [jobId, setJobId] = useState(JOB);
      useEffect(() => expose(setJobId), [expose]);
      return <RunLogPanel jobId={jobId} joined={false} onFinished={(run) => finished(run)} />;
    }
    render(<Connection expose={(set) => (point = set)} />);
    fireEvent.click(screen.getByText(en.settings.runMoreDetails));
    const switched = new MutationObserver(() => {
      if (!document.body.textContent?.includes(NEXT)) return;
      switched.disconnect();
      answerLeft(page([1500], "failed"));
    });
    switched.observe(document.body, { subtree: true, childList: true, characterData: true });
    vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", false);
    point(NEXT);
    await vi.waitFor(() => expect(toNext).toHaveBeenCalledOnce()); // sent from the new job's effect, after the teardown
    expect([asked(), shown(), labelled(en.settings.runProcessing), finished.mock.calls])
      .toEqual([[after(0)], [], true, []]);
    answerNext(page([1001], "running", NEXT));
    await vi.waitFor(() => expect(shown()).toEqual(["line 1001"]));
  });

  it("drops the answer of an effect torn down mid-poll, as StrictMode's double mount does in development", async () => {
    answers.push(page([1, 2]), page([1, 2]));
    render(<StrictMode>{panel()}</StrictMode>);
    fireEvent.click(screen.getByText(en.settings.runMoreDetails));
    await advance(0);
    expect([asked(), shown()]).toEqual([[after(0), after(0)], ["line 1", "line 2"]]);
  });

  it("reads a finished run to its end when the panel is more than a page behind", async () => {
    answers.push(page([1, 2, 3]));
    await mount();
    await tab("hidden");
    // The run writes 520 more lines and ends while the tab is away. A page stops at 500 lines (_MAX_LINES), and every
    // page of a finished run says complete.
    const missed = Array.from({ length: 520 }, (_, i) => i + 4);
    answers.push(page(missed.slice(0, 500), "succeeded"), page(missed.slice(500), "succeeded"), page([], "succeeded"));
    await tab("visible");
    expect(asked()).toEqual([after(0), after(3), after(503), after(523)]);
    expect([shown().length, shown().at(-1)]).toEqual([523, "line 523"]);
    expect([finished.mock.calls.length, vi.getTimerCount()]).toEqual([1, 0]);
  });

  it("finishes reading a finished run after a failed page and a hidden tab", async () => {
    answers.push(page([1, 2, 3]));
    await mount();
    await tab("hidden");
    // The tab comes back to a finished run (onFinished fires), the next page fails, and the tab goes away again before
    // the tick that would retry it. Its return must pick the reading up, though the run has already said it finished.
    const missed = Array.from({ length: 500 }, (_, i) => i + 4);
    answers.push(page(missed, "succeeded"), 502);
    await tab("visible");
    await tab("hidden");
    answers.push(page([504], "succeeded"), page([], "succeeded"));
    await tab("visible");
    expect(asked()).toEqual([after(0), after(3), after(503), after(503), after(504)]);
    expect([shown().at(-1), finished.mock.calls.length, vi.getTimerCount()]).toEqual(["line 504", 1, 0]);
  });
});
