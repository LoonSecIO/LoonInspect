// @vitest-environment jsdom
/** The run-now poller's contract (#31, #104), driven through RunLogPanel with a stubbed fetch and a fake clock. Its rules
 *  break without a visible sign, so each has a test: stop on a terminal status and never on a quiet page; stand down while
 *  the tab is hidden and come back with one request from the held cursor; ask only after the last line id held; keep the
 *  log through a failed poll; call onFinished once. The one file in this lane with a DOM (jsdom, opted in on line 1):
 *  effects and `visibilitychange` are what is under test, and server rendering runs neither. */

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
const RUN: Run = {
  id: JOB, mdmConnectionId: 1, collectionId: null, trigger: "manual", comparison: "delta", lockClass: "device_sweep",
  status: "running", windowStart: "2026-10-06T09:00:00Z", windowEnd: null, startedAt: "2026-10-06T09:00:00Z",
  finishedAt: null, heartbeatAt: "2026-10-06T09:00:00Z", deviceCount: 1200, groupCount: 14, devicesProcessed: 1200,
  devicesFailed: 0, observations: null, error: null, actorLabel: null
};

/** One answer of GET /runs/{jobId}/log: these line ids, and the run in `status` — complete once it is no longer
 *  running, as backend/app/api/runs.py decides it. */
const page = (ids: number[], status: Run["status"] = "running"): RunLogResponse => ({
  run: { ...RUN, status },
  lines: ids.map((id) => ({ id, ts: "2026-10-06T09:00:00Z", level: "info", message: `line ${id}`, fields: null })),
  complete: status !== "running"
});

// What the stubbed fetch answers, in order: a page, a page that answers when the test says, a 502, or no answer.
type Answer = RunLogResponse | Promise<RunLogResponse> | 502 | "unreachable";
const answers: Answer[] = [];
const fetchStub = vi.fn<typeof fetch>(async () => {
  const next = answers.shift();
  if (next === undefined || next === "unreachable") throw new TypeError("Failed to fetch");
  if (next === 502) return { ok: false, status: 502, json: async () => ({ detail: "Bad Gateway" }) } as Response;
  // A bare answer rather than a Response: its body is one promise, so a poll settles inside the act that fired it.
  const body = await next;
  return { ok: true, status: 200, json: async () => body } as Response;
});
const asked = () => fetchStub.mock.calls.map(([url]) => String(url));
const after = (id: number) => `/api/runs/${JOB}/log?after=${id}`;
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

  it("stops on the run's terminal status, and the tab coming back does not start it again", async () => {
    answers.push(page([1]), page([2, 3], "succeeded"));
    await mount();
    await advance(2000);
    expect([asked(), vi.getTimerCount()]).toEqual([[after(0), after(1)], 0]);
    await advance(60_000);
    await tab("hidden");
    await tab("visible");
    expect(asked()).toHaveLength(2);
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
    // The first answer is held past the next tick, so two answers say finished. The last is a trap: a poller that
    // starts again after finishing is answered "finished" once more.
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
});
