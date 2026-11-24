// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, useLocation, useNavigate } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiRequest, ApiError } from "@/config/api";
import { AIActivityPage } from "./AIActivityPage";
import { AIActivityEntry } from "./AIActivityEntry";
import { LiveActivityPanel } from "./LiveActivityPanel";
import { ActivitySummary } from "./ActivitySummary";
import { activityQuery, isActivityReport, isLiveActivity, rangeError, utcDay, type ActivityMetrics, type ActivityReport, type LiveActivity } from "./activity";

vi.mock("@/config/api", async original => ({ ...await original<typeof import("@/config/api")>(), apiRequest: vi.fn() }));
const permission = vi.hoisted(() => vi.fn(() => true));
vi.mock("@/features/auth/store", () => ({ useHasPermission: permission }));
vi.mock("@/i18n/LocaleContext", () => ({ useLocale: () => ({ locale: "en" }) }));
const request = vi.mocked(apiRequest);
const metrics: ActivityMetrics = {
  attempts: 1, answered: 1, failed: 0, dispatches: 1, dispatchReports: 1, usefulResults: 1, usefulReports: 1,
  unusable: 0, waitingTimeouts: 0, retries: 0, fallbacks: 0, inputTokens: null, inputReports: 0,
  outputTokens: null, outputReports: 0, cachedTokens: null, cacheReports: 0,
  avgWaitMs: 500, waitReports: 1, avgRequestMs: 1500, requestReports: 1, avgTotalMs: 2000, totalReports: 1, avgProviderMs: null, providerReports: 0,
};
function report(): ActivityReport {
  const services = [
    { serviceId: "fm-original", serviceLabel: "Apple Foundation Models", serviceKind: "apple_fm", provider: "apple_fm" },
    { serviceId: "openai-original", serviceLabel: "OpenAI production", serviceKind: "openai", provider: "openai_compatible" },
    { serviceId: "ollama-original", serviceLabel: "Local Ollama", serviceKind: "ollama", provider: "openai_compatible" },
  ];
  const totals = { ...metrics, attempts: 3, answered: 3, dispatches: 3, dispatchReports: 3, usefulResults: 3, usefulReports: 3, waitReports: 3, requestReports: 3, totalReports: 3 };
  return {
    asOf: new Date().toISOString(), start: utcDay(), end: utcDay(), timeZone: "UTC", firstMeasured: utcDay(), detailedSince: new Date().toISOString(), retentionDays: 90,
    state: "ready", aiEnabled: true, usageEnabled: true, configuredServices: [{ ...services[1], serviceLabel: "Renamed current service" }],
    totals, services: services.map(service => ({ ...service, ...metrics })), purposes: [{ feature: "changes", label: "Change Detection questions", ...totals }],
    trend: [{ day: utcDay(), ...totals }], groups: services.map(service => ({ ...service, ...metrics, feature: "changes", purpose: "Change Detection questions", requested: "requested-model", reported: "reported-model", outcome: "completed", legacy: false })),
    facets: { services, purposes: [{ id: "changes", label: "Change Detection questions" }], models: ["requested-model", "reported-model"], outcomes: [{ id: "completed", label: "Useful result" }] },
    work: { arrivals: 2, completed: 1, failed: 1, cached: 1, skipped: 0, expired: 0, retries: 1, fallbacks: 1 },
    coverage: { legacyAttempts: 0, detailedAttempts: 3, recordingDegradedSince: null, missing: [] },
  };
}
function live(overrides: Partial<LiveActivity> = {}): LiveActivity {
  return {
    asOf: new Date().toISOString(), windowStart: new Date(Date.now() - 900_000).toISOString(), windowSeconds: 900, windowComplete: true,
    state: "keeping_up", label: "Keeping up", message: "Measured completions match arrivals.", nextCheck: "", rule: "Arrivals do not exceed useful completions and no work is overdue.",
    aiEnabled: true, usageEnabled: true, waiting: 0, running: 1, oldestWaitingSeconds: null, arrivals: 2, usefulCompletions: 2, failed: 0, expired: 0, rateLimited: 0, timeouts: 0, waitingTimeouts: 0,
    inventory: { waiting: 0, running: 0, oldestWaitingSeconds: null, enabled: true }, interactive: { waiting: 0, running: 1, oldestWaitingSeconds: null },
    patchInvestigations: { running: 0, oldestRunningSeconds: null, coverage: "partial" }, coverage: { detailedSince: new Date().toISOString(), recordingDegradedSince: null, missing: [] }, ...overrides,
  };
}
function HistoryControls() {
  const location = useLocation(), navigate = useNavigate();
  return <><output aria-label="Current query">{location.search}</output><button onClick={() => navigate(-1)}>Go back</button><button onClick={() => navigate(1)}>Go forward</button></>;
}
function page(query = "") { return render(<MemoryRouter initialEntries={[`/settings/ai/activity${query}`]}><HistoryControls /><AIActivityPage /></MemoryRouter>); }
beforeEach(() => {
  permission.mockReturnValue(true);
  vi.spyOn(document, "visibilityState", "get").mockReturnValue("visible");
  request.mockImplementation(async path => path === "/system/ai/activity/live" ? live() : report());
});
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); vi.clearAllMocks(); });

describe("AI Activity", () => {
  it("has a permission-gated entry and no provider call just to discover it", () => {
    const view = render(<MemoryRouter><AIActivityEntry /></MemoryRouter>);
    expect(screen.getByRole("link", { name: /AI Activity/ }).getAttribute("href")).toBe("/settings/ai/activity");
    expect(request).not.toHaveBeenCalled();
    permission.mockReturnValue(false); view.rerender(<MemoryRouter><AIActivityEntry /></MemoryRouter>);
    expect(screen.queryByRole("link")).toBeNull();
  });
  it("shows actual service attribution, unknown coverage, and separate current work", async () => {
    page(); await screen.findByText("Which services handled the calls?");
    for (const name of ["Apple Foundation Models", "OpenAI production", "Local Ollama"]) expect(screen.getByRole("button", { name })).toBeTruthy();
    expect(screen.queryByText("Renamed current service")).toBeNull();
    expect(screen.getAllByText("Unknown").length).toBeGreaterThan(1);
    expect(screen.getAllByText("0/1 attempts measured").length).toBeGreaterThan(1);
    expect(screen.getByText("Keeping up")).toBeTruthy();
    expect(screen.getByRole("link", { name: "Provider setup" }).getAttribute("href")).toBe("/settings/ai");
    expect(request.mock.calls.every(([, options]) => !options?.method || options.method === "GET")).toBe(true);
  });
  it("composes URL filters, chart drilldown and back/forward without filtering the live read", async () => {
    page("?purpose=changes&model=requested-model&outcome=completed");
    fireEvent.click(await screen.findByRole("button", { name: "Local Ollama" }));
    await waitFor(() => expect(screen.getByLabelText("Current query").textContent).toContain("service=ollama-original"));
    expect(screen.getByLabelText("Current query").textContent).toContain("purpose=changes");
    await screen.findByText("Which services handled the calls?");
    fireEvent.click(screen.getByRole("button", { name: `${utcDay()}: 3 attempts` }));
    await waitFor(() => expect(screen.getByLabelText("From (UTC)").getAttribute("value")).toBe(utcDay()));
    fireEvent.click(screen.getByRole("button", { name: "Go back" }));
    await waitFor(() => expect(screen.getByLabelText("From (UTC)").getAttribute("value")).toBe(utcDay(-29)));
    fireEvent.click(screen.getByRole("button", { name: "Go forward" }));
    await waitFor(() => expect(screen.getByLabelText("From (UTC)").getAttribute("value")).toBe(utcDay()));
    expect(request.mock.calls.filter(([path]) => path.startsWith("/system/ai/activity/live"))).toHaveLength(1);
    expect(request.mock.calls.some(([path]) => path.includes("service=ollama-original") && path.includes("purpose=changes") && path.includes("model=requested-model") && path.includes("outcome=completed"))).toBe(true);
  });
  it("clears settled history during a filter read and never paints old totals as the new answer", async () => {
    page(); await screen.findByText("Which services handled the calls?");
    let finish!: (value: ActivityReport) => void;
    request.mockImplementation(path => path === "/system/ai/activity/live" ? Promise.resolve(live()) : new Promise(resolve => { finish = resolve; }));
    fireEvent.change(screen.getByLabelText("Service"), { target: { value: "fm-original" } });
    expect(screen.queryByText("Which services handled the calls?")).toBeNull();
    expect(screen.getByText("Reading AI history…")).toBeTruthy();
    await act(async () => finish({ ...report(), state: "no_matches", services: [], groups: [], purposes: [] }));
    expect(screen.getByText(/No attempts match these filters/)).toBeTruthy();
  });
  it("retains disabled history and distinguishes no calls, no matches and unreadable history", async () => {
    request.mockImplementation(async path => path === "/system/ai/activity/live" ? live({ state: "disabled", label: "Not running" }) : { ...report(), aiEnabled: false, state: "no_calls" });
    page(); expect(await screen.findByText(/AI inference is disabled/)).toBeTruthy();
    expect(screen.getByText(/No inference attempts were recorded/)).toBeTruthy();
    request.mockRejectedValue(new ApiError(403, "forbidden")); fireEvent.click(screen.getByRole("button", { name: "Refresh history" }));
    expect(await screen.findByText(/Ask an administrator for system read access/)).toBeTruthy();
    expect(screen.queryByText("Inference attempts")).toBeNull();
  });
  it("rejects malformed history and invalid date ranges without pretending there were no calls", async () => {
    request.mockImplementation(async path => path === "/system/ai/activity/live" ? live() : null);
    page("?start=2026-01-01&end=2026-01-01");
    expect(await screen.findByText(/AI history could not be read/)).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Through (UTC)"), { target: { value: "2026-05-01" } });
    expect(screen.getByText(/inclusive range of 1–90 days/)).toBeTruthy();
    expect(screen.queryByText(/No inference attempts were recorded/)).toBeNull();
  });
});

describe("live workload freshness", () => {
  it("removes a healthy verdict on a failed refresh and recovers only on a successful read", async () => {
    render(<LiveActivityPanel />); await screen.findByText("Keeping up");
    request.mockRejectedValue(new Error("offline")); fireEvent.click(screen.getByRole("button", { name: "Refresh live workload" }));
    await screen.findByText("Measurement unavailable");
    expect(screen.queryByText("Keeping up")).toBeNull(); expect(screen.queryByText("Waiting")).toBeNull();
    expect(screen.getByText(/Last successful reading/)).toBeTruthy();
    request.mockResolvedValue(live({ state: "backlog_growing", label: "Backlog growing", waiting: 4, arrivals: 5, usefulCompletions: 2 }));
    fireEvent.click(screen.getByRole("button", { name: "Refresh live workload" }));
    expect(await screen.findByText("Backlog growing")).toBeTruthy();
  });
  it("expires a stalled read, pauses polling while hidden, and refreshes on return", async () => {
    vi.useFakeTimers(); vi.setSystemTime(new Date("2026-11-23T12:00:00Z"));
    const visibility = vi.spyOn(document, "visibilityState", "get"); visibility.mockReturnValue("visible");
    render(<LiveActivityPanel />); await act(async () => { await Promise.resolve(); });
    expect(screen.getByText("Keeping up")).toBeTruthy();
    request.mockImplementation(() => new Promise(() => {}));
    await act(async () => { await vi.advanceTimersByTimeAsync(46_000); });
    expect(screen.getByText("Measurement unavailable")).toBeTruthy(); expect(screen.queryByText("Keeping up")).toBeNull();
    visibility.mockReturnValue("hidden"); fireEvent(document, new Event("visibilitychange"));
    const calls = request.mock.calls.length;
    await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
    expect(request).toHaveBeenCalledTimes(calls);
    request.mockResolvedValue(live({ state: "idle", label: "Idle" })); visibility.mockReturnValue("visible");
    await act(async () => { fireEvent(document, new Event("visibilitychange")); await Promise.resolve(); });
    expect(screen.getByText("Idle")).toBeTruthy();
  });
  it("rejects a successful HTTP read with an unreadable measurement body", async () => {
    request.mockResolvedValue({ state: "keeping_up" }); render(<LiveActivityPanel />);
    expect(await screen.findByText("Measurement unavailable")).toBeTruthy(); expect(screen.queryByText("Keeping up")).toBeNull();
  });
});

it("validates real report shapes, leap dates and preserved safe filters", () => {
  expect(isActivityReport(report())).toBe(true); expect(isLiveActivity(live())).toBe(true);
  expect(isLiveActivity({ ...live(), waiting: -1 })).toBe(false);
  expect(isActivityReport({ ...report(), totals: { ...metrics, attempts: "3" } })).toBe(false);
  expect(rangeError("2026-02-30", "2026-03-01")).toMatch(/valid/);
  expect(rangeError("2024-02-29", "2024-02-29")).toBeNull();
  expect(activityQuery(new URLSearchParams("?provider=openai_compatible&model=example&password=ignored")).has("password")).toBe(false);
});


describe("historical logical-work measurement coverage", () => {
  it.each([null, "2026-11-23T10:00:00Z"])("does not turn a period before granular measurement into zero work (%s)", since => {
    const data = { ...report(), start: "2026-10-01", end: "2026-10-03", detailedSince: since,
      coverage: { ...report().coverage, legacyAttempts: 3, detailedAttempts: 0 } };
    render(<ActivitySummary report={data} select={vi.fn()} />);
    expect(screen.getByText(/Logical work was not measured in this period/)).toBeTruthy();
    expect(screen.queryByText(/Measured logical work:/)).toBeNull();
  });
  it("labels the measured part of a period without claiming legacy work was counted", () => {
    const data = { ...report(), start: "2026-11-22", end: "2026-11-23", detailedSince: "2026-11-23T10:00:00Z",
      coverage: { ...report().coverage, legacyAttempts: 1, detailedAttempts: 2 } };
    render(<ActivitySummary report={data} select={vi.fn()} />);
    expect(screen.getByText(/Measured logical work:/)).toBeTruthy();
    expect(screen.getByText(/Work counts cover only recorded lifecycle events/)).toBeTruthy();
    expect(screen.getByText(/Arrivals use arrival time; terminal outcomes use completion time/)).toBeTruthy();
  });
});
