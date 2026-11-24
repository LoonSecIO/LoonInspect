// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter, MemoryRouter, useLocation, useNavigate } from "react-router";
import { Suspense, type ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "@/config/api";
import { LocaleProvider } from "@/i18n/LocaleContext";
import { ChangesPage } from "./ChangesPage";
import { getChangePolicy, getPromptStatus, listChanges } from "./api";
import { localTime } from "./filters";
import type { ChangeFilters, ChangePolicy, DeviceChange } from "./types";

vi.mock("./api", () => ({ getChangePolicy: vi.fn(), getPromptStatus: vi.fn(), listChanges: vi.fn(), askPrompt: vi.fn() }));
const policy: ChangePolicy = { version: "v0", minimumLevel: "normal", systemAppsIndividually: false, mutedGroups: [], mutedExtensionAttributes: [],
  sections: [{ section: "operating_system", fields: [{ key: "operating_system.version", field: "version", scalar: true,
    label: "OS version", level: "high", why: "Patch state", default: true, enabled: true, overridden: false }] }],
  entries: [], knownGroups: [], knownExtensionAttributes: [], updatedAt: null };
const row: DeviceChange = { id: 870, mdmConnectionId: 7, subjectKind: "computer", subjectId: "42", subjectLabel: "Synthetic Mac",
  serialNumber: "SYNTHETIC870", udid: null, spanId: null, previousSpanId: null, observedAt: "2026-11-23T12:00:00Z",
  collectedAt: "2026-11-24T12:00:00Z", trigger: "sweep", section: "operating_system", field: "version", entryKind: null,
  entryIdentity: null, entryLabel: null, change: "changed", oldValue: { value: "27.2" }, newValue: { value: "27.2.1" },
  level: "high", details: null, deviceMeta: null, policyVersion: "v0" };
function Navigation() {
  const location = useLocation(), navigate = useNavigate();
  return <><output data-testid="query">{location.search}</output><button onClick={() => navigate(-1)}>Back</button><button onClick={() => navigate(1)}>Forward</button></>;
}
function open(search = "") {
  return render(<LocaleProvider><MemoryRouter initialEntries={[`/devices/changes${search}`]}><Navigation /><ChangesPage /></MemoryRouter></LocaleProvider>);
}
beforeEach(() => {
  localStorage.setItem("locale", "en");
  vi.mocked(getChangePolicy).mockResolvedValue(policy);
  vi.mocked(getPromptStatus).mockResolvedValue({ available: false, reason: "flag_off", providers: [] });
  vi.mocked(listChanges).mockImplementation(async (filters: ChangeFilters) => ({ items: filters.changedTo ? [row] : [], total: filters.changedTo ? 51 : 0,
    devicesTotal: filters.changedTo ? 3 : 0, page: filters.page ?? 1, pageSize: 50, userFilter: null }));
});
afterEach(() => { cleanup(); window.history.replaceState(null, "", "/"); vi.resetAllMocks(); });

describe("Changes deterministic filters", () => {
  it("answers exact OS changed-to with AI disabled, local bounds, evidence, counts and browser history", async () => {
    open("?artifact=Synthetic+App&level=low&spanId=synthetic-link");
    await screen.findByRole("option", { name: "Operating system" });
    fireEvent.change(screen.getByLabelText("Observed from (inclusive)"), { target: { value: "2026-11-20T09:00" } });
    fireEvent.change(screen.getByLabelText("Observed until (exclusive)"), { target: { value: "2026-11-24T17:00" } });
    fireEvent.change(screen.getByLabelText("Department ID"), { target: { value: "870" } });
    fireEvent.click(screen.getByRole("button", { name: "Example: OS changed to 27.2.1" }));
    await screen.findByText("51 matching changes · 3 distinct devices");
    expect(screen.queryByLabelText("Prompt")).toBeNull();
    expect(screen.getByText("Synthetic Mac")).toBeTruthy();
    expect(screen.getByText("Subject type: Computer")).toBeTruthy();
    expect(screen.getByText("27.2")).toBeTruthy();
    expect(screen.getByText("27.2.1")).toBeTruthy();
    const applied = vi.mocked(listChanges).mock.calls.at(-1)![0];
    expect(applied).toMatchObject({ section: "operating_system", field: "version", changedTo: "27.2.1", subjectKind: "computer", department: "870",
      artifact: undefined, level: undefined, spanId: undefined, since: new Date("2026-11-20T09:00").toISOString(), until: new Date("2026-11-24T17:00").toISOString() });
    expect(screen.getByText(/Times use your browser timezone:/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() => expect(vi.mocked(listChanges).mock.calls.at(-1)![0]).toMatchObject({ ...applied, page: 2 }));
    fireEvent.click(screen.getByRole("button", { name: "Clear" }));
    await waitFor(() => expect(screen.getByTestId("query").textContent).toBe(""));
    fireEvent.click(screen.getByRole("button", { name: "Back" }));
    await waitFor(() => expect((screen.getByLabelText("Changed to exactly") as HTMLInputElement).value).toBe("27.2.1"));
    expect((screen.getByLabelText("Observed until (exclusive)") as HTMLInputElement).value).toBe(localTime(applied.until).replace(/:00\.000$/, ""));
    fireEvent.click(screen.getByRole("button", { name: "Forward" }));
    await waitFor(() => expect(screen.getByTestId("query").textContent).toBe(""));
  });
  it("restores drafts when browser Back cancels a filter render before it commits", async () => {
    const initial = "/devices/changes?section=operating_system&field=version&changedTo=27.2.1&q=Original";
    window.history.replaceState(null, "", initial);
    let holdIntermediate = true;
    let release = () => {};
    const pending = new Promise<void>(resolve => { release = resolve; });
    function PendingNavigation({ children }: { children: ReactNode }) {
      // Hold the intermediate navigation to reproduce Back arriving before React commits it.
      const location = useLocation();
      if (holdIntermediate && new URLSearchParams(location.search).get("changedTo") === "27.2.10") throw pending;
      return children;
    }
    render(<LocaleProvider><BrowserRouter><Suspense fallback={<p>Pending navigation</p>}>
      <PendingNavigation><ChangesPage /></PendingNavigation>
    </Suspense></BrowserRouter></LocaleProvider>);
    await screen.findByText("51 matching changes · 3 distinct devices");
    fireEvent.change(screen.getByLabelText("Changed to exactly"), { target: { value: "27.2.10" } });
    fireEvent.change(screen.getByLabelText("Device search"), { target: { value: "Unapplied device" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply field, time and device filters" }));
    await waitFor(() => expect(new URLSearchParams(window.location.search).get("changedTo")).toBe("27.2.10"));
    expect(vi.mocked(listChanges).mock.calls.every(([filters]) => filters.changedTo === "27.2.1")).toBe(true);
    window.history.back();
    await waitFor(() => expect(window.location.pathname + window.location.search).toBe(initial));
    await waitFor(() => expect((screen.getByLabelText("Changed to exactly") as HTMLInputElement).value).toBe("27.2.1"));
    expect((screen.getByLabelText("Device search") as HTMLInputElement).value).toBe("Original");
    expect(screen.getByText("51 matching changes · 3 distinct devices")).toBeTruthy();
    expect(listChanges).toHaveBeenCalledTimes(1);
    holdIntermediate = false;
    release();
    window.history.forward();
    await waitFor(() => expect((screen.getByLabelText("Changed to exactly") as HTMLInputElement).value).toBe("27.2.10"));
    await waitFor(() => expect(vi.mocked(listChanges).mock.calls.at(-1)![0]).toMatchObject({ changedTo: "27.2.10", q: "Original" }));
  });
  it("preserves an empty exact target from a shared link when applying device filters", async () => {
    open("?section=operating_system&field=version&changedTo=");
    await screen.findByRole("option", { name: "OS version" });
    fireEvent.change(screen.getByLabelText("Connection ID"), { target: { value: "7" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply field, time and device filters" }));
    await waitFor(() => expect(vi.mocked(listChanges).mock.calls.at(-1)![0]).toMatchObject({ connectionId: 7, changedTo: "" }));
  });
  it("shows and clears a subject-type filter even without a subject ID", async () => {
    open("?subjectKind=computer");
    fireEvent.click(await screen.findByText("Subject type: Computer"));
    await waitFor(() => expect(vi.mocked(listChanges).mock.calls.at(-1)![0].subjectKind).toBeUndefined());
  });
  it("offers catalog fields, applies historical dimensions, and clears field/target when the section changes", async () => {
    open("?section=operating_system");
    await screen.findByRole("option", { name: "OS version" });
    fireEvent.change(screen.getByLabelText("Changed field"), { target: { value: "version" } });
    fireEvent.change(screen.getByLabelText("Changed to exactly"), { target: { value: "27.2.1" } });
    fireEvent.change(screen.getByLabelText("Connection ID"), { target: { value: "7" } });
    fireEvent.change(screen.getByLabelText("Managed by Jamf"), { target: { value: "false" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply field, time and device filters" }));
    await screen.findByText("51 matching changes · 3 distinct devices");
    expect(vi.mocked(listChanges).mock.calls.at(-1)![0]).toMatchObject({ changedTo: "27.2.1", connectionId: 7, managed: "false" });
    fireEvent.change(screen.getByLabelText("Section"), { target: { value: "applications" } });
    await waitFor(() => expect(vi.mocked(listChanges).mock.calls.at(-1)![0]).toMatchObject({ section: "applications", field: undefined, changedTo: undefined, managed: "false" }));
  });
  it("keeps unapplied window and device drafts when Section, Level or another chip moves the URL", async () => {
    open("?trigger=sweep"); await screen.findByText("Found by a sweep");
    const value = (label: string) => (screen.getByLabelText(label) as HTMLInputElement).value;
    fireEvent.change(screen.getByLabelText("Observed from (inclusive)"), { target: { value: "2026-11-20T09:00" } });
    fireEvent.change(screen.getByLabelText("Observed until (exclusive)"), { target: { value: "2026-11-24T17:00" } });
    fireEvent.change(screen.getByLabelText("Department ID"), { target: { value: "870" } });
    fireEvent.change(screen.getByLabelText("Section"), { target: { value: "operating_system" } });
    await waitFor(() => expect(vi.mocked(listChanges).mock.calls.at(-1)![0].section).toBe("operating_system"));
    fireEvent.change(screen.getByLabelText("Level"), { target: { value: "high" } });
    fireEvent.click(screen.getByText("Found by a sweep"));
    await waitFor(() => expect(vi.mocked(listChanges).mock.calls.at(-1)![0]).toMatchObject({ level: "high", trigger: undefined }));
    expect([value("Observed from (inclusive)"), value("Observed until (exclusive)"), value("Department ID")])
      .toEqual(["2026-11-20T09:00", "2026-11-24T17:00", "870"]);
    expect((screen.getByRole("button", { name: "Clear" }) as HTMLButtonElement).disabled).toBe(false);
    fireEvent.change(screen.getByLabelText("Changed field"), { target: { value: "version" } });
    fireEvent.change(screen.getByLabelText("Changed to exactly"), { target: { value: "27.2.1" } });
    // A field belongs to its section: a new section takes the unapplied field and target with it.
    fireEvent.change(screen.getByLabelText("Section"), { target: { value: "applications" } });
    await waitFor(() => expect(value("Changed field")).toBe(""));
    expect(value("Changed to exactly")).toBe("");
    expect(value("Department ID")).toBe("870");
    fireEvent.change(screen.getByLabelText("Section"), { target: { value: "operating_system" } });
    await screen.findByRole("option", { name: "OS version" });
    fireEvent.change(screen.getByLabelText("Changed field"), { target: { value: "version" } });
    fireEvent.change(screen.getByLabelText("Changed to exactly"), { target: { value: "27.2.1" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply field, time and device filters" }));
    await screen.findByText("51 matching changes · 3 distinct devices");
    expect(vi.mocked(listChanges).mock.calls.at(-1)![0]).toMatchObject({ section: "operating_system", field: "version", changedTo: "27.2.1",
      level: "high", department: "870", since: new Date("2026-11-20T09:00").toISOString(), until: new Date("2026-11-24T17:00").toISOString() });
  });
  it("refuses a reversed window before fetching and makes unapplied drafts clearable", async () => {
    open(); await waitFor(() => expect(listChanges).toHaveBeenCalledTimes(1));
    fireEvent.change(screen.getByLabelText("Observed from (inclusive)"), { target: { value: "2026-11-24T12:00" } });
    fireEvent.change(screen.getByLabelText("Observed until (exclusive)"), { target: { value: "2026-11-23T12:00" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply field, time and device filters" }));
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", expect.stringContaining("end must be later"));
    expect(listChanges).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole("button", { name: "Clear" }));
    expect((screen.getByLabelText("Observed from (inclusive)") as HTMLInputElement).value).toBe("");
  });
  it("shows an actionable API validation error without stale result rows or counts", async () => {
    vi.mocked(listChanges).mockRejectedValue(new ApiError(422, "Choose a section and field before filtering by Changed to."));
    open("?changedTo=27.2.1");
    await screen.findByText("Choose a section and field before filtering by Changed to.");
    expect(screen.queryByText(/matching changes/)).toBeNull();
    expect(screen.queryByText("Synthetic Mac")).toBeNull();
  });
  it("keeps u_ usernames and token-shaped text literal while editing the assigned-user draft", async () => {
    open(); await waitFor(() => expect(listChanges).toHaveBeenCalledTimes(1));
    const input = screen.getByLabelText("Assigned user contains") as HTMLInputElement;
    for (const character of "u_admin") {
      const value = input.value + character;
      fireEvent.change(input, { target: { value } });
      expect(input.value).toBe(value);
    }
    fireEvent.click(screen.getByRole("button", { name: "Apply field, time and device filters" }));
    await waitFor(() => expect(vi.mocked(listChanges).mock.calls.at(-1)![0].user).toBe("u_admin"));
    expect(screen.getByText("Assigned user matching “u_admin”")).toBeTruthy();
    const appliedInput = screen.getByLabelText("Assigned user contains") as HTMLInputElement;
    const literal = "u_1234567890123456";
    fireEvent.change(appliedInput, { target: { value: literal } });
    expect(appliedInput.value).toBe(literal);
  });
  it("does not reuse another token's resolved name while the next query waits or fails", async () => {
    const previous = "u_0000000000000000", current = "u_1111111111111111";
    let rejectPending: (reason: Error) => void = () => {};
    const pending = new Promise<never>((_, reject) => { rejectPending = reject; });
    vi.mocked(listChanges).mockImplementation(async filters => filters.user === previous
      ? { items: [], total: 0, devicesTotal: 0, page: 1, pageSize: 50, userFilter: { token: previous, display: "Previous Person" } }
      : pending);
    render(<LocaleProvider><MemoryRouter initialEntries={[
      `/devices/changes?user=${current}`, `/devices/changes?user=${previous}`
    ]} initialIndex={1}><Navigation /><ChangesPage /></MemoryRouter></LocaleProvider>);
    await waitFor(() => expect((screen.getByLabelText("Assigned user contains") as HTMLInputElement).value).toBe("Previous Person"));
    fireEvent.click(screen.getByRole("button", { name: "Back" }));
    await waitFor(() => expect(vi.mocked(listChanges).mock.calls.at(-1)![0].user).toBe(current));
    expect((screen.getByLabelText("Assigned user contains") as HTMLInputElement).value).toBe("Assigned user from shared link");
    rejectPending(new ApiError(503, "Synthetic query unavailable."));
    await screen.findByText("Synthetic query unavailable.");
    expect((screen.getByLabelText("Assigned user contains") as HTMLInputElement).value).toBe("Assigned user from shared link");
  });
  it("offers retry when the policy read fails", async () => {
    vi.mocked(getChangePolicy).mockRejectedValueOnce(new Error("offline"));
    open("?section=operating_system");
    fireEvent.click(await screen.findByRole("button", { name: "Retry field choices" }));
    await screen.findByRole("option", { name: "OS version" });
    expect(screen.queryByRole("button", { name: "Retry field choices" })).toBeNull();
  });
});
