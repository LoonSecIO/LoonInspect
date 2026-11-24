// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, useLocation, useNavigate } from "react-router";
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
afterEach(() => { cleanup(); vi.resetAllMocks(); });

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
  it("offers retry when the policy read fails", async () => {
    vi.mocked(getChangePolicy).mockRejectedValueOnce(new Error("offline"));
    open("?section=operating_system");
    fireEvent.click(await screen.findByRole("button", { name: "Retry field choices" }));
    await screen.findByRole("option", { name: "OS version" });
    expect(screen.queryByRole("button", { name: "Retry field choices" })).toBeNull();
  });
});
