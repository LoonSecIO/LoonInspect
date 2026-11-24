// @vitest-environment jsdom
import { createRef } from "react";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiRequest } from "@/config/api";
import { PatchPlanWorkspace, type PatchPlanActions } from "./PatchPlanWorkspace";
import { forgetReviewDraft, forgetSubmittedReviewDraft, readReviewDraft, rememberReviewDraft } from "./patchPlanDraft";
import type { PatchPlan } from "./patchPlanTypes";

vi.mock("@/config/api", async importOriginal => ({ ...await importOriginal<typeof import("@/config/api")>(), apiRequest: vi.fn() }));
vi.mock("@/features/auth/store", () => ({ useHasPermission: () => true, useAuthStore: () => ({ id: "operator", tenant: { id: "tenant" } }) }));
const request = vi.mocked(apiRequest);
const appHash = "a".repeat(32);
const plan: PatchPlan = {
  id: "saved-plan", title: "Engineering pilot", createdAt: "2026-11-22T18:00:00Z", createdBy: "Operator", revision: 1,
  sha256: "a".repeat(64), researchStatus: "not_started", researchStartedAt: null, research: null,
  snapshot: { organization: "Example", status: "Draft", asOf: "2026-11-22T18:00:00Z", scope: { match: "all", rules: [] },
    scopeDescription: ["Managed Engineering Macs"], scopedDevices: 5, applicationDevices: 2, sources: [], limitations: ["Draft plan"],
    applications: [{ appHash, name: "GitHub Desktop.app", bundleId: "com.github.GitHubClient", devices: 2, status: "draft",
      targetVersion: "3.4.14", versions: [], options: [], gaps: ["Verify Jamf configuration"], steps: ["Verify identity", "Pilot in Jamf"] }] },
};
beforeEach(() => {
  sessionStorage.clear();
  request.mockImplementation(async (path, options) => {
    if (path.endsWith("ai-status")) return { available: true, reason: null, providers: [{ provider: "openai_compatible", model: "qwen3.8:27b-mlx" }] };
    if (path === "/application-patch-plans" && !options?.method) return [{ ...plan, applications: plan.snapshot.applications }];
    if (options?.method === "PATCH") return { ...plan, revision: 2, snapshot: { ...plan.snapshot, operatorReview: options.json } };
    return plan;
  });
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); forgetReviewDraft("looninspect.patch-review.tenant.operator.saved-plan"); forgetReviewDraft("looninspect.patch-review.tenant.operator.other-plan"); vi.clearAllMocks(); });

describe("Installed Applications patch plans", () => {
  it("shows a next check instead of a link when a source URL was withheld", async () => {
    const original = request.getMockImplementation()!;
    const withheld: PatchPlan = { ...plan, snapshot: { ...plan.snapshot, applications: [{ ...plan.snapshot.applications[0],
      options: [{ source: "Jamf Patch", title: "Synthetic title", reference: "title", status: "catalog_match", targetVersion: "2",
        url: "", observedAt: null, sourceRevision: "synthetic", detail: "Verify source identity." }] }] } };
    request.mockImplementation((path, options) => path === "/application-patch-plans/saved-plan"
      ? Promise.resolve(withheld) : original(path, options));
    render(<MemoryRouter><PatchPlanWorkspace ref={createRef()} scope='{"match":"all","rules":[]}' selected={[]}
      planId="saved-plan" onOpen={vi.fn()} onClear={vi.fn()} /></MemoryRouter>);
    expect(await screen.findByText("Source URL withheld. Check the configured catalog address.")).toBeTruthy();
    expect(screen.queryByRole("link", { name: "View source" })).toBeNull();
  });

  it("builds the selected app with the exact applied device filter", async () => {
    const actions = createRef<PatchPlanActions>();
    const onOpen = vi.fn();
    const scope = JSON.stringify({ match: "all", connectionId: 4, rules: [{ field: "managed", operator: "is", value: "true", key: "" }] });
    render(<MemoryRouter><PatchPlanWorkspace ref={actions} scope={scope} selected={[appHash]} planId={null} onOpen={onOpen} onClear={vi.fn()} /></MemoryRouter>);
    await act(async () => { actions.current?.build([appHash]); });
    expect(request).toHaveBeenCalledWith("/application-patch-plans", expect.objectContaining({ method: "POST", json: {
      scope: JSON.parse(scope), appHashes: [appHash], title: "Application patch plan" } }));
    expect(onOpen).toHaveBeenCalledWith("saved-plan");
  });

  it("explains an invalid device scope from a direct planning link without creating a plan", async () => {
    render(<MemoryRouter><PatchPlanWorkspace scope="invalid-json" selected={[appHash]} planId={null} onOpen={vi.fn()} onClear={vi.fn()} /></MemoryRouter>);
    fireEvent.click(screen.getByRole("button", { name: "Build plan for 1 selected apps" }));
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", expect.stringContaining("device scope is invalid"));
    expect(request.mock.calls.some(([, options]) => options?.method === "POST")).toBe(false);
  });

  it("blocks export until visible review notes have been saved to a new revision", async () => {
    render(<MemoryRouter><PatchPlanWorkspace ref={createRef()} scope='{"match":"all","rules":[]}' selected={[]}
      planId="saved-plan" onOpen={vi.fn()} onClear={vi.fn()} /></MemoryRouter>);
    const owner = await screen.findByLabelText("Plan owner");
    const exporter = screen.getByRole("button", { name: "Export plan as PDF" }) as HTMLButtonElement;
    expect(exporter.disabled).toBe(false);
    fireEvent.change(owner, { target: { value: "Endpoint engineering" } });
    expect(exporter.disabled).toBe(true);
    expect((screen.getByRole("button", { name: "Refresh plans and AI" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Save review notes" }));
    await waitFor(() => expect(exporter.disabled).toBe(false));
    expect(request).toHaveBeenCalledWith("/application-patch-plans/saved-plan", expect.objectContaining({ method: "PATCH",
      json: expect.objectContaining({ owner: "Endpoint engineering", revision: 1 }) }));
    expect(screen.getByText(/revision 2/)).toBeTruthy();
  });

  it("uses an explicit AI choice for background investigation", async () => {
    render(<MemoryRouter><PatchPlanWorkspace ref={createRef()} scope='{"match":"all","rules":[]}' selected={[]}
      planId="saved-plan" onOpen={vi.fn()} onClear={vi.fn()} /></MemoryRouter>);
    fireEvent.click(await screen.findByLabelText("Include AI review priorities"));
    fireEvent.click(await screen.findByRole("button", { name: "Investigate patch methods" }));
    await waitFor(() => expect(request).toHaveBeenCalledWith("/application-patch-plans/saved-plan/research", expect.objectContaining({
      method: "POST", json: { installomator: true, provider: "openai_compatible" } })));
  });

  it("keeps export blocked when notes change during a refresh of the same revision", async () => {
    render(<MemoryRouter><PatchPlanWorkspace ref={createRef()} scope='{"match":"all","rules":[]}' selected={[]}
      planId="saved-plan" onOpen={vi.fn()} onClear={vi.fn()} /></MemoryRouter>);
    const owner = await screen.findByLabelText("Plan owner");
    const original = request.getMockImplementation()!;
    let finish!: (value: PatchPlan) => void;
    const pending = new Promise<PatchPlan>(resolve => { finish = resolve; });
    request.mockImplementation((path, options) => path === "/application-patch-plans/saved-plan" && !options?.method
      ? pending : original(path, options));
    fireEvent.click(screen.getByRole("button", { name: "Refresh plans and AI" }));
    fireEvent.change(owner, { target: { value: "Unsaved owner" } });
    await act(async () => { finish({ ...plan }); });
    expect((screen.getByLabelText("Plan owner") as HTMLTextAreaElement).value).toBe("Unsaved owner");
    expect((screen.getByRole("button", { name: "Export plan as PDF" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("does not replace the selected plan when an earlier plan's save finishes", async () => {
    const original = request.getMockImplementation()!;
    let finish!: (value: PatchPlan) => void;
    const pending = new Promise<PatchPlan>(resolve => { finish = resolve; });
    const other = { ...plan, id: "other-plan", title: "Another pilot" };
    request.mockImplementation((path, options) => options?.method === "PATCH" ? pending
      : path === "/application-patch-plans/other-plan" ? Promise.resolve(other) : original(path, options));
    const actions = createRef<PatchPlanActions>();
    const view = (id: string) => <MemoryRouter><PatchPlanWorkspace ref={actions} scope='{"match":"all","rules":[]}' selected={[]}
      planId={id} onOpen={vi.fn()} onClear={vi.fn()} /></MemoryRouter>;
    const rendered = render(view("saved-plan"));
    fireEvent.change(await screen.findByLabelText("Plan owner"), { target: { value: "Owner" } });
    fireEvent.click(screen.getByRole("button", { name: "Save review notes" }));
    rendered.rerender(view("other-plan"));
    await screen.findByRole("heading", { name: "Another pilot" });
    await act(async () => { finish({ ...plan, revision: 2 }); });
    expect(screen.getByRole("heading", { name: "Another pilot" })).toBeTruthy();
    expect((screen.getByRole("button", { name: "Export plan as PDF" }) as HTMLButtonElement).disabled).toBe(false);
  });

  it("restores unsaved notes and keeps export blocked when reopening a plan", async () => {
    const actions = createRef<PatchPlanActions>();
    const view = (id: string | null) => <MemoryRouter><PatchPlanWorkspace ref={actions} scope='{"match":"all","rules":[]}' selected={[]}
      planId={id} onOpen={vi.fn()} onClear={vi.fn()} /></MemoryRouter>;
    const rendered = render(view("saved-plan"));
    fireEvent.change(await screen.findByLabelText("Plan owner"), { target: { value: "Discarded owner" } });
    rendered.rerender(view(null));
    rendered.rerender(view("saved-plan"));
    await waitFor(() => expect((screen.getByLabelText("Plan owner") as HTMLTextAreaElement).value).toBe("Discarded owner"));
    expect((screen.getByRole("button", { name: "Export plan as PDF" }) as HTMLButtonElement).disabled).toBe(true);
  });
});

it("keeps an unsaved review across navigation when browser storage fails", async () => {
  vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new Error("Storage unavailable"); });
  const view = (id: string | null) => <MemoryRouter><PatchPlanWorkspace scope='{"match":"all","rules":[]}' selected={[]}
    planId={id} onOpen={vi.fn()} onClear={vi.fn()} /></MemoryRouter>;
  const rendered = render(view("saved-plan"));
  fireEvent.change(await screen.findByLabelText("Plan owner"), { target: { value: "Unsaved tab draft" } });
  expect(screen.getByText(/Browser storage is unavailable/)).toBeTruthy();
  rendered.rerender(view(null));
  const leaving = new Event("beforeunload", { cancelable: true }); window.dispatchEvent(leaving);
  expect(leaving.defaultPrevented).toBe(true);
  rendered.rerender(view("saved-plan"));
  expect((await screen.findByLabelText("Plan owner") as HTMLTextAreaElement).value).toBe("Unsaved tab draft");
  expect((screen.getByRole("button", { name: "Export plan as PDF" }) as HTMLButtonElement).disabled).toBe(true);
});


it("clears the matching persisted draft when a save succeeds after navigation", async () => {
  const original = request.getMockImplementation()!;
  let finish!: (value: PatchPlan) => void;
  const pending = new Promise<PatchPlan>(resolve => { finish = resolve; });
  let saved = false;
  const next = { ...plan, revision: 2, snapshot: { ...plan.snapshot, operatorReview: { owner: "Owner" } } };
  request.mockImplementation((path, options) => options?.method === "PATCH" ? pending
    : path === "/application-patch-plans/saved-plan" && saved ? Promise.resolve(next) : original(path, options));
  const view = (id: string | null) => <MemoryRouter><PatchPlanWorkspace scope='{"match":"all","rules":[]}' selected={[]}
    planId={id} onOpen={vi.fn()} onClear={vi.fn()} /></MemoryRouter>;
  const rendered = render(view("saved-plan"));
  fireEvent.change(await screen.findByLabelText("Plan owner"), { target: { value: "Owner" } });
  fireEvent.click(screen.getByRole("button", { name: "Save review notes" }));
  rendered.rerender(view(null));
  saved = true;
  await act(async () => { finish(next); });
  rendered.rerender(view("saved-plan"));
  await waitFor(() => expect(screen.getByText("Example · revision 2 · Draft")).toBeTruthy());
  expect(screen.queryByText(/This draft is from revision/)).toBeNull();
  expect((screen.getByRole("button", { name: "Export plan as PDF" }) as HTMLButtonElement).disabled).toBe(false);
});


it("preserves newer draft edits when an earlier save finishes after navigation", async () => {
  const original = request.getMockImplementation()!;
  let finish!: (value: PatchPlan) => void;
  const pending = new Promise<PatchPlan>(resolve => { finish = resolve; });
  request.mockImplementation((path, options) => options?.method === "PATCH" ? pending : original(path, options));
  const view = (id: string | null) => <MemoryRouter><PatchPlanWorkspace scope='{"match":"all","rules":[]}' selected={[]}
    planId={id} onOpen={vi.fn()} onClear={vi.fn()} /></MemoryRouter>;
  const rendered = render(view("saved-plan"));
  fireEvent.change(await screen.findByLabelText("Plan owner"), { target: { value: "Submitted owner" } });
  fireEvent.click(screen.getByRole("button", { name: "Save review notes" }));
  rendered.rerender(view(null)); rendered.rerender(view("saved-plan"));
  fireEvent.change(await screen.findByLabelText("Plan owner"), { target: { value: "Newer owner" } });
  await act(async () => { finish({ ...plan, revision: 2 }); });
  expect(JSON.parse(sessionStorage.getItem("looninspect.patch-review.tenant.operator.saved-plan")!).values.owner).toBe("Newer owner");
  expect((screen.getByLabelText("Plan owner") as HTMLTextAreaElement).value).toBe("Newer owner");
  expect((screen.getByRole("button", { name: "Export plan as PDF" }) as HTMLButtonElement).disabled).toBe(true);
});


it("does not clear a newer draft revision even when its note values match the completed save", () => {
  const key = "looninspect.patch-review.tenant.operator.saved-plan";
  const values = { owner: "Owner", window: "", pilot: "", recovery: "", exceptions: "", approval: "" };
  rememberReviewDraft(key, { revision: 2, values });
  expect(forgetSubmittedReviewDraft(key, { revision: 1, values })).toBe(true);
  expect(readReviewDraft(key)).toEqual({ revision: 2, values });
});
