// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "@/config/api";
import { useAuthStore } from "@/features/auth/store";
import type { AuthUser } from "@/features/auth/types";
import { LocaleProvider } from "@/i18n/LocaleContext";
import { McpSettingsPage } from "./McpSettingsPage";
import type { McpSettings } from "./api";

const request = vi.hoisted(() => vi.fn());
vi.mock("@/config/api", async importOriginal => ({ ...await importOriginal<typeof import("@/config/api")>(), apiRequest: request }));
const permissions = ["token:create", "mcp:connect", "device:read", "app:read", "vuln:read", "device:sync", "patch:catalog-sync", "system:read", "system:write", "feature-flag:write", "connection:credential-read"];
const user: AuthUser = { id: "user-a", email: "a@example.test", displayName: "A", roles: ["admin"], permissions,
  tenant: { id: "org-a", name: "A", slug: "a" }, tenants: [], isBreakGlass: false, mfaEnrolmentRequired: false };
const settings: McpSettings = { organizationId: "org-a", enabled: true, aiFeaturesEnabled: true, canManage: true,
  endpoint: "/mcp", scopes: permissions.map(value => ({ value, label: value, description: value })), requiredScopes: ["mcp:connect"], disclosure: "Assistant data disclosure." };
const token = { id: "token-a", name: "Codex", scopes: ["mcp:connect", "device:read", "app:read", "vuln:read"],
  token: "li_secret_for_test_only", createdAt: "2026-11-22T10:00:00Z", expiresAt: "2026-12-22T10:00:00Z", lastUsedAt: null };
const headers = { "X-Expected-Tenant-ID": "org-a" };
const open = () => render(<MemoryRouter><LocaleProvider><McpSettingsPage /></LocaleProvider></MemoryRouter>);

beforeEach(() => {
  request.mockReset();
  useAuthStore.setState({ status: "authenticated", user });
  window.localStorage.setItem("locale", "en");
  Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: vi.fn().mockResolvedValue(undefined) } });
  request.mockImplementation(async (path: string, options?: { method?: string }) => {
    if (path === "/mcp/settings") return settings;
    if (path === "/auth/tokens" && options?.method === "POST") return token;
    if (path === "/auth/tokens") return [];
    if (path === "/mcp/test") return { ok: true, toolCount: 8, organizationId: "org-a" };
    return undefined;
  });
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe("AI connection settings", () => {
  it("creates a finite, explicit read token and never embeds its secret in client setup text", async () => {
    open();
    const create = await screen.findByRole("button", { name: "Create connection token" });
    expect((screen.getByLabelText("Expires in (days)") as HTMLInputElement).value).toBe("30");
    expect(screen.queryByText("connection:credential-read")).toBeNull();
    expect((screen.getByLabelText("Start device inventory refreshes") as HTMLInputElement).checked).toBe(false);
    fireEvent.click(create);
    const secret = await screen.findByLabelText("New connection token") as HTMLInputElement;
    expect(secret.type).toBe("password");
    expect(secret.value).toBe(token.token);
    expect(request).toHaveBeenCalledWith("/auth/tokens", { method: "POST", headers, json: {
      name: "Codex", expiresInDays: 30, scopes: ["mcp:connect", "device:read", "app:read", "vuln:read"],
    } });
    expect(screen.getByLabelText("MCP client configuration").textContent).not.toContain(token.token);
    fireEvent.click(screen.getByRole("button", { name: "Copy token" }));
    await waitFor(() => expect(navigator.clipboard.writeText).toHaveBeenCalledWith(token.token));
    fireEvent.click(screen.getByRole("button", { name: "Test connection" }));
    await screen.findByText("Connection accepted; 8 tools available to this token.");
    fireEvent.click(screen.getByRole("button", { name: "I have saved the token" }));
    expect(screen.queryByLabelText("New connection token")).toBeNull();
    expect((screen.getByLabelText("Connection token to test") as HTMLInputElement).value).toBe("");
    expect(screen.queryByText("Connection accepted; 8 tools available to this token.")).toBeNull();
    expect(window.localStorage.getItem("LOONINSPECT_MCP_TOKEN")).toBeNull();
  });

  it("keeps consent and the master flag independent, with existing tokens still revocable", async () => {
    request.mockImplementation(async (path: string, options?: { method?: string }) => {
      if (path === "/auth/tokens") return [token, { ...token, id: "unrelated", name: "Legacy automation", scopes: [] }];
      if (path === "/mcp/settings") return { ...settings, enabled: options?.method === "PATCH", aiFeaturesEnabled: false };
    });
    open();
    fireEvent.click(await screen.findByRole("button", { name: "Allow AI connections" }));
    await screen.findByRole("button", { name: "Turn off AI connections" });
    expect(request).toHaveBeenCalledWith("/mcp/settings", { method: "PATCH", headers, json: { enabled: true } });
    expect((screen.getByRole("button", { name: "Create connection token" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByRole("link", { name: "Open Feature Flags" })).toBeTruthy();
    expect(screen.queryByText("Legacy automation")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Revoke" }));
    await screen.findByText("You have no AI connection tokens in this organization.");
    expect(request).toHaveBeenCalledWith("/auth/tokens/token-a", { method: "DELETE", headers });
    expect(request.mock.calls.some(([path]) => String(path).startsWith("/feature-flags"))).toBe(false);
  });

  it("offers only the user's scopes and never offers a non-admin the consent toggle", async () => {
    useAuthStore.setState({ user: { ...user, permissions: ["token:create", "mcp:connect", "device:read"] } });
    request.mockImplementation(async (path: string) => path === "/mcp/settings" ? { ...settings, canManage: false } : []);
    open();
    await screen.findByText("An administrator must change this organization's consent setting.");
    expect(screen.queryByRole("button", { name: "Turn off AI connections" })).toBeNull();
    expect(screen.getByLabelText("Read devices and inventory changes")).toBeTruthy();
    expect(screen.queryByLabelText("Start device inventory refreshes")).toBeNull();
    expect(screen.queryByLabelText("Read system health")).toBeNull();
  });

  it("checks the token for this organization and distinguishes discovery from client reachability", async () => {
    open();
    fireEvent.change(await screen.findByLabelText("Connection token to test"), { target: { value: token.token } });
    fireEvent.click(screen.getByRole("button", { name: "Test connection" }));
    await screen.findByText("Connection accepted; 8 tools available to this token.");
    expect(request).toHaveBeenCalledWith("/mcp/test", { method: "POST", headers, json: { token: token.token } });
    expect(screen.getByText(/It does not test whether the assistant can reach/)).toBeTruthy();
    fireEvent.change(screen.getByRole("combobox", { name: "Assistant" }), { target: { value: "claude-desktop" } });
    fireEvent.change(screen.getByRole("combobox", { name: "LoonInspect deployment" }), { target: { value: "http" } });
    expect(screen.getByText(/Claude connects from Anthropic's cloud/)).toBeTruthy();
    expect(screen.getByLabelText("MCP client configuration").textContent).not.toContain(token.token);
  });

  it("refuses blank expiry even when a form submission bypasses browser validation", async () => {
    open();
    fireEvent.change(await screen.findByLabelText("Expires in (days)"), { target: { value: "" } });
    fireEvent.submit(screen.getByRole("form", { name: "Create a connection" }));
    expect((await screen.findByRole("alert")).textContent).toContain("between 1 and 365");
    expect(request.mock.calls.some(([, options]) => options?.method === "POST")).toBe(false);
  });

  it("clears organization secrets immediately and ignores the previous organization's late creation", async () => {
    let finish!: (answer: typeof token) => void;
    request.mockImplementation(async (path: string, options?: { method?: string }) => {
      if (path === "/auth/tokens" && options?.method === "POST") return new Promise(resolve => { finish = resolve; });
      if (path === "/mcp/settings") return { ...settings, organizationId: useAuthStore.getState().user?.tenant?.id };
      return [];
    });
    open();
    fireEvent.click(await screen.findByRole("button", { name: "Create connection token" }));
    act(() => useAuthStore.setState({ user: { ...user, tenant: { id: "org-b", name: "B", slug: "b" } } }));
    await screen.findByRole("button", { name: "Create connection token" });
    await act(async () => finish(token));
    expect(screen.queryByLabelText("New connection token")).toBeNull();
    expect((screen.getByLabelText("Connection token to test") as HTMLInputElement).value).toBe("");
    expect(request).toHaveBeenCalledWith("/mcp/settings", { headers: { "X-Expected-Tenant-ID": "org-b" } });
  });

  it("does not render another organization's settings and explains a stale-tab refusal", async () => {
    request.mockImplementation(async (path: string) => path === "/mcp/settings" ? { ...settings, organizationId: "org-b" } : []);
    open();
    expect((await screen.findByRole("alert")).textContent).toContain("active organization changed");
    expect(screen.queryByRole("button", { name: "Create connection token" })).toBeNull();
  });

  it("offers a retry on read failure and clears its error when the retry succeeds", async () => {
    request.mockRejectedValueOnce(new Error("offline"));
    open();
    fireEvent.click(await screen.findByRole("button", { name: "Try again" }));
    await screen.findByRole("button", { name: "Create connection token" });
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("clears a created token after a stale session is refused", async () => {
    open();
    fireEvent.click(await screen.findByRole("button", { name: "Create connection token" }));
    await screen.findByLabelText("New connection token");
    request.mockRejectedValueOnce(new ApiError(409, "Organization changed"));
    fireEvent.click(screen.getByRole("button", { name: "Turn off AI connections" }));
    expect((await screen.findByRole("alert")).textContent).toContain("active organization changed");
    expect(screen.queryByLabelText("New connection token")).toBeNull();
    expect(screen.queryByLabelText("MCP client configuration")).toBeNull();
  });
});
