// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useAuthStore } from "@/features/auth/store";
import type { AuthUser } from "@/features/auth/types";
import { LocaleProvider } from "@/i18n/LocaleContext";
import { DestinationsPage } from "./DestinationsPage";
import type { Destination, OutboxDepth } from "./types";

const request = vi.hoisted(() => vi.fn());
vi.mock("@/config/api", async importOriginal => ({ ...await importOriginal<typeof import("@/config/api")>(), apiRequest: request }));
const user: AuthUser = { id: "synthetic-user", email: "user@example.test", displayName: "Test", roles: ["admin"], permissions: ["destination:read", "destination:write"], tenant: { id: "org-a", name: "A", slug: "a" }, tenants: [], isBreakGlass: false, mfaEnrolmentRequired: false };
const depth: OutboxDepth = { held: { events: 0, oldestAgeSeconds: null, reason: null }, pending: { deliveries: 0, oldestAgeSeconds: null }, deadLettered: { deliveries: 0, oldestExpiresAt: null }, retention: { eventRetentionDays: 7, deadLetterRetentionDays: 30, nextPurgeAt: "2026-11-24T02:00:00Z" } };
const destination: Destination = { id: 848, name: "Warehouse", type: "snowflake", url: "https://example-test.snowflakecomputing.com", allowInsecureHttp: false, authType: "snowflake_jwt", authHeaderName: null, elasticIndex: null, hasSecret: true, enabled: true, subscribedEvents: null, lastError: null, pendingCount: 0, failedCount: 0, failed24h: 0, deadLetterOldestExpiresAt: null, lastSuccessAt: null, lastFailureAt: null, createdAt: "2026-11-23T12:00:00Z", updatedAt: "2026-11-23T12:00:00Z", snowflakeConfig: { account: "EXAMPLE-TEST", user: "LOON_WRITER", database: "LOONINSPECT", schema: "PUBLIC", pipe: "LOON_EVENTS_PIPE", role: "LOON_WRITER" } };
const open = () => render(<MemoryRouter><LocaleProvider><DestinationsPage /></LocaleProvider></MemoryRouter>);

beforeEach(() => {
  request.mockReset();
  useAuthStore.setState({ status: "authenticated", user });
  window.localStorage.setItem("locale", "en");
  Element.prototype.scrollIntoView = vi.fn();
  request.mockImplementation(async (path: string, options?: { method?: string }) => {
    if (path === "/outbox") return depth;
    if (path === "/destinations" && options?.method === "POST") return destination;
    if (path === "/destinations") return [];
    return undefined;
  });
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe("Snowflake destination setup", () => {
  it("keeps the PEM multiline, derives HTTPS and sends explicit subscriptions", async () => {
    open();
    fireEvent.click(await screen.findByRole("button", { name: "Add destination" }));
    fireEvent.change(screen.getByLabelText("Type"), { target: { value: "snowflake" } });
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Warehouse" } });
    fireEvent.change(screen.getByLabelText("Organization-account identifier"), { target: { value: "EXAMPLE-TEST" } });
    const key = "-----BEGIN PRIVATE KEY-----\nSYNTHETIC_LOCAL_ONLY\n-----END PRIVATE KEY-----";
    fireEvent.change(screen.getByLabelText("RSA private key (PEM)"), { target: { value: key } });
    expect((screen.getByLabelText("URL") as HTMLInputElement).value).toBe(destination.url);
    expect((screen.getByLabelText("URL") as HTMLInputElement).readOnly).toBe(true);
    fireEvent.click(screen.getByLabelText("All event types"));
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(request.mock.calls.some(([, options]) => options?.method === "POST")).toBe(true));
    const [, options] = request.mock.calls.find(([, value]) => value?.method === "POST")!;
    expect(options.json.authSecret).toBe(key);
    expect(options.json.snowflakeConfig).toEqual(destination.snowflakeConfig);
    expect(options.json.subscribedEvents).toEqual(["device.inventory", "device.change"]);
    expect(options.json.authType).toBe("snowflake_jwt");
    expect(options.json.allowInsecureHttp).toBe(false);
    expect(window.localStorage.getItem("snowflakeKey")).toBeNull();
  });

  it("keeps target settings fixed while a rotated key remains optional", async () => {
    request.mockImplementation(async (path: string) => path === "/outbox" ? depth : [destination]);
    open();
    fireEvent.click(await screen.findByRole("button", { name: "Edit" }));
    expect((screen.getByLabelText("Organization-account identifier") as HTMLInputElement).readOnly).toBe(true);
    expect((screen.getByLabelText("RSA private key (PEM)") as HTMLTextAreaElement).value).toBe("");
    expect((screen.getByLabelText("RSA private key (PEM)") as HTMLTextAreaElement).required).toBe(false);
    expect(screen.getByText(/Target settings are fixed/)).toBeTruthy();
  });

  it("shows unresolved test evidence as pending and exposes its lookup key", async () => {
    request.mockImplementation(async (path: string) => {
      if (path === "/outbox") return depth;
      if (path.endsWith("/test")) return { ok: false, pending: true, detail: "Snowflake committed row counts are pending.", statusCode: null, sourceEventKey: "synthetic-event-key" };
      return [destination];
    });
    open();
    fireEvent.click(await screen.findByRole("button", { name: "Test" }));
    expect(await screen.findByText(/Snowflake committed row counts are pending/)).toBeTruthy();
    expect(screen.getByText("synthetic-event-key")).toBeTruthy();
    expect(screen.queryByText(/Test delivery refused/)).toBeNull();
    expect(screen.queryByText(/Delivered —/)).toBeNull();
  });
});
