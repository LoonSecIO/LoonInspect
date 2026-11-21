// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, expect, it, vi } from "vitest";
import { SupportPage } from "@/features/support/SupportPage";

vi.mock("@/i18n/LocaleContext", async () => {
  const { en } = await import("@/i18n/en");
  return { useLocale: () => ({ t: en }) };
});
vi.mock("@/features/auth/store", () => ({ useHasPermission: () => false }));
const api = vi.hoisted(() => ({ getVersion: vi.fn() }));
vi.mock("@/features/system/api", async (actual) => ({ ...(await actual<object>()), ...api }));
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it("shows and copies the bundle and backend identities to a reader without system privileges", async () => {
  api.getVersion.mockResolvedValue({ version: "2026.11.21+1234567", kind: "mac-app", appVersion: "1.2.0", appBuild: "42" });
  const writeText = vi.fn().mockResolvedValue(undefined);
  vi.stubGlobal("navigator", { clipboard: { writeText } });
  await act(async () => { render(<MemoryRouter><SupportPage /></MemoryRouter>); });
  for (const word of ["App version", "1.2.0", "App build", "42", "Backend build", "2026.11.21+1234567"]) {
    expect(screen.getByText(word)).toBeTruthy();
  }
  await act(async () => { fireEvent.click(screen.getByRole("button", { name: "Copy" })); });
  expect(writeText).toHaveBeenCalledWith("App version: 1.2.0\nApp build: 42\nBackend build: 2026.11.21+1234567");
  vi.unstubAllGlobals();
});

it("explains where to find an older package's missing identity", async () => {
  api.getVersion.mockResolvedValue({ version: "2026.11.21+1234567", kind: "mac-app" });
  await act(async () => { render(<MemoryRouter><SupportPage /></MemoryRouter>); });
  expect(screen.getAllByText("Not recorded")).toHaveLength(2);
  expect(screen.getByText(/This package did not record its full app identity/)).toBeTruthy();
});
