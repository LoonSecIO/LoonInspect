// @vitest-environment jsdom
import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { BuildVersion } from "@/features/system/BuildVersion";

vi.mock("@/i18n/LocaleContext", async () => {
  const { en } = await import("@/i18n/en");
  return { useLocale: () => ({ t: en }) };
});
const api = vi.hoisted(() => ({ getVersion: vi.fn() }));
vi.mock("@/features/system/api", () => api);
afterEach(() => { cleanup(); vi.clearAllMocks(); });

it("shows the Mac release after login and retains app/build diagnostics when collapsed", async () => {
  api.getVersion.mockResolvedValue({ version: "2026.11.21+1234567", kind: "mac-app", appVersion: "1.2.0", appBuild: "42" });
  let view: ReturnType<typeof render>;
  await act(async () => { view = render(<BuildVersion />); });
  expect(screen.getByText("LoonInspect.app 1.2.0").title).toContain("App build: 42");
  view!.rerender(<BuildVersion collapsed />);
  expect(screen.getByTitle(/App version: 1.2.0/).textContent).toContain("Backend build: 2026.11.21+1234567");
});

it("does not show guessed metadata after a failed read", async () => {
  api.getVersion.mockRejectedValue(new Error("offline"));
  await act(async () => { render(<BuildVersion />); });
  expect(document.body.textContent).toBe("");
});
