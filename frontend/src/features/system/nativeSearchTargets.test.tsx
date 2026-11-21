// @vitest-environment jsdom
import { act, cleanup, fireEvent, render } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { PromptBar } from "@/features/changes/PromptBar";
import { SearchBox } from "@/features/vulnerabilities/SearchBox";

vi.mock("@/i18n/LocaleContext", async () => {
  const { en } = await import("@/i18n/en");
  return { useLocale: () => ({ t: en }) };
});
const api = vi.hoisted(() => ({ getPromptStatus: vi.fn(), askPrompt: vi.fn(), getLeverStatus: vi.fn(), askLever: vi.fn() }));
vi.mock("@/features/changes/api", () => ({ getPromptStatus: api.getPromptStatus, askPrompt: api.askPrompt }));
vi.mock("@/features/vulnerabilities/prompt", async (actual) => ({
  ...(await actual<object>()), getLeverStatus: api.getLeverStatus, askLever: api.askLever
}));
const shown = { vuln: "findings", band: null, jamf: null, order: "exposure" };
const available = { available: true, reason: null, providers: [{ provider: "apple_fm", model: "system" }] };
beforeEach(() => { localStorage.clear(); vi.clearAllMocks(); });
afterEach(cleanup);

async function open(status: unknown) {
  api.getPromptStatus.mockResolvedValue(status);
  api.getLeverStatus.mockResolvedValue(status);
  await act(async () => {
    render(<MemoryRouter>
      <PromptBar filters={{}} onApply={vi.fn()} />
      <SearchBox term="retained query" onTerm={vi.fn()} onMode={vi.fn()} onApply={vi.fn()} shown={shown} />
    </MemoryRouter>);
  });
}

it.each(["flag_off", "consent_off", "no_provider"])("offers no native AI target when %s", async (reason) => {
  await open({ available: false, reason, providers: [] });
  expect(document.querySelector("[data-page-ai-search], [data-page-ai-toggle]")).toBeNull();
  expect(document.querySelector("[data-page-search]")).toBeTruthy();
  expect(api.askPrompt).not.toHaveBeenCalled();
  expect(api.askLever).not.toHaveBeenCalled();
});

it("offers no AI target when the status is unreadable", async () => {
  await open(null);
  expect(document.querySelector("[data-page-ai-search], [data-page-ai-toggle]")).toBeNull();
});

it("focus and an explicit AI mode choice never submit the existing prompt", async () => {
  await open(available);
  const question = document.querySelector<HTMLInputElement>("[data-page-ai-search]")!;
  const search = document.querySelector<HTMLInputElement>("[data-page-search]")!;
  await act(async () => {
    question.focus();
    search.focus();
    fireEvent.click(document.querySelector("[data-page-ai-toggle]")!);
  });
  expect(search.hasAttribute("data-page-ai-search")).toBe(true);
  expect(search.hasAttribute("data-page-search")).toBe(false);
  expect(search.value).toBe("retained query");
  expect(api.askPrompt).not.toHaveBeenCalled();
  expect(api.askLever).not.toHaveBeenCalled();
});
