// @vitest-environment jsdom
import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { PatchPolicyFeedBlock } from "@/features/support/PatchPolicyFeedBlock";

vi.mock("@/i18n/LocaleContext", async () => {
  const { en } = await import("@/i18n/en");
  return { useLocale: () => ({ t: en }) };
});
const api = vi.hoisted(() => ({ getPatchPolicyApps: vi.fn() }));
vi.mock("@/features/support/patchPolicyFeed", async (actual) => ({ ...(await actual<object>()), ...api }));
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

const base = {
  algorithm: "patch_walk/1",
  coverageSince: null,
  until: null,
  outcome: null,
  httpStatus: null,
  detail: null,
  fromFile: false,
  builtAt: null,
  publisherRunning: null
};

it("says a download failed, names the copy still shown, and when the last attempt was", async () => {
  api.getPatchPolicyApps.mockResolvedValue({
    feed: {
      ...base,
      state: "download_failed",
      sentence: "",
      docId: "a5b281246cafda4be00cb02e1d74475c5a30fb54d52043770a43a120d7363359",
      asOf: "2026-11-23T20:00:00Z",
      fetchedAt: "2026-11-24T02:00:00Z",
      attemptedAt: "2026-11-25T02:00:00Z",
      source: "exchange",
      host: "bucket.s3.us-east-1.amazonaws.com",
      detail: "the patch-policy download did not complete (HTTP 403)"
    },
    apps: []
  });
  await act(async () => { render(<PatchPolicyFeedBlock />); });
  expect(screen.getByText("LoonSec patch-policy data")).toBeTruthy();
  expect(screen.getByText(/could not be downloaded from bucket\.s3\.us-east-1\.amazonaws\.com: .*HTTP 403\)\. Showing the copy dated 2026-11-23\./)).toBeTruthy();
  expect(screen.getByText(/^Document a5b281246caf…, received /)).toBeTruthy();
  expect(screen.getByText(/^Last attempt .*, from the data-sharing exchange\.$/)).toBeTruthy();
});

it("says the organization's tier is the reason, and shows no document", async () => {
  api.getPatchPolicyApps.mockResolvedValue({
    feed: { ...base, state: "tier_off", sentence: "", docId: null, asOf: null, fetchedAt: null, attemptedAt: null, source: null, host: null },
    apps: null
  });
  await act(async () => { render(<PatchPolicyFeedBlock />); });
  expect(screen.getByText(/does not share data with LoonSec/)).toBeTruthy();
  expect(screen.queryByText(/^Document /)).toBeNull();
});

it("says the state could not be read when the request fails", async () => {
  api.getPatchPolicyApps.mockRejectedValue(new Error("500"));
  await act(async () => { render(<PatchPolicyFeedBlock />); });
  expect(screen.getByText("The patch-policy data's state could not be read from this instance.")).toBeTruthy();
});
