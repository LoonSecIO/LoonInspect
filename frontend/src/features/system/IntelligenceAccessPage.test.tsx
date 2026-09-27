/** Settings › Intelligence Access (#622): the page mounts the Community contribution panel for every account that opens
 *  it, after paid access and before the case list (#705). Node lane: server rendering runs no effect, and each panel
 *  draws nothing until its read answers, so the page's markup was the same with the panel mounted or not. Here the
 *  panel stands in with its read answered, a receipt held, and paid access as the section it draws once read. */

import { afterEach, describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { useHasPermission } from "@/features/auth/store";
import { PERMISSIONS } from "@/features/auth/types";
import type { ReceiptRead } from "@/features/system/ContributionReceipt";
import { IntelligenceAccessPage } from "@/features/system/IntelligenceAccessPage";
import { en } from "@/i18n/en";

vi.mock("@/features/auth/store", async (importOriginal) => ({ ...(await importOriginal<typeof import("@/features/auth/store")>()), useHasPermission: vi.fn() }));
vi.mock("@/i18n/LocaleContext", async () => {
  const { en: t } = await import("@/i18n/en");
  return { useLocale: () => ({ t, locale: "en" }) };
});
vi.mock("@/features/system/IntelligenceAccess", async () => {
  const [{ createElement }, { en: t }] = await Promise.all([import("react"), import("@/i18n/en")]);
  return { IntelligenceAccess: () => createElement("section", { "aria-label": t.intelligence.paidTitle }) };
});
vi.mock("@/features/system/ContributionReceipt", async (importOriginal) => {
  const [panel, { createElement }, { en: t }] = await Promise.all([
    importOriginal<typeof import("@/features/system/ContributionReceipt")>(), import("react"), import("@/i18n/en")]);
  const read: ReceiptRead = { state: "ready", now: 0, sharing: { tier: "keys", envDisabled: false, participation: { enabled: true,
    receiptPresent: true, state: "contributing", acceptedAt: null, updatesUntil: null, withdrawalRequestedAt: null,
    lastWithdrawalAttemptAt: null, withdrawnAt: null, lastRedeemedAt: null, retryAfter: null, error: null } } };
  return { ...panel, ContributionReceipt: () => createElement(panel.ContributionReceiptView, { read, copy: t.intelligence, locale: "en" }) };
});
afterEach(() => vi.clearAllMocks());

// Each part of the page by the label its section carries; `drawn` names the parts a page shows, in the order it shows them.
const PARTS = { paid: en.intelligence.paidTitle, receipt: en.intelligence.contribution.title, cases: en.submissionCases.title };
const drawn = (page: string) => Object.entries(PARTS).map(([part, label]) => [part, page.indexOf(`aria-label="${label}"`)] as const)
  .filter(([, at]) => at >= 0).sort(([, a], [, b]) => a - b).map(([part]) => part);

describe("Settings › Intelligence Access (#622)", () => {
  it("mounts the Community contribution panel for a reader and an administrator, after paid access and before the case list", () => {
    // SYSTEM_READ opens the page and reads the receipt's status; the case list is SYSTEM_WRITE's.
    vi.mocked(useHasPermission).mockImplementation((permission) => permission === PERMISSIONS.SYSTEM_READ);
    expect(drawn(renderToStaticMarkup(<IntelligenceAccessPage />))).toEqual(["paid", "receipt"]);
    vi.mocked(useHasPermission).mockReturnValue(true);
    expect(drawn(renderToStaticMarkup(<IntelligenceAccessPage />))).toEqual(["paid", "receipt", "cases"]);
  });
});
