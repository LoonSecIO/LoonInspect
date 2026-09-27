import { create } from "zustand";
import { apiRequest } from "@/config/api";

/**
 * Whether this instance offers intelligence access at all (#622), read once where the
 * signed-in layout mounts, like `corpusStore`, so the sidebar can list Settings ›
 * Intelligence Access before the page is open. The rollout switches live in deployment
 * configuration and are never customer toggles; this only reads their verdict.
 *
 * The entry is listed while the page has something for this reader (#706): the paid
 * preview (`enabled`), contribution receipts (`receipts`), or a case this organization can
 * still withdraw, which the instance answers to an administrator only (`casesToWithdraw`).
 * A read that failed, or one refused for lack of SYSTEM_READ, hides the entry exactly as
 * all three off do, and an answer without a field reads it as off.
 */

export const INTELLIGENCE_ACCESS = "intelligenceAccess";

/** The fields of `GET /api/system/intelligence` this store reads. */
interface Status {
  enabled: boolean;
  submissions?: boolean;
  receipts?: boolean;
  casesToWithdraw?: boolean;
}

interface IntelligenceStore {
  /** The paid preview alone: INTELLIGENCE_ACCESS with the two corpus flags. Receipts never widen it. */
  enabled: boolean;
  /** INTELLIGENCE_SUBMISSIONS as the instance reports it (#692). The row actions need both it and `enabled`; it never
   *  lists the Settings entry, and an answer without it reads as off. */
  submissions: boolean;
  /** Contribution receipts: CONTRIBUTION_RECEIPTS with the same two corpus flags (#706). */
  receipts: boolean;
  /** `visibleNavigation`'s data gate, held as state so a selector never builds a new Set. */
  answering: ReadonlySet<string>;
  load: () => Promise<void>;
}

const NONE: ReadonlySet<string> = new Set();
const OFFERED: ReadonlySet<string> = new Set([INTELLIGENCE_ACCESS]);
const OFF = { enabled: false, submissions: false, receipts: false, answering: NONE };

export const useIntelligenceStore = create<IntelligenceStore>((set) => ({
  ...OFF,

  async load() {
    try {
      const status = await apiRequest<Status>("/system/intelligence");
      const enabled = status.enabled === true;
      const receipts = status.receipts === true;
      const listed = enabled || receipts || status.casesToWithdraw === true;
      set({ enabled, submissions: status.submissions === true, receipts, answering: listed ? OFFERED : NONE });
    } catch {
      set(OFF);
    }
  }
}));

/** Which routes Data sharing's link to the page names (#706), or null for no link: a case list alone gets none, as
 *  cases are no part of sharing. */
export function sharingPointer(enabled: boolean, receipts: boolean): "paid" | "receipts" | "both" | null {
  if (enabled) return receipts ? "both" : "paid";
  return receipts ? "receipts" : null;
}
