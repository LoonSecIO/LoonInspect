/** Settings › Intelligence Access, the community contribution panel (#622): what it decides from the Data sharing
 *  status rather than draws. Kept pure so the frontend lane (#285) pins every state (docs/diagnosability.md rule 1). */

import type { DataSharingSettings, Participation } from "@/features/system/api";

/** The state the panel names: the status's five, and `unknown` for a word this build lacks. A receipt still stored
 *  as contributing that fetches nothing must not read as one that does, so two more split off from `contributing`:
 *  `lapsed`, past its deadline, and `idle`, inside it while the receipt switches are off or COMMUNITY_SHARING=false. */
export type ReceiptState = "none" | "contributing" | "idle" | "lapsed" | "withdrawal_pending" | "withdrawn" | "ended" | "unknown";

const STORED: ReadonlySet<string> = new Set(["none", "contributing", "withdrawal_pending", "withdrawn", "ended"]);

/** Absent where receipts are off (the three switches behind `enabled`), unless a receipt is still held or a
 *  withdrawal still waits: that withdrawal holds uploads with the switches off too, so it stays readable. */
export function receiptShown(receipt: Participation | null | undefined): receipt is Participation {
  return !!receipt && (receipt.enabled || receipt.receiptPresent || receipt.state === "withdrawal_pending");
}

export function receiptState(receipt: Participation, sharing: Pick<DataSharingSettings, "envDisabled">, now: number): ReceiptState {
  if (!STORED.has(receipt.state)) return "unknown";
  if (receipt.state !== "contributing") return receipt.state as ReceiptState;
  if (receipt.updatesUntil !== null && Date.parse(receipt.updatesUntil) <= now) return "lapsed";
  return receipt.enabled && !sharing.envDisabled ? "contributing" : "idle";
}

/** When the scheduler next fetches with the receipt alone, or null when it will not: the backend's `usable` test
 *  (app/core/participation.py). A stale `retryAfter` under any other state is never a promise. */
export function nextFetch(sharing: Pick<DataSharingSettings, "tier">, receipt: Participation, state: ReceiptState): string | null {
  return state === "contributing" && receipt.receiptPresent && sharing.tier !== "off" ? receipt.retryAfter : null;
}
