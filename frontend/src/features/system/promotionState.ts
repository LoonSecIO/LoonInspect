import type { Promotion, Promotions } from "@/features/system/api";
import type { Translations } from "@/i18n/en";

type Copy = Translations["system"]["sharing"]["promotions"];

/** What the next exchange does with one promoted title (#793), in the page's words. Held back is said
 *  before paused: it is the reason that would still hold once sharing is on, so it is the one to fix. */
export function promotionState(promotion: Promotion, paused: Promotions["paused"], copy: Copy): string {
  if (promotion.held === "excluded") return copy.heldExcluded(promotion.excludedBy ?? "");
  if (promotion.held === "not_installed") return copy.heldNotInstalled;
  return paused === null ? copy.stateSending : copy.statePaused;
}
