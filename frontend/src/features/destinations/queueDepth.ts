/** The two sentences Settings › Destinations prints above the list (#468), as decisions
 *  rather than markup. Both conditional: a permanent counter reading zero on a healthy
 *  stack teaches the reader to stop looking at it. */

import type { OutboxDepth } from "@/features/destinations/types";

const DAY_MS = 86_400_000;

/** When the oldest held event ages out of `eventRetentionDays` and is purged with the
 *  baseline it belongs to — null unless it is held for a reason a sentence can fix. */
export function heldExpiresAt(depth: OutboxDepth, now: Date): Date | null {
  const { events, oldestAgeSeconds, reason } = depth.held;
  if (events < 1 || reason !== "no_enabled_destination" || oldestAgeSeconds === null) return null;
  return new Date(now.getTime() - oldestAgeSeconds * 1000 + depth.retention.eventRetentionDays * DAY_MS);
}

/** Whole days until the oldest dead letter stops being redrivable, null when there are none.
 *  Rounded **down** and floored at 0, because a deadline must never promise more time than there
 *  is: rounding up prints "in 1 day" over a window closing in two hours, and leaves "today" a
 *  word that only arrives once the redrive is already impossible. */
export function deadLetterDaysLeft(depth: OutboxDepth, now: Date): number | null {
  const { deliveries, oldestExpiresAt } = depth.deadLettered;
  if (deliveries < 1 || oldestExpiresAt === null) return null;
  return Math.max(Math.floor((new Date(oldestExpiresAt).getTime() - now.getTime()) / DAY_MS), 0);
}
