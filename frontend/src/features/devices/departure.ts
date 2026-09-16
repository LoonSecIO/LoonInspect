/** The seven-day tail, in the browser (#475, from #183). "Left the fleet" has one definition —
 *  `left_the_fleet` in `backend/app/observations/departure.py` — and the API has already applied it.
 *  Nothing here decides: these read the row's own `departedAt` so a page can say when the tail runs
 *  out instead of leaving a Mac to vanish unannounced. `DEPARTURE_TAIL_DAYS` mirrors the constant of
 *  that name — a number the page prints, never one it judges on. */
export const DEPARTURE_TAIL_DAYS = 7;

export type DepartureState = "present" | "in_tail" | "left";

/** When the tail runs out: `departedAt` plus the tail, in elapsed time as `left_the_fleet` counts it
 *  — not `setDate`, which counts local calendar days and lands an hour off across a DST change.
 *  Invalid in, invalid out: the caller checks. */
export function leavesTheFleetAt(departedAt: string): Date {
  return new Date(new Date(departedAt).getTime() + DEPARTURE_TAIL_DAYS * 86_400_000);
}

/** What the chip and the device page's sentence are about. An instant the browser cannot parse still
 *  means departed — it is the row's own column — but not *left*: that claim needs a date. */
export function departureState(departedAt: string | null, now: Date): DepartureState {
  if (!departedAt) return "present";
  const leaves = leavesTheFleetAt(departedAt).getTime();
  if (Number.isNaN(leaves)) return "in_tail";
  return leaves > now.getTime() ? "in_tail" : "left";
}

/** The toggle's half of the URL: `?includeDeparted=true` and nothing else, so a link without it opens
 *  the current fleet — the list's default answer, as the API's is. */
export function includeDepartedFrom(params: URLSearchParams): boolean | undefined {
  return params.get("includeDeparted") === "true" ? true : undefined;
}
