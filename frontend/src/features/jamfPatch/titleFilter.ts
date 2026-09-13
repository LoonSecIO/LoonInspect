/**
 * The Jamf Patch list's filter and its empty states (#403) — pure, so the rules the page
 * paints by are pinned in the node lane (`titleFilter.test.ts`) rather than checked by eye,
 * for the reason `patchLaggards.ts` gives.
 *
 * The list is Jamf's whole patch catalog, one list for the container, and on every fleet
 * measured almost every row is a title no device has (99% of 1,553 on the development
 * tenant, all of them on a pod before its first sweep). **Only titles with devices** hides
 * those, ticked by default as the Catalog tab's *Installed now only* is.
 *
 * "With devices" is the *Devices with app* column: devices with an app **matched** to the
 * title. It is not "installed": about 300 titles are never matched at all
 * (`docs/jamf-patch-matching.md` §3, Firefox among them), so the label never says
 * installed, and the footer and the empty messages always say what the box hid.
 */

/** A title "has devices" exactly when its *Devices with app* count is above zero. */
export function hasDevices(title: { deviceCount: number }): boolean {
  return title.deviceCount > 0;
}

/** Why the table has no rows — four states, and none may borrow another's message
 *  (`docs/diagnosability.md` rule 1). The checkbox alone can produce only the middle two. */
export type EmptyReason =
  /** The catalog has no rows at all: nothing has been synced. */
  | "noCatalog"
  /** The catalog has rows, the box is ticked, no search, and no title has a device. */
  | "noneWithDevices"
  /** A search matches titles, and every one of them has no device. */
  | "matchesOnlyWithoutDevices"
  /** A search matches nothing, with or without the box. */
  | "noMatch";

export interface TitleFilterResult<T> {
  /** What the table shows: the search, then the checkbox. */
  visible: T[];
  /** Titles the search matched that the checkbox then hid — what the footer and the empty
   *  messages count. Zero whenever the box is unticked. */
  hidden: number;
  /** Why `visible` is empty, or null when it is not. */
  empty: EmptyReason | null;
}

export function filterTitles<T extends { deviceCount: number }>(
  titles: readonly T[],
  options: { matches: (title: T) => boolean; searching: boolean; onlyWithDevices: boolean }
): TitleFilterResult<T> {
  const matched = options.searching ? titles.filter(options.matches) : [...titles];
  const visible = options.onlyWithDevices ? matched.filter(hasDevices) : matched;
  const hidden = matched.length - visible.length;
  return { visible, hidden, empty: visible.length > 0 ? null : emptyReason(titles.length, matched.length, options.searching) };
}

function emptyReason(catalog: number, matched: number, searching: boolean): EmptyReason {
  if (catalog === 0) return "noCatalog";
  if (matched === 0) return "noMatch";
  // Rows matched and none are visible, so the checkbox hid every one of them.
  return searching ? "matchesOnlyWithoutDevices" : "noneWithDevices";
}
