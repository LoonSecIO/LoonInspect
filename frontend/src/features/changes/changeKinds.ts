import { canMatch, sectionShape } from "@/features/changes/render";
import { type ChangeFilters, type ChangeKind, HIDDEN_KEYS } from "@/features/changes/types";
import type { Translations } from "@/i18n/en";

/**
 * What the Changes page says about its two change vocabularies and about an empty table
 * (#437), kept out of the component so the node-only test lane can hold the sentences to
 * the ruling.
 *
 * A list section's entries are added, removed or updated; every other section's values
 * are only ever changed (`ENTRY_SECTIONS` in render.ts). The Change list greys out what
 * the chosen section never records, but a pair from the wrong side still arrives in a
 * hand-edited link, and the empty table it produces has to say why rather than read as a
 * log with nothing in it.
 */

type ChangesStrings = Translations["changes"];

const sectionName = (section: string, strings: ChangesStrings) => strings.sections[section] ?? section;

/** The line under the filters when choosing `section` put the Change filter back to Any
 *  change. `null` for a section the page does not know, which never resets anything. */
export function changeResetLine(section: string, strings: ChangesStrings): string | null {
  const shape = sectionShape(section);
  return shape ? strings.changeReset[shape](sectionName(section, strings)) : null;
}

/** Why `section` and `change` can never match a row together, or `null` when they can. */
export function neverMatchesReason(
  section: string | undefined,
  change: ChangeKind | undefined,
  strings: ChangesStrings
): string | null {
  const shape = sectionShape(section);
  if (!section || !shape || canMatch(section, change)) return null;
  return strings.neverMatches[shape](sectionName(section, strings));
}

/** Every key the page's URL can carry but the page number: the controls' own, the ones only a
 *  link sets (a `since` window, a `minLevel` range, the device chip), and the hidden dimensions
 *  (#447) a link, a row or the Prompt bar applies. A table empty under one of those is a filtered
 *  table, not an empty log — the same sentence #437 fixed for a mistyped name, missed for these
 *  ten until the token chip of #446 made the state routine. */
const FILTER_KEYS = [
  "q",
  "artifact",
  "level",
  "minLevel",
  "change",
  "section",
  "since",
  "connectionId",
  "subjectId",
  "subjectKind",
  ...HIDDEN_KEYS
] as const satisfies readonly (keyof ChangeFilters)[];

/** Whether any filter narrows the feed. */
export function isFiltered(filters: ChangeFilters): boolean {
  return FILTER_KEYS.some((key) => filters[key] !== undefined && filters[key] !== "");
}

/** What an empty table says: a lead, and for a pair that can never match, the reason. */
export interface EmptyTable {
  lead: string;
  reason: string | null;
}

/**
 * The sentence for a table with no rows, which is three different states:
 *
 * - rows match, but on earlier pages — `total` counts them and this page is past the last;
 * - no filter is set and the log holds no row — the only state "No changes yet" is true of;
 * - a filter is set and nothing matches it — said as such, with the reason when the
 *   section and the change can never meet, so an impossible pair does not read as a quiet
 *   fleet.
 */
export function emptyTable(filters: ChangeFilters, total: number, strings: ChangesStrings): EmptyTable {
  if (total > 0) return { lead: strings.emptyPastEnd, reason: null };
  if (!isFiltered(filters)) return { lead: strings.empty, reason: null };
  return { lead: strings.emptyFiltered, reason: neverMatchesReason(filters.section, filters.change, strings) };
}
