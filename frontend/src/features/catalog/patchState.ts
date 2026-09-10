/**
 * The colours a Jamf Patch state is painted in, shared by every surface that paints one
 * (the catalog and the device page, #300). Fixed, never themed, per the dataviz palette:
 * good / critical / warning / warning.
 */
export const PATCH_STATE_COLORS: Record<string, string> = {
  latest: "#0ca30c",
  behind: "#d03b3b",
  ahead: "#fab219",
  unknown: "#fab219"
};
