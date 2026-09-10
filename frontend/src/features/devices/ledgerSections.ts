/**
 * The wire's section registry, mirrored: the keys of `SECTION_WRAPPERS` in
 * `backend/app/core/wire_vocabulary.py`, in that dict's order.
 *
 * The device page's footer names the sections the ledger collects and the page does not
 * render, and it names them from this list rather than from a hand-typed one, so the page
 * and the Splunk event enumerate identically (#300). `backend/tests/test_device_page_sections.py`
 * pins this array to that dict: add a section to the wire and the backend lane fails until
 * it is added here too, which is the point.
 */
export const LEDGER_SECTIONS = [
  "general",
  "hardware",
  "operating_system",
  "user_and_location",
  "purchasing",
  "security",
  "disk_encryption",
  "local_user_accounts",
  "applications",
  "extension_attributes",
  "group_memberships",
  "configuration_profiles",
  "certificates",
  "software_updates"
] as const;

export type LedgerSection = (typeof LEDGER_SECTIONS)[number];

/** The sections the device page renders in full, entry by entry. Everything else the
 *  ledger holds for a Mac rides `device.inventory` to the SIEM and has no read endpoint. */
export const SECTIONS_ON_DEVICE_PAGE: readonly LedgerSection[] = ["applications", "extension_attributes"];

/** What the footer lists: collected, not on this page yet, in registry order. */
export function collectedNotOnPage(): LedgerSection[] {
  return LEDGER_SECTIONS.filter((section) => !SECTIONS_ON_DEVICE_PAGE.includes(section));
}
