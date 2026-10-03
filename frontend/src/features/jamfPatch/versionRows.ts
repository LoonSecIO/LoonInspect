/**
 * The rows the Jamf Patch title page charts and tabulates — pure, so the rules the page
 * paints by are pinned in the node lane (`versionRows.test.ts`), for the reason
 * `titleFilter.ts` gives.
 *
 * Two kinds of version reach the page. **Listed** versions are Jamf's own, in the order the
 * catalog gives them. **Unlisted** versions are ones a Mac reports and Jamf does not list —
 * ahead of the catalog, or a build Jamf never recorded — and they exist here only because a
 * device has one, so they are never "0 devices". The chart shows both, because a bar is a
 * count of Macs and those Macs are real; the table is Jamf's list and names the rest in its
 * footer.
 */
import type { JamfPatchTitleDetail } from "@/features/jamfPatch/types";

export interface VersionRow {
  version: string;
  releaseDate: string | null;
  /** Distinct devices whose matched app is on this version. */
  devices: number;
  /** Whether Jamf lists the version. */
  listed: boolean;
  /** Whether it is the title's current version. */
  latest: boolean;
}

type TitleVersions = Pick<JamfPatchTitleDetail, "patches" | "versionDeviceCounts" | "currentVersion">;

/** Listed versions in catalog order, then unlisted ones with the most devices first. */
export function versionRows(title: TitleVersions): VersionRow[] {
  const listed = new Set<string>();
  const rows: VersionRow[] = [];
  for (const patch of title.patches) {
    if (listed.has(patch.version)) continue;
    listed.add(patch.version);
    rows.push({
      version: patch.version,
      releaseDate: patch.releaseDate ?? null,
      devices: title.versionDeviceCounts[patch.version] ?? 0,
      listed: true,
      latest: patch.version === title.currentVersion
    });
  }
  const unlisted = Object.entries(title.versionDeviceCounts)
    .filter(([version, devices]) => !listed.has(version) && devices > 0)
    .sort(([a, devicesA], [b, devicesB]) => devicesB - devicesA || a.localeCompare(b))
    .map(([version, devices]) => ({ version, releaseDate: null, devices, listed: false, latest: false }));
  return [...rows, ...unlisted];
}

export interface VersionFilterResult {
  visible: VersionRow[];
  /** Rows the checkbox hid — what the footer counts. Zero whenever the box is unticked. */
  hidden: number;
}

/** "Hide versions with 0 devices": the page's one filter, over the chart and the table alike. */
export function filterVersionRows(rows: readonly VersionRow[], hideEmpty: boolean): VersionFilterResult {
  const visible = hideEmpty ? rows.filter((row) => row.devices > 0) : [...rows];
  return { visible, hidden: rows.length - visible.length };
}

/** Whether the box starts ticked: only where ticking it leaves something to read. A title
 *  no device has would open on an empty table, so it opens on Jamf's whole list instead. */
export function hideEmptyByDefault(rows: readonly VersionRow[]): boolean {
  return rows.some((row) => row.devices > 0);
}
