import type { ReplayEntry } from "@/features/patchPolicy/replayIndex";

/** What the picker reads off a row of Jamf's patch catalog: the title and its bundle ID, and nothing
 *  about the fleet. The device counts that list also carries are never read here. */
export interface CatalogTitle {
  name: string;
  bundleId: string | null;
}

export interface PickerApp {
  key: string;
  name: string;
  /** The replay to open, or `null`: an app with no reference replay yet, which is listed and cannot
   *  be picked. Never a replay of zeros. */
  replayId: string | null;
}

/**
 * The picker's rows: the apps with a replay first, then every other app in Jamf's patch catalog by
 * name. Jamf lists some apps as several titles (Wireshark, Wireshark 4.4, Wireshark 4.6), so titles
 * sharing a bundle ID are one row under the shortest name, and a title that is a replay's app is that
 * replay's row and not a second one. With no catalog to read, the replays are still listed.
 */
export function pickerApps(titles: readonly CatalogTitle[], index: readonly Pick<ReplayEntry, "id" | "name" | "bundleIds">[]): PickerApp[] {
  const replayed = new Set(index.flatMap((entry) => entry.bundleIds.map((bundleId) => bundleId.toLowerCase())));
  const others = new Map<string, string>();
  for (const title of titles) {
    const bundleId = title.bundleId?.trim().toLowerCase() || null;
    if (bundleId && replayed.has(bundleId)) continue;
    const key = bundleId ?? `title:${title.name}`;
    const known = others.get(key);
    if (known === undefined || title.name.length < known.length) others.set(key, title.name);
  }
  return [
    ...index.map((entry) => ({ key: entry.id, name: entry.name, replayId: entry.id })),
    ...[...others].map(([key, name]) => ({ key, name, replayId: null })).sort((a, b) => a.name.localeCompare(b.name))
  ];
}
