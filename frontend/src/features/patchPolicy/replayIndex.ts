import { readReplay, type ReadResult } from "@/features/patchPolicy/replay";

/**
 * Which apps have a reference replay, and how each file is loaded (#614, first slice). This module is
 * the page's whole data layer for replays: the views are handed a read replay and never load one.
 *
 * The files ship with the build and load on demand, as a chunk of their own, when an app is picked.
 * A static file and not an endpoint beside `backend/app/catalog`, on purpose: the file is the same
 * for every organization, so an endpoint would add a tenant-scoped, permissioned route for data that
 * is not the tenant's, and would be the first step toward storing it as if it were. When LoonSupport
 * distributes these, `load` is the one line that changes.
 */
export interface ReplayEntry {
  /** The `?app=` value, and the key the picker selects by. */
  id: string;
  name: string;
  /** How a row of Jamf's patch catalog is recognised as this app in the picker. Each is one of the
   *  file's own `product.bundle_ids`; `replay.test.ts` holds the two together. */
  bundleIds: readonly string[];
  /** The file under `replays/` that `load` imports, as `replays/README.md`'s sources table names it.
   *  `replay.test.ts` holds the three together: the loaded file, the file on disk, and its row. */
  file: string;
  load: () => Promise<unknown>;
}

/**
 * One entry per app with a reference replay, in the order the picker lists them. The four files are
 * LoonVD's schema-2 output, on the old count, so the page refuses each in words until
 * LoonVD-Internal#151's schema-3 files replace them (`replays/README.md`); the picker still lists
 * the app, and the refusal stands where its replay would be. Each file names its
 * own release-date source (`timeline`), and the page prints that name and no other. Wireshark is
 * first, so it stays the app the page opens on, as it was when it was the only replay, and it is the
 * smallest file to load; the rest follow by name. An app is listed here only once its file is in
 * `replays/` and in the README's table, and an empty index draws a page that says no replay ships,
 * never a page of zeros.
 *
 * `bundleIds` is the one bundle ID each file replays (its `product.device_bundle_id`), not every ID
 * its `product.bundle_ids` names: Chrome's Beta and Canary and Firefox's Developer Edition are other
 * channels, so a catalog row for one of them keeps its own *no reference replay yet* and is not
 * folded under a replay of the release channel. Firefox ESR and Thunderbird ESR share their release
 * channel's bundle ID, so they do fold in, and the page says those replays are the release channel.
 */
export const REPLAY_INDEX: readonly ReplayEntry[] = [
  {
    id: "wireshark",
    name: "Wireshark",
    bundleIds: ["org.wireshark.Wireshark"],
    file: "wireshark-2026-11-23.json",
    load: () => import("./replays/wireshark-2026-11-23.json").then((file) => file.default)
  },
  {
    id: "firefox",
    name: "Firefox",
    bundleIds: ["org.mozilla.firefox"],
    file: "firefox-2026-11-23.json",
    load: () => import("./replays/firefox-2026-11-23.json").then((file) => file.default)
  },
  {
    id: "chrome",
    name: "Google Chrome",
    bundleIds: ["com.google.Chrome"],
    file: "chrome-2026-11-17.json",
    load: () => import("./replays/chrome-2026-11-17.json").then((file) => file.default)
  },
  {
    id: "thunderbird",
    name: "Thunderbird",
    bundleIds: ["org.mozilla.thunderbird"],
    file: "thunderbird-2026-11-23.json",
    load: () => import("./replays/thunderbird-2026-11-23.json").then((file) => file.default)
  }
];

/** The file, read and checked. A file that will not load at all is refused like one that will not
 *  parse: the page has one sentence for *this file cannot be drawn*, with the reason in it. */
export function loadReplay(entry: Pick<ReplayEntry, "load">): Promise<ReadResult> {
  return entry.load().then(readReplay, (): ReadResult => ({ refusal: { why: "unreadable" } }));
}
