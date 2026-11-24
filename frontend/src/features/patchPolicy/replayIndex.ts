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
 * One entry per app with a schema-2 replay, in the order the picker lists them. Each file names its
 * own release-date source (`timeline`), and the page prints that name and no other. The planned set
 * is Google Chrome (`com.google.Chrome`, replayed as one release line), Wireshark
 * (`org.wireshark.Wireshark`, held on 4.4), and later Firefox (`org.mozilla.firefox`) and Thunderbird
 * (`org.mozilla.thunderbird`); an app is listed here only once its file is in `replays/` and in the
 * README's table. An empty index draws a page that says no replay ships, never a page of zeros.
 */
export const REPLAY_INDEX: readonly ReplayEntry[] = [];

/** The file, read and checked. A file that will not load at all is refused like one that will not
 *  parse: the page has one sentence for *this file cannot be drawn*, with the reason in it. */
export function loadReplay(entry: Pick<ReplayEntry, "load">): Promise<ReadResult> {
  return entry.load().then(readReplay, (): ReadResult => ({ refusal: { why: "unreadable" } }));
}
