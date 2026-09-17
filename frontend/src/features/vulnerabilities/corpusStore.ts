import { create } from "zustand";
import { apiRequest } from "@/config/api";

/**
 * Whether a vulnerability corpus is answering for this session's organization (#529).
 *
 * A store beside `flagStore`, for its reasons and read the same way: once, where the
 * signed-in layout mounts, shared, never polled. The sidebar decides whether to list
 * Posture › Vulnerabilities before any page is open, so this cannot come off
 * `GET /api/catalog`'s `corpusAsOf` the way the banner's date does.
 *
 * **A read that failed is not "off".** `read` is a third state for the reason `FlagRead`
 * has one (#150): the entry stays hidden either way, and nothing may report the corpus as
 * silent on the strength of a request that did not come back.
 */

export type CorpusRead = "loading" | "read" | "failed";

/** What `visibleNavigation` judges `requires` against: a date, from a read that landed. A
 *  set rather than a boolean so the tree's data gate reads like its flag gate, and so
 *  #536's own requirement can join it without changing the signature again. */
export function answeringKeys(read: CorpusRead, corpusAsOf: string | null): ReadonlySet<string> {
  return new Set(read === "read" && corpusAsOf !== null ? ["corpus"] : []);
}

interface CorpusStore {
  read: CorpusRead;
  /** The date the loaded epoch was generated, or `null` — which is `off` and has two causes
   *  the response deliberately cannot tell apart (docs/vulnerabilities.md §8). */
  corpusAsOf: string | null;
  /** Held as state rather than derived in the selector, as `flagStore.enabled` is: a
   *  selector that built a new Set per render would hand React a new snapshot every time. */
  answering: ReadonlySet<string>;
  load: () => Promise<void>;
}

function answered(read: CorpusRead, corpusAsOf: string | null) {
  return { read, corpusAsOf, answering: answeringKeys(read, corpusAsOf) };
}

export const useCorpusStore = create<CorpusStore>((set) => ({
  ...answered("loading", null),

  async load() {
    set(answered("loading", null));
    try {
      const status = await apiRequest<{ corpusAsOf: string | null }>("/vulnerabilities/status");
      set(answered("read", status.corpusAsOf));
    } catch {
      // Never throws: the failure is a state, and it keeps the entry hidden exactly as a
      // corpus that is genuinely silent does — without ever calling it silent.
      set(answered("failed", null));
    }
  }
}));
