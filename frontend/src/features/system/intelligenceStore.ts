import { create } from "zustand";
import { apiRequest } from "@/config/api";

/**
 * Whether this instance offers intelligence access at all (#622), read once where the
 * signed-in layout mounts, like `corpusStore`, so the sidebar can list Settings ›
 * Intelligence Access before the page is open. The rollout switches live in deployment
 * configuration and are never customer toggles; this only reads their verdict.
 *
 * A read that failed, or one refused for lack of SYSTEM_READ, hides the entry exactly as
 * a disabled preview does.
 */

export const INTELLIGENCE_ACCESS = "intelligenceAccess";

interface IntelligenceStore {
  enabled: boolean;
  /** `visibleNavigation`'s data gate, held as state so a selector never builds a new Set. */
  answering: ReadonlySet<string>;
  load: () => Promise<void>;
}

const NONE: ReadonlySet<string> = new Set();
const OFFERED: ReadonlySet<string> = new Set([INTELLIGENCE_ACCESS]);

export const useIntelligenceStore = create<IntelligenceStore>((set) => ({
  enabled: false,
  answering: NONE,

  async load() {
    try {
      const status = await apiRequest<{ enabled: boolean }>("/system/intelligence");
      set(status.enabled ? { enabled: true, answering: OFFERED } : { enabled: false, answering: NONE });
    } catch {
      set({ enabled: false, answering: NONE });
    }
  }
}));
