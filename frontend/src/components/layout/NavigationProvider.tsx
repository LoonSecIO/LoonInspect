import { useEffect, useMemo, type PropsWithChildren } from "react";
import { visibleNavigation } from "@/components/layout/navigation";
import { NavigationContext } from "@/components/layout/useNavigation";
import { useAuthStore } from "@/features/auth/store";
import { useFeatureFlagStore } from "@/features/settings/flagStore";
import { useCorpusStore } from "@/features/vulnerabilities/corpusStore";

/**
 * The tree this account may see, resolved once for every surface that draws it — the
 * sidebar at `md` and above, the drawer below it (#141). Resolving it here rather than in
 * each surface is what keeps the two from disagreeing, and keeps the flags read to one
 * request: the flags endpoint needs a session but no permission, and a failure simply
 * hides the flag-gated entries.
 *
 * The flags themselves live in `flagStore` (#402), not here. This is still where they are
 * read — once, when the signed-in layout mounts — but the answer is shared, so the toggle
 * on Settings › Feature Flags reaches this tree without a reload, in both directions.
 *
 * The third input is the data (#529), read the same way into `corpusStore`: one request,
 * shared, and a failure that simply hides the entries that need it.
 */
export function NavigationProvider({ children }: PropsWithChildren) {
  const permissions = useAuthStore((state) => state.user?.permissions);

  const enabledFlags = useFeatureFlagStore((state) => state.enabled);
  const load = useFeatureFlagStore((state) => state.load);
  const answering = useCorpusStore((state) => state.answering);
  const loadCorpus = useCorpusStore((state) => state.load);
  useEffect(() => {
    void load();
    void loadCorpus();
  }, [load, loadCorpus]);

  const items = useMemo(
    () => visibleNavigation(permissions, enabledFlags, answering),
    [permissions, enabledFlags, answering]
  );

  return <NavigationContext.Provider value={items}>{children}</NavigationContext.Provider>;
}
