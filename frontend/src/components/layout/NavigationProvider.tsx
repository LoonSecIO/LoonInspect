import { useEffect, useMemo, type PropsWithChildren } from "react";
import { visibleNavigation } from "@/components/layout/navigation";
import { NavigationContext } from "@/components/layout/useNavigation";
import { useAuthStore } from "@/features/auth/store";
import { useFeatureFlagStore } from "@/features/settings/flagStore";

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
 */
export function NavigationProvider({ children }: PropsWithChildren) {
  const permissions = useAuthStore((state) => state.user?.permissions);

  const enabledFlags = useFeatureFlagStore((state) => state.enabled);
  const load = useFeatureFlagStore((state) => state.load);
  useEffect(() => {
    void load();
  }, [load]);

  const items = useMemo(() => visibleNavigation(permissions, enabledFlags), [permissions, enabledFlags]);

  return <NavigationContext.Provider value={items}>{children}</NavigationContext.Provider>;
}
