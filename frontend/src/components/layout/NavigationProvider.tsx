import { useEffect, useMemo, useState, type PropsWithChildren } from "react";
import { visibleNavigation } from "@/components/layout/navigation";
import { NavigationContext } from "@/components/layout/useNavigation";
import { useAuthStore } from "@/features/auth/store";
import { listFeatureFlags } from "@/features/settings/api";

/**
 * The tree this account may see, resolved once for every surface that draws it — the
 * sidebar at `md` and above, the drawer below it (#141). Resolving it here rather than in
 * each surface is what keeps the two from disagreeing, and keeps the flags read to one
 * request: the flags endpoint needs a session but no permission, and a failure simply
 * hides the flag-gated entries.
 */
export function NavigationProvider({ children }: PropsWithChildren) {
  const permissions = useAuthStore((state) => state.user?.permissions);

  // Flags are read once per mount of the signed-in layout.
  const [enabledFlags, setEnabledFlags] = useState<Set<string>>(() => new Set());
  useEffect(() => {
    let cancelled = false;
    listFeatureFlags()
      .then((flags) => {
        if (!cancelled) setEnabledFlags(new Set(flags.filter((f) => f.enabled).map((f) => f.key)));
      })
      .catch(() => {
        if (!cancelled) setEnabledFlags(new Set());
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const items = useMemo(() => visibleNavigation(permissions, enabledFlags), [permissions, enabledFlags]);

  return <NavigationContext.Provider value={items}>{children}</NavigationContext.Provider>;
}
