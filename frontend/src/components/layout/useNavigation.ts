import { createContext, useContext } from "react";
import type { NavItem } from "@/components/layout/navigation";

/** Filled by `NavigationProvider` (NavigationProvider.tsx); read by every surface that
 *  draws the tree. The context lives beside the hook rather than the provider so the
 *  provider's file exports a component and nothing else. */
export const NavigationContext = createContext<NavItem[] | null>(null);

/** The tree this account may see — see `visibleNavigation` in navigation.ts. */
export function useNavigation(): NavItem[] {
  const items = useContext(NavigationContext);
  if (!items) throw new Error("useNavigation must be used within a NavigationProvider");
  return items;
}
