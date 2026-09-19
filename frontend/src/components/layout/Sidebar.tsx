import { NavTree } from "@/components/layout/NavTree";
import { useNavigation } from "@/components/layout/useNavigation";
import { BuildVersion } from "@/features/system/BuildVersion";
import { useSidebarMode } from "@/hooks/SidebarModeContext";
import { cn } from "@/lib/utils";

/** The navigation at `md` and above. Below that breakpoint this is `display: none` and
 *  the drawer in the navbar (MobileNav.tsx) draws the same tree (#141); the tree itself
 *  and the rules for who sees what live in `navigation.ts`. */
export function Sidebar() {
  const { sidebarMode } = useSidebarMode();
  const items = useNavigation();

  if (sidebarMode === "hidden") return null;

  const collapsed = sidebarMode === "collapsed";

  return (
    <aside
      className={cn(
        "app-sidebar app-nav-surface hidden flex-col border-r p-3 md:flex",
        collapsed ? "w-16" : "w-60"
      )}
    >
      <NavTree items={items} collapsed={collapsed} />

      <div className="mt-auto pt-4">
        <BuildVersion collapsed={collapsed} />
      </div>
    </aside>
  );
}
