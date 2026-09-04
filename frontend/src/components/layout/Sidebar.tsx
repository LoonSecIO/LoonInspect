import { useMemo } from "react";
import { AppWindow, Database, Flag, Gauge, History, Home, KeyRound, LifeBuoy, ListChecks, Plug, Send, Settings, UserCircle, UserCog, Share2, type LucideIcon } from "lucide-react";
import { NavLink } from "react-router";
import { cn } from "@/lib/utils";
import { useAuthStore } from "@/features/auth/store";
import { BuildVersion } from "@/features/system/BuildVersion";
import { PERMISSIONS, type PermissionName } from "@/features/auth/types";
import { useLocale } from "@/i18n/LocaleContext";
import type { Translations } from "@/i18n/en";
import { useSidebarMode } from "@/hooks/SidebarModeContext";

type NavKey = keyof Translations["nav"];

interface NavItem {
  labelKey: NavKey;
  icon: LucideIcon;
  to: string;
  end: boolean;
  /** Omitted where every role can see the page. */
  permission?: PermissionName;
  children?: NavItem[];
}

const navigationItems: NavItem[] = [
  { labelKey: "overview", icon: Home, to: "/", end: true },
  {
    labelKey: "devices",
    icon: Database,
    to: "/devices",
    end: false,
    children: [
      { labelKey: "applications", icon: AppWindow, to: "/devices/applications", end: false },
      { labelKey: "smartGroupCost", icon: Gauge, to: "/devices/groups/cost", end: false },
      { labelKey: "changes", icon: History, to: "/devices/changes", end: false }
    ]
  },
  {
    labelKey: "settings",
    icon: Settings,
    to: "/settings/connections",
    end: false,
    children: [
      {
        labelKey: "connections",
        icon: Plug,
        to: "/settings/connections",
        end: false,
        permission: PERMISSIONS.CONNECTION_READ
      },
      {
        labelKey: "changeTracking",
        icon: ListChecks,
        to: "/settings/change-tracking",
        end: false,
        permission: PERMISSIONS.CONNECTION_READ
      },
      {
        labelKey: "featureFlags",
        icon: Flag,
        to: "/settings/feature-flags",
        end: false,
        permission: PERMISSIONS.FEATURE_FLAG_WRITE
      },
      {
        labelKey: "apiTokens",
        icon: KeyRound,
        to: "/settings/api-tokens",
        end: false,
        permission: PERMISSIONS.TOKEN_CREATE
      },
      {
        labelKey: "dataSharing",
        icon: Share2,
        to: "/settings/data-sharing",
        end: false,
        permission: PERMISSIONS.SYSTEM_READ
      },
      {
        labelKey: "destinations",
        icon: Send,
        to: "/settings/destinations",
        end: false,
        permission: PERMISSIONS.DESTINATION_READ
      },
      {
        labelKey: "accounts",
        icon: UserCog,
        to: "/settings/accounts",
        end: false,
        permission: PERMISSIONS.ACCOUNT_READ
      },
      // Ungated: everyone has a profile and a password to change.
      { labelKey: "myAccount", icon: UserCircle, to: "/settings/my-account", end: false },
      // Ungated on purpose, and last so it is where a person scans when nothing else
      // worked: the one page whose reader may well be someone a permission has
      // already refused (#301).
      { labelKey: "support", icon: LifeBuoy, to: "/settings/support", end: false }
    ]
  }
];

const linkClasses =
  "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors";
const linkStateClasses = (isActive: boolean) =>
  isActive
    ? "bg-accent text-accent-foreground"
    : "text-muted-foreground hover:bg-accent hover:text-accent-foreground";

export function Sidebar() {
  const { t } = useLocale();
  const { sidebarMode } = useSidebarMode();
  const permissions = useAuthStore((state) => state.user?.permissions);

  const visibleItems = useMemo(() => {
    const granted = new Set(permissions ?? []);
    const allowed = (item: NavItem) => !item.permission || granted.has(item.permission);

    return navigationItems.filter(allowed).flatMap((item) => {
      if (!item.children) return [item];

      const children = item.children.filter(allowed);
      // A section whose every child is hidden has nothing left to show.
      if (children.length === 0) return [];

      // The parent's own target may itself be one of the hidden children (Settings
      // points at Connections). Re-point it rather than linking somewhere this
      // account will just be refused.
      const ownTargetHidden = item.children.some(
        (child) => child.to === item.to && !allowed(child)
      );

      return [{ ...item, children, to: ownTargetHidden ? children[0].to : item.to }];
    });
  }, [permissions]);

  if (sidebarMode === "hidden") return null;

  const collapsed = sidebarMode === "collapsed";

  return (
    <aside
      className={cn(
        "hidden min-h-[calc(100vh-3.5rem)] flex-col border-r bg-muted/30 p-4 md:flex",
        collapsed ? "w-16" : "w-64"
      )}
    >
      <nav className="space-y-1">
        {visibleItems.map((item) => {
          const Icon = item.icon;

          return (
            <div key={item.labelKey}>
              <NavLink
                to={item.to}
                end={item.end}
                title={collapsed ? t.nav[item.labelKey] : undefined}
                className={({ isActive }) =>
                  cn(linkClasses, linkStateClasses(isActive), collapsed && "justify-center px-2")
                }
              >
                <Icon className="h-4 w-4 shrink-0" />
                {!collapsed && t.nav[item.labelKey]}
              </NavLink>
              {!collapsed && item.children && (
                <div className="ml-4 mt-1 space-y-1 border-l pl-3">
                  {item.children.map((child) => {
                    const ChildIcon = child.icon;

                    return (
                      <NavLink
                        key={child.labelKey}
                        to={child.to}
                        end={child.end}
                        className={({ isActive }) => cn(linkClasses, linkStateClasses(isActive))}
                      >
                        <ChildIcon className="h-4 w-4 shrink-0" />
                        {t.nav[child.labelKey]}
                      </NavLink>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </nav>

      <div className="mt-auto pt-4">
        <BuildVersion collapsed={collapsed} />
      </div>
    </aside>
  );
}
