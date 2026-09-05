import { useEffect, useMemo, useState } from "react";
import { AppWindow, Database, Flag, Gauge, History, Home, KeyRound, LifeBuoy, ListChecks, Plug, Send, Settings, Sparkles, UserCircle, UserCog, Share2, type LucideIcon } from "lucide-react";
import { NavLink } from "react-router";
import { cn } from "@/lib/utils";
import { useAuthStore } from "@/features/auth/store";
import { useAttentionStore } from "@/features/overview/attentionStore";
import { BuildVersion } from "@/features/system/BuildVersion";
import { PERMISSIONS, type PermissionName } from "@/features/auth/types";
import { useLocale } from "@/i18n/LocaleContext";
import type { Translations } from "@/i18n/en";
import { useSidebarMode } from "@/hooks/SidebarModeContext";
import { listFeatureFlags } from "@/features/settings/api";

type NavKey = keyof Translations["nav"];

interface NavItem {
  labelKey: NavKey;
  icon: LucideIcon;
  to: string;
  end: boolean;
  /** Omitted where every role can see the page. */
  permission?: PermissionName;
  /** Listed only while this feature flag is on (Settings › AI, #319). */
  flag?: string;
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
      // Flag-gated as well as permission-gated: no top-level /ai exists, and this
      // entry appears only once the `ai_features` switch is on (#319).
      {
        labelKey: "ai",
        icon: Sparkles,
        to: "/settings/ai",
        end: false,
        permission: PERMISSIONS.SYSTEM_READ,
        flag: "ai_features"
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
      // Last, so it is where a person scans when nothing else worked. The permission
      // matches the route's own gate in routes.tsx — DEVICE_READ, the floor every
      // role holds — so this entry cannot become a nav item pointing at a page the
      // reader is then refused (#301).
      {
        labelKey: "support",
        icon: LifeBuoy,
        to: "/settings/support",
        end: false,
        permission: PERMISSIONS.DEVICE_READ
      }
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
  // The Needs Attention count (#106), read from the store the panel on "/" fills rather
  // than counted here. That is the ruling: the composition has exactly one
  // implementation and this badge is its only off-page rendering — a sidebar that ran
  // the five checks itself would be a second implementation of the list, and four more
  // requests on every page in the product. The cost is that the badge is blank until
  // "/" has been visited once in this session.
  //
  // `total`, never `rows.length`. `rows` is post-`slice(0, MAX_ROWS)` and excludes the
  // degraded entries, so counting it would make the badge under-deliver on the one job
  // the ruling gives it twice over: nine problems would render "5", and a pod where all
  // five checks error — the case where nobody knows anything — would render no badge at
  // all.
  const attentionCount = useAttentionStore((state) => state.total);

  // Flags are read once per mount; the flags endpoint needs a session but no
  // permission, and a failure simply hides the flag-gated entries.
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

  const visibleItems = useMemo(() => {
    const granted = new Set(permissions ?? []);
    const allowed = (item: NavItem) =>
      (!item.permission || granted.has(item.permission)) && (!item.flag || enabledFlags.has(item.flag));

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
  }, [permissions, enabledFlags]);

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
          const badge = item.labelKey === "overview" && attentionCount > 0 ? attentionCount : null;

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
                {badge !== null && (
                  // Labelled, not a bare number: a screen reader reading "Overview 3"
                  // has been told a count without being told of what. Its own string,
                  // not the footer's `andMore` — that one means "N *more* than the five
                  // shown", and reusing it made the badge announce "3 more items need
                  // attention" when three is the whole list.
                  <span
                    aria-label={t.overview.attention.badge(badge)}
                    className={cn(
                      "flex h-5 min-w-5 items-center justify-center rounded-full bg-destructive px-1.5 text-xs font-semibold text-destructive-foreground",
                      !collapsed && "ml-auto"
                    )}
                  >
                    {badge}
                  </span>
                )}
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
