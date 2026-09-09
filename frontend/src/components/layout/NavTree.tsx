import { NavLink } from "react-router";
import type { NavItem } from "@/components/layout/navigation";
import { useAttentionStore } from "@/features/overview/attentionStore";
import { useLocale } from "@/i18n/LocaleContext";
import { cn } from "@/lib/utils";

const linkClasses =
  "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors";
const linkStateClasses = (isActive: boolean) =>
  isActive
    ? "bg-accent text-accent-foreground"
    : "text-muted-foreground hover:bg-accent hover:text-accent-foreground";

interface NavTreeProps {
  items: NavItem[];
  /** Icons only, with the label in the title — the sidebar's 64px rail. */
  collapsed?: boolean;
  /** Called after any link is chosen. The drawer closes itself on it; the sidebar has
   *  nothing to do. */
  onNavigate?: () => void;
}

/** The tree as links. One rendering for both surfaces (#141), so the sidebar and the
 *  drawer cannot drift apart in what they list or how they mark the current page. */
export function NavTree({ items, collapsed = false, onNavigate }: NavTreeProps) {
  const { t } = useLocale();
  // The Needs Attention count (#106), read from the store the panel on "/" fills rather
  // than counted here. That is the ruling: the composition has exactly one
  // implementation and this badge is its only off-page rendering — a nav that ran
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

  return (
    <nav className="space-y-1">
      {items.map((item) => {
        const Icon = item.icon;
        const badge = item.labelKey === "overview" && attentionCount > 0 ? attentionCount : null;

        return (
          <div key={item.labelKey}>
            <NavLink
              to={item.to}
              end={item.end}
              title={collapsed ? t.nav[item.labelKey] : undefined}
              onClick={onNavigate}
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
                      onClick={onNavigate}
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
  );
}
