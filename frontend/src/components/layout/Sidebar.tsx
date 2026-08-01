import { AlertTriangle, Database, Home, Settings } from "lucide-react";
import { cn } from "@/lib/utils";

const navigationItems = [
  {
    label: "Overview",
    icon: Home,
    href: "#"
  },
  {
    label: "MDM",
    icon: Database,
    href: "#"
  },
  {
    label: "Vulnerabilities",
    icon: AlertTriangle,
    href: "#"
  },
  {
    label: "Settings",
    icon: Settings,
    href: "#"
  }
];

export function Sidebar() {
  return (
    <aside className="hidden min-h-[calc(100vh-3.5rem)] w-64 border-r bg-muted/30 p-4 md:block">
      <nav className="space-y-1">
        {navigationItems.map((item) => {
          const Icon = item.icon;

          return (
            <a
              key={item.label}
              href={item.href}
              className={cn(
                "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium text-muted-foreground transition-colors",
                "hover:bg-accent hover:text-accent-foreground"
              )}
            >
              <Icon className="h-4 w-4" />
              {item.label}
            </a>
          );
        })}
      </nav>
    </aside>
  );
}