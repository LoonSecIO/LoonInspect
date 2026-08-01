import { AlertTriangle, Database, Home, Settings } from "lucide-react";
import { NavLink } from "react-router";
import { cn } from "@/lib/utils";

const navigationItems = [
  { label: "Overview", icon: Home, to: "/", end: true },
  { label: "Devices", icon: Database, to: "/devices", end: false },
  { label: "Vulnerabilities", icon: AlertTriangle, to: "/vulnerabilities", end: false },
  { label: "Settings", icon: Settings, to: "/settings/connections", end: false }
];

export function Sidebar() {
  return (
    <aside className="hidden min-h-[calc(100vh-3.5rem)] w-64 border-r bg-muted/30 p-4 md:block">
      <nav className="space-y-1">
        {navigationItems.map((item) => {
          const Icon = item.icon;

          return (
            <NavLink
              key={item.label}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                  isActive
                    ? "bg-accent text-accent-foreground"
                    : "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
                )
              }
            >
              <Icon className="h-4 w-4" />
              {item.label}
            </NavLink>
          );
        })}
      </nav>
    </aside>
  );
}
