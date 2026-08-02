import { useEffect, useRef, useState } from "react";
import { PanelLeft } from "lucide-react";
import { useSidebarMode, type SidebarMode } from "@/hooks/SidebarModeContext";
import { useLocale } from "@/i18n/LocaleContext";
import { cn } from "@/lib/utils";

const modes: SidebarMode[] = ["expanded", "collapsed", "hidden"];

export function SidebarModeSwitcher() {
  const { sidebarMode, setSidebarMode } = useSidebarMode();
  const { t } = useLocale();
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  const modeLabels: Record<SidebarMode, string> = {
    expanded: t.common.sidebarExpanded,
    collapsed: t.common.sidebarCollapsed,
    hidden: t.common.sidebarHidden
  };

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  return (
    <div className="relative" ref={containerRef}>
      <button
        type="button"
        aria-label={t.common.sidebar}
        onClick={() => setOpen((current) => !current)}
        className="flex h-9 w-9 items-center justify-center rounded-md border border-input bg-background hover:bg-accent"
      >
        <PanelLeft className="h-4 w-4" />
      </button>

      {open && (
        <div className="absolute left-0 z-50 mt-1 w-40 rounded-md border bg-popover p-1 text-popover-foreground shadow-md">
          {modes.map((mode) => (
            <button
              key={mode}
              type="button"
              onClick={() => {
                setSidebarMode(mode);
                setOpen(false);
              }}
              className={cn(
                "flex w-full items-center rounded-sm px-2 py-1.5 text-left text-sm hover:bg-accent hover:text-accent-foreground",
                sidebarMode === mode && "bg-accent text-accent-foreground"
              )}
            >
              {modeLabels[mode]}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
