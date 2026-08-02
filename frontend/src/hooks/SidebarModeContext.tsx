import { createContext, useCallback, useContext, useEffect, useMemo, useState, type PropsWithChildren } from "react";

export type SidebarMode = "expanded" | "collapsed" | "hidden";

interface SidebarModeContextValue {
  sidebarMode: SidebarMode;
  setSidebarMode: (mode: SidebarMode) => void;
}

const SidebarModeContext = createContext<SidebarModeContextValue | null>(null);

function getInitialSidebarMode(): SidebarMode {
  const stored = window.localStorage.getItem("sidebarMode");
  if (stored === "expanded" || stored === "collapsed" || stored === "hidden") return stored;
  return "expanded";
}

export function SidebarModeProvider({ children }: PropsWithChildren) {
  const [sidebarMode, setSidebarModeState] = useState<SidebarMode>(getInitialSidebarMode);

  useEffect(() => {
    window.localStorage.setItem("sidebarMode", sidebarMode);
  }, [sidebarMode]);

  const setSidebarMode = useCallback((mode: SidebarMode) => {
    setSidebarModeState(mode);
  }, []);

  const value = useMemo(() => ({ sidebarMode, setSidebarMode }), [sidebarMode, setSidebarMode]);

  return <SidebarModeContext.Provider value={value}>{children}</SidebarModeContext.Provider>;
}

export function useSidebarMode() {
  const context = useContext(SidebarModeContext);
  if (!context) throw new Error("useSidebarMode must be used within a SidebarModeProvider");
  return context;
}
