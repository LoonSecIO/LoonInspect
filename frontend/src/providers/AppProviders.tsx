import type { PropsWithChildren } from "react";
import { LocaleProvider } from "@/i18n/LocaleContext";
import { SidebarModeProvider } from "@/hooks/SidebarModeContext";

export function AppProviders({ children }: PropsWithChildren) {
  return (
    <LocaleProvider>
      <SidebarModeProvider>{children}</SidebarModeProvider>
    </LocaleProvider>
  );
}
