import { Moon, Sun } from "lucide-react";
import { FlaskLogo } from "@/components/icons/FlaskLogo";
import { LanguageSwitcher } from "@/components/layout/LanguageSwitcher";
import { SidebarModeSwitcher } from "@/components/layout/SidebarModeSwitcher";
import { useTheme } from "@/hooks/useTheme";
import { useLocale } from "@/i18n/LocaleContext";

export function Navbar() {
  const { theme, toggleTheme } = useTheme();
  const { t } = useLocale();

  return (
    <header className="sticky top-0 z-40 border-b bg-background/95 backdrop-blur">
      <div className="flex h-14 items-center justify-between px-6">
        <div className="flex items-center gap-3">
          <SidebarModeSwitcher />
          <div className="flex items-center gap-2 font-semibold">
            <FlaskLogo className="h-5 w-5 text-primary" />
            <span>LoonInspect</span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <LanguageSwitcher />
          <button
            type="button"
            aria-label={theme === "dark" ? t.common.lightMode : t.common.darkMode}
            onClick={toggleTheme}
            className="flex h-9 w-9 items-center justify-center rounded-md border border-input bg-background hover:bg-accent"
          >
            {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
          </button>
        </div>
      </div>
    </header>
  );
}
