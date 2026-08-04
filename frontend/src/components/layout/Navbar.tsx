import { LogOut, Moon, Sun } from "lucide-react";
import { useNavigate } from "react-router";
import { FlaskLogo } from "@/components/icons/FlaskLogo";
import { LanguageSwitcher } from "@/components/layout/LanguageSwitcher";
import { SidebarModeSwitcher } from "@/components/layout/SidebarModeSwitcher";
import { useAuthStore } from "@/features/auth/store";
import { useTheme } from "@/hooks/useTheme";
import { useLocale } from "@/i18n/LocaleContext";

export function Navbar() {
  const { theme, toggleTheme } = useTheme();
  const { t } = useLocale();
  const navigate = useNavigate();
  const user = useAuthStore((state) => state.user);
  const logout = useAuthStore((state) => state.logout);

  async function handleSignOut() {
    await logout();
    navigate("/login", { replace: true });
  }

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

          {user && (
            <div className="ml-1 flex items-center gap-2 border-l pl-3">
              <span className="hidden text-sm text-muted-foreground sm:inline">
                {user.displayName}
              </span>
              <button
                type="button"
                aria-label={t.auth.signOut}
                title={t.auth.signOut}
                onClick={handleSignOut}
                className="flex h-9 w-9 items-center justify-center rounded-md border border-input bg-background hover:bg-accent"
              >
                <LogOut className="h-4 w-4" />
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
