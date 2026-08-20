import { Info } from "lucide-react";
import { useAuthStore } from "@/features/auth/store";
import { useLocale } from "@/i18n/LocaleContext";

/** The (i) under the pre-auth cards: which build this instance is running.
 *  Renders nothing until /auth/status has answered — an empty badge would just
 *  be a mystery icon. */
export function VersionBadge() {
  const { t } = useLocale();
  const version = useAuthStore((state) => state.version);

  if (!version) return null;

  return (
    <p
      className="flex items-center justify-center gap-1.5 text-xs text-muted-foreground/80"
      title={`${t.auth.versionLabel} ${version}`}
    >
      <Info aria-hidden="true" className="h-3.5 w-3.5" />
      <span>
        <span className="sr-only">{t.auth.versionLabel} </span>
        {version}
      </span>
    </p>
  );
}
