import { Info } from "lucide-react";
import { useBuildVersion } from "@/features/system/useBuildVersion";
import { useLocale } from "@/i18n/LocaleContext";

interface BuildVersionProps {
  /** Sidebar is collapsed to icons. A 64px rail cannot hold the string — it renders
   *  as a ~30px stub — so this becomes an icon and the value moves to the tooltip,
   *  which is what the collapsed nav links above already do. */
  collapsed?: boolean;
}

/** The build this instance is running, in the sidebar footer.
 *
 *  Ambient, not authoritative: the sidebar is hidden below 768px and can be switched
 *  off entirely, so Settings → My Account carries the same value as the surface that
 *  cannot disappear. Both exist because #130 took this answer off the sign-in page. */
export function BuildVersion({ collapsed = false }: BuildVersionProps) {
  const { t } = useLocale();
  const version = useBuildVersion();

  if (!version) return null;

  const label = `${t.auth.versionLabel} ${version}`;

  if (collapsed) {
    return (
      <p className="flex justify-center border-t pt-2 text-muted-foreground/70" title={label}>
        <Info aria-hidden="true" className="h-3.5 w-3.5" />
        <span className="sr-only">{label}</span>
      </p>
    );
  }

  return (
    <p
      className="truncate border-t px-3 py-2 text-center font-mono text-[11px] text-muted-foreground/70"
      title={label}
    >
      <span className="sr-only">{t.auth.versionLabel} </span>
      {version}
    </p>
  );
}
