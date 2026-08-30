import { useEffect, useState } from "react";
import { Info } from "lucide-react";
import { getVersion } from "@/features/system/api";
import { useLocale } from "@/i18n/LocaleContext";

interface BuildVersionProps {
  /** Sidebar is collapsed to icons. A 64px rail cannot hold the string — it renders
   *  as a ~30px stub — so this becomes an icon and the value moves to the tooltip,
   *  which is what the collapsed nav links above already do. */
  collapsed?: boolean;
}

/** The build this instance is running, parked in the sidebar footer so a signed-in
 *  operator can always answer "what am I on?" without hunting for a page.
 *
 *  Fetches rather than reading the auth store: /auth/status only carries the version
 *  for a caller who was already signed in when it ran, so a fresh login in the same
 *  page load would leave the store holding the anonymous null (issue #130). */
export function BuildVersion({ collapsed = false }: BuildVersionProps) {
  const { t } = useLocale();
  const [version, setVersion] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    getVersion()
      .then((result) => {
        if (!cancelled) setVersion(result.version);
      })
      .catch(() => {
        // Unreachable backend or a stale session: show nothing rather than an error
        // in a chrome element nobody came here to read.
      });
    return () => {
      cancelled = true;
    };
  }, []);

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
