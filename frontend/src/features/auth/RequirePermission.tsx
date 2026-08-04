import { Lock } from "lucide-react";
import { Outlet } from "react-router";
import { useHasPermission } from "@/features/auth/store";
import type { PermissionName } from "@/features/auth/types";
import { useLocale } from "@/i18n/LocaleContext";

interface RequirePermissionProps {
  permission: PermissionName;
}

/** Guards a route the current account can't use.
 *
 *  Renders an explanation rather than redirecting: someone who followed a bookmark
 *  after being moved to a narrower role should learn why the page is gone, not get
 *  silently bounced to the dashboard and wonder whether the link broke.
 */
export function RequirePermission({ permission }: RequirePermissionProps) {
  const { t } = useLocale();
  const allowed = useHasPermission(permission);

  if (!allowed) {
    return (
      <section className="flex flex-col items-center justify-center gap-3 rounded-lg border border-dashed bg-muted/30 px-6 py-16 text-center">
        <Lock className="h-6 w-6 text-muted-foreground" />
        <h1 className="text-lg font-semibold">{t.auth.noAccessTitle}</h1>
        <p className="max-w-md text-sm text-muted-foreground">{t.auth.noAccessDescription}</p>
      </section>
    );
  }

  return <Outlet />;
}
