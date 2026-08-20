import { useEffect, useState } from "react";
import { ArrowUpCircle, X } from "lucide-react";
import { PERMISSIONS } from "@/features/auth/types";
import { useHasPermission } from "@/features/auth/store";
import { getUpdateStatus } from "@/features/system/api";
import { useLocale } from "@/i18n/LocaleContext";

/** Session-scoped, deliberately: an update the operator chose to ignore today
 *  should still greet them tomorrow. */
const DISMISSED_KEY = "looninspect.update-banner-dismissed";

/** "A newer build of main exists." Renders nothing while unknown — a failed or
 *  disabled check must be indistinguishable from being current (see issue #43). */
export function UpdateBanner() {
  const { t } = useLocale();
  const canSee = useHasPermission(PERMISSIONS.SYSTEM_READ);
  const [latestSha, setLatestSha] = useState<string | null>(null);
  const [dismissed, setDismissed] = useState(
    () => sessionStorage.getItem(DISMISSED_KEY) === "true"
  );

  useEffect(() => {
    if (!canSee) return;
    let cancelled = false;
    getUpdateStatus()
      .then((status) => {
        if (!cancelled && status.updateAvailable) setLatestSha(status.latestSha);
      })
      .catch(() => {
        // Unreachable backend or a 403 from a stale session: show nothing.
      });
    return () => {
      cancelled = true;
    };
  }, [canSee]);

  if (!canSee || dismissed || !latestSha) return null;

  return (
    <div
      role="status"
      className="flex items-center justify-between gap-4 border-b border-primary/20 bg-primary/5 px-6 py-2 text-sm"
    >
      <p className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <ArrowUpCircle aria-hidden="true" className="h-4 w-4 shrink-0 text-primary" />
        <span>
          {t.system.updateAvailable} ({latestSha.slice(0, 7)})
        </span>
        <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">
          git pull && GIT_SHA=$(git rev-parse --short HEAD) docker compose up -d --build
        </code>
      </p>
      <button
        type="button"
        aria-label={t.system.dismissUpdate}
        onClick={() => {
          sessionStorage.setItem(DISMISSED_KEY, "true");
          setDismissed(true);
        }}
        className="flex h-6 w-6 shrink-0 items-center justify-center rounded hover:bg-accent"
      >
        <X className="h-4 w-4" />
      </button>
    </div>
  );
}
