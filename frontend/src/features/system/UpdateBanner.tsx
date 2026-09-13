import { useEffect, useState } from "react";
import { Link } from "react-router";
import { ArrowUpCircle, X } from "lucide-react";
import { ExternalLink } from "@/components/ui/external-link";
import { PERMISSIONS } from "@/features/auth/types";
import { useHasPermission } from "@/features/auth/store";
import { getUpdateStatus } from "@/features/system/api";
import { bannerRelease, UPDATES_HREF } from "@/features/system/updateStatus";
import { useLocale } from "@/i18n/LocaleContext";

/** Session-scoped, deliberately: an update the operator chose to ignore today
 *  should still greet them tomorrow. */
const DISMISSED_KEY = "looninspect.update-banner-dismissed";

/** "LoonInspect v2026.09.17 is available — what changed · how to update" (#407): a
 *  published release this build does not contain, never a merge to main. Renders nothing
 *  while unknown — a failed or disabled check must never look like a notice (#43) — and
 *  the Updates block on Settings › Support is where the reason is read. The bare command
 *  it used to print skipped the dump; the steps now live in the block, dump first. */
export function UpdateBanner() {
  const { t } = useLocale();
  const canSee = useHasPermission(PERMISSIONS.SYSTEM_READ);
  const [release, setRelease] = useState<{ tag: string | null; releaseUrl: string | null } | null>(null);
  const [dismissed, setDismissed] = useState(
    () => sessionStorage.getItem(DISMISSED_KEY) === "true"
  );

  useEffect(() => {
    if (!canSee) return;
    let cancelled = false;
    getUpdateStatus()
      .then((status) => {
        if (!cancelled) setRelease(bannerRelease(status));
      })
      .catch(() => {
        // Unreachable backend or a 403 from a stale session: show nothing.
      });
    return () => {
      cancelled = true;
    };
  }, [canSee]);

  if (!canSee || dismissed || !release) return null;

  return (
    <div
      role="status"
      className="flex items-center justify-between gap-4 border-b border-primary/20 bg-primary/5 px-6 py-2 text-sm"
    >
      <p className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <ArrowUpCircle aria-hidden="true" className="h-4 w-4 shrink-0 text-primary" />
        <span>{release.tag ? t.system.updateAvailable(release.tag) : t.system.updateAvailableUntagged}</span>
        <span aria-hidden="true">—</span>
        {release.releaseUrl && (
          <>
            <ExternalLink href={release.releaseUrl}>{t.system.updateWhatChanged}</ExternalLink>
            <span aria-hidden="true">·</span>
          </>
        )}
        <Link
          to={UPDATES_HREF}
          className="font-medium text-primary underline underline-offset-4 hover:no-underline"
        >
          {t.system.updateHowTo}
        </Link>
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
