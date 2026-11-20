import { useEffect, useState } from "react";
import { Link } from "react-router";
import { Info } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ApiError } from "@/config/api";
import { PERMISSIONS } from "@/features/auth/types";
import { useHasPermission } from "@/features/auth/store";
import { dismissUpdateNotice, getUpdateStatus, type UpdateStatusResponse } from "@/features/system/api";
import { UPDATES_HREF } from "@/features/system/updateStatus";
import { useLocale } from "@/i18n/LocaleContext";

type Kind = UpdateStatusResponse["kind"];
/** Why a dismissal did not land: refused (403), another error the instance answered with, or no answer read. */
type Failure = "refused" | number | "unreachable";

/** The kind to word the notice for, or null: shown while it is pending and the check asks LoonSec's service. With
 *  the check off, or asking a GitHub-shaped address, it is not shown and stays pending, for the day the check does. */
function shownFor(status: UpdateStatusResponse): Kind | null {
  const asks = status.reason !== "disabled" && status.reason !== "dev_build";
  return status.noticePending && status.provider === "loonsec" && asks ? status.kind : null;
}

const failure = (error: unknown): Failure =>
  error instanceof ApiError ? (error.status === 403 ? "refused" : error.status) : "unreachable";

/**
 * Told once, after the update (#819): an administrator of an instance that held an account when it was updated
 * is told that the update check now asks LoonSec's update service, what the request carries, that LoonSec counts
 * running instances from it, where it is shown word for word and how to turn it off. A fresh install is told on
 * the setup page instead, and its migration leaves this pending only where an account already existed.
 *
 * Only an account that may dismiss it sees it (SYSTEM_WRITE, which the route needs); the flag is the instance's,
 * so a dismissal clears it for every administrator, for good. A dismissal that fails leaves it up and says why
 * (`docs/troubleshooting.md` §10 step 6). Mounted under the update banner in the signed-in shell only.
 */
export function UpdateCheckNotice() {
  const { t } = useLocale();
  const tn = t.updateCheckNotice;
  const canDismiss = useHasPermission(PERMISSIONS.SYSTEM_WRITE);
  const [kind, setKind] = useState<Kind | null>(null);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState<Failure | null>(null);

  useEffect(() => {
    if (!canDismiss) return;
    let cancelled = false;
    getUpdateStatus()
      .then((status) => {
        if (!cancelled) setKind(shownFor(status));
      })
      .catch(() => {
        // Not read, so nothing is shown; the notice stays pending for the next page load.
      });
    return () => {
      cancelled = true;
    };
  }, [canDismiss]);

  if (!canDismiss || kind === null) return null;

  async function dismiss() {
    setBusy(true);
    setFailed(null);
    try {
      setKind(shownFor(await dismissUpdateNotice()));
    } catch (error) {
      setFailed(failure(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section
      aria-label={tn.label}
      className="flex flex-col gap-2 border-b bg-muted px-6 py-3 text-sm sm:flex-row sm:items-start sm:justify-between sm:gap-4"
    >
      <div className="flex min-w-0 gap-2">
        <Info aria-hidden="true" className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
        <div className="max-w-4xl space-y-2">
          <p>
            {tn.asks}{" "}
            <Link to={UPDATES_HREF} className="font-medium text-primary underline underline-offset-4 hover:no-underline">
              {tn.updates}
            </Link>
            {tn.shows[kind]}
          </p>
          {failed !== null && (
            <p role="alert" className="text-destructive">
              {failed === "refused" ? tn.refused : failed === "unreachable" ? tn.unreachable : tn.failed(failed)}
            </p>
          )}
        </div>
      </div>
      <Button variant="outline" size="sm" className="shrink-0 self-start" disabled={busy} onClick={() => void dismiss()}>
        {busy ? tn.dismissing : tn.dismiss}
      </Button>
    </section>
  );
}
