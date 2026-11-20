import { useEffect, useState } from "react";
import { ExternalLink } from "@/components/ui/external-link";
import { SUPPORT_LINKS } from "@/features/support/links";
import { getUpdateStatus, type UpdateStatusResponse } from "@/features/system/api";
import { type BodyView, describeSends, describeUpdate, shellSafeTag, type Unsent, UPDATES_ANCHOR, upgradeCommands } from "@/features/system/updateStatus";
import { useLocale } from "@/i18n/LocaleContext";

/** `readAt`: when the status arrived, which a next check already past is judged against. */
type Loaded = { state: "ready"; status: UpdateStatusResponse; readAt: number } | { state: "failed" } | null;

function formatInstant(value: string | null): string | null {
  return value ? new Date(value).toLocaleString() : null;
}

/** One body as the JSON text sent, to read and copy, or the sentence that says why there is none. */
function BodySlot({ label, view, none }: { label: string; view: BodyView; none: Record<Unsent, string> }) {
  return (
    <figure className="min-w-0 space-y-1">
      <figcaption className="text-xs text-muted-foreground">{label}</figcaption>
      {"json" in view ? (
        <pre className="overflow-x-auto rounded-md border bg-background px-3 py-2 font-mono text-xs leading-relaxed">{view.json}</pre>
      ) : (
        <p className="text-sm text-muted-foreground">{none[view.none]}</p>
      )}
    </figure>
  );
}

/**
 * Settings › Support › **Updates** (#407): this build, the latest published release, when
 * the check last ran, what the answer is — and, when it could not answer, why
 * (`docs/diagnosability.md` rule 1). Then what the check sends (#819): to whom, when, and the
 * literal bodies of the last check and the next, so nobody learns them from a traffic capture.
 * The banner and the Needs Attention row both link here, because this is where the upgrade
 * steps are: the dump first, then the release tag, then the build. Updating stays a host-side
 * act; nothing here runs anything, and reading the block asks no one.
 *
 * Rendered only for readers who hold SYSTEM_READ, like the banner: whether an instance is
 * behind is the sensitive half of the version question (`backend/app/api/system.py`).
 */
export function UpdatesBlock() {
  const { t } = useLocale();
  const tu = t.support.updates;
  const [loaded, setLoaded] = useState<Loaded>(null);

  useEffect(() => {
    let cancelled = false;
    getUpdateStatus()
      .then((status) => {
        if (!cancelled) setLoaded({ state: "ready", status, readAt: Date.now() });
      })
      .catch(() => {
        if (!cancelled) setLoaded({ state: "failed" });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const status = loaded?.state === "ready" ? loaded.status : null;
  const view = status ? describeUpdate(status) : null;
  const sends = loaded?.state === "ready" ? describeSends(loaded.status, loaded.readAt) : null;
  const ts = tu.sends;
  const tag = view?.tag ?? null;

  return (
    <div id={UPDATES_ANCHOR} className="scroll-mt-20 space-y-3 rounded-lg border bg-card p-4">
      <h2 className="text-lg font-semibold">{tu.heading}</h2>
      <p className="max-w-3xl text-sm text-muted-foreground">{tu.help}</p>

      {loaded === null && <p className="text-sm text-muted-foreground">{tu.loading}</p>}
      {loaded?.state === "failed" && <p className="text-sm text-destructive">{tu.errorLoading}</p>}

      {status && view && (
        <>
          <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-3">
            <div>
              <dt className="text-xs text-muted-foreground">{tu.thisBuild}</dt>
              <dd className="font-mono text-xs">{status.currentVersion}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">{tu.latestRelease}</dt>
              <dd>
                {tag && view.releaseUrl ? (
                  <ExternalLink href={view.releaseUrl}>{tag}</ExternalLink>
                ) : (
                  (tag ?? <span className="text-muted-foreground">{view.kind === "unknown" && view.reason === "no_release" ? tu.noneYet : "—"}</span>)
                )}
              </dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">{tu.lastChecked}</dt>
              <dd>{formatInstant(status.checkedAt) ?? <span className="text-muted-foreground">{tu.notChecked}</span>}</dd>
            </div>
          </dl>

          {/* The answer in one sentence, and for an unknown, its reason and next check. */}
          <p className={`max-w-3xl text-sm ${view.kind === "available" ? "font-medium" : ""}`}>
            {view.kind === "available"
              ? tag
                ? tu.available(tag)
                : tu.availableUntagged
              : view.kind === "current"
                ? tag
                  ? tu.current(tag)
                  : tu.currentUntagged
                : view.reason
                  ? tu.reasons[view.reason]
                  : tu.unknownNoReason}
          </p>
        </>
      )}

      {sends && (
        <div className="space-y-3 border-t pt-3">
          <h3 className="text-sm font-semibold">{ts.heading}</h3>
          <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
            <div>
              <dt className="text-xs text-muted-foreground">{ts.host}</dt>
              <dd className="font-mono text-xs wrap-anywhere">{sends.host ?? ts.unreadableHost}</dd>
              <dd className="text-muted-foreground">{ts.shape[sends.provider]}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">{ts.nextCheck}</dt>
              {"at" in sends.owed ? (
                <>
                  <dd>{formatInstant(sends.owed.at)}</dd>
                  {sends.owed.due && <dd className="text-muted-foreground">{ts.owedNow}</dd>}
                </>
              ) : (
                <dd className="text-muted-foreground">{ts.none[sends.owed.none]}</dd>
              )}
            </div>
          </dl>
          <div className="grid gap-3 lg:grid-cols-2">
            <BodySlot label={ts.lastSent} view={sends.last} none={ts.none} />
            <BodySlot label={ts.nextSends} view={sends.next} none={ts.none} />
          </div>
        </div>
      )}

      <div className="space-y-2 pt-1">
        <h3 className="text-sm font-semibold">{tu.stepsHeading}</h3>
        <p className="max-w-3xl text-sm text-muted-foreground">{tu.stepsIntro}</p>
        <pre className="overflow-x-auto rounded-md border bg-background px-3 py-2 font-mono text-xs leading-relaxed">
          {upgradeCommands(tag).join("\n")}
        </pre>
        {shellSafeTag(tag) === null && (
          <p className="max-w-3xl text-sm text-muted-foreground">
            {tu.tagPlaceholder}{" "}
            <ExternalLink href={SUPPORT_LINKS.releases}>{tu.releasesPage}</ExternalLink>
          </p>
        )}
        <p className="max-w-3xl text-sm text-muted-foreground">
          {tu.rollback} <ExternalLink href={SUPPORT_LINKS.rollbackDocs}>{tu.rollbackLink}</ExternalLink>
        </p>
        <p className="max-w-3xl text-xs text-muted-foreground">{tu.selfHostedOnly}</p>
      </div>
    </div>
  );
}
