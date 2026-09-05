import { useCallback, useEffect, useState } from "react";
import { Check, Copy, Globe, MessagesSquare, ShieldAlert, Bug } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ExternalLink } from "@/components/ui/external-link";
import { useBuildVersion } from "@/features/system/useBuildVersion";
import {
  NOTES_URL,
  SECURITY_EMAIL,
  SLACK_CHANNEL,
  SUPPORT_LINKS,
  SUPPORT_REPO,
  WEBSITE_URL,
  copyableBuild
} from "@/features/support/links";
import { useLocale } from "@/i18n/LocaleContext";

/** How long "Copied" stands before the button gives the word back. Matches the
 *  Overview status strip, which copies a job ID the same way. */
const COPIED_VISIBLE_MS = 2000;

/** Settings → Support: the security carve-out, the build string a report needs, and
 *  the two channels — in that order on purpose, because the carve-out is the only one
 *  of the three that costs something when it is read second (see the comment on it).
 *
 *  Gated on DEVICE_READ, like the seven other /settings routes that carry a permission
 *  (/settings/my-account is the one that does not; see routes.tsx for why DEVICE_READ
 *  and not a new permission). DEVICE_READ is the floor every authenticated role holds,
 *  so the route table shows a gate without locking a Viewer out of the page they reach
 *  when something is already broken. A reader with no session at all is answered on
 *  the login page instead.
 *
 *  It reads one endpoint (`/system/version`, via useBuildVersion) and posts nothing.
 *  No ticketing, no contact form, no telemetry: LoonInspect is self-hosted and this
 *  page keeps that promise the way ErrorBoundary does.
 */
export function SupportPage() {
  const { t } = useLocale();
  const version = useBuildVersion();
  const build = copyableBuild(version);

  const [copied, setCopied] = useState(false);
  const copy = useCallback(() => {
    if (build === null) return;
    // Best-effort, like the Overview strip: an insecure origin or a browser that
    // refuses clipboard access leaves the string on screen to select by hand.
    void navigator.clipboard?.writeText(build).then(
      () => setCopied(true),
      () => undefined
    );
  }, [build]);

  useEffect(() => {
    if (!copied) return;
    const handle = window.setTimeout(() => setCopied(false), COPIED_VISIBLE_MS);
    return () => window.clearTimeout(handle);
  }, [copied]);

  return (
    <section className="space-y-6">
      <div>
        <p className="text-sm font-medium text-muted-foreground">{t.settings.eyebrow}</p>
        <h1 className="text-3xl font-bold tracking-tight">{t.support.title}</h1>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t.support.description}</p>
      </div>

      {/* First, above both channels, because reading order here is a safety property.
          Rendered, the old order put this heading below the fold on anything shorter
          than about 900px while "Open an issue" stayed fully visible — 1164px down a
          375x812 phone, and clipped at 800x450 — so the one reader who must not use
          the public tracker met the public tracker first and the carve-out second, or
          never. It fit on a 1440x900 laptop, which is why the order looked fine when
          it was written. On the day the repository goes public the cost of that is a
          vulnerability report sitting in a public issue, so it leads: still not a card
          among cards, still its own tint, just no longer something to scroll for. */}
      <div className="space-y-3 rounded-lg border border-destructive/40 bg-destructive/5 p-4">
        <div className="flex items-center gap-2">
          <ShieldAlert aria-hidden="true" className="h-4 w-4 text-destructive" />
          <h2 className="text-lg font-semibold">{t.support.securityHeading}</h2>
        </div>
        <p className="max-w-3xl text-sm text-muted-foreground">{t.support.securityBody}</p>
        <p className="max-w-3xl text-sm text-muted-foreground">
          {t.support.securityFallback(SECURITY_EMAIL, SLACK_CHANNEL)}
        </p>
        <div className="flex flex-wrap gap-x-6 gap-y-2 pt-1 text-sm">
          <ExternalLink href={SUPPORT_LINKS.privateReport}>
            {t.support.securityReport}
          </ExternalLink>
          <ExternalLink href={SUPPORT_LINKS.securityPolicy}>
            {t.support.securityPolicy}
          </ExternalLink>
        </div>
      </div>

      {/* Before the two channels, because it is the round trip every support
          conversation otherwise starts with: "which build?" */}
      <div className="space-y-3 rounded-lg border bg-card p-4">
        <h2 className="text-lg font-semibold">{t.support.buildHeading}</h2>
        <p className="max-w-3xl text-sm text-muted-foreground">{t.support.buildHelp}</p>
        <div className="flex flex-wrap items-center gap-2">
          <code className="flex-1 overflow-x-auto rounded-md border bg-background px-3 py-2 font-mono text-xs">
            {build ?? "—"}
          </code>
          <Button variant="outline" size="sm" onClick={copy} disabled={build === null}>
            {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
            <span className="ml-2">{copied ? t.support.copied : t.support.copy}</span>
          </Button>
        </div>
        {build === null && (
          <p className="text-xs text-muted-foreground">{t.support.buildUnavailable}</p>
        )}
      </div>

      {/* The site and its docs: where the how-to pages live, so a question that is
          "how do I set this up" has somewhere to go before it becomes an issue. */}
      <div className="space-y-3 rounded-lg border bg-card p-4">
        <div className="flex items-center gap-2">
          <Globe aria-hidden="true" className="h-4 w-4 text-muted-foreground" />
          <h2 className="text-lg font-semibold">{t.support.siteHeading}</h2>
        </div>
        <p className="max-w-3xl text-sm text-muted-foreground">{t.support.siteBody}</p>
        <div className="flex flex-wrap gap-x-6 gap-y-2 pt-1 text-sm">
          <ExternalLink href={WEBSITE_URL}>{t.support.siteOpen}</ExternalLink>
          <ExternalLink href={NOTES_URL}>{t.support.docsOpen}</ExternalLink>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="flex flex-col gap-3 rounded-lg border bg-card p-4">
          <div className="flex items-center gap-2">
            <Bug aria-hidden="true" className="h-4 w-4 text-muted-foreground" />
            <h2 className="text-lg font-semibold">{t.support.githubHeading}</h2>
          </div>
          <p className="text-sm text-muted-foreground">{t.support.githubBody(SUPPORT_REPO)}</p>
          <p className="text-sm text-muted-foreground">{t.support.githubInclude}</p>
          <div className="mt-auto flex flex-wrap gap-x-6 gap-y-2 pt-1 text-sm">
            <ExternalLink href={SUPPORT_LINKS.issues}>{t.support.githubBrowse}</ExternalLink>
            <ExternalLink href={SUPPORT_LINKS.newIssue}>{t.support.githubOpen}</ExternalLink>
          </div>
        </div>

        <div className="flex flex-col gap-3 rounded-lg border bg-card p-4">
          <div className="flex items-center gap-2">
            <MessagesSquare aria-hidden="true" className="h-4 w-4 text-muted-foreground" />
            <h2 className="text-lg font-semibold">{t.support.slackHeading}</h2>
            <code className="rounded border bg-background px-1.5 py-0.5 font-mono text-xs">
              {SLACK_CHANNEL}
            </code>
          </div>
          <p className="text-sm text-muted-foreground">{t.support.slackBody(SLACK_CHANNEL)}</p>
          {/* Stated rather than left to be discovered by clicking a channel link that
              refuses an account the reader does not have. Both links are shown, in
              that order: the workspace first, the channel second. */}
          <p className="text-sm text-muted-foreground">{t.support.slackSignupNote(SLACK_CHANNEL)}</p>
          <div className="mt-auto flex flex-wrap gap-x-6 gap-y-2 pt-1 text-sm">
            <ExternalLink href={SUPPORT_LINKS.slackJoin}>{t.support.slackJoin}</ExternalLink>
            <ExternalLink href={SUPPORT_LINKS.slackChannel}>
              {t.support.slackOpenChannel(SLACK_CHANNEL)}
            </ExternalLink>
          </div>
        </div>
      </div>

      <p className="max-w-3xl text-xs text-muted-foreground">{t.support.privacyNote}</p>
    </section>
  );
}
