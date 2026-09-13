import type { UpdateReason, UpdateStatusResponse } from "@/features/system/api";

/**
 * What the update check's answer means on a page (#407) — pure, so the decision each
 * surface paints by is table-tested in the node lane (`updateStatus.test.ts`) rather than
 * checked by eye.
 *
 * Kyle, 2026-09-11: `main` is staging, and publishing a GitHub Release is the release. An
 * update is available when this build does not contain the latest published release's
 * commit. Three surfaces read the one answer: the banner and the Needs Attention row say
 * it only when it is `true`, and the Updates block on Settings › Support says every state,
 * including the reason when the check could not answer (`docs/diagnosability.md` rule 1).
 */

/** The Updates block's anchor, and where the banner and the Needs Attention row send a
 *  reader to read the steps. */
export const UPDATES_ANCHOR = "updates";
export const UPDATES_HREF = `/settings/support#${UPDATES_ANCHOR}`;

export type UpdateView =
  | { kind: "available"; tag: string | null; releaseUrl: string | null }
  | { kind: "current"; tag: string | null; releaseUrl: string | null }
  /** `reason` is null only from a server that predates #407; the block says it could
   *  not answer and names nothing, rather than guessing which reason it was. */
  | { kind: "unknown"; reason: UpdateReason | null; tag: string | null; releaseUrl: string | null };

export function describeUpdate(status: UpdateStatusResponse): UpdateView {
  const names = { tag: status.latestTag, releaseUrl: status.releaseUrl };
  if (status.updateAvailable === true) return { kind: "available", ...names };
  if (status.updateAvailable === false) return { kind: "current", ...names };
  return { kind: "unknown", reason: status.reason, ...names };
}

/** What the banner names, or null when it renders nothing. `true` only: an unknown must
 *  never look like a notice, and a current build has nothing to say (#43). */
export function bannerRelease(status: UpdateStatusResponse): { tag: string | null; releaseUrl: string | null } | null {
  return status.updateAvailable === true ? { tag: status.latestTag, releaseUrl: status.releaseUrl } : null;
}

/** A tag is pasted into a shell by whoever copies the steps, so only a tag that is
 *  unmistakably a tag is interpolated. The ruled form is `vYYYY.MM.DD` or `vYYYY.MM.DD.1`;
 *  anything with a space, a quote, a `;` or a `$` in it stays a placeholder instead —
 *  the provider is whatever `UPDATE_CHECK_URL` names, and a copied command is a command run. */
export function shellSafeTag(tag: string | null): string | null {
  return tag !== null && /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(tag) ? tag : null;
}

export const TAG_PLACEHOLDER = "<tag>";

/**
 * The upgrade for a Docker Compose install, in the order `docs/operations.md` §4 runs it:
 * the dump first, because the downgrade is manual and this dump is the documented way
 * back (KNOWN_ISSUES.md) — owner-only, with the umask inside a subshell so it ends with the
 * dump: left in force, it would make the files the checkout writes owner-only too, and the
 * image build copies those modes in, where the non-root app cannot read them
 * (`docs/operations.md` §2); then the release tag, not `git pull` of main — the notice is
 * about a release, and an install tracking main past it never sees the notice (Kyle's
 * default to overrule, #407); then the build that stamps the commit; then the log.
 */
export function upgradeCommands(tag: string | null): string[] {
  const target = shellSafeTag(tag) ?? TAG_PLACEHOLDER;
  return [
    '(umask 077 && docker compose exec -T db pg_dump -U looninspect -d looninspect | gzip > "looninspect-preupgrade-$(date -u +%Y%m%dT%H%M%SZ).sql.gz")',
    `git fetch --tags && git checkout ${target}`,
    "GIT_SHA=$(git rev-parse --short HEAD) docker compose up -d --build",
    "docker compose logs -f app"
  ];
}
