#!/usr/bin/env bash
#
# Applies the repository configuration that docs/BRANCHING.md §6 specifies as
# `repo-setting` or `ruleset` enforcement. Idempotent: safe to re-run, and the
# intended way to reconcile the repository after editing
# .github/rulesets/main.json.
#
#   Usage:  .github/scripts/apply-repo-config.sh [--dry-run]
#
# Requires the gh CLI, authenticated as a user with admin on the repository.
#
# Rulesets and secret scanning are unavailable on a private repository under a
# free plan. This script reports those as BLOCKED rather than failing, so the
# settings that *are* available still get applied. See §8.
set -euo pipefail

REPO="${REPO:-LoonSecIO/LoonInspect}"
RULESET_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/.github/rulesets/main.json"
DRY_RUN=false
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true

ok()      { printf '  \033[32m✓\033[0m %s\n' "$1"; }
blocked() { printf '  \033[33m⊘ BLOCKED\033[0m %s\n' "$1"; }
fail()    { printf '  \033[31m✗\033[0m %s\n' "$1"; }
step()    { printf '\n\033[1m%s\033[0m\n' "$1"; }

run() {
  if $DRY_RUN; then
    # stderr, so the marker survives the caller's >/dev/null and a dry run can
    # never print a bare tick for something it did not do.
    printf '  [dry-run] would run: %s\n' "$*" >&2
    return 0
  fi
  "$@"
}

# --- Repository settings — BR-04, MG-01 ------------------------------------
# Available on every plan.
step "Repository settings (BR-04, MG-01)"

if run gh api -X PATCH "repos/$REPO" \
     -F delete_branch_on_merge=true \
     -F allow_squash_merge=true \
     -F allow_merge_commit=false \
     -F allow_rebase_merge=false \
     -f squash_merge_commit_title=PR_TITLE \
     -f squash_merge_commit_message=PR_BODY \
     >/dev/null; then
  ok "BR-04  head branches auto-delete on merge"
  ok "MG-01  squash is the only permitted merge method"
  ok "§5     squash subject defaults to the pull request title"
else
  fail "could not update repository settings"
  exit 1
fi

# --- Ruleset on main — BR-06, BR-07, MG-02, MG-03, PR-07, AG-03 ------------
# Requires GitHub Pro/Team on a private repository, or a public repository.
step "Ruleset on main (BR-06, BR-07, MG-02, MG-03, PR-07, AG-03)"

[[ -f "$RULESET_FILE" ]] || { fail "ruleset definition not found at $RULESET_FILE"; exit 1; }

# gh writes the API error body to stdout, so read the exit status rather than
# the output to tell "no ruleset yet" apart from "endpoint unavailable".
if existing=$(gh api "repos/$REPO/rulesets" --jq '.[] | select(.name=="main") | .id' 2>/dev/null); then
  rulesets_available=true
else
  rulesets_available=false
  existing=""
fi

if ! $rulesets_available; then
  blocked "rulesets need GitHub Pro/Team on a private repo, or a public repo"
  blocked "BR-06, BR-07, MG-02, MG-03, PR-07 and AG-03 stay unenforced until then"
elif [[ -n "$existing" ]]; then
  run gh api -X PUT "repos/$REPO/rulesets/$existing" --input "$RULESET_FILE" >/dev/null
  ok "updated existing ruleset (id $existing) from $(basename "$RULESET_FILE")"
else
  run gh api -X POST "repos/$REPO/rulesets" --input "$RULESET_FILE" >/dev/null
  ok "created ruleset from $(basename "$RULESET_FILE")"
fi

# --- Secret scanning — CM-03 ----------------------------------------------
# Free on public repositories; needs Advanced Security on a private one.
step "Secret scanning and push protection (CM-03)"

if $DRY_RUN; then
  printf '  [dry-run] enable secret_scanning + secret_scanning_push_protection\n'
elif gh api -X PATCH "repos/$REPO" \
       -F 'security_and_analysis[secret_scanning][status]=enabled' \
       -F 'security_and_analysis[secret_scanning_push_protection][status]=enabled' \
       >/dev/null 2>&1; then
  ok "CM-03  secret scanning and push protection enabled"
else
  blocked "secret scanning needs a public repo or GitHub Advanced Security"
  blocked "CM-03 is only partly covered by the policy workflow's path checks"
fi

# --- Private vulnerability reporting --------------------------------------
# SECURITY.md names this as the ONLY disclosure channel and tells reporters not to
# open a public issue. Until this runs, that instruction points at a 404 — which is
# inert while the repository is private and nobody outside can reach it, and becomes
# the front door the moment it is public (INSPECT-0175). Available on every plan.
step "Private vulnerability reporting (SECURITY.md's disclosure channel)"

if $DRY_RUN; then
  printf '  [dry-run] enable private vulnerability reporting\n'
elif run gh api -X PUT "repos/$REPO/private-vulnerability-reporting" >/dev/null 2>&1; then
  ok "private vulnerability reporting enabled — SECURITY.md's channel is live"
else
  blocked "could not enable private vulnerability reporting; SECURITY.md's only"
  blocked "  disclosure channel stays closed. Enable it under Settings → Security."
fi

# --- Fork pull request approval -------------------------------------------
# A public repository accepts pull requests from forks, and a fork's workflow run
# executes the fork's code on this repository's runners. GitHub's default only
# holds first-time contributors for approval; requiring it for every outside
# contributor's run is the conservative setting for a repository whose CI can
# publish images. The endpoint returns 422 while the repository is private.
step "Fork pull request workflow approval"

if $DRY_RUN; then
  printf '  [dry-run] set fork PR approval_policy=all_external_contributors\n'
elif gh api -X PUT "repos/$REPO/actions/permissions/fork-pr-contributor-approval" \
       -f approval_policy=all_external_contributors >/dev/null 2>&1; then
  ok "fork PR workflow runs need a maintainer's approval for every outside contributor"
else
  blocked "fork PR approval policy is a public-repository setting; re-run after the flip"
fi

# --- Non-provider secret patterns ------------------------------------------
# Provider scanning only knows tokens a partner can verify. secret-scan.yml names
# what that misses — a Fernet ENCRYPTION_KEY, a Postgres password, a Splunk HEC
# token — and GitHub's generic patterns are the nearest native cover for that
# class. Separate call so a rejection here can never undo the CM-03 enable above.
step "Secret scanning: non-provider patterns"

if $DRY_RUN; then
  printf '  [dry-run] enable secret_scanning_non_provider_patterns\n'
elif gh api -X PATCH "repos/$REPO" \
       -F 'security_and_analysis[secret_scanning_non_provider_patterns][status]=enabled' \
       >/dev/null 2>&1; then
  ok "non-provider secret patterns enabled"
else
  blocked "non-provider patterns need a public repo or Advanced Security; re-run after the flip"
fi

step "Done"
echo "  Anything marked BLOCKED is a plan constraint, not a failure. See"
echo "  docs/BRANCHING.md §8 for the current state and how to unblock it."
