#!/usr/bin/env bash
#
# Fails when a workflow uses an action by a mutable ref (#20).
#
#   Usage:  .github/scripts/check-action-pins.sh
#
# A tag like `actions/checkout@v5` is repointable by whoever controls that repository,
# and the commit it then names runs in CI with the workflow token. Every `uses:` must
# name a full 40-hex commit SHA, with the human-readable version in a trailing comment:
#
#   - uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5.1.0
#
# Local actions (`uses: ./path`) and Docker actions (`uses: docker://...`) carry no ref
# and are left alone. This is the guard that keeps the pins from drifting back to tags
# in a later edit, which is the failure Dependabot's grouped PRs cannot cause but a
# hand edit can.

set -uo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)" || exit 2

fail=0
while IFS= read -r line; do
  ref=$(sed -E 's/^.*uses:[[:space:]]*//; s/[[:space:]]*(#.*)?$//' <<<"$line")
  case "$ref" in
    ./*|docker://*) continue ;;
  esac
  if ! [[ $ref =~ @[0-9a-f]{40}$ ]]; then
    echo "not pinned to a commit SHA: $line"
    fail=1
  fi
done < <(grep -rn --include='*.yml' --include='*.yaml' -E '^[[:space:]]*-?[[:space:]]*uses:' .github/workflows)

if [[ $fail -ne 0 ]]; then
  echo "every action must be pinned to a full commit SHA with the version in a trailing comment (#20)"
  exit 1
fi
echo "all actions are pinned to commit SHAs"
