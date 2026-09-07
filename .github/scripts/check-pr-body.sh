#!/usr/bin/env bash
#
# Fails a pull request whose body does not carry what CONTRIBUTING.md › Pull
# requests calls required: a filled-in "## Validation" section and the
# `posture_snapshot: <keys | none>` line. This is control PR-02 in
# docs/BRANCHING.md §6.3; .github/workflows/pr-body.yml runs `--self-test` and
# then feeds it the body from the pull_request event.
#
#   Usage:  gh pr view "$PR" --json body --jq .body | .github/scripts/check-pr-body.sh
#           .github/scripts/check-pr-body.sh --self-test
#
# Deliberately narrow, for the reason check-readme-claims.sh gives: a check that
# fails on style is one people learn to bypass, and a check that reports nothing
# is worse than none. It does not judge the prose, does not require the other
# template headings (Scope and Risk are read in review), and does not parse the
# key list — tests/test_posture_registry.py owns the keys.
set -euo pipefail

check() {
  # GitHub delivers bodies with CRLF line endings; the template's prompts are HTML
  # comments, and a section that still holds only its prompt has not been filled
  # in. Normalise the first and strip the second before looking for content.
  # No `grep -q` on a pipe anywhere below: a body can be 64 KiB, the pipe buffer
  # is 64 KiB, and an early exit would hand the writer SIGPIPE under pipefail.
  local stripped validation status=0
  stripped=$(tr -d '\r' | perl -0pe 's/<!--.*?-->//gs')

  # 1. A Validation heading (## or deeper) followed by at least one non-blank line
  #    before the next heading at its own level or above. Sub-headings inside the
  #    section count as content, so "### Backend / ### Frontend" under Validation
  #    passes. No early exit in awk, for the same pipe reason.
  validation=$(printf '%s\n' "$stripped" | awk '
    !inside && !done && /^#+[[:space:]]+Validation([[:space:]]|$)/ {
      match($0, /^#+/); level = RLENGTH; inside = 1; next
    }
    inside && /^#+[[:space:]]/ {
      match($0, /^#+/); if (RLENGTH <= level) { inside = 0; done = 1 }
    }
    inside { print }
  ')
  if ! printf '%s\n' "$stripped" | grep -E '^#+[[:space:]]+Validation([[:space:]]|$)' >/dev/null; then
    echo "::error::no '## Validation' section — record the commands run, where, and what was not run (CONTRIBUTING.md › Pull requests)"
    status=1
  elif ! printf '%s\n' "$validation" | grep '[^[:space:]]' >/dev/null; then
    echo "::error::'## Validation' is empty — record the commands run, where, and what was not run (CONTRIBUTING.md › Pull requests)"
    status=1
  fi

  # 2. The measurement line, in any of the shapes merged pull requests already use:
  #    bare, in backticks, in bold, or as a list item. The value must be non-empty;
  #    `none` is a first-class answer, and a missing line means the question was
  #    never asked.
  if ! printf '%s\n' "$stripped" | grep -E '^[[:space:]]*([-*][[:space:]]+)?[`*_]*posture_snapshot:[`*_]*[[:space:]]*[^[:space:]`*_]' >/dev/null; then
    echo "::error::no 'posture_snapshot: <keys | none>' line (CONTRIBUTING.md › Measurement)"
    status=1
  fi

  if [ "$status" -eq 0 ]; then
    echo "PR body: Validation is filled in and the posture_snapshot line is present"
  fi
  return "$status"
}

# The cases the check exists for, kept next to the check so the two cannot drift.
# The first reads the real template: the unfilled form must fail on both counts.
self_test() {
  local root failures=0
  root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
  expect() { # expect <pass|fail> <name>, body on stdin
    local want=$1 name=$2 got
    if check >/dev/null; then got=pass; else got=fail; fi
    if [ "$got" = "$want" ]; then
      printf '  ok    %s → %s\n' "$name" "$got"
    else
      printf '  FAIL  %s → wanted %s, got %s\n' "$name" "$want" "$got"
      failures=$((failures + 1))
    fi
  }

  expect fail "the unfilled template" < "$root/.github/PULL_REQUEST_TEMPLATE.md"
  expect pass "filled in, bare line" <<'CASE'
## Validation

Ran `uv run pytest -q` in the uv image: 991 passed. Not run: RUN_DB_TESTS=1.

## Measurement

posture_snapshot: none
CASE
  expect pass "sub-heading, backticked keys, CRLF" < <(printf '## Validation\r\n\r\n### Backend\r\n\r\npytest: 991 passed\r\n\r\n## Measurement\r\n\r\n`posture_snapshot: alerts.open, alerts.opened_24h`\r\n')
  expect fail "line present, Validation heading absent" <<'CASE'
## Summary

Words.

posture_snapshot: none
CASE
  expect fail "Validation holding only its prompt" <<'CASE'
## Validation

<!-- a prompt
across lines -->

## Risk

None.

posture_snapshot: none
CASE
  expect fail "empty value" <<'CASE'
## Validation

Ran it.

posture_snapshot:
CASE
  expect pass "### headings, bold line as a list item" <<'CASE'
### Validation

Ran it.

#### Notes

More.

### Risk

- **posture_snapshot:** none
CASE
  expect fail "blank Validation" <<'CASE'
## Validation



## Risk

none

posture_snapshot: none
CASE
  expect fail "no headings at all" <<'CASE'
Nothing here.
CASE

  echo "self-test: $failures failure(s)"
  [ "$failures" -eq 0 ]
}

if [ "${1:-}" = "--self-test" ]; then self_test; else check; fi
