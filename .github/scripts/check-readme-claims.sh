#!/usr/bin/env bash
#
# Fails when README.md makes a claim the codebase does not back.
#
#   Usage:  .github/scripts/check-readme-claims.sh
#
# WHY THIS EXISTS
# ---------------
# Every defect that survived to the pre-flip review was of one kind: a loud,
# immediate, stranger-facing claim that no code supported — a README advertising
# SCIM, WebAuthn MFA, CVE/EPSS enrichment, a vulnerability scanner and
# multi-architecture images, none of which exist (#192). Silent, delayed,
# irreversible bugs get caught here by reading. Claims do not, because reading
# the README does not feel like reviewing code. The remedy for that is a machine,
# not more care.
#
# WHY A TABLE AND NOT A SWEEP
# ---------------------------
# The obvious design — regex the prose for marketing verbs and demand evidence —
# produces false positives forever, and a check that cries wolf is deleted within
# a month. So this is an explicit table: one row per claim, each row naming the
# exact grep that would only find something if the claim were true. It is boring,
# it cannot surprise anyone, and adding a claim to the README means adding its
# proof here. That last property is the whole point; the table is small on
# purpose and is meant to stay small.
#
# The corollary is that this check does not prove the README is true. It proves
# that a specific list of claims that were once false cannot come back, and that
# a handful of load-bearing true claims still have code under them. Everything
# else in the file is still on the reader.
#
# WHAT A PROOF MAY BE
# -------------------
# The narrowest thing that exists only if the claim is true. Prose does not
# count: `grep -ri scim backend/` passes today on comments that say SCIM has NOT
# landed, and `grep -ri datadog frontend/` passes on an integrations card that
# honestly says "coming soon". Both would have waved the original false claims
# straight through. So proofs target route prefixes, type literals, identifiers
# and build flags — things that are the feature rather than talk about it.
#
# TWO ROW KINDS
# -------------
#   guard   If the marker appears in the README, the proof must find something.
#           Absent marker means the row is inert — armed, waiting, costing
#           nothing. This is the class that was actually wrong.
#   anchor  The marker MUST appear AND the proof must find something. Anchors are
#           true claims that exist so this check always has live work to do. A
#           table of guards alone goes vacuously green the day someone rewrites
#           the README, and prints a tick while checking nothing.
#
# SCOPE: README.md and backend/README.md. #87 found that backend/README.md carried
# the exact same false claim class this check exists to prevent (fabricated
# `webauthn`/`scim2-models` dependencies) while sitting entirely outside this
# script's reach — a second storefront page, invisible to the machine. docs/
# carries the same risk beyond these two and is still not covered.

set -uo pipefail
# Deliberately not `set -e`: one failing row must not hide the other ten. Every
# row is evaluated, then the script exits on the tally.

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)" || exit 2

README=README.md
BACKEND_README=backend/README.md
[[ -f $README ]] || { echo "no $README at $(pwd)"; exit 2; }
[[ -f $BACKEND_README ]] || { echo "no $BACKEND_README at $(pwd)"; exit 2; }

# The "What it does not do" section is where absences are named, so it is full of
# the very words the guards look for ("No CVE or EPSS enrichment. No SCIM, no
# MFA."). Scanning it would fail the build for telling the truth. Stripped from
# its heading to the next heading. If that section is ever deleted the strip
# becomes a no-op and this check gets stricter, never weaker. backend/README.md
# has no equivalent section and is scanned whole.
SCANNED=$(
  awk '
    /^#+[[:space:]]+What it does not do[[:space:]]*$/ { skip = 1; next }
    skip && /^#/ { skip = 0 }
    !skip
  ' "$README"
  cat "$BACKEND_README"
)

pass=0 armed=0 inert=0 failed=0

# CI reads ::error:: annotations (the image job in ci.yml already uses them);
# a terminal reads the plain line. Points at README.md specifically — the more
# common offender and the file GitHub renders on the repo's front page — even
# though $SCANNED merges both files, so a claim only backend/README.md makes
# still fails the build; the annotation just isn't pinpoint about which file.
annotate() {
  [[ -n ${GITHUB_ACTIONS:-} ]] && printf '::error file=%s::%s\n' "$README" "$1"
  printf '  FAIL  %s\n' "$1"
}

# claim <kind> <id> <marker-ERE> <proof-command>
claim() {
  local kind=$1 id=$2 marker=$3 proof=$4 claimed=no backed=no

  grep -qiE -- "$marker" <<<"$SCANNED" && claimed=yes
  eval "$proof" >/dev/null 2>&1 && backed=yes

  if [[ $claimed == no ]]; then
    if [[ $kind == anchor ]]; then
      annotate "$id: neither README.md nor backend/README.md makes this anchor claim anymore. Anchors are what stop this check going vacuously green — restore the claim, or retire the row deliberately."
      ((failed++))
    else
      printf '  ----  %-13s not claimed\n' "$id"
      ((inert++))
    fi
    return
  fi

  ((armed++))
  if [[ $backed == yes ]]; then
    printf '  ok    %-13s claimed, and backed by: %s\n' "$id" "$proof"
    ((pass++))
  else
    annotate "$id: README.md or backend/README.md claims this and nothing in the codebase backs it. The proof that found nothing was: $proof"
    ((failed++))
  fi
}

# ---------------------------------------------------------------------------
# The table. One row per claim. Add a claim to the README, add its row here.
# ---------------------------------------------------------------------------

# --- anchors: true claims, load-bearing, live today ---

claim anchor splunk \
  '\bSplunk\b' \
  "grep -q 'splunk_hec' backend/app/schemas/destinations.py"

claim anchor runreveal \
  '\bRunReveal\b' \
  "grep -q 'runreveal' backend/app/schemas/destinations.py"

claim anchor rls \
  'row-level security' \
  "grep -rq 'ENABLE ROW LEVEL SECURITY' backend/migrations"

claim anchor fernet \
  '\bFernet\b' \
  "grep -rq 'Fernet' backend/app/core"

# The licence is the one claim a stranger acts on without reading anything else.
# The proof is the file and both manifests agreeing with the README, so a licence
# that changes in one place and not the others fails here, not in a fork.
claim anchor license \
  'Apache-2\.0' \
  "grep -q 'Version 2.0, January 2004' LICENSE \
   && grep -q '^license = \"Apache-2.0\"' backend/pyproject.toml \
   && grep -q '\"license\": \"Apache-2.0\"' frontend/package.json"

# --- guards: every one of these was claimed and false before #192 ---

# Comments about SCIM are all over app/models/schema.py, describing columns kept
# for a SCIM that has not landed. Provisioning is irreducibly an endpoint.
claim guard scim \
  '\bSCIM\b' \
  "grep -rq 'prefix=\"/api/scim' backend/app/api"

claim guard mfa \
  'WebAuthn|FIDO2|YubiKey|Touch ID|\bMFA\b|multi-factor|two-factor|\bTOTP\b' \
  "grep -rqiE 'webauthn|fido2|pyotp|totp_secret' backend/app frontend/src"

# Not a bare 'vulnerability': the README legitimately says the word about Jamf
# Patch state and about the community feeds. The claim being guarded is scoring
# and enrichment, which needs identifiers, not adjectives.
claim guard cve \
  '\bCVE\b|\bEPSS\b|\bCVSS\b|vulnerability scan|vulnerability scor|vulnerability engine|CVE intelligence' \
  "grep -rqiwE 'epss|cvss|cve_id|cve_score' backend/app frontend/src"

claim guard loonvd \
  '\bLoonVD\b' \
  "grep -rqi 'loonvd' backend/app"

# frontend/src/features/integrations/data.ts lists Datadog as "coming soon", so
# any grep over the frontend would pass this. The destination type literal is the
# only place a destination becomes real.
claim guard datadog \
  '\bDatadog\b' \
  "grep -qi 'datadog' backend/app/schemas/destinations.py"

claim guard multiarch \
  'arm64|aarch64|multi-arch|multi-architecture' \
  "grep -rq 'linux/arm64' .github/workflows Dockerfile"

claim guard hardened-base \
  'hardened base|hardened image|distroless|chainguard' \
  "grep -rqiE 'distroless|chainguard' Dockerfile"

# ---------------------------------------------------------------------------

printf '\n%d claim(s) armed, %d backed, %d inert, %d failed\n' \
  "$armed" "$pass" "$inert" "$failed"

if (( failed > 0 )); then
  printf '\nA README and the code disagree. Either remove the claim, or ship the\n'
  printf 'thing and point its row at the proof.\n'
  exit 1
fi

# A table of guards with no armed rows is a green tick over an empty check.
if (( armed == 0 )); then
  printf '\nNo row in this table is armed, so this check verified nothing.\n'
  exit 1
fi
