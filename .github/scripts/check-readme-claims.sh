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
#
# KNOWN_ISSUES.md is not scanned for markers either, and deliberately: its whole job is
# to name limits, so it is the README's "What it does not do" section at page length,
# and the guards below would find their words there in the honest sense. One row's
# proof reads it instead — the retention enumeration, which README.md sends the reader
# to, and which #490 found drifted in both files at once.

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
  local kind=$1 id=$2 marker=$3 proof=$4 claimed=no backed=no detail

  grep -qiE -- "$marker" <<<"$SCANNED" && claimed=yes
  # A proof's stdout is noise and its stderr is its reason, when it has one to give: a
  # grep says nothing unless a file is missing, which is worth hearing, and a function
  # proof with several conditions says which one failed, so the FAIL line names the
  # finding rather than the function (docs/diagnosability.md).
  detail=$(eval "$proof" 2>&1 >/dev/null) && backed=yes
  detail=${detail//$'\n'/; }

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
    annotate "$id: README.md or backend/README.md claims this and nothing in the codebase backs it. The proof that found nothing was: $proof${detail:+ — it said: $detail}"
    ((failed++))
  fi
}

# A counting claim, which is the one shape a grep cannot prove: the README says how many
# ordered paths docs/troubleshooting.md holds, and adding a path to that document touches
# neither the README nor any code, so the number goes stale silently. It did — #388 added
# section 6 and left "five ordered paths" standing. The proof is the document counting
# itself: a path is a numbered section whose heading is the operator's own words in
# quotes (`## 6. "The Jamf Patch table is empty…"`), which is what separates the paths
# from section 0's inventory of readable surfaces and the two closing sections.
# The vocabulary runs well past today's count on purpose: it stopped at "ten", one path
# away, and a count it cannot spell fails as `out-of-range`, which reads like a broken
# script rather than like the stale number that is the actual finding (#402). It had
# reached its end again by #529's sixteenth path, so it now runs to twenty.
PATH_COUNT_MARKER='\b(one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty) (ordered )?paths\b'

readme_path_count_matches_troubleshooting() {
  local doc=docs/troubleshooting.md counted written
  local words=(zero one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty)
  [[ -f $doc ]] || return 1
  counted=$(grep -cE '^## [0-9]+\. "' "$doc")
  written=$(grep -oiE "$PATH_COUNT_MARKER" "$README" | head -1 | tr '[:upper:]' '[:lower:]' | cut -d' ' -f1)
  [[ -n $written && ${words[counted]:-out-of-range} == "$written" ]]
}

# The retention sentence, which is a set rather than a count. README.md enumerates every
# clock that deletes by age — "the machinery around that record, never the record" — and
# KNOWN_ISSUES.md §1, the page that sentence sends the reader to, carries the same list.
# It went false twice inside one pull request (#490): "the only three things this project
# ever prunes" was four, then six, because the method behind the number
# (`grep '^async def purge'`) could see a module-level purge function and nothing else —
# not the share log's inline delete on every exchange, not the hourly session sweep. Both
# files carry no numeral now, so the path-count shape (a written word against a counted
# one) does not fit; what is left to hold is that the sentences and the code name the
# same clocks, and the proof is set equality, in both directions.
#
# The code's side of the set is a token, `retention-clock: <name>`, on the line above
# each statement that deletes by age (the audit log rotates rather than deletes, and its
# token sits on the rotation). A token rather than a registry in core/config.py: a
# registry the code does not read is a comment in a different file, further from the
# statement it describes, and a registry the code does read turns the share log's 90
# days and the session grace — constants on purpose — into settings, which is the knob
# the alert-latch ruling refused (alerts/service.py, `purge_closed_alerts`). The token
# sits on the delete, so whoever reads the delete reads the token, and whoever reads a
# delete without one has a one-word question to ask.
#
# What makes the token mandatory rather than polite: every statement-level `delete(` and
# `sa_delete(` under backend/app is inventoried, and one that is neither tokened nor in
# RETENTION_NOT_A_CLOCK fails with the classification question. That list is #490's hand
# classification — operator-initiated and replace-on-refresh deletes — keyed by file and
# model, so a moved line does not fire and a new model does; an entry the code no longer
# has fails too, so the list cannot rot into a waiver. A clock written in another shape
# (a rotation, a raw SQL string, an ORM `db.delete` loop) is still on the reader.
#
# Not held: the durations. README.md gives them in days and KNOWN_ISSUES.md by setting
# name, on purpose, and the drift that happened was in the list.
RETENTION_TOKEN='retention-clock: '
RETENTION_MARKER='What this project prunes|machinery around (that|the) record'

# name|the words both sentences use for it. Matched inside each sentence's own paragraph,
# so an "outbox" elsewhere in the README cannot stand in for the one in the list.
RETENTION_CLOCKS=(
  'outbox|\boutbox\b'
  'runs|\bruns\b'
  'alert-latches|alert latches'
  'audit-log|audit log'
  'share-log|share log'
  'sessions|\bsessions\b'
  'summary-jobs|summary jobs'
  'summary-metrics|summary metric counters'
)

# file:Model of every statement-level delete that is not a clock.
RETENTION_NOT_A_CLOCK=(
  # Operator-initiated: a person removed the connection, destination, role or config.
  backend/app/api/accounts.py:AccountRole
  backend/app/api/connections.py:Device
  backend/app/api/connections.py:DeviceExtensionAttribute
  backend/app/api/connections.py:InstalledApp
  backend/app/api/connections.py:MdmSyncState
  backend/app/api/destinations.py:OutboxDelivery
  backend/app/core/ai_configs.py:AIProviderConfig
  # Replace-on-refresh: the rows come straight back from the next read of the source.
  backend/app/catalog/index.py:AppCatalogVersion
  backend/app/catalog/service.py:AppCatalogTitleMatch
  backend/app/core/vuln_library.py:VulnLibraryEpoch
  backend/app/core/vuln_library.py:VulnLibraryRow
  backend/app/core/vuln_library.py:VulnLibraryTitle
  backend/app/mdm/org_units.py:JamfOrgUnit
)

# `comm` wants one line per item and an empty set as an empty stream, not a blank line.
as_lines() { if [[ -n $1 ]]; then printf '%s\n' "$1"; fi; }

readme_retention_clocks_match_code() {
  local known=KNOWN_ISSUES.md readme_para known_para declared listed untokened row name words off
  [[ -f $known ]] || { echo "no $known at $(pwd)" >&2; return 1; }

  # Each file's sentence is the paragraph carrying the marker, and the words are looked
  # for there and nowhere else.
  readme_para=$(awk -v re="$RETENTION_MARKER" 'BEGIN { RS = "" } $0 ~ re { print; exit }' "$README")
  known_para=$(
    awk '/^## 1\. / { s = 1; next } s && /^## / { exit } s' "$known" |
      awk -v re="$RETENTION_MARKER|ages out on a clock" 'BEGIN { RS = "" } $0 ~ re { print; exit }'
  )
  [[ -n $readme_para ]] || { echo "README.md has no paragraph matching /$RETENTION_MARKER/, so the sentence that armed this row cannot be found" >&2; return 1; }
  [[ -n $known_para ]] || { echo "$known §1 has no paragraph saying what ages out on a clock; the README sends the reader there for it" >&2; return 1; }

  # The clocks the code declares and the clocks this table knows are the same set.
  declared=$(grep -rhoE --include='*.py' -- "${RETENTION_TOKEN}[a-z-]+" backend/app | sed "s/^$RETENTION_TOKEN//" | sort -u)
  listed=$(printf '%s\n' "${RETENTION_CLOCKS[@]}" | cut -d'|' -f1 | sort -u)
  off=$(comm -13 <(as_lines "$declared") <(as_lines "$listed") | head -1)
  [[ -z $off ]] || { echo "no '${RETENTION_TOKEN}${off}' token under backend/app: the sentences name a clock the code no longer declares" >&2; return 1; }
  off=$(comm -23 <(as_lines "$declared") <(as_lines "$listed") | head -1)
  [[ -z $off ]] || { echo "the code declares '${RETENTION_TOKEN}${off}' and RETENTION_CLOCKS has no row for it: add the row, and the clock to both sentences" >&2; return 1; }

  # Both sentences name every clock.
  for row in "${RETENTION_CLOCKS[@]}"; do
    name=${row%%|*} words=${row#*|}
    grep -qiE -- "$words" <<<"$readme_para" || { echo "README.md's retention sentence no longer names the $name clock (nothing in its paragraph matches /$words/)" >&2; return 1; }
    grep -qiE -- "$words" <<<"$known_para" || { echo "$known §1's retention sentence no longer names the $name clock (nothing in its paragraph matches /$words/)" >&2; return 1; }
  done

  # Every statement-level delete is tokened or classified, and the classification is
  # current. A delete is tokened when the token is on its line or one of the three above.
  untokened=$(
    find backend/app -name '*.py' -print0 | xargs -0 awk -v token="$RETENTION_TOKEN" '
      FNR == 1 { above1 = above2 = above3 = "" }
      /(^|[^.A-Za-z0-9_])(sa_)?delete\([A-Za-z_]+/ && !/def (sa_)?delete\(/ && !/^[ \t]*#/ && !/`/ {
        if (!index($0, token) && !index(above1, token) && !index(above2, token) && !index(above3, token)) {
          match($0, /(sa_)?delete\([A-Za-z_]+/); s = substr($0, RSTART, RLENGTH); sub(/.*\(/, "", s)
          print FILENAME ":" s
        }
      }
      { above3 = above2; above2 = above1; above1 = $0 }
    ' | sort -u
  )
  listed=$(printf '%s\n' "${RETENTION_NOT_A_CLOCK[@]}" | sort -u)
  off=$(comm -23 <(as_lines "$untokened") <(as_lines "$listed") | head -1)
  [[ -z $off ]] || { echo "$off is deleted with no '${RETENTION_TOKEN}<name>' token above it and no RETENTION_NOT_A_CLOCK entry: decide which it is" >&2; return 1; }
  off=$(comm -13 <(as_lines "$untokened") <(as_lines "$listed") | head -1)
  [[ -z $off ]] || { echo "RETENTION_NOT_A_CLOCK lists $off and no such delete exists now: remove the entry" >&2; return 1; }
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

# The newest claim in the README, and the one with the shortest history of being
# false: that this product answers, per installed build, whether the build carries
# known vulnerabilities — and names the three states a person sees. It was false
# until the loader and the per-build join landed on 2026-09-11, which puts it in
# exactly the class this table exists for. The proofs are the two seams the claim
# is made of: the exchange's corpus channel, and the stored per-build answer the
# pages and the wire read back. Prose about either would have passed while both
# were open, so neither proof is prose. The third proof is the word itself: the
# README quotes what a person sees, so a rename in the locale file has to fail here
# rather than in a screenshot.
claim guard vuln-corpus \
  'Outside the corpus|published corpus|vulnerability corpus' \
  "grep -q 'def load_epoch_if_new' backend/app/core/vuln_library.py \
   && grep -q 'def stored_corpus' backend/app/core/vuln_answer.py \
   && grep -q 'stateUnknownApp: \"Outside the corpus\"' frontend/src/i18n/en.ts"

claim guard multiarch \
  'arm64|aarch64|multi-arch|multi-architecture' \
  "grep -rq 'linux/arm64' .github/workflows Dockerfile"

claim guard hardened-base \
  'hardened base|hardened image|distroless|chainguard' \
  "grep -rqiE 'distroless|chainguard' Dockerfile"

# A guard, not an anchor, because the mistake it catches only exists while the sentence
# does: a README that stops counting the paths has no count left to be wrong about.
claim guard path-count \
  "$PATH_COUNT_MARKER" \
  "readme_path_count_matches_troubleshooting"

# A guard for the reason path-count is one: the mistake it catches only exists while the
# sentence does. KNOWN_ISSUES.md §1 is read by the proof and not by the marker — if the
# README stops enumerating the clocks there is no one-click contradiction left to hold,
# and the §1 copy is on the reader like the rest of that file.
claim guard retention \
  "$RETENTION_MARKER" \
  "readme_retention_clocks_match_code"

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
