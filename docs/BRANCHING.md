# LoonInspect Branching Strategy

**Status:** Draft v1 · **Owner:** @kylepazandak · **Applies to:** `LoonSecIO/LoonInspect`

This document defines how work enters `main`. It is written to be read by three
audiences: contributors deciding how to start a piece of work, reviewers deciding
whether a pull request is admissible, and the automation that will eventually
enforce both. Every rule is therefore stated as a numbered **control** with an
explicit validation method, so it can be lifted into a PR check without
reinterpretation.

Controls marked `proposed` are agreed policy but not yet mechanically enforced.
Nothing in this document is enforced by tooling today; see
[Enforcement roadmap](#enforcement-roadmap) for the honest current state.

---

## 1. The model

**Trunk-based development with short-lived branches.** `main` is the single
long-lived branch and is always releasable. There is no `develop`, no
`release/*`, and no long-running integration branch.

The organising rule, from which most controls follow:

> **One unit of work = one branch = one pull request = one squashed commit on `main`.**

A branch exists to carry exactly one pull request to `main` and is deleted when
that pull request merges. If follow-on work is needed, it gets a new branch.

**Why this shape.** LoonInspect has one deploy target, a small number of
concurrent contributors, and a high proportion of agent-assisted changes.
Agent sessions are cheap to start in parallel but are poor at reasoning about
which parts of a long-lived branch have already shipped. Branches that outlive a
single pull request are the primary source of that ambiguity, so the strategy
optimises for making each branch's state unambiguous and short-lived rather than
for elaborate integration topology.

## 2. Branch naming

All branch names are lowercase and match:

```
^(inspect-[0-9]{4}|fix|chore|docs|spike)/[a-z0-9]+(-[a-z0-9]+)*$
```

| Prefix | Use for | Example |
| --- | --- | --- |
| `inspect-NNNN/` | Tracked work, where NNNN is a GitHub issue number | `inspect-0012/device-table-pagination` |
| `fix/` | Untracked defect repair | `fix/jamf-patch-sort-crash` |
| `chore/` | Dependencies, tooling, config, CI | `chore/bump-fastapi` |
| `docs/` | Documentation only | `docs/branching-strategy` |
| `spike/` | Time-boxed exploration, never merged | `spike/okta-scim-feasibility` |

Lowercase is mandatory, not cosmetic: it makes the name a case-insensitively
safe key on the macOS and Linux filesystems both used here, and it removes the
class of near-miss typos that case-mixed names invite. The slug is
kebab-case, describes the outcome rather than the activity, and is short enough
to read in a branch picker.

**Ticket numbers come from GitHub Issues and are never assigned by hand.** The
`NNNN` in an `inspect-NNNN/` branch is the issue's number, zero-padded to four
digits. Padding is what makes branches sort correctly in a listing; it is not
decoration, and an unpadded number fails BR-01.

Hand-assigned numbers are the specific failure this replaces. Picking the next
number by eye is how `INSPECT-0005` came to carry four pull requests — minting a
number by inspection is harder than reusing one you can already see. It is worse
still for agent sessions, which cannot observe what a parallel session has
claimed and will confidently choose a number already in use. `gh issue create`
returns a number atomically and settles the question.

Two consequences worth expecting. GitHub draws issues and pull requests from a
single counter, so issue numbers skip wherever a pull request took one; gaps are
harmless, since the property required is uniqueness, not contiguity. And numbers
below the counter's value at adoption do not correspond to issues at all — see
§10.

`spike/` branches are exempt from the pull request controls in §6.3 because their
code is never merged. They are time-boxed and terminate through the conversion
workflow in §3.1, which is where their actual output — a written finding —
reaches `main`.

## 3. Branch lifecycle

1. **Cut** from the current `origin/main`. Never from another feature branch.
2. **Work**, committing freely — intermediate commit quality is not policed,
   because the merge squashes them.
3. **Open a pull request** against `main`. Draft is fine and encouraged early.
4. **Merge** by squash, once required checks pass and the branch is current.
5. **Delete** the branch on both the remote and every local clone and worktree.

A branch that has reached step 4 is terminal. It is never checked out again,
never reopened, and never carries a second pull request. This is control BR-05
and it is the single most important rule in this document: reusing a merged
branch is what makes "what is actually on `main`?" unanswerable without reading
the full commit graph.

**Size and duration.** A branch should reach step 4 within about two working
days and change fewer than ~400 lines excluding generated files. These are
advisory thresholds, not hard limits — they exist to prompt the question "should
this be two branches?" rather than to block work. Exceeding them is a signal to
split, not a violation to appeal.

### 3.1 Spike lifecycle and conversion

A spike's deliverable is a written finding, not a diff. The time-box exists to
force that finding out of the branch and into `main` while it is still fresh; it
is not a mechanism for cleaning up stale branches. A spike that is still
genuinely under investigation is renewed, not killed. What it may not do is
drift silently — the failure this guards against is not an old branch, it is a
spike that answered its question weeks ago and whose answer was deleted along
with the checkout.

**Open.** The first commit on a `spike/` branch creates
`docs/spikes/<slug>.md`, where `<slug>` matches the branch's slug, containing at
minimum:

```markdown
---
question: Can we drive SCIM provisioning through Okta's API?
owner: kylepazandak
opened: 2026-08-18
review-date: 2026-08-28
---
```

This file is the export vehicle. It starts as a stub and becomes the findings
document.

**Renew.** At the review date the spike is renewed or terminated. Renewal is
unlimited and requires no approval, but it is never silent: append a dated entry
recording what has been learned so far and set a new `review-date`. A long
investigation stays legitimate; an abandoned one becomes visible.

**Terminate.** Three outcomes, one exit path. In every case the findings
document merges to `main` through a `docs/` branch and the spike branch is then
deleted.

| Outcome | Meaning | Successor |
| --- | --- | --- |
| Abandoned | The answer was no, or the approach is not viable | None |
| Implementation | The answer was yes and the work is worth doing | An `inspect-NNNN/` branch |
| Documentation | The finding itself is the deliverable — an ADR, a comparison | None |

An abandoned spike is still written up. A negative result is the outcome most
worth recording, because an unrecorded one gets re-investigated from scratch.

**A spike branch is never renamed or retargeted into an `inspect-NNNN/`
branch.** This is the load-bearing rule of the workflow. A spike moves quickly
precisely because nothing held it to the quality bar the other branch types
promise; retargeting it merges code that never paid that cost, under a label
asserting it did. Conversion transfers the knowledge, not the commits — the
implementation branch is cut fresh from `origin/main` and treats the spike as
reference material to read and deliberately re-derive.

### 3.2 Security findings as an input to branching

Continuous dynamic testing runs against a dev instance that tracks `main`, not
against branches or pull requests. The scanner is therefore downstream of
everything else in this document: it observes what has already merged, and its
findings return as new branches. It gates nothing, and no pull request waits on
it.

This is the direction of flow:

```
main ──▶ dev instance ──▶ continuous DAST ──▶ finding
 ▲                                              │
 └──────── fix/ or inspect-NNNN/ branch ◀───────┘
```

**Why squash and linear history pay off here.** Because every merge to `main` is
a single commit (MG-01) on a linear history (MG-02), and the dev instance tracks
`main`, each finding is attributable to exactly one commit by bisection. On a
branchy history with merge commits, a finding that appears between two scans
implicates every commit in the merged range. This is the concrete reason for
those two controls, not a stylistic preference.

**Traceability.** A finding is closed by a full circuit, and each hop must be
recoverable from the one before it:

```
finding ID → branch → squashed commit on main → redeploy → rescan → closed
```

The branch remediating a finding names the finding ID in its pull request
description, and the finding is not closed on merge — it is closed when a rescan
of the redeployed dev instance no longer reports it. Merging is a claim; the
rescan is the evidence.

**The dev instance is a live target.** It is continuously attacked by the
scanner and is exposed to whatever the scanner reaches. It therefore holds no
production data, no live MDM tenant credentials, and no real `ENCRYPTION_KEY` —
only seeded fixtures and disposable secrets. LoonInspect stores encrypted MDM
connection credentials, so an instance carrying real ones would turn the
security testing practice into the largest exposure in the system.

## 4. Working with agent sessions

Concurrent Claude Code sessions must not share a working copy. Each session gets
a dedicated git worktree on its own branch:

```bash
git worktree add ../LoonInspect-0006 -b inspect-0006/device-pagination origin/main
```

Worktrees share one `.git` directory but have independent checkouts, so two
sessions can build, run, and edit simultaneously without colliding.

Three things do **not** come along with a worktree, because they are gitignored,
and each session needs its own:

- `.env` — copy from the primary checkout and adjust.
- **A distinct compose project name and database volume.** The database is a
  container now, not a file, so two worktrees running `docker compose up` from
  the same project name attach to the same volume — producing migration and
  fixture interference that is very hard to attribute. Set `COMPOSE_PROJECT_NAME`
  in the worktree's `.env` (it namespaces the volumes as well as the containers).
- **A distinct backend port.** The default 8001 is baked into
  `.claude/launch.json` and the permission allowlist; a second session on 8001
  fails at bind, usually silently from the agent's perspective.

Remove the worktree when the branch merges:

```bash
git worktree remove ../LoonInspect-0006
```

## 5. Merge mechanics

- **Squash merge only.** Merge commits and rebase-merge are disabled at the
  repository level. One issue produces one commit on `main`.
- **The squash commit subject is the pull request title**, so the title carries
  the issue reference and is written as a real commit subject
  (`INSPECT-0012: paginate the device table`), not as a chat message.
- **Linear history.** `main` never contains a merge commit.
- **Up to date before merge.** The branch must include current `main` before it
  can merge, so required checks are evaluated against the tree that will exist
  after the merge rather than a stale one.

---

## 6. Control register

Each control has a stable identifier, a normative statement, an enforcement
point, and a severity. Identifiers are permanent: a retired control keeps its
ID and is marked `retired` rather than being reused or renumbered.

**Enforcement points**

| Value | Meaning |
| --- | --- |
| `ruleset` | GitHub branch ruleset on `main` |
| `repo-setting` | Repository configuration |
| `ci` | Automated check on `pull_request` |
| `review` | Human judgement; not automatable |
| `scheduled` | Recurring job over `origin`, independent of any pull request |

**Severity** — `block` prevents merge · `warn` annotates the PR · `manual`
records a reviewer decision.

**Status** — `proposed` is agreed but not yet implemented · `active` is
mechanically enforced today · `blocked` is agreed and implemented, but prevented
from taking effect by something outside the repository · `retired` keeps its ID
and is never reused.

### 6.1 Branch controls

| ID | Control | Enforcement | Severity | Status |
| --- | --- | --- | --- | --- |
| BR-01 | Branch name matches the canonical pattern in §2 | `ci` | block | proposed |
| BR-02 | Pull request base is `main` | `ci` | block | proposed |
| BR-03 | Branch is merged within 5 calendar days of its first commit | `ci` | warn | proposed |
| BR-04 | Head branch is deleted automatically on merge | `repo-setting` | block | active |
| BR-05 | A branch name that has previously merged is never reused | `ci` | block | proposed |
| BR-06 | `main` accepts no direct pushes; all changes arrive by pull request | `ruleset` | block | blocked |
| BR-07 | `main` cannot be force-pushed or deleted | `ruleset` | block | blocked |
| BR-08 | An `inspect-NNNN/` branch's number is an open GitHub issue, zero-padded to four digits | `ci` | block | proposed |

### 6.2 Commit and content controls

| ID | Control | Enforcement | Severity | Status |
| --- | --- | --- | --- | --- |
| CM-01 | Pull request title matches the squash-subject format in §5 | `ci` | block | proposed |
| CM-02 | No branch contains consecutive commits with identical subjects | `ci` | warn | proposed |
| CM-03 | No secret material or local state is committed (`.env`, `*.db`, keys, tokens) | `ci` | block | active (detection); prevention `blocked` — see §8.3 |
| CM-04 | Diff excludes editor and OS artefacts (`.idea/`, `.vscode/`, `.DS_Store`) | `ci` | block | proposed |

### 6.3 Pull request controls

| ID | Control | Enforcement | Severity | Status |
| --- | --- | --- | --- | --- |
| PR-01 | Changed lines, excluding lockfiles and generated output, are under 400 | `ci` | warn | proposed |
| PR-02 | Description states scope and the verification actually performed | `ci` | warn | proposed |
| PR-03 | Agent-assisted pull requests carry the `agent-authored` label | `ci` | block | proposed |
| PR-04 | Frontend typechecks and lints clean | `ci` | block | active |
| PR-05 | Backend test suite passes | `ci` | block | active |
| PR-06 | Schema changes ship with an Alembic migration | `ci` | warn | proposed |
| PR-07 | Every required status check passes before merge is available | `ruleset` | block | blocked |
| PR-08 | Agent-authored changes are read in full by a human before merge | `review` | manual | proposed |
| PR-09 | An `inspect-NNNN/` pull request body closes its issue with `Closes #NNNN` | `ci` | block | proposed |

PR-08 has no automated form and is deliberately listed anyway. Recording it as a
control means its absence is a known gap rather than an oversight, and it
becomes enforceable as a required approval once a second maintainer exists.

### 6.4 Merge controls

| ID | Control | Enforcement | Severity | Status |
| --- | --- | --- | --- | --- |
| MG-01 | Squash is the only permitted merge method | `repo-setting` | block | active |
| MG-02 | `main` maintains linear history | `ruleset` | block | blocked |
| MG-03 | Branch is up to date with `main` before merge | `ruleset` | block | blocked |

### 6.5 Agent isolation controls

| ID | Control | Enforcement | Severity | Status |
| --- | --- | --- | --- | --- |
| AG-01 | Concurrent agent sessions use separate worktrees on separate branches | `review` | manual | proposed |
| AG-02 | Each worktree has its own `.env`, compose project name, and backend port | `review` | manual | proposed |
| AG-03 | No agent session commits directly to `main` | `ruleset` | block | blocked |

---

### 6.6 Spike controls

| ID | Control | Enforcement | Severity | Status |
| --- | --- | --- | --- | --- |
| SP-01 | A `spike/` branch's first commit creates `docs/spikes/<slug>.md` with question, owner, and review date | `ci` | block | proposed |
| SP-02 | A `spike/` branch past its review date is renewed or terminated | `scheduled` | warn | proposed |
| SP-03 | A spike terminates only after its findings document merges to `main` | `review` | manual | proposed |
| SP-04 | No branch of any other type is cut from a `spike/` branch | `ci` | block | proposed |
| SP-05 | Renewal is recorded in the findings document with a date and what was learned | `review` | manual | proposed |

SP-04 is the mechanical half of the no-retargeting rule in §3.1; SP-03 and SP-05
are its judgement-dependent half and are listed as `manual` rather than omitted.

---

### 6.7 Security feedback controls

| ID | Control | Enforcement | Severity | Status |
| --- | --- | --- | --- | --- |
| SF-01 | A merge to `main` deploys to the dev instance with no manual step | `ci` | block | proposed |
| SF-02 | A branch remediating a finding closes the issue that records it | `ci` | block | proposed |
| SF-03 | Reported findings are filed as `security`-labelled issues and triaged within 5 days | `scheduled` | warn | proposed |
| SF-04 | A finding is closed only after a rescan of the redeployed dev instance | `review` | manual | proposed |
| SF-05 | The dev instance holds no production data, live MDM credentials, or real encryption key | `review` | manual | proposed |
| SF-06 | Security-domain changes carry the `security` label regardless of branch prefix | `ci` | warn | proposed |

SF-06 is why security work has no branch prefix of its own. A finding fix is
genuinely a `fix/`, and a hardening change is genuinely a `chore/`; the domain is
a label so it composes across all branch types and stays queryable.

SF-05 is `manual` because it is a property of the environment rather than the
repository, and nothing in a pull request can observe it. It is the highest
consequence control in this document.

**SF-01 is blocked on infrastructure.** As of 2026-08-18 there is no deploy
target. The choice between AWS and a self-hosted QNAP is open and expected
around October 2026. Until one exists the circuit in §3.2 is run by hand —
redeploy, rescan, close — which is slower but not weaker. SF-01 automates the
redeploy step; it is not a precondition for the loop, and the rest of §6.7
should not wait on it.

The deployment target is a decision with real trade-offs and no code output,
which makes it a `spike/` by §3.1 rather than an issue. The material difference
is exposure, not cost: an AWS target can be isolated in its own VPC, whereas a
QNAP sits on a network with other hosts on it, and SF-05 becomes materially
harder to satisfy when the continuously-attacked instance shares a LAN with
unrelated data. That trade-off is the question the spike should answer.

---

## 7. Validation specifications

Concrete checks for the automatable controls, expressed against the GitHub
Actions `pull_request` context. These are the definitions to implement; they are
kept separate from the register above so the register stays readable.

**BR-01** — branch name

```bash
grep -Eq '^(inspect-[0-9]{4}|fix|chore|docs|spike)/[a-z0-9]+(-[a-z0-9]+)*$' <<<"$HEAD_REF"
```

**BR-02** — base branch

```
github.event.pull_request.base.ref == 'main'
```

**BR-03** — branch age

```bash
first=$(git log --reverse --format=%ct "origin/main..$HEAD_REF" | head -1)
(( ( $(date +%s) - first ) / 86400 <= 5 ))
```

**BR-04** — auto-delete enabled

```bash
gh api repos/LoonSecIO/LoonInspect --jq '.delete_branch_on_merge == true'
```

**BR-05** — no reuse of a merged branch name

```bash
test "$(gh pr list --state merged --search "head:$HEAD_REF" --json number --jq 'length')" -eq 0
```

**CM-01** — squash subject format

```bash
grep -Eq '^(INSPECT-[0-9]{4}|fix|chore|docs): .{10,60}$' <<<"$PR_TITLE"
```

**CM-02** — no consecutive duplicate subjects

```bash
test -z "$(git log --format=%s "origin/main..$HEAD_REF" | uniq -d)"
```

**CM-03 / CM-04** — forbidden paths in the diff

```bash
git diff --name-only origin/main... \
  | grep -Eq '(^|/)\.env$|\.db$|(^|/)\.idea/|(^|/)\.vscode/|\.DS_Store$' && exit 1
```

CM-03 additionally requires a secret scanner over the diff content; path
exclusion alone does not satisfy it. GitHub's push protection covers part of
this and should be enabled as the first increment.

**PR-01** — diff size

```
github.event.pull_request.additions + .deletions, minus paths matching
package-lock.json, *.lock, migrations/versions/*
```

**BR-08** — branch number is a real open issue

```bash
n=$(sed -E 's|^inspect-0*([0-9]+)/.*|\1|' <<<"$HEAD_REF")
test "$(gh issue view "$n" --json state --jq .state)" = OPEN
```

**PR-09** — pull request closes its issue

```bash
n=$(sed -E 's|^inspect-0*([0-9]+)/.*|\1|' <<<"$HEAD_REF")
gh pr view "$PR" --json body --jq .body | grep -Eq "(Closes|Fixes|Resolves) #$n\b"
```

**PR-03** — agent label

```bash
gh pr view "$PR" --json labels --jq '.labels[].name' | grep -qx 'agent-authored'
```

**PR-04 / PR-05** — build and test

```bash
cd frontend && npx tsc --noEmit && npx eslint .
cd backend  && uv run --frozen pytest
```

**PR-06** — migration accompanies schema change

```bash
# if any file under backend/app/models changed, require a new file under
# backend/migrations/versions in the same diff
```

**SP-01** — findings document exists for the branch

```bash
test -f "docs/spikes/${HEAD_REF#spike/}.md"
```

**SP-02** — scheduled sweep of open spikes

```bash
today=$(date +%F)
for b in $(git branch -r --list 'origin/spike/*' --format='%(refname:short)'); do
  doc="docs/spikes/${b#origin/spike/}.md"
  review=$(git show "$b:$doc" 2>/dev/null | sed -n 's/^review-date: //p')
  [[ -z "$review" || "$review" < "$today" ]] && echo "overdue or unreadable: $b"
done
```

**SP-04** — no branch descends from a spike

```bash
for s in $(git branch -r --list 'origin/spike/*' --format='%(refname:short)'); do
  git merge-base --is-ancestor "$s" HEAD && exit 1
done
```

## 8. Enforcement roadmap

Sequencing matters less than starting, but this order front-loads the controls
that prevent damage over those that enforce tidiness:

1. **Repository settings and rulesets** — BR-04, BR-06, BR-07, MG-01, MG-02,
   MG-03, AG-03, plus secret push protection. These are configuration changes
   with no code to write and they close the irreversible failure modes.
   *Partially done — see [Repository configuration](#81-repository-configuration).*
2. **A build-and-test workflow** — PR-04, PR-05, wired as required checks to
   activate PR-07. *PR-04 and PR-05 done; see #11 for what the suite covers.*
3. **A policy workflow** — BR-01, BR-02, BR-05, CM-01, CM-03, CM-04 as blocking;
   BR-03, CM-02, PR-01 as annotations.
4. **Spike enforcement** — SP-01 and SP-04 join the policy workflow; SP-02 needs
   a scheduled workflow, the first control here with no pull request to hang on.
5. **Security feedback loop** — SF-02 and SF-06 in the policy workflow; the
   §3.2 circuit runs manually until a deploy target exists. SF-01 lands with that
   target, expected around October 2026. SF-05 is an environment review and must
   be confirmed before the dev instance is first exposed, ahead of everything
   else in this list.
6. **The judgement-dependent remainder** — PR-02, PR-03, PR-06, SP-03, SP-05,
   SF-04, and eventually PR-08 once a second maintainer can approve.

A machine-readable manifest of this register (control ID, severity, enforcement
point, check definition) should be added as `docs/controls.yml` when step 3
begins, so the workflow and this document cannot drift.

### 8.1 Repository configuration

The configuration in step 1 is version-controlled rather than clicked in, so it
is reviewable and reproducible:

- `.github/rulesets/main.json` — the ruleset definition for `main`.
- `.github/scripts/apply-repo-config.sh` — applies it, plus the plain repository
  settings, idempotently. `--dry-run` shows what would change.

**Rulesets are blocked on the GitHub plan.** `LoonSecIO` is on the free plan and
this repository is private, a combination for which the rulesets and branch
protection APIs return `403`. Secret scanning and push protection are gated the
same way. The definition and the script are complete and correct; nothing in
them needs revisiting when the constraint lifts, which is why the affected
controls are `blocked` rather than `proposed`.

**This resolves itself.** The repository goes public during the release
schedule in §8.2. Every blocked control here becomes available at no cost at the
flip, because the constraint is the combination of *private* and *free* rather
than either alone. Paying for GitHub Team to unblock rulesets sooner would buy
about four weeks and would not cover secret scanning, which needs Advanced
Security on top; it is not worth it.

The controls are therefore `blocked` in the same sense SF-01 is: agreed,
implemented, waiting on something with a known date. Running
`apply-repo-config.sh` again after the flip is the whole of the remaining work,
and §8.2 places it in the quiet window rather than at the announcement.

What is enforced today: BR-04 and MG-01 through repository settings, and PR-04
through the CI workflow. Everything else in step 1 is `blocked`.

### 8.2 The release schedule

Four phases, of which only the last has a fixed date:

| Phase | Ends | What it is |
| --- | --- | --- |
| Feature work | ~2026-09-07 | Ordinary development |
| Cleanup | ~2026-09-15 | No new features; the work in the pre-publication checklist |
| Quiet public | before 2026-09-17 | Repository made public, deliberately unannounced |
| Announcement | **2026-09-17** | Fixed date |

**The announcement date is fixed and the flip date is not**, so schedule
pressure lands on cleanup. When cleanup runs long the correct response is to
shorten the quiet window, never to skip an item in it — the checklist exists
because those items cannot be done after publication.

**The quiet window is a control, not a gap.** It is the only period in which the
repository is public but not yet attracting attention, so a mistake found then
is cheap. Everything that needs the repository to be public — re-running
`apply-repo-config.sh`, enabling native secret scanning and push protection,
confirming the ruleset was actually accepted — belongs in that window, not after
the announcement. Do not shorten it to nothing.

**Publishing is a history event, not a state change.** It exposes every ref the
remote holds — all branches, and `refs/pull/*` for every pull request ever
opened, including those whose branches were deleted. A credential committed once
and removed in the next commit is still published. This is the failure mode that
cannot be fixed after the fact: rotation is the only remedy, and it has to
happen before the flip rather than after.

CM-03's scanner (§8.3) is what makes this checkable. A full-history scan of a
mirror clone on 2026-08-18 found **0 verified secrets across all 20 refs**, and
`.env` has never been committed on any ref. That is the baseline; it must be
re-established during cleanup, not inherited from this document.

```bash
git clone --mirror https://github.com/LoonSecIO/LoonInspect.git audit.git
# trufflehog needs a work tree, so present the mirror as one
mkdir audit && mv audit.git audit/.git && git -C audit config core.bare false
git -C audit reset --mixed
docker run --rm -v "$PWD/audit":/repo ghcr.io/trufflesecurity/trufflehog:3.97.0 \
  git file:///repo
```

Note that this is deliberately run without `--only-verified`: an expired or
already-rotated credential still tells you a practice existed, and a detector
that cannot reach its provider reports unverified rather than nothing.

### 8.3 Secret scanning

CM-03 requires a scanner over diff *content*; the path exclusions in the policy
workflow do not satisfy it on their own. GitHub's own scanning is blocked with
the rest of §8.1, so `.github/workflows/secret-scan.yml` runs TruffleHog on
every pull request, on pushes to `main`, and weekly over full history. The job's
check context (`TruffleHog`) is listed in `.github/rulesets/main.json`'s
required status checks, so when the ruleset activates at the flip a verified
finding blocks the merge rather than merely reporting one; until then it fails
visibly but gates nothing, like every required check.

**It detects; it does not prevent.** By the time the job fails, the secret is in
remote history and must be rotated. `.githooks/pre-commit` is the preventive
half and is the closer analogue to the push protection that is blocked — it is
opt-in per clone, and per worktree, which matters given §4:

```bash
git config core.hooksPath .githooks
```

CM-03 is therefore recorded as `active` for detection with prevention still
`blocked`, rather than as a single satisfied control.

The blocking jobs use `--only-verified`, which reports a candidate only once it
proves live against its provider. This is not noise-aversion for its own sake:
the first full scan flagged a `sha256` package hash in `backend/uv.lock` as a
Sentry token, and a blocking check that fails on every lockfile change is one
people learn to bypass. The cost is that verification sends candidate secrets to
third-party APIs, which is a deliberate trade rather than an oversight.

Once the repository is public, GitHub's native scanning and push protection
become available and should be enabled alongside this rather than instead of it:
push protection closes the prevention gap, and TruffleHog's verification covers
detectors GitHub's partner program does not.

## 9. Exceptions

An exception is requested in the pull request description under an
`## Exception` heading naming the control ID and the reason, and is granted by
the repository owner. Controls at `block` severity that must be bypassed are
overridden through the ruleset bypass list, which produces an audit entry.
Advisory (`warn`) controls need no formal exception — acknowledging the
annotation in review is sufficient.

## 10. Known deviations at time of writing

Recorded so the first enforcement pass does not mistake existing history for
compliance:

- `INSPECT-0005-AUTHLAYER` carried four pull requests (#6–#9), violating BR-05.
- Historical branch names violate §2 casing: `inspect-001-rework-side-bar`,
  `Inpsect-0003-FilterSortJamfPatchTable`, `INSPECT-0004-RemoveFleet`.
- Merged branches were not deleted; `INSPECT-0005-AUTHLAYER` remains on `origin`.
- Merges to date are merge commits, not squashes, violating MG-01 and MG-02.
  Existing history is grandfathered; these controls apply from adoption forward.
- `INSPECT-0001` through `INSPECT-0005` were assigned by hand before GitHub
  Issues became the source of truth and correspond to no issue. They are
  historical labels only. Real numbering begins at whatever value the repository
  counter holds when the first issue is filed, which is above the pull request
  numbers already consumed (#1–#9).

## Change log

| Version | Date | Change |
| --- | --- | --- |
| v1 | 2026-08-18 | Initial draft |
| v1.1 | 2026-08-18 | Added spike lifecycle and conversion workflow (§3.1), SP-01–SP-05, `scheduled` enforcement point |
| v1.2 | 2026-08-18 | Added security feedback loop (§3.2) and SF-01–SF-06 |
| v1.3 | 2026-08-18 | Recorded SF-01 as blocked on an undecided deploy target |
| v1.4 | 2026-08-18 | GitHub Issues as ticket source of truth; added BR-08, PR-09 |
| v1.5 | 2026-08-18 | Added `active`/`blocked` status values; recorded rulesets as blocked on the GitHub plan (§8.1); marked BR-04, MG-01, PR-04 active |
| v1.6 | 2026-08-18 | Added §8.2 (release schedule and history exposure) and §8.3 (secret scanning); CM-03 active for detection; public flip recorded as the unblock date for §8.1 |
| v1.7 | 2026-08-29 | TruffleHog's check context added to the ruleset's required status checks (§8.3), so CM-03's detection gates merges once §8.1 unblocks |
