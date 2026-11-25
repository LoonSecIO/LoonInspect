# Fleet's maintained-apps catalog

Status: **built, behind a flag that ships off**, 2026-11-15
([#794](https://github.com/LoonSecIO/LoonInspect/issues/794)); each title's version history
from Fleet's commits, 2026-11-21 ([#838](https://github.com/LoonSecIO/LoonInspect/issues/838),
[below](#version-history)) · the flag is
`fleet_maintained_apps` ([the register](feature-flags.md)) · when the tab is missing, empty or
says its last check got no answer, [`troubleshooting.md`](troubleshooting.md) §27 · read
against GitHub once, on 2026-11-15, with the numbers under [Validation](#validation).

## What it is

Fleet keeps a catalog of the Mac apps it maintains in its public repository,
[`fleetdm/fleet`](https://github.com/fleetdm/fleet), under `ee/maintained-apps/outputs`: one
index of titles and one manifest per title, updated as vendors release. With the flag on,
LoonInspect reads that folder once a day and shows it under **Devices › Applications › Fleet
catalog**: each title, Fleet's latest version of it, how many of this organization's Macs have
it and how many of those are behind. In the background, slowly, it also reads the version
history of the titles installed here from the same repository's commits: every version Fleet's
catalog carried, and the day it took each.

Each title also has a **Fleet source** link to its current `darwin.json` manifest on
GitHub (#840). It is separate from the button that opens version history and works with
the keyboard. In LoonInspect.app it opens in the default browser; on the web it opens
in a new tab.

It is a second public list of titles and latest versions, beside Jamf's patch catalog, and it
needs no Jamf Pro connection. It is a display. Nothing here feeds the vulnerability join, the
App Catalog's judgements, the wire or the posture tape, and LoonInspect installs nothing.

Fleet builds its Mac manifests from Homebrew metadata (the folder's own README says so), so
*Fleet's latest* is the version Fleet last recorded for the title, not a vendor's
announcement.

Saved application plans and auditor PDFs start from **Installed Apps**, with the same
workflow also available in Catalog. Installed Fleet titles link to that workflow. See
[Installed application patch plans](application-patch-plans.md).

## The flag, and what it decides

`fleet_maintained_apps` is a switch under **Settings › Feature Flags**, per organization, off
by default. It decides three things, and it is the only switch in that list that decides an
outbound call.

- **Whether GitHub is asked.** While no organization on the instance has the flag on, the
  instance makes no request to GitHub for this catalog or its history. One organization turning it on is
  enough for the instance to read it: the catalog is one copy for the whole instance, like
  Jamf's patch catalog, because it holds nothing of any organization's.
- **Whether the tab is listed.** The tab appears for an organization with the flag on, and
  its address says the area is off for one without.
- **Whether the API answers.** `GET /api/fleet-catalog` answers `enabled: false` and no titles
  for an organization with the flag off, whatever the instance holds for another
  organization. `POST /api/fleet-catalog/refresh` is refused in words.

## The licence

Fleet's repository carries more than one licence. Its root `LICENSE` says everything under
the `ee/` folder is licensed under `ee/LICENSE`, the Fleet Enterprise Edition licence, and the
maintained-apps catalog is under that folder. That licence says the software and its
documentation files "may only be used in production" (Fleet, `ee/LICENSE`) by someone who has
agreed to Fleet's subscription terms and holds a valid Fleet Enterprise Edition subscription
for the right number of hosts, and that copying and modifying it for development and testing
needs no subscription. [Read it](https://github.com/fleetdm/fleet/blob/main/ee/LICENSE) before
turning the flag on.

Whether reading a title's name, bundle identifier and versions from those files, in your
deployment, is a use that licence covers is a question for whoever answers licence questions
for your organization. The version history reads the same files at earlier commits, so it is
the same question, asked of more of them. This document does not answer it and the product does not decide it.
The flag ships off, nothing is read until an administrator turns it on, and the flag's own
description says what this section says. Kyle chose this source with that stated (2026-11-15,
#794).

**Each instance reads for itself.** Nothing here is collected by LoonSec, shipped in the image,
or sent anywhere: every request is the instance's own, to GitHub, under its own operator's
answer to the licence question. A history gathered once by LoonSec and served to instances
would be LoonSec copying and using these files in production, which is why it is not built
that way (Kyle, 2026-11-21, #838).

## What is read, and what is kept

| Read | From | Kept |
| --- | --- | --- |
| The listing of `ee/maintained-apps` | `api.github.com` | The `outputs` folder's git tree sha, to tell whether anything moved. |
| The `outputs` tree, listed whole | `api.github.com` | Each Mac manifest's git blob sha, to tell which manifests changed. |
| `apps.json`, the index | `raw.githubusercontent.com` | Each Mac title's name and `unique_identifier`, which for a Mac title is its bundle identifier. |
| `<slug>/darwin.json`, a title's manifest | `raw.githubusercontent.com` | The first version entry's `version` string. |
| The list of changes to one `<slug>/darwin.json` (the commits API, by path), a hundred at a time | `api.github.com` | Each change's commit sha and the date GitHub records for it. |
| `<slug>/darwin.json` as of one of those commits | `raw.githubusercontent.com` | The first version entry's `version` string. |

Per title, the instance holds: Fleet's directory name for it (the slug), the name, the bundle
identifier, the latest version, the version before the last move this instance saw and when
it saw the move, when it first read the title, the manifest's blob sha, and how far the version
history reached (when it was last read, its oldest and newest change, and a sentence for what
it left undated). That is the whole row (`fleet_maintained_apps`). The history is one row per
title and version (`fleet_app_versions`): the version, the date of the first commit that
carried it, that commit's sha, and the version it replaced. One more row holds the last check
and the last history read (`fleet_catalog_state`).

**Never kept**, and never parsed beyond being skipped over: a manifest's installer address,
its checksums, its install and uninstall scripts (`refs`), its osquery queries and its
categories. Windows manifests are not read at all.

**Sent:** nothing of the instance or its organizations. Every request is a GET naming one of
Fleet's files, under the user agent `LoonSecIO/<build> fleet-catalog`, the form the container's
outbound calls take; the update check's request to LoonSec's update service is the exception,
and names only the release (`LoonSecIO/<release> update-check`, #819). No inventory, count,
identifier, token or cookie goes with it. GitHub sees the address the request came from, as it
does for the update check when `UPDATE_CHECK_URL` points it at GitHub.

## The check

The scheduler looks once an hour, at twenty past, and checks **once a day**: a check that got
an answer is not repeated for about a day, and one that did not is tried again within the
hour. A process started with `SCHEDULER_ENABLED=false` never checks. **Check now** on the tab
runs the same check with a person waiting; it needs the permission Jamf's **Sync now** needs
(`patch:catalog-sync`, held by Analyst and Admin), because it is the same kind of act, an
outbound read of a public catalog. A press is in the audit log as `fleet-catalog.checked`
with what it found. The daily check is the scheduler's and is in the container log.

What one check asks:

1. **The folder's listing**, one request to the GitHub API. It names the `outputs` tree by
   its git sha. The same sha as the last complete read is the same content, so the check
   stops here. This is every check on a day Fleet changed nothing: one request.
2. **The tree, listed whole**, one more API request. The listing GitHub's Contents API gives
   for a folder stops at 1,000 entries and this folder holds more, so the Git Trees API is
   asked instead. It gives every Mac manifest's blob sha.
3. **The index**, one request to `raw.githubusercontent.com`.
4. **Each manifest whose blob sha differs from the one held**, eight at a time, from the same
   host. On the first check that is every title. After it, it is the titles Fleet changed.

So the GitHub API, whose limit for requests without a sign-in is 60 an hour for each address,
is asked at most twice per check. The manifests come from the raw file host, which that limit
does not count.

Then the titles are written: a new title is added, a title whose version changed keeps the
old version as *previous* and the time as *when it moved*, a title the index renamed takes
the new name, and **a title Fleet no longer lists is removed**. The first reading of a title
is not a move, so its *previous* and *moved* stay empty until the version changes while this
instance is watching.

The hosts are fixed in the code and no setting points the check elsewhere. A redirect is not
followed; it is reported. Before dialling, each name is resolved and refused if it resolves to
loopback or link-local, the rule every other outbound call's host passes.

## Version history

The daily check keeps one step of history: the version before the last move this instance
saw. Fleet's repository holds the rest. Each manifest has one commit per change, so reading the
manifest at each of them gives every version Fleet's catalog carried and the day it took each
one (#838, `app.core.fleet_history`).

**Slow on purpose, and only for the titles in your space.** In the background the instance
reads one title at a time, with at least two minutes between titles, and that title's
manifests one at a time, half a second apart. It reads a title only when it is installed on a
Mac in an organization with the flag on, the most-installed first, and only once the daily check
has read the catalog. It reads a title again only after the daily check sees its version move,
and then only from the newest change it already read. A title takes from a few seconds to a
minute at that pace (Firefox's 97 changes took 59 seconds on 2026-11-21), so a fleet with 100
of Fleet's titles installed has every history read in four to five hours. After that it costs
one API request and a manifest or two for each title whose version moves.

**It never spends GitHub's last 20 requests of the hour.** GitHub's answers say how many of
this address's 60 requests an hour without a sign-in are left. While that is 20 or fewer, the
history makes no API request and waits for the hour to reset, so the daily check, **Check now**
and every other tool behind the same address keep theirs. The status line says *Paused until
…* while it waits.

**What one title costs.** One request to `api.github.com` per hundred changes to its manifest,
then one request to `raw.githubusercontent.com` per change. Titles had 31 to 113 changes on
2026-11-21; a list longer than ten pages is read back ten pages and no further.

**A version is dated only where the commits show it arriving**: at a change where it replaced
another version or a missing manifest, or at the title's first change in Fleet's history. A
version the read cannot see arrive is left out of the history rather than given a date that is
only a bound, and the title's history says what was left out. Three things do that:

- the first version in a history longer than the read's thousand changes;
- the version after a change whose manifest this build could not read;
- a version that left and came back keeps the date of its first arrival, never its return, and
  while it is the latest again the tab shows the move this instance saw instead of that date.

The title's history panel says which of the first two applied, and keeps saying it after later
reads add to the history. **These are Fleet's dates, not the vendor's.**
Fleet builds its manifests from Homebrew (its README says so) and commits them some hours later.
For Firefox in October and November 2026, Fleet's commit came 5 to 13 hours after Homebrew's.

**A person can read any title's history now.** A title's row on the tab opens its history.
**Read history** reads the whole of it at once, four manifests at a time, for an account holding
`patch:catalog-sync`, the permission **Check now** needs. That includes a title no Mac here has,
which the background never reads. It is held to the same reserve, and it is in the audit log as
`fleet-catalog.history.read`.

| Last read's word | Means | The history held |
| --- | --- | --- |
| `ok` | The title's changes were read and every version that could be dated was. | Added to; nothing removed. |
| `waiting` | GitHub said 20 or fewer requests were left this hour. It carries on by itself after the time given. | As it was. |
| `refused`, `unreachable`, `unexpected` | The daily check's words and sentences (below). The background pauses a quarter of an hour and leaves the title that failed for an hour, so one title GitHub keeps refusing never holds up the rest. Nothing is marked read, so once the cause is gone every title is read. | As it was. |

*Paused until …* comes off the status line by itself once the hour has reset, whether or not a
title was left to read. A person's read refused for the reserve is their own `409`, and is not
written to the status line.

The API is `GET /api/fleet-catalog/{slug}/history` (`app:read`, asks GitHub nothing) and `POST`
to the same address (`patch:catalog-sync`, reads it now). Both are refused in words with the
flag off. A refused read is a `409` with the sentence as its `detail`.

## What a check can find

The last check's outcome is one word, with a sentence when there is something to say. Both are
on the tab's status line and, for a failed check, in the container log.

| Outcome | Means | The titles held |
| --- | --- | --- |
| `ok` | The catalog had changed and was read. A sentence follows only if some manifests could not be read as a title with a version; they are named, left as they were, and read again when Fleet next changes its catalog. | Now what Fleet publishes. |
| `unchanged` | GitHub answered and nothing had moved. | As they were. |
| `refused` | GitHub's rate limit answered (a 403 or 429 carrying its limit headers). | As they were. |
| `unreachable` | No answer, an answer GitHub does not give (a proxy's 403, a 502), or a name that resolved to an address this instance will not dial. | As they were. |
| `unexpected` | An answer that was not Fleet's catalog: a page that is not JSON, a redirect, a folder that is gone, a listing GitHub cut short, an index with no Mac app. | As they were. |

**A failed check never removes or blanks what is held.** Three rules make that true. A check
that fails before reading manifests writes nothing but its own outcome. A check cut short
part-way through the manifests keeps the ones it read, says how many, and does not record the
new tree sha, so the next check lists the tree again and reads only the rest. And titles are
removed only by a complete read that no longer lists them, never by a listing that failed or
was cut short.

Before the first check there is no outcome at all, and the tab says the catalog has not been
read yet. That is its own state, not an empty catalog.

## The tab

**Devices › Applications › Fleet catalog** lists, per title: the name, the bundle identifier,
Fleet's latest version, *Macs with app*, *Macs behind*, and when the version last moved with
the version before it.

- **The match is the exact bundle identifier.** A title is on a Mac when an installed app
  there carries the title's bundle identifier, letter for letter. Fleet's own check for a
  title is the same equality. Only Macs are counted: an iPad app sharing the identifier is not
  the Mac title.
- **Behind is any copy older than Fleet's latest.** The installed version is compared with
  Fleet's by the comparison the Jamf Patch matcher uses, on the numbers in the version
  string. A Mac with two copies of an app, one current and one stale, is behind. A Mac on a
  build newer than Fleet lists is not behind. *Macs behind* and the rest are both served, so
  the page never subtracts.
- **Only titles installed here** is ticked by default and hides Fleet's titles no Mac has.
  Unticked, the whole catalog is listed. A title on no Mac shows a dash under *Macs behind*,
  not a zero.
- **The status line** says when GitHub was last asked and what it answered. After a failed
  check it shows the sentence and says the titles below are as read on the earlier date. Under
  it, how many of the titles installed here have their version history read, and the
  sentence when the last history read held back or failed.
- **When the version moved** is the version history's date when it has one: the day Fleet's
  catalog took the latest version, and the version it replaced. Without one, it is the move
  this instance saw, or that there is neither yet.
- **A title's name opens its version history**, newest first, each date linked to its commit
  in Fleet's repository.

The API is `GET /api/fleet-catalog` (`app:read`; `installedOnly`, `q`, `page`, `pageSize`) and
`POST /api/fleet-catalog/refresh` (`patch:catalog-sync`). A refresh that could not read GitHub
answers `409` with the sentence as its `detail`, and stores the same sentence as the catalog's
state.

### The migration report (API only, so far)

`GET /api/fleet-catalog/migration` (#895) starts from what is installed: each app on the selected
Macs, with the Fleet titles that carry its bundle identifier. It needs `app:read` and `device:read`
and takes `deviceScope`, the filter Installed Apps and Patch Plans use, so all three count the same
Macs. It asks GitHub and Jamf nothing, and no page reads it yet. With the flag off it answers
`enabled: false` and counts nothing.

- **`scope`.** *Eligible* is every current Jamf Mac the filter's connection and style allow;
  departed Macs and other platforms never count. *Selected* is the eligible Macs the conditions
  keep; the rest of the report counts only these. *Unknown contact* and *unknown inventory* are
  eligible Macs whose date is missing or in the future, which only *is unknown* selects.
- **`match`.** `exact` is one Fleet title in a complete snapshot; `none`, no title in a complete
  snapshot; `ambiguous`, several titles, an EA-assumed build or more than one Jamf Patch title;
  `unknown`, anything else. In `fleetDeviceCounts`, Fleet titles that share a bundle identifier
  share a count.
- **One known difference from a patch plan.** When an app's one Jamf Patch title is in the synced
  Jamf Patch catalog but missing from some of its builds or Macs, this reads `exact`, while a
  patch plan withholds Fleet's version as its target and asks for identity review.

## What it leaves out

- **No vulnerability or patch judgement.** Fleet's titles are not joined to the vulnerability
  corpus, are not a Jamf Patch title match, and do not count as a public source where the
  product asks whether one knows an app.
- **Nothing on the wire.** No event, no posture key, no alert when Fleet's version moves.
- **No vendor release dates.** The history's dates are when Fleet's catalog took a version.
- **No history in the background for a title no Mac here has.** A person's **Read history**
  reads one.
- **No Windows or iOS titles**, and no installers: LoonInspect deploys nothing.
- **No setting for another source.** The check reads Fleet's repository on GitHub and nothing
  else; the two hosts are fixed.
- **A skipped manifest waits for Fleet's next change.** While the tree sha does not move, the
  check stops at its first request, so a manifest it could not read is not retried until
  Fleet changes the folder again.

## Validation

On 2026-11-15, from one Mac, against the live repository, with the code as committed for #794
and a throwaway database:

- **First check:** outcome `ok`, **953 Mac titles**, no manifest skipped. Two requests to
  `api.github.com`, 954 to `raw.githubusercontent.com` (the index and 953 manifests), 12.6
  seconds. Every bundle identifier was distinct; the longest version string was 30 characters.
- **Second check, immediately after:** outcome `unchanged`, one request to `api.github.com`,
  none to the raw host, 0.16 seconds.
- Sample rows as read: `010-editor` (010 Editor, `com.SweetScape.010Editor`, 17.0.1),
  `1password` (1Password, `com.1password.1password`, 8.12.44).

**The version history (#838)**, on 2026-11-21, from the same Mac, against the live repository,
with the reader as committed and no database (the database half is the test suite's, against a
stand-in GitHub):

- **Firefox** (`firefox`), read at the background's pace: 97 changes from 2025-03-12 to
  2026-11-18, **68 versions dated**, none unreadable, the history whole. One request to
  `api.github.com`, 97 to `raw.githubusercontent.com`, 59.0 seconds. The newest four: 159.0 on
  2026-10-27 18:22Z, 159.0.1 on 2026-11-03, 160.0 on 2026-11-11 05:12Z, 160.0.1 on 2026-11-18
  02:27Z, each replacing the one before. Homebrew had the same four 5 to 13 hours earlier.
- **010 Editor** (`010-editor`): 31 changes from 2025-11-07, 5 versions dated, one API request,
  31 manifests, 19.4 seconds.
- **A resumed read** from each title's newest change, as after a move: one API request and one
  manifest each, nothing new to date.
- GitHub's allowance headers were read on every API answer: 59, then 57 left of 60.

Not run: a check from behind a proxy or a rate-limited address (covered by tests against a
stand-in for GitHub, not against GitHub), a version move observed on the live catalog across
two days, and the tab in a browser against a real fleet. For the history: the background
loop across a whole fleet's titles against the live repository, and the reserve met on a real
address rather than a stand-in.

posture_snapshot: none
