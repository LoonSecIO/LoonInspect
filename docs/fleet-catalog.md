# Fleet's maintained-apps catalog

Status: **built, behind a flag that ships off**, 2026-11-15
([#794](https://github.com/LoonSecIO/LoonInspect/issues/794)); each title's version history
from Fleet's commits, 2026-11-21 ([#838](https://github.com/LoonSecIO/LoonInspect/issues/838),
[below](#version-history)); whether the titles held are complete, 2026-11-23
([#859](https://github.com/LoonSecIO/LoonInspect/issues/859), [below](#complete-or-partial)) · the flag is
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
catalog carried, and the day it took each. The tab opens on
[**Migration review**](#migration-review), the installed apps on the Macs in the device filter
against both catalogs, with these titles beside it as **Fleet titles**.

Each title also has a **Fleet source** link to its current `darwin.json` manifest on
GitHub (#840). It is separate from the button that opens version history and works with
the keyboard. In LoonInspect.app it opens in the default browser; on the web it opens
in a new tab.

It is a second public list of titles and latest versions, beside Jamf's patch catalog, and it
needs no Jamf Pro connection. It is a display. Nothing here feeds the vulnerability join, the
App Catalog's judgements, the wire or the posture tape, and LoonInspect installs nothing. The
one other reader is Posture › Patch policy's **Fleet** source (#614): a reference walk of one
app's track over the days in this history, computed on this instance for an organization with
the flag on, and neither stored nor sent anywhere ([`troubleshooting.md`](troubleshooting.md)
§33).

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
  organization. `POST /api/fleet-catalog/refresh` is refused in words, and so is Posture ›
  Patch policy's **Fleet** source (`GET /api/patch-policy/walk?source=fleet`), with the same
  sentence.

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
carried it, that commit's sha, and the version it replaced. One more row holds the last check,
the last history read and the completeness record, `snapshot_status`: `unread`, `partial` or
`complete` ([below](#complete-or-partial)) (`fleet_catalog_state`).

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
   its git sha. When it matches the last listing a check finished, whether that check read
   every title or skipped some, the content is the same, so the check stops after this
   request and the titles held keep the coverage they had,
   [complete or partial](#complete-or-partial). This is every check on a day Fleet changed
   nothing: one request.
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
the new name, and **a title that neither the tree nor the index lists any more is removed**.
The first reading of a title is not a move, so its *previous* and *moved* stay empty until
the version changes while this instance is watching.

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

### Observed upgrades

Each [migration detail](#migration-detail) carries `observedChanges` (#900): how this fleet has
been taking the app's updates, read from the [change log](change-log.md) and timed against
Fleet's dates. It counts only the Macs the request's `deviceScope` selects, and only the
detail's app identities. An app with no bundle ID is matched under its name, as inventory
stores it.

- **The counts.** `windowDays` is 90, the window everything covers. `versionChanges` counts the
  change log's application updates there in which `version`, `cfBundleShortVersionString` or
  `cfBundleVersion` moved, with both sides present; `macs` counts the distinct Macs among them,
  and `lastAt` is the newest, null with none. Rows dated after the request are left out.
- **They need the change log.** Applications are recorded only with **Settings › Change
  tracking** at *High + normal* (the default) or *Everything*, with applications not switched
  off, and a Mac's first sweep is its baseline, so it counts from its second.
- **The pairing.** `adoptionSamples` counts (Mac, version) pairs: a Mac's move from one plain
  dotted number to a higher one (`2.0` to `2.1`; `2.1-beta` is never ordered), to a version
  this title's history dated, with Jamf's short version, where sent, equal to `version`. A pair
  counts when its first recorded upgrade is inside the window and on or after Fleet's date. A
  Mac that took the version before the window, rolled back and took it again is not counted; a
  rollback alone drops nothing. `medianDaysAfterFleetPublication` is the median of the days from
  Fleet's date to each pair's first upgrade, to two decimals.
- **Null is not 0.** Timing is measured only when the detail has one Fleet title to compare:
  a [complete](#complete-or-partial) catalog and every identity `exact`. Otherwise both
  adoption fields are null, because nobody looked. Measured with nothing paired,
  `adoptionSamples` is 0 and the median null.
- **The interval ends at the sweep that recorded the upgrade**, not at the install, so each is
  long by up to the time between two sweeps of that Mac.

## What a check can find

The last check's outcome is one word, with a sentence when there is something to say. Both are
on the tab's status line and, for a failed check, in the container log.

| Outcome | Means | The titles held |
| --- | --- | --- |
| `ok` | The catalog had changed and was read. A sentence follows only if some titles were skipped: a manifest or an index entry this build could not read, or a title the index and the file listing disagree about. They are named (a name this build cannot read as *unrecognized Mac manifest path* or *unrecognized Mac index entry*), left as they were, and read again when Fleet next changes its catalog. | What Fleet publishes, except the titles the sentence names: each keeps the copy held before, or stays unlisted if it is new. |
| `unchanged` | GitHub answered and nothing had moved. While the titles held are [partial](#complete-or-partial), it says so: *The catalog tree is unchanged. The held snapshot still has unread Mac titles. They are checked again when Fleet changes its catalog.* | As they were. |
| `refused` | GitHub's rate limit answered (a 403 or 429 carrying its limit headers). | As they were. |
| `unreachable` | No answer, an answer GitHub does not give (a proxy's 403, a 502), or a name that resolved to an address this instance will not dial. | As they were. |
| `unexpected` | An answer that was not Fleet's catalog: a page that is not JSON, a redirect, a folder that is gone, a listing GitHub cut short, an index with no Mac app. | As they were. |

**A failed check never removes or blanks what is held.** Three rules make that true. A check
that fails before reading manifests writes nothing but its own outcome. A check cut short
part-way through the manifests keeps the ones it read and says how many. Once it has changed
the titles held, it also clears the tree sha and marks them partial, so the next check lists
the whole tree again and reads only the rest, even if Fleet has since gone back to the tree
that sha named: a half-applied read cannot pass for a complete one. A check cut short before
it changed any title leaves the sha and the coverage as they were. And a title is
removed only by a check that finished the whole listing and found it in neither the tree nor
the index, never by a listing that failed or was cut short.

Before the first check there is no outcome at all, and the tab says the catalog has not been
read yet. That is its own state, not an empty catalog.

### Complete or partial

Since 1.3.0 the instance also records whether the titles it holds are a whole copy of Fleet's
listing (#859). The record describes the titles held, not the last check, and has three values:

- **`unread`**: no check has finished a listing or changed a title yet. A new instance starts
  here, and one that had never read the catalog stays here through the 1.3.0 upgrade.
- **`partial`**: a check finished the listing and skipped a title (the `ok` row above), a check
  cut short had already changed the titles held, or the 1.3.0 upgrade found a catalog already
  read (below).
- **`complete`**: a check finished the listing and skipped nothing.

A check that fails before it changes a title leaves the value as it was. The tab never shows
the value itself, and of the API only the migration report carries it, as `fleetCatalogReadiness`
([below](#the-api)), which **Migration review** words. **Fleet titles** shows the check's sentence instead: an
`ok` check names the titles it skipped, and an `unchanged` check says unread Mac titles remain.

**Besides the check and its schedule, one thing reads it: a saved application patch plan**
([Installed application patch plans](application-patch-plans.md)). A plan looks up the Fleet
titles that carry each selected app's bundle identifier, and the value decides what it may
conclude from them:

- **Complete.** A plan marks a Fleet title as the app's match, and can propose Fleet's latest
  version as the target, only from a complete catalog with exactly one title for the bundle
  ID. It reads no Fleet title as no Fleet coverage only from a complete catalog, recording
  *No matching Fleet title in the completed cached catalog.*
- **Unread or partial.** A plan lists every Fleet title it finds for identity review,
  proposes no Fleet version as the target, and records
  *Fleet catalog is unread or incomplete; absence cannot establish lack of coverage.*
  under **Open review items at plan creation**, in the plan and in its PDF: the title that
  would match may be one this instance has not read. A saved plan keeps the item; a plan
  built once the catalog is complete does not carry it.

**Upgrading to 1.3.0.** During the 1.3.0 upgrade, an existing cache is marked partial until
the next eligible scheduled check reconciles it. 1.3.0 reads titles whose directory names
contain `@` or `+`, of the form `python@3.13+`, which earlier builds left out without saying
so: a catalog an earlier build read whole can lack those titles. The migration (`b13008440001`)
runs once: where a catalog had been read, it marks the titles partial and clears the tree
sha, so the next check cannot stop at its first request. It removes no title and no history.
`due()` then makes the scheduler's next hourly look check at once, rather than a day after the
last check; after a failed last check, the usual retry within the hour applies. **Check now**
does the same with a person waiting. Either check lists the tree, reads the index, and reads
only the manifests the instance lacks and those Fleet has changed since, never the whole
catalog again.

## The tab

**Fleet titles**, the tab's second view, under the device filter [Migration review](#migration-review) uses, lists per
title: the name, the bundle identifier, Fleet's latest version, *Macs with app*, *Macs in scope*, *Macs behind*, and
when the version last moved with the version before it.

- **The match is the exact bundle identifier.** A title is on a Mac when an installed app
  there carries the title's bundle identifier, letter for letter. Fleet's own check for a
  title is the same equality. Only Macs are counted: an iPad app sharing the identifier is not
  the Mac title.
- **Behind is any copy older than Fleet's latest.** The installed version is compared with
  Fleet's by the comparison the Jamf Patch matcher uses, on the numbers in the version
  string. A Mac with two copies of an app, one current and one stale, is behind. A Mac on a
  build newer than Fleet lists is not behind. *Macs behind* and the rest are both served, so
  the page never subtracts.
- **Macs in scope** counts the Macs the device filter selects (every current Jamf Mac without
  one) that carry the title's bundle identifier: `fleetDeviceCounts` in [the migration
  report](#the-api). *Macs with app* and *Macs behind* count every Mac the organization has
  collected, and *installed here*, in the footer and the version history line, means on any of
  them, whatever the filter. A title Fleet listed after the counts were read shows *Unknown*.
- **Only titles installed here** starts unticked. Ticked, it keeps the titles on a Mac the filter
  selects; the page reads the whole catalog once and filters what it holds. The search and the
  box are in the address as `q` and `installedOnly=1`. A title on no Mac shows a dash under
  *Macs behind*, not a zero.
- **Build a patch plan**, under a title on at least one Mac the filter selects, opens Installed
  Apps with the same `deviceScope`, searched by the title's bundle identifier.
- **The status line** says when GitHub was last asked and what it answered. After a failed
  check it shows the sentence and says the titles below are as read on the earlier date.
  While the titles held are [partial](#complete-or-partial), an unchanged check's line says
  unread Mac titles remain. Under it, how many of the titles installed here have their
  version history read, and the sentence when the last history read held back or failed.
- **When the version moved** is the version history's date when it has one: the day Fleet's
  catalog took the latest version, and the version it replaced. Without one, it is the move
  this instance saw, or that there is neither yet.
- **A title's name opens its page** ([below](#migration-review)), and the arrow before it its version history, newest first, each date linked to its commit
  in Fleet's repository.

The API is `GET /api/fleet-catalog` (`app:read`; `installedOnly`, `q`, `page`, `pageSize`), `GET /api/fleet-catalog/migration` for *Macs in scope* (`app:read` and `device:read`) and
`POST /api/fleet-catalog/refresh` (`patch:catalog-sync`). A refresh that could not read GitHub
answers `409` with the sentence as its `detail`, and stores the same sentence as the catalog's
state.

## Migration review

**Migration review** (#904) lists each app Jamf inventoried on the Macs the device filter selects:
the Macs that have it and their share of those in scope, its coverage in both catalogs, its
patch-policy verdict and its installed builds' vulnerability evidence ([`troubleshooting.md`](troubleshooting.md) §27 step 12).

- **The device filter is Installed Apps' and Patch Plans'**, carried between the tabs as
  `deviceScope`, so all three count the same Macs. Without one, it counts every current Jamf Mac.
- **Patch priority**, the default sort, weighs most a finding on CISA's Known Exploited
  Vulnerabilities list, then a build outside its confirmed Jamf Patch rule, then findings Fleet's
  latest would address. Less: how many Macs have the app (capped, so reach alone outranks none of
  those three), a high or critical finding, a build behind Fleet's latest, how long a newer Jamf
  release has waited, and a title Fleet updated twice or more in 90 days. Unknown evidence weighs
  nothing. Ties go to the app on more Macs, then the name.
- **Outside both catalogs** needs a *complete* Fleet snapshot ([above](#complete-or-partial)), not
  merely a populated one, and synced Jamf Patch titles. Until both, it reads *Unknown*, never 0: a
  partial snapshot may lack the very title.
- **Evidence can trail its reason by up to an hour.** After a sweep first judges a build, the other
  Macs' copies take the answer on the hourly refresh, so until then a row can count the build as not
  assessed (every selected Mac's copy needs the answer) beside a reason or an *addressed at target*
  line that reads the build's one catalog answer and already rests on it.

**An app's or a title's page** (#906): an app's name here, or a title's under Fleet titles, opens it with the list's query, so it counts the same Macs
and **Back to Fleet catalog** restores the list. It shows the installed builds and their Macs, the Fleet and Jamf Patch titles that match the bundle
identifier, and once one Fleet title is known its release history ([`troubleshooting.md`](troubleshooting.md) §27 step 13). Opening it asks GitHub
nothing; only **Read history** does, for `patch:catalog-sync`. The cadence above the history counts dated versions by week over the 13 UTC weeks ending
on the day the history was read, and gives the median gap between dated versions only for a whole history, one the read dated with no version left out.

### The API

`GET /api/fleet-catalog/migration` (#895) starts from what is installed: each app on the selected
Macs, with the Fleet titles that carry its bundle identifier. It needs `app:read` and `device:read`
and takes `deviceScope`, the filter Installed Apps and Patch Plans use, so all three count the same
Macs. It asks GitHub and Jamf nothing. With the flag off it answers
`enabled: false` and counts nothing.

- **`scope`.** *Eligible* is every current Jamf Mac the filter's connection and style allow;
  departed Macs and other platforms never count. *Selected* is the eligible Macs the conditions
  keep; the rest of the report counts only these. *Unknown contact* and *unknown inventory* are
  eligible Macs whose date is missing or in the future, which only *is unknown* selects.
- **`match`.** `exact` is one Fleet title in a complete snapshot; `none`, no title in a complete
  snapshot; `ambiguous`, several titles, an EA-assumed build or more than one Jamf Patch title;
  `unknown`, anything else. In `fleetDeviceCounts`, Fleet titles that share a bundle identifier
  share a count.
- **`installedEvidence`.** One entry per app in `items`, keyed by `appHash`, from the same
  snapshot: the vulnerability answer each of its builds on the selected Macs already stores, read
  by Installed Apps' rule, so an answer from an earlier corpus release, or one that does not
  parse, is unknown. A build is assessed only when every selected Mac's copy of it is.
  `assessment` is `off` (nothing answers for this organization), `unknown_app` (no build of the
  app is assessed), `partial` or `covered`, and `asOf` is the corpus date, null under `off`.
  `assessedBuilds` and `unknownBuilds` count distinct builds, one per version however many Macs
  carry it, where Installed Apps counts device/build pairs: a build on 500 Macs is 500 there and
  1 here. `affectedBuilds`, `highOrCriticalBuilds` and `kevBuilds` count the assessed builds with
  any finding, with a high or critical one, and with one on CISA's Known Exploited
  Vulnerabilities list, never findings added across builds. Under `off` and `unknown_app` they
  are null, not zero: nobody looked.
- **`appAssessments`.** One entry per `exact` app, keyed by `appHash`: its builds on the selected
  Macs against the version its one Fleet title lists now. It counts the builds behind that version,
  the findings updating them would close, open or leave, and the builds out of, within or exempt
  from the confirmed patch rule. `priority`, `priorityReason`, `management`, `comparison` and each
  verdict are codes. The list carries no per-build rows and no finding IDs. A build's verdict is
  `policy.judge`'s for its one Jamf Patch title, the same as on the title page
  ([troubleshooting §23](troubleshooting.md#23-out-of-policy-is-missing-a-title-is-not-judged-or-the-rule-draft-fills-nothing)).
  An installed build's findings are its stored answer as served, so one judged by another corpus
  release is unknown, never clean. Only a target version no selected Mac carries is asked of the
  corpus, from the same release.
- **One known difference from a patch plan.** When an app's one Jamf Patch title is in the synced
  Jamf Patch catalog but missing from some of its builds or Macs, this reads `exact`, while a
  patch plan withholds Fleet's version as its target and asks for identity review.

### Migration detail

`GET /api/fleet-catalog/migration/apps/<appHash>` (one installed app) and `…/titles/<slug>` (one
Fleet title and every installed identity with its bundle ID) take the report's `deviceScope` and
`targetVersion`, which defaults to Fleet's latest and may name any version the title's history
holds. Each lists the builds with distinct Macs, `installedMacs` and the matched Jamf Patch titles.
`impact` counts each Mac once as older, at or above, or unknown; when it is null,
`impactUnavailable` says why. Finding IDs need `vuln:read`; every caller gets the counts.
`observedChanges` is described under [Observed upgrades](#observed-upgrades).
Refusals: [`troubleshooting.md`](troubleshooting.md) §27 step 11.

## What it leaves out

- **No vulnerability or patch judgement of Fleet's titles.** The corpus is asked about a Fleet
  version only as the version an installed app's builds would move to (`appAssessments`), under
  that app's own name and bundle identifier. Fleet's titles are not a Jamf Patch title match, and
  do not count as a public source where the product asks whether one knows an app.
- **Dataset scope.** The migration report repeats the answer each installed build already
  carries and asks the corpus nothing new for it. It writes nothing, and it leaves the source
  catalogs, the Jamf matches and the organization's patch rules unchanged.
- **Nothing on the wire.** No event, no posture key, no alert when Fleet's version moves.
- **No vendor release dates.** The history's dates are when Fleet's catalog took a version.
- **No history in the background for a title no Mac here has.** A person's **Read history**
  reads one.
- **No Windows or iOS titles**, and no installers: LoonInspect deploys nothing.
- **No setting for another source.** The check reads Fleet's repository on GitHub and nothing
  else; the two hosts are fixed.
- **A skipped manifest waits for Fleet's next change.** While the tree sha does not move, the
  check stops at its first request, so a manifest it could not read is not retried until
  Fleet changes the folder again. Until then the titles stay partial, and each unchanged
  check says so.

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
