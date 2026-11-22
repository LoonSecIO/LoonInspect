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
LoonInspect reads that folder daily and makes the public titles available under
**Devices › Applications › Fleet catalog**. Patch planning opens on the organization's
Jamf-inventoried apps. Fleet titles opens on the full public catalog. Select an app or a
title to inspect its version distribution, release history, update options and evidence.

Every public title links to its current manifest. A dated version links to the manifest at
the corresponding commit. The date records when Fleet published that catalog version.
Historical reads continue in the background for installed titles.

Fleet builds its Mac manifests from Homebrew metadata (the folder's own README says so), so
*Fleet's latest* is the version Fleet last recorded for the title, not a vendor's
announcement.

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

**Each instance reads for itself.** The instance fetches the public manifests and their history directly from GitHub under its operator’s answer to the licence question. A history gathered once by LoonSec and served to instances
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
   its git sha. When it matches the last reconciled listing, the check stops after this request.
   An unchanged listing keeps its previous complete or partial coverage.
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
| `ok` | The catalog had changed and was read. A sentence follows only if some manifests could not be read as a title with a version; they are named, left as they were, and read again when Fleet next changes its catalog. | Readable current titles, with earlier copies retained for skipped entries. |
| `unchanged` | GitHub answered and nothing had moved. | As they were. |
| `refused` | GitHub's rate limit answered (a 403 or 429 carrying its limit headers). | As they were. |
| `unreachable` | No answer, an answer GitHub does not give (a proxy's 403, a 502), or a name that resolved to an address this instance will not dial. | As they were. |
| `unexpected` | An answer that was not Fleet's catalog: a page that is not JSON, a redirect, a folder that is gone, a listing GitHub cut short, an index with no Mac app. | As they were. |

**A failed check never removes or blanks what is held.** Three rules make that true. A check
that fails before reading manifests writes nothing but its own outcome. A check cut short
part-way through the manifests keeps the ones it read and reports how many. If the held
rows changed, the cache becomes partial. The next check reconciles the full listing, even
if Fleet reverted to its earlier tree. A title is removed when both the completed tree
listing and the index omit it.

Patch planning can rule out a Fleet match or confirm a single channel only with a complete
snapshot. Partial snapshots still show known candidates and local installed builds. During
the 1.3.0 upgrade, an existing cache is marked partial until the next eligible scheduled
check reconciles it. A previous failure keeps its usual retry interval.

Before the first check there is no outcome at all, and the tab says the catalog has not been
read yet. That is its own state, not an empty catalog.

## Planning a Jamf-to-Fleet migration

The application tab opens on seven days of last contact. Use **Inventory scope** to choose a Jamf connection, time window and clock. Last contact
means the Mac checked in. Last inventory dates the software observation. **All dates**
includes computers with missing timestamps. A dated window lists missing and future-dated observations separately from
Macs known to be outside it. Counts use distinct Macs and omit finalized departures.
Prevalence is the share of in-scope Macs with an installation.

- Select **Outside policy** to find apps with a build past the organization's confirmed
  Jamf patch deadline or release limit. The report uses the applicable title override,
  exemption or default. An app may meet its deadline while Fleet already has a newer
  release. **Unassessed** means the rule or supporting identity, clock or release evidence
  is missing. See the app for build-level reasons.
- Sort by **Most installed** to see reach or **Oldest open patch gap** to find longstanding
  gaps. **Patch priority** combines observed prevalence, the age of a confirmed gap,
  policy, release cadence, and vulnerability evidence. A known-exploited finding carries
  more weight than prevalence alone. Select an app to see the reasons and the underlying
  counts. Installation counts measure reach. Application runtime requires usage telemetry.
- Select **Fleet titles** to search the full public catalog, including apps absent from
  the selected Macs. Titles show the number of in-scope devices whose bundle identifiers
  match. Multiple release channels can use the same identifier. Their counts may overlap.
- Open an installed app to find the count on an exact version. Recorded version changes
  and dated Fleet versions describe local update behavior and upstream release cadence.
  The dated sample on the detail page shows how long after Fleet publication matching
  upgrades were first observed. Inventory collection intervals affect that measurement.
- Select the current or an earlier cached Fleet target to see how many Macs have an older
  copy. Dotted numeric releases can be ordered. Different prerelease or vendor-qualified strings stay unknown when their order cannot be established. One Mac with multiple copies counts once in the projection. Distinct sampled
  versions, installs and Macs have different denominators. The report shows exact
  addressed, introduced and remaining findings only where both build records have
  complete evidence in the organization's selected corpus. A capped ID list supports
  only the difference in total. Authorized vulnerability readers can open individual IDs.
- **Outside both catalogs** requires a checked Jamf Patch identity and a populated Fleet
  catalog. A missing bundle ID, unread catalog, or unchecked Jamf match stays unresolved.
  Open the app to review custom packages, Installomator and Munki.
- The pilot guide describes patching existing installs, offering a title in Self-service
  and installing on Macs missing it. Review target fleet, labels, settings and a pilot
  result in Fleet before broadening deployment. Public catalog availability alone gives
  no evidence that a policy is deployed. Chrome, Falcon and Zwift include identity-specific
  notes on update settings, sensor health or launcher scope.
- When AI is enabled with consent and a saved provider, **Generate briefing** sends
  aggregate counters after an explicit request. The selected provider can rank up to
  three evidence-backed highlights. The app renders the text locally and identifies the model.
  Local report highlights remain available if the inference call fails.

**Check now** refreshes the instance's public catalog. **Version history** displays the
locally held dates and offers a separately permissioned refresh. The status reports the
last GitHub response and the date of retained data after a failed refresh.

## What it leaves out

- **Dataset scope.** The migration report reads existing corpus and Jamf match evidence. Changing a Fleet target recalculates the local projection. It leaves the source catalogs and the organization’s patch rules intact.
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
