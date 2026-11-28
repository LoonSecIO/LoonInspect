# Patch policy: the page, its three sources, and their terms

Status: **built**, 2026-11-24 (#614): the reference replays (first slice) and the day-walk page;
the built-in policy definitions on the day-walk, 2026-11-28 (#954).
The step-throughs are [troubleshooting.md](troubleshooting.md) §22 (the replays), §32 (LoonSec's
data arriving) and §33 (the walk). The terms below were recorded before the source toggle shipped,
as ruling R10 asked; where a term's reach is not verified, this document says so rather than guess.

## What the page is

Posture › Patch policy is a **reference analysis**: one hypothetical Mac that runs one app, walked
day by day under each stop of a patch-policy slider (install each release 0, 1, 3, 7, 14, 30 or 60
days after it is dated, or never), and on the day-walk under each built-in policy definition beside
it ([Policy definitions](#policy-definitions)), against public CVE records. It is not this
organization's exposure. It reads no inventory, and nothing it computes is stored, queued or sent
anywhere.

**A stop's label is the days it waits** (ruled 2026-11-27, "0 = same day"): the 0-day stop installs
a release on the day its source dates it, the 1-day stop the day after, the 3-day stop three days
after. The slider opens on its first stop, 0 days, and an address that names a stop (`?policy=7d`)
keeps naming it, so a link saved before the ruling opens the same stop, now seven days waited.
The rule replaced the 2026-10-02 one, under which a stop of D days waited D − 1 days: 0 days is the
device the 1-day stop was then, and every other stop installs a day later than its label did.

The walk that counts this way is `patch_walk/2`, and LoonSec publishes its data, and the totals each
instance holds its own walk to, under that name; `patch_walk/1`, the six stops on the old count, is
never published (ruled 2026-11-27). An instance the exchange offers only another way of reading the
data says so, in a sentence that says whether updating helps, and draws the reference replays below
([troubleshooting.md](troubleshooting.md) §32 step 4).

It has two modes:

- **The day-walk**, once LoonSec's patch-policy data is held for this organization (it rides the
  data-sharing exchange, [data-sharing.md](data-sharing.md); §32). The instance walks the data
  (`backend/app/core/patch_policy_walk.py`) and the page draws the answer: a day graph of the CVEs
  open each day at the selected stop, the totals at every stop, each CVE with the clock that placed
  it, the exclusions, and Evidence (the data's id and date, the release timeline's name, digest and
  read date, how its versions joined the data's, every cut of the window, and how many CVEs count
  from the first day they were detectable against how many count from NVD publication).
- **The reference replays**, otherwise: files that ship inside the build, each naming its public
  release record and counting each CVE from NVD publication
  ([`frontend/src/features/patchPolicy/replays/README.md`](../frontend/src/features/patchPolicy/replays/README.md)).
  They stay as this fallback until LoonSec's data is live in production, so the page is never blank
  between a release and the data reaching an instance (ruled 2026-11-24). The page reads replays of
  schema 3, which count the days waited and state each day row's wait (`install_delay_days`). A
  schema-2 replay counts the old way, its N-day row being N − 1 days waited, so it is refused whole,
  in words, rather than drawn a day early or relabelled here: LoonSec writes the replays, and the
  page computes nothing in them ([troubleshooting.md](troubleshooting.md) §22 step 4).

## Policy definitions

Status: **built**, 2026-11-28 (#954), on the day-walk only, as ruled that day. A policy people hold
is often not one number of days: "patch when it is on the KEV list", "patch only for a critical".
Beside the slider, the day-walk can load a **built-in policy definition** and walk it in place of a
stop.

**A definition is data**, `{id, name, otherwise, when[]}`, in a small closed vocabulary:

- `otherwise` is what happens to a release no trigger names sooner: a day count, installing it that
  many days after it is dated as a day stop does, or `never`.
- `when[]` holds triggers over a closed set, `kev_listed`, `critical` and `critical_or_high`, each
  with `within_days`.
- `otherwise` and `within_days` take only the slider's own day counts (0, 1, 3, 7, 14, 30 and 60),
  so the longest wait is still 60 days and the window rule does not move.
- A slider stop is a definition with no `when`.

The build ships three:

| Id | Name | `otherwise` | `when` |
| --- | --- | --- | --- |
| `kev-only` | Patch on a KEV | `never` | `kev_listed` within 0 days |
| `critical-only` | Patch only on a critical | `never` | `critical` within 0 days |
| `30d-or-kev` | 30 days, same day on a KEV | 30 days | `kev_listed` within 0 days |

None is named for a framework, and nothing on the page says a policy is met, passed or complied
with: "Patch on a KEV" is a rule about a public list (the 2026-08-31 scope ruling). Only built-in
definitions load. The organization's confirmed Jamf Patch rule does not, nor does a file an operator
supplies: nothing is uploaded or stored.

**Where they live.** In the build, beside the stops (`POLICY_DEFINITIONS` in
`backend/app/core/patch_policy_walk.py`). The module's one tuple `POLICIES` names every policy
LoonSec's published check covers, the stops then the definitions in order. LoonSec publishes a
`check` entry for each definition from its pinned copy of the walk (`check_totals`), and the
instance holds a definition's numbers to it exactly as it holds a stop's. For a definition the walk
cannot run on that data, the entry is its refusal, `{"refused": "<reason>"}`, which both sides
compute alike. A check that lacks a definition's entry is refused as parity, as one that lacks a
stop's entry is, so no definition is drawn unchecked ([troubleshooting.md](troubleshooting.md) §33
step 7). The stops and the definitions are one algorithm, `patch_walk/2`.

**The trigger day.** A policy decision reads only what was knowable that day.

- A trigger names the release that fixes a CVE of its kind. That is the fix LoonSec's data compiled,
  dated by the walk's own fix dating: the version `fix_dated_by` names, on a line the device can
  install. The instance compares no version strings.
- That release's trigger day is the later of two days: the day it is available, and the day the
  fact was knowable. The release is due `within_days` after its trigger day.
- A release's install day is the earliest of its `otherwise` day and the due day of every trigger
  naming it. The installed version only rises, and two releases due on one day install only the
  higher, as under a stop.
- The triggers read every CVE row the walk places that it does not exclude, whether its clock day
  falls before, in or after the window.
- Each install a definition makes names what installed it (`installs[].by`): the trigger, its CVE,
  and the day its fact was knowable with that day's basis, or `otherwise`.

**The fixing release, not the newest.** When a CVE is listed on KEV after newer releases are out, the
definition installs the release that fixes it, not the newest one. The newer ones install on their
own install days, as every stop gives each release its own install day. A fixing release ranked
below the version already running installs nothing.

**Severity's day** (ruled 2026-11-28). For `kev_listed` the fact's day is the CVE's
`kev_date_added`. A severity trigger fires on the day LoonSec's data says the CVE first scored that
severity, where the data states one. The walk reads two optional keys on a CVE row when they are
present:

- `first_scored.critical`: the first UTC day LoonSec's record of NVD changes held a critical score
  for the CVE.
- `first_scored.critical_or_high`: the first UTC day it held a high or a critical score.

Where a row states none, the CVE's clock day stands in: the day that placed it, first detectable,
else NVD publication. Today's severity stands in for the score: `critical` names a CVE that is
critical today, `critical_or_high` one that is high or critical today. A CVE whose severity is null
was not scored, and no severity trigger names it from today's severity.

Each CVE row says which day counted and its basis (`knowable`: `first_scored`, `clock_day`, or
`kev_date_added`), as it says which clock placed it, and `counts.knowable` counts them. The page
says so in the definition's sentence under the slider and beside each CVE's severity. LoonSec's data
states no first-scored day yet. Once it does, the walk reads it with no change of algorithm, because
that is a change in the data.

**The opening.** A definition opens the window on the release its `otherwise` opens it on as a plain
stop, raised by any trigger already due by the window's first day:

- with `otherwise` `never`, the newest release available by the window's first day, the one the never
  stop keeps. A trigger due by then cannot rank above it.
- with a day count, the newest release whose install day (the earliest of its `otherwise` day and its
  due days) is on or before that day.

`opening_by` says what installed it, and the page says so when a trigger did.

**On the page.** A control beside the slider lists the definitions the walk offers. A loaded
definition is selected like a stop, and the address carries it the same way (`?policy=kev-only`):

- its totals sit beside the stops' totals;
- the day graph and each CVE's outcome follow it;
- its rule is the one sentence under the slider, in the reader's language;
- each update it installs says what installed it;
- its definition is printed under Definitions in the walk's own words.

The reference replays that stand in until LoonSec's data is held offer no definition. An address
naming one there opens the first stop under a sentence that says why
([troubleshooting.md](troubleshooting.md) §22 step 11).

**Refusals.** A definition the walk cannot run on the data it holds is not walked, and every stop
still is. The walk answers each one in `policy_refusals` with its reason and its sentence, and the
page draws it disabled beside the slider with that sentence:

- `kev_unknown`: the data cannot say whether a CVE is on CISA's KEV list. Under a named KEV source
  (`sources.kev`), a null `kev_date_added` means "not listed" and refuses nothing. The refusal is for
  a document that names no KEV source, where a null says nothing, and for a row without the key or
  with a value that is not a date.
- `severity_unknown`: a severity the walk does not read, or a `first_scored` that is not an object
  of days.
- `definition_invalid`: a definition names a trigger outside the closed set, or a day count the
  slider does not have. That is a defect in LoonInspect.

The step-throughs are [troubleshooting.md](troubleshooting.md) §33 steps 7, 8, 10 and 13. An
address naming a policy the page does not have, or a definition the walk does not offer, opens the
first stop under a sentence that says so. `GET /api/patch-policy/walk?stop=` takes a definition's id
as it takes a stop's, and answers an id it does not know with a 422 that names every id it accepts.

**The reference replays' row.** The replay files carry a `critical_or_kev` row, computed in the file
and never drawn. The ruled definitions superseded it on 2026-11-28, and LoonSec replaces it with rows
on them when it writes the files again. The page reads a file with that row, without it, or with
rows keyed by a definition's id, and draws and quotes none of them in this release.

## The three sources of release dates

A walk installs each release on the day a **source** dates it. The page's toggle picks one; Public
is the default.

| Toggle | What is read | Where | What leaves the instance |
| --- | --- | --- | --- |
| **Public** | The release dates LoonSec's data carries for the track, each table naming the public release record it was read from (`sources.timelines` in the data) | Inside the data this instance already holds | Nothing |
| **Jamf** | This instance's copy of Jamf's public patch catalog: each patch's version and release date, for every title whose bundle ID is the app's | The catalog the instance syncs hourly from Jamf's public server, with no Jamf Pro connection ([jamf-patch-matching.md](jamf-patch-matching.md); troubleshooting.md §6) | Nothing |
| **Fleet** | This instance's copy of Fleet's version history: the day Fleet's catalog first carried each version | The history the instance reads while this organization's **Fleet catalog (maintained apps)** flag is on ([fleet-catalog.md](fleet-catalog.md)) | Nothing |

The Jamf and Fleet positions are computed on the instance from what the instance itself holds, for
the apps LoonSec's data references, and every view of them says so. A Jamf or Fleet timeline is
joined to the track by the spelling of each version, never by comparing numbers: a version the track
lists is walked; one another track of the app lists is set aside as that track's; one a channel
lists that LoonSec's data names beside the app's tracks and does not walk yet (`other_channels`:
Firefox ESR, whose Jamf title and Fleet title share Firefox's bundle ID) is set aside and counted
per channel; and anything else is unmatched, never installed, and above 5% of the versions in reach
refuses the view ([troubleshooting.md](troubleshooting.md) §33 step 4). A version spelled with
Mozilla's `esr` suffix is tried as given, then without it, and a track still takes it first. Fleet's
dates are Fleet's, not the vendor's: Fleet builds its catalog from Homebrew and commits it some hours
later, and every Fleet view prints that sentence.

A source often does not date the exact build LoonSec's data names as a CVE's fix. Such a CVE is not
left out: its fix is counted from the next version the source dates at or above it, on its line and
outside the CVE's affected range (ruled 2026-11-25), and each row of the page says which version
dated each fix and when ([troubleshooting.md](troubleshooting.md) §33 step 12).

## Release-date sources and their terms (R10)

Recorded 2026-11-24 by reading each public source's own pages (Google's API terms and the
VersionHistory guide, the product-details directory, GitLab's terms page); the Chrome Releases
blog's terms were not read. "Unverified" means nobody has yet confirmed
whether the terms named reach this use; the ruling is the maintainer's to make, and nothing here
should be read as that ruling.

| Source | Read by, and for what | Terms as found | Verified |
| --- | --- | --- | --- |
| Google's Chrome VersionHistory API (`versionhistory.googleapis.com`, platform mac, channel stable) | LoonSec, when it builds its data: one release date per Chrome version, published in the data for the Public position | The API's own guide states no terms, licence, key or rate limit. Google's APIs Terms of Service (developers.google.com/terms, last modified 2021-11-09) govern Google's APIs generally; section 5(e) restricts copying, redistributing or building permanent copies of content an API returns unless the content owner or the law permits it, and the terms do not say whether they reach an API that needs no key | **Unverified**: whether those terms reach a version number's release date read without a key, and so whether republishing the dates needs more than the record of where they came from |
| Google's Chrome Releases blog (`chromereleases.googleblog.com`) | LoonSec, when it builds its data: the day each Chrome major version was promoted to stable on desktop, one row per major in the data's promotion table, each row naming the post it was read from (its `source`); and, for three Chrome releases, which Mac build carries the fixes that release's post names ([troubleshooting.md](troubleshooting.md) §33 step 12). Every walk of Chrome, whichever source dates its releases, and the Chrome reference replay install a major version no earlier than its promotion day | Not read for this record. The blog is a Blogger site on Google's `googleblog.com`, so Google's Terms of Service are the likely terms; no page stating terms for the blog's posts was found or read | **Unverified**: which terms govern the posts, and whether republishing the promotion days and Mac builds read from them needs more than the record of the post each came from |
| Mozilla's product-details (`product-details.mozilla.org/1.0/firefox.json`, `thunderbird.json`) | LoonSec, when it builds its data: the date of each release-channel row | The directory serving the files states no licence and no terms of use | **Unverified**: which of Mozilla's terms, if any, govern these files |
| Wireshark's release tags on GitLab (`gitlab.com/wireshark/wireshark`, read through GitLab's REST API) | LoonSec, when it builds its data: the date of the commit each `vX.Y.Z` tag points to | The repository is Wireshark's, under GPL-2.0. GitLab's terms page maps use of GitLab's public APIs to its API Terms of Use, and use of its services to its Acceptable Use Policy | **Unverified**: whether GitLab's API Terms of Use restrict republishing tag dates read from a public project |
| Jamf's public patch catalog (`jamf-patch.jamfcloud.com/v1`, `JAMF_PATCH_BASE_URL`) | Each LoonInspect instance, hourly, for Devices › Applications › Jamf Patch and for the Jamf position of this page; nothing of it leaves the instance | No terms specific to this endpoint were found or read for this record, and whether Jamf's API License Agreement covers it is not known; both were already open questions when this page was planned | **Unverified** |
| Fleet's maintained-apps catalog and its history (`fleetdm/fleet` on GitHub) | Each LoonInspect instance, only while this organization's flag is on, for the Fleet catalog tab and the Fleet position of this page | [fleet-catalog.md, "The licence"](fleet-catalog.md#the-licence): the catalog sits under Fleet's Enterprise Edition licence | As that section says: a question for whoever answers licence questions for the deployment |

Homebrew's cask history is planned as a later public source and is not read yet; its terms are
recorded here when it is.
