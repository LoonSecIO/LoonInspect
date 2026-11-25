# Patch policy: the page, its three sources, and their terms

Status: **built**, 2026-11-24 (#614): the reference replays (first slice) and the day-walk page.
The step-throughs are [troubleshooting.md](troubleshooting.md) §22 (the replays), §32 (LoonSec's
data arriving) and §33 (the walk). The terms below were recorded before the source toggle shipped,
as ruling R10 asked; where a term's reach is not verified, this document says so rather than guess.

## What the page is

Posture › Patch policy is a **reference analysis**: one hypothetical Mac that runs one app, walked
day by day under each stop of a patch-policy slider (install each release 1, 7, 14, 30 or 60 days
after it is dated, or never), against public CVE records. It is not this organization's exposure.
It reads no inventory, and nothing it computes is stored, queued or sent anywhere.

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
  between a release and the data reaching an instance (ruled 2026-11-24).

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
