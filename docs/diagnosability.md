# Diagnosability: the design language

Status: **ruled**, 2026-09-10 ([#291](https://github.com/LoonSecIO/LoonInspect/issues/291)) ·
Applies to every new failure path from that date; existing sites move when they are next
touched, or under their own issue · The operator-facing artifact this keeps true is
[`troubleshooting.md`](troubleshooting.md) ([#290](https://github.com/LoonSecIO/LoonInspect/issues/290))

Read this before writing a feature. It is short on purpose.

## 1. The one idea, and where the product already enforces it

This product already has a rule for what it tells a *customer*: **a state must say which
state it is, and never let a reader infer the wrong one from a shape that looks like
data.** It is written down four times, for four surfaces, and every one of them governs
the wire or the tape — none governed what the product tells the *person debugging it*.

| Rule | Where it is ruled | What it says |
| --- | --- | --- |
| `assessment: off` | [`vulnerabilities.md`](vulnerabilities.md) §4a, the whole `vuln` vocabulary | *"Nobody looked"* is a first-class value; the counts are absent, never zero, so a careless `stats sum(vuln.counts.total)` cannot hand a fleet nobody assessed a clean bill. |
| No zero-priming | [`posture-snapshot.md`](posture-snapshot.md), `posture.RESERVED_KEYS` and `posture.VULN_KEYS` | No key records before the thing it measures exists; a run of primed zeros is a lie about when measurement began. *"Absent means 'did not apply', never zero."* Since #250 the four `vuln.*` keys carry it per tenant: no rows at all until something has been assessed. |
| Failure ≠ emptiness | #150, quoted in `frontend/src/features/overview/OverviewPage.tsx` | A pod whose endpoints are down has not "not started" setup; a strip that quietly vanished would read as "nothing to report". |
| Absence is the ruling | [`vulnerabilities.md`](vulnerabilities.md) §4a, additive-only clause 4 | An absent key is a statement, and `assessment` is always present to say which statement. |

The evidence that the gap was live, from 2026-09-04: a scheduled run reported
`deviceCount: 0`, `status: succeeded`. Correct — it was a `catalog` collection, which
reads smart-group definitions and never devices. But `0` and `succeeded` is exactly the
shape a broken device sweep has, and telling them apart took opening the collections API
and knowing that `lockClass: catalog` means "not a device sweep". **A zero that meant "not
applicable" wore the costume of a zero that means "nothing found"** — the no-zero-priming
rule, violated in the diagnostics by the codebase that enforces it on the wire.

## 2. The five rules

**1. A terminal state names its reason.** `succeeded` with a zero count says which kind
of zero it is. `0 devices (catalog collection — reads group definitions, not devices)`
costs one string and removes a class of support ticket. The same for an empty list: *no
connection yet*, *no sync has finished*, *the last sync reported none*, and *no match for
this search* are four states, and a table that shows one blank for all four has hidden
three of them (the Applications table says all four since #299).

**2. A log line that reports a surprising state names the next check.** Not a stack
trace and not a lecture: the one thing to look at next. `extension attribute definitions
not readable; census skipped` is halfway there — it says what happened. The whole line
adds where to look: `…; the API Role lacks "Read Computer Extension Attributes"`. The run
log (`GET /api/runs/{jobId}/log`, the panel under a connection's row) is the surface an
operator has; a Python `logger.warning` at the same site is for us, not for them, and
does not count.

**3. An error message says what failed, why, and what to check — in that order, in the
operator's vocabulary.** `Failed to decrypt stored value — ENCRYPTION_KEY may have
changed` has the first two and lacks the third (*compare the key in the environment with
the one this database was written under; see KNOWN_ISSUES §5*). `lockClass: catalog` is
the code's vocabulary; *this collection reads smart-group definitions, not devices* is the
operator's. §3 below is the translation table.

**4. Every new failure path gets its step-through at the same time as the code.** When a
PR adds a way for something to be wrong, [`troubleshooting.md`](troubleshooting.md) gains
the path in the same PR, and the PR's `## Validation` names the path it exercised. This is
the clause that keeps that document from decaying: a feature that ships without its path
is what turns a document into an archaeology exercise a year later.

**5. A diagnostic that requires reading source is a defect in the product.** The
lowest-quartile admin does not have the repository open, and neither does a support
engineer on a call. When a path cannot be written with what a fresh operator has — the
app, its API, `docker compose logs`, and the run log — file the missing surface as an issue
rather than writing the source-reading step down. A troubleshooting document is not a
place to keep workarounds for the product's silences.

## 3. The operator's vocabulary

What a message may say, and the code word it must not say instead.

| Say | Not | Because |
| --- | --- | --- |
| a device sweep · a catalog refresh · a webhook run · a re-emit | `lockClass: device_sweep` / `catalog` / `webhook` / `re_emit` | The class is the mutex's name; the kind of run is what the operator started. |
| the sections the sweep read | the aperture | The aperture is the contract's word for the same thing ([`jamf-observations.md`](jamf-observations.md)); an operator picked sections on a collection. |
| the last observation of this Mac | the current span | Spans are the ledger's rows. |
| first sweep · changes since the last · every device's current snapshot | `comparison: baseline` / `delta` / `re-emit` | The wire value is fine on the wire and cryptic in a sentence. |
| the API Role's privileges | 403 from `/api/v1/…` | The role is the thing the operator can change ([README §3](../README.md)). |
| this instance's key for stored credentials (`ENCRYPTION_KEY`) | Fernet, InvalidToken | The variable name is what they set; the library's exception is ours. |
| the run's window · when it started | `window_start`, `_time` | |
| gave up after ten attempts (a dead letter) · queued · delivered | `status: failed` / `pending` / `delivered` | The Destinations page already uses the words. |

The rule for a word not in the table: **if the operator did not type it, click it, or read
it on a page, it is not their vocabulary.** Names of settings, buttons, pages, and the
Jamf Pro strings they configured are theirs; module paths, column names and enum members
are ours.

## 4. Where a diagnostic lives

An operator has exactly these surfaces, and a new failure path lands its words in one of
them — never only in a Python log line at DEBUG:

- **The run log** — `GET /api/runs/{jobId}/log`, shown under the connection's row after
  Sync now, Run now and Re-emit inventory. Milestones and surprising states, never
  per-device noise ([`runs.md`](runs.md) §5).
- **The run row** — `GET /api/runs/{jobId}`: `status`, `error`, the counts. A count that
  is zero for a structural reason names the reason on the row or in the log's last line.
- **The container log** — `docker compose logs app`: what happened before there was a
  run to write to, and the one place a wrong `ENCRYPTION_KEY` is announced today
  ([`KNOWN_ISSUES.md`](../KNOWN_ISSUES.md) §5).
- **The Destinations page** — per destination: queued, gave up, last error, and the test
  button's verdict.
- **The Overview's status strip** and the setup stepper — the first line an operator
  reads, and why #150 governs it.
- **The audit log** — who did what; the answer to *"did someone change this?"*.

## 5. Three lines, before and after

| Before | After |
| --- | --- |
| `sweep complete` · row: `deviceCount: 0, status: succeeded` (a catalog collection) | `catalog refresh complete: 3 group definitions observed, 0 devices — this collection reads smart-group definitions, not devices` |
| `jamf sweep failed` · error: `403 Forbidden` | `jamf sweep failed: Jamf refused the inventory read (403). Test connection checks only sign-in; check the API Role holds "Read Computers" (README §3)` |
| `Failed to decrypt stored value — ENCRYPTION_KEY may have changed` | `…may have changed: the key in the environment is not the one this database's credentials were written under. Restore the original key, or re-enter every connection's and destination's secret (KNOWN_ISSUES §5)` |

None of the three needs a new endpoint or a new table. Each is a string at a site that
already exists, and each removes a support call.

## 6. How a PR shows it

The pull request template's `## Validation` names the failure path the change exercised
and where its words landed (run log, row, container log, page). `## Risk` names any state
the change can leave an operator in without a path. A PR that adds a failure path and
touches neither is the decay this document exists to prevent, and a reviewer may say so.

Agent sessions: this repository is substantially agent-authored, and an agent has no
memory of the support call a missing diagnostic caused. This document is the memory.
[`CLAUDE.md`](../CLAUDE.md) points here for that reason.
