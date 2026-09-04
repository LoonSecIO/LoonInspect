# The v-never list

Status: **standing** · Target: every version · **Prose only — this document changes no code**

Roadmaps say "not yet". This list says "not ever". An entry here is a capability the
product will not grow, ruled out on purpose, with the reason attached — so that the next
person to want it finds the argument instead of an empty backlog and a shrug.

Entries are transcribed here, never authored here. The wording belongs to whatever made
the decision — a design document, a module docstring — and each entry names that source
so the argument can be read in full where it was made. Nothing belongs on this list
because it merely has not been built; that is a roadmap. A v-never entry is a thing that
*could* be built, that someone will ask for, and that is being refused with a reason.

The reverse also holds: anything citing this list as normative should be reachable from
an entry below. Today that is `docs/data-access-grain.md` §7,
`backend/app/core/ai.py`'s module docstring, and
`frontend/src/features/overview/needsAttention.ts`'s.

---

## Row-level data scoping

> **Row-level data scoping.** What a caller may see is decided by the kind of thing it
> is, never by which rows they are. Two callers with the same permissions, in the same
> tenant, on the same pod, passing the same parameters, get identical numbers — forever,
> on every surface. Site- and department-scoped operators, per-viewer row filters, and
> any permission that names rows instead of kinds are permanently out of scope. The
> demand they represent is served at a grain that already exists: a tenant per scope, a
> pod per scope where residency demands it, or a scope-limited MDM credential that
> narrows what the deployment holds before the data becomes a number. Filters remain,
> and remain the operator's own: chosen, visible in the URL, and carried beside any
> number they produced. Ruled 2026-08-30 (#111) — because a board is a named claim, an
> evidence stamp cannot mean two things, and a number whose meaning depends on who is
> looking cannot be un-published.

Ruled 2026-08-30 (#111). Full argument: [docs/data-access-grain.md](data-access-grain.md).

---

## The AI doctrine

Four entries, ruled together and restated in full at the top of
`backend/app/core/ai.py` — the gate every AI feature has to pass through. They are on
this list rather than in that docstring alone because they bind the product, not the
module: a feature that never calls the gate is still bound by them.

> **No model-sourced numbers anywhere.** Counts, versions, CVE data, dates — every
> number in the product comes from a real data path. A model may explain numbers; it may
> never be the source of one.

> **Fleet-identifying payloads run BYO-key or on-device only, never a hosted default.**
> Run logs, hostnames, serials — and typed search strings are ruled fleet data. If it can
> identify a fleet, it does not go to a vendor endpoint the product configured on its own.

> **Everything defaults off.** The flag, the consent, and any feature behind them.
> Enabling an AI feature must show field-level disclosure of exactly what leaves the pod
> and to where.

> **No silent egress.** If the gate did not log it, the call was not permitted to happen.
> Call `require_ai` before the request is made, not after.

Founder-ruled; transcribed from the module docstring that landed with the gate under
INSPECT-0112. Source and enforcement:
[backend/app/core/ai.py](../backend/app/core/ai.py).

---

## A second Needs Attention

> **Needs Attention has exactly one composition, and no other surface mirrors or
> recomposes it.** There is one function that decides what needs attention, and every
> surface that shows any part of the answer reads its output rather than asking the
> questions again. The sidebar's count badge is its only off-page rendering. A second
> implementation — a tile that counts failures, a header dot with its own thresholds —
> would be two products disagreeing about whether a customer's pod is healthy, on the
> same screen, and no amount of care keeps two copies of five predicates in step.

Ruled 2026-09-04 (#106). Transcribed from the module docstring that owns the
composition: [frontend/src/features/overview/needsAttention.ts](../frontend/src/features/overview/needsAttention.ts).

---

## A written all-clear

> **The dated all-clear line is template-only, forever.** "Nothing needs your attention
> · checked 14:32 UTC" is not a status message; it is the product attesting, with a
> timestamp, that it looked and found nothing. Every word of it is a template filled
> from the same checks that would have produced rows. No model ever writes it, softens
> it, or summarises it — a generated all-clear is a claim about a fleet whose evidence
> is a sampled distribution, and this is the one sentence in the product a customer may
> paste into an audit.

Ruled 2026-09-04 (#106). The narrower, load-bearing case of "no model-sourced numbers
anywhere" above: here the model is barred from the *sentence*, not only from the figures
in it. Transcribed from
[frontend/src/features/overview/needsAttention.ts](../frontend/src/features/overview/needsAttention.ts).

---

## What this list is not

* **Not a record of everything unbuilt.** SimpleMDM and Addigy support, MFA, a
  vulnerability scanner — none of those are here. They are absent, which is a different
  claim, and README.md's "What it does not do" is where absence is stated.
* **Not a place to park a hard problem.** An entry is a decision with an argument. If
  the argument is "this is difficult", it is a roadmap item wearing the wrong coat.
* **Not silently reversible.** Removing an entry is a ruling of the same weight as
  adding one, and wants the same paper trail. That is the entire value of writing them
  down: the cost of the reversal is visible before it is paid.
