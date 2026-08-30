# The data-access grain

Status: **ruled (#111, 2026-08-30)** · Target: V0 · **Prose only — this pass changes no code**

The ruling in one sentence:

> A **filter** is something the operator applies and can see. A **scope** is something
> applied to the operator that they cannot see. LoonInspect has filters, and never
> scopes.

---

## 1. Why this was a v0 blocker

Personal dashboards will, by design, show different data under the same graph — a board
composes only reads its owner holds, so a board one operator can source may be a board
another cannot see at all. That is whole-board gating working correctly. The founder's
question was whether the *next* step follows from it: if the product ever grows a
row-level filter — site- or department-scoped operators — the same board, with the same
name, shows two different totals to two different people.

That collides head-on with four standing rulings, each of which is a promise that the
same request returns the same number to everyone entitled to make it:

* **Whole-board gating** — "a board is a named claim." It renders identically for
  everyone who can see it, or not at all. Row-level scoping breaks this *silently*:
  same board, same name, different totals, no signal that anything differed.
* **The evidence stamp** — two PDFs carrying one `Definitions vN` + run ID + UTC stamp
  must not differ in content by audience. A scoped read makes the stamp a lie told
  truthfully by both copies.
* **The landing** — "nothing above the fold varies per user"; below-fold tiles are
  release content.
* **`posture_snapshot`** — every key records a fleet-level truth. Under scoped reads,
  "whose fleet?" has no answer.

The blocker was not that scoping is hard. It is that scoping is the one change that
cannot be walked back after launch: it makes previously-published numbers retroactively
ambiguous, and no migration recovers what a number meant to whom.

---

## 2. The ruling

**Row-level, identity-bound data scoping never exists in this product.** The entry goes
to the v-never list (§7 below carries the drop-in text). V0 proceeds on whole-fleet
reads everywhere, exactly as it does today.

### 2.1 Access is decided by kind, never by row

What a caller may see is decided by the *kind* of thing it is —
`app/core/permissions.py`'s closed `Permission` enum, checked per endpoint — and never
by *which rows* they are. Two callers holding the same permissions, on the same pod, in
the same tenant, passing the same parameters, get byte-identical answers. Forever, on
every surface, with no exceptions and no exempt list.

This is already true, and the ruling's practical content is that it stays true rather
than that it becomes true. Worth naming what enforces it today:

* `Permission` is a closed vocabulary of kinds (`device:read`, `destination:read`,
  `audit:read`, …) — `backend/app/core/permissions.py:14`. No permission names a row,
  and none ever will.
* The only row-scoping mechanism in the system is the tenant, enforced in Postgres RLS
  through a per-transaction session GUC — `backend/app/core/tenancy.py:13`. It is
  deliberately not a request-level filter: an unset GUC fails every query outright
  rather than matching everything.
* The posture recorder reads the database directly and never its own HTTP API
  (`backend/app/core/posture.py`, ruled in #102 for a different reason). A
  request-level filter, had one ever existed, could not have reached the tape. The tape
  is structurally immune, not carefully guarded.

### 2.2 What the product has instead: filters

`site`, `building` and `department` already exist — as device columns and as
caller-supplied query parameters on `/api/devices`
(`backend/app/api/devices.py:78`). They stay. They are legal precisely because they are
the operator's own choice, visible in the URL, reproducible by anyone who follows the
link, and identical for everyone who does.

Nothing about this ruling narrows filtering. It fixes who holds the filter: the person
reading the number, never the system deciding what they deserve to see.

### 2.3 The demand path, for the customer this was really about

The demand behind row-level scoping is real. Multi-campus universities, MSPs and
regional IT exist, and Jamf Pro has Sites because those customers asked for them. That
demand has two sanctioned answers, both at grains already built, and neither of which
produces two numbers under one name:

1. **A tenant per scope** — and a pod per scope where residency or contract demands it.
   A tenant *is* a fleet: `posture_snapshot` already stamps `tenant_id` on every row, so
   "whose fleet" has an answer requiring no new mechanism. Each operator sees a whole
   fleet; it is simply not the same fleet as their colleague's.
2. **Scoping at ingest** — the cheap version. A site-scoped Jamf API account means the
   pod only ever *holds* that subset. The data is narrowed before it becomes a number,
   so every viewer still sees identical totals over identical rows, and the evidence
   stamp still means what it says.

Both preserve the invariant: scoping happens **above** the read, at the boundary of what
a deployment holds — never **inside** it, at the boundary of who is asking.

### 2.4 The accepted cost, stated plainly

A device belongs to exactly one tenant. Therefore overlapping visibility — the campus
lead who sees their campus, the CISO who sees everything — costs an account per tenant,
the tenant switcher (#36), per-tenant identity resolution (#35), and **no combined
number across tenants**. There is no view in this product that sums two fleets.

If cross-tenant rollups are ever wanted, they arrive as their own designed, audited
feature with their own stamp semantics — never as an increment of this ruling, and never
as a filter. That is a deliberate speed bump: the feature that would quietly reintroduce
"one graph, two numbers" is the one that must be argued from scratch.

---

## 3. What the ruling closes

Each collision named in §1, and how it survives:

| Ruling | Survives because |
| --- | --- |
| Whole-board gating | Gating stays whole-board and permission-shaped. A board is refused entirely or served entirely; it is never served *narrowed*. |
| The evidence stamp | Two copies under one stamp are two copies of one query. Audience is not an input to any number. |
| The landing | Nothing above the fold varies per user, and the one thing that does vary carries its parameter (§4). |
| `posture_snapshot` | "Whose fleet" is answered by `tenant_id`, which is on every row already. Fleet-level scalars stay fleet-level truths. |

---

## 4. The clause that has v0 teeth

The ruling above costs v0 nothing. This one is an obligation, and it holds regardless:

> **A number born of a filter carries its filter where the number is read** — in the
> URL, in the pinned tile's spec, and in the stamp chrome of any board that prints it.

A filtered number that arrives without its filter is indistinguishable from a fleet
number, which is the exact failure row-level scoping would have caused, reached by a
different road. Chosen filters are safe *because* they are visible; strip the label and
the safety goes with it.

There is precedent, and it is why this clause is a restatement rather than a new rule.
The changes feed (#107) anchors to a per-browser last-visit timestamp — the one number
in the product that genuinely varies per viewer — and the way it was made safe was to
print the absolute timestamp in the header and bake it as an absolute `since=` into
every click-through URL. Same move, generalised: state the parameter beside the number,
and a personal number can never impersonate a shared one.

Mechanically, for the surfaces that will consume it:

* Pin-what-you-see already serializes the page's canonical query params into the tile
  spec. The render must show them, not merely store them.
* Print/stamp chrome renders the tile's params inside the printed frame, on the same
  uncroppable line as `Definitions vN` · run ID · UTC.
* A tile whose params are empty says so by saying nothing — an unfiltered number needs
  no label, and that asymmetry is the signal.

---

## 5. User boards: personal, not secret — confirmed, with two riders

The design record's 2-2 split is **confirmed**. A user-scope board is enumerable under
`audit:read`, carries owner and last-edited metadata only, and has **no edit ledger** —
a scratchpad does not get a revision history. Two riders close what the original wording
left open, and both belong in the `/dashboards` v1 API contract before it prints:

**Rider 1 — audit access reveals the specification, never the data.** Enumeration
returns what a board *is*: owner, title, last-edited, and its tile specs. It never
returns tile *values*. Rendering continues to obey the reader's own grants under
whole-board gating. Without this rider, an enumeration endpoint gated on `audit:read`
becomes a permission bypass wearing an auditor's badge — an auditor reading destination
health or device counts their own role refuses them, because someone else pinned it.

**Rider 2 — a cross-owner read is itself audited.** Reading a board you do not own
writes one audit event (proposed action name `dashboard.board.read`, fired only when
actor ≠ owner; the existing dotted namespacing lets a SIEM alert on `dashboard.*`).
"No edit ledger on a scratchpad" and "nobody browses a colleague's boards unobserved"
are a coherent pair. It costs one `audit()` call on a path that does not exist yet.

Two facts that make the confirmation less risky than the dissent priced it:

* **Free text is never tileable.** A user board is a set of registry-legal saved views,
  not a search history. The typed-search-strings precedent the split was decided on is
  strictly *more* revealing than the thing being decided.
* **`audit:read` today gates exactly one endpoint** — the share-log download
  (`backend/app/api/system.py:137`) — and there is no audit read API at all; the JSONL
  file is the interface (`docs/auth-design.md` §6.6). So "enumerable under `audit:read`"
  is not a use of the audit log. It describes a **new API surface** the v1 contract
  invents, and the contract must say so in those words rather than implying an
  existing capability.

One disclosure obligation follows, at the only moment it matters: the naming field for
a user board states that titles and tile specs are visible to auditors. Disclosure at
authoring, in the same idiom as the AI gate's field-level disclosure — the surprise, not
the visibility, is what would make "personal, not secret" indefensible.

---

## 6. What v0 must and must not do

**Must not** — the shortcuts that would foreclose this ruling, named so that adding one
is an argument rather than an oversight:

* No scoping column on `Account` — no `site`, no `department`, no `scope_filter`, in any
  form. This is the column someone adds in a hurry; it has no legitimate use here.
* No permission that names rows. `Permission` members name kinds. A member like
  `device:read:own-site` is the ruling being reversed by enum entry.
* No request-level narrowing of any read by caller identity — no implicit `WHERE` added
  from the session, no default filter the operator did not choose and cannot see.
* No aggregate computed over a filtered set and presented without its filter (§4).

**Must** — and all of it already holds, which is the point:

* Reads stay whole-fleet within the tenant.
* The recorder keeps reading the database, never its own API.
* Filters stay caller-supplied, canonical in the URL, and reproducible by whoever
  follows the link.

No migration, no schema change, no endpoint change. The ruling's whole cost to v0 is
that it is written down.

---

## 7. The v-never entry

Drop-in text for `docs/v-never.md`:

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

---

## 8. What this ruling does not decide

* **Cross-tenant rollups.** Out of scope by §2.4, not by silence. If ever built, they
  are their own design with their own stamp semantics.
* **The tenant switcher (#36) and per-tenant identity resolution (#35).** Named here as
  the sanctioned path for multi-scope customers; their own designs are unchanged and
  unblocked by this.
* **The `/dashboards` v1 API contract.** §5's riders are inputs to it, not the contract
  itself.
