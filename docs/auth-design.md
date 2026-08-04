# LoonInspect Auth & Logging Design

Status: **proposal** · Target: v1 local accounts + RBAC + audit log, built so OIDC/Okta drops in without a rewrite.

---

## 1. Problem

Today every route is unauthenticated. `main.py` mounts six routers with no guard, which means anyone who can reach `:8000` can read and rewrite MDM connection credentials (`/api/mdm/connections`), flip feature flags, and read the full device inventory. For a tool whose whole job is holding Jamf API secrets, that's the highest-severity open item in the repo.

Three things need to be true when we're done:

1. Nothing is reachable without an authenticated principal, **by default** — not "by remembering to add a decorator."
2. Adding Okta/OIDC later changes *configuration and one new identity row type*, not the account model, the session model, or the role model.
3. Every security-relevant action is attributable to a specific principal, durably, in a form that survives an email change.

---

## 2. Non-negotiable design constraints

| Constraint | Consequence |
| --- | --- |
| OIDC is coming fast | No credential fields on the account row; identity is a separate table |
| Break-glass must always work | Local password login survives "SSO required" mode, by design, loudly audited |
| Native macOS client planned | Bearer-token path must exist alongside cookies from day one |
| Self-hosted / air-gapped installs | Must boot and be usable with zero external dependencies |
| Webhooks are called by Jamf, not a browser | `/webhooks/*` can never sit behind a session cookie; it carries its own per-connection credential (§4.7) |
| Scheduler jobs have no user | The actor model needs a first-class `system` principal |

---

## 3. Data model

### 3.1 The regret analysis

These are the specific choices that make OIDC painful if you get them wrong. Each row is a decision we're making *now* to avoid a migration later.

| Naive choice | What breaks when Okta arrives | What we do instead |
| --- | --- | --- |
| `account.password_hash` column | OIDC users have no password; column is either NOT NULL (broken) or nullable-with-`if None` checks everywhere. Can't represent an account with *both* a password and an Okta identity — which is exactly what break-glass is. | `auth_identity` table, one row per (account, method). An account may hold several. |
| Email as the join key | IdPs change emails (name changes, domain migrations). Sessions and audit events pointing at an email lose their history. Matching an OIDC login to a local account *by email* is account takeover if the IdP doesn't verify emails. | Immutable `account.id` (UUID). OIDC identity keyed on `(issuer, subject)`, never email. Email is a mutable attribute. |
| `account.role` column | SCIM/OIDC group sync overwrites manually granted roles, and you can't tell an IdP-derived grant from a human one — so the sync silently demotes your break-glass admin. | `account_role` rows carrying `source` (`manual` \| `oidc_group` \| `scim`). A sync only touches rows of its own source. |
| Session row that assumes password login | No way to record *how* someone authenticated, which blocks per-method audit, step-up MFA, and IdP backchannel logout. | Session references `identity_id` + `auth_method`, with a nullable `idp_session_id` reserved for backchannel logout. |
| Hard-deleting accounts | SCIM deprovision is `active: false`, not DELETE. Deleting also strands the `actor_id` on every historical audit event, so past actions become unattributable. | `status` enum; accounts are never hard-deleted. |
| Global "disable local login" boolean | Turning on SSO enforcement bricks your break-glass account. | `local_login_policy` = `enabled` \| `break_glass_only` \| `disabled`, with `is_break_glass` accounts exempt from the last two. |
| `if account.role == "admin"` in endpoints | Every new role means editing every endpoint. | Endpoints depend on **permissions**; roles are named bundles of permissions. New role = data, not code. |
| SCIM bearer token owned by a person | That admin is eventually deprovisioned *by Okta*, which kills the token Okta was using to tell us about deprovisioning. Provisioning stops silently and can't be fixed through the broken path. | `is_service_account` flag; the SCIM token belongs to a non-human principal. §3.5 |
| Reusing the OIDC `sub` as SCIM's `externalId` | They're distinct values, and a SCIM identity can exist before the user has ever logged in — so `auth_identities.subject` may be empty when SCIM first needs to correlate. | Dedicated `account.external_id`, unique per `external_source`. §3.5 |
| Assuming SCIM `userName` == email | Okta can map `userName` to `samAccountName`/UPN. On a mismatch every sync creates duplicate accounts. | Nullable unique `account.username`. §3.5 |

### 3.2 Tables

Written in the repo's existing `Mapped`/`mapped_column` idiom, to land in `app/models/schema.py`.

```python
class Account(Base):
    """A LoonInspect operator. Distinct from the MDM-synced end users on the Users
    page — those are people who own devices, these are people who log in here."""
    __tablename__ = "accounts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)  # uuid4
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(16), default="active")  # active|disabled|invited

    # SCIM's required unique login identifier. Usually the email, but Okta can map it
    # to samAccountName or similar — so it can't be assumed equal to email. See §3.5.
    username: Mapped[str | None] = mapped_column(String(255), unique=True, index=True)

    # Break-glass accounts keep local password login even under SSO enforcement,
    # and every authentication by one emits a high-severity audit + SIEM event.
    is_break_glass: Mapped[bool] = mapped_column(Boolean, default=False)

    # Non-human principals (the SCIM bearer token's owner, CI, the macOS app's
    # service identity). Never authenticate interactively, never IdP-managed. §3.5.
    is_service_account: Mapped[bool] = mapped_column(Boolean, default=False)

    # Set when an external system (SCIM) owns this record's lifecycle, plus that
    # system's own identifier for the user (SCIM `externalId`) — which is NOT
    # necessarily the OIDC `sub`. See §3.5.
    external_source: Mapped[str | None] = mapped_column(String(32), nullable=True)
    external_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    # __table_args__ = (UniqueConstraint("external_source", "external_id"),)

    created_at / updated_at / last_login_at


class AuthIdentity(Base):
    """One way an account can authenticate. Password today; 'oidc' rows join the
    same account later without touching the account row."""
    __tablename__ = "auth_identities"
    __table_args__ = (UniqueConstraint("provider", "subject"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.id"), index=True)

    provider: Mapped[str] = mapped_column(String(64))   # "local" | "oidc:okta" | ...
    subject: Mapped[str] = mapped_column(String(255))   # local: account_id; oidc: the `sub` claim

    secret_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)  # argon2id, local only
    password_changed_at / last_used_at


class AccountRole(Base):
    __tablename__ = "account_roles"
    __table_args__ = (UniqueConstraint("account_id", "role", "source"),)

    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.id"), primary_key=True)
    role: Mapped[str] = mapped_column(String(32), primary_key=True)
    source: Mapped[str] = mapped_column(String(16), primary_key=True, default="manual")
    granted_by: Mapped[str | None]
    granted_at: Mapped[datetime]


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)  # sha256
    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.id"), index=True)
    identity_id: Mapped[str | None] = mapped_column(ForeignKey("auth_identities.id"))
    auth_method: Mapped[str] = mapped_column(String(32))  # password | oidc

    idp_session_id: Mapped[str | None]   # reserved: OIDC backchannel logout
    ip / user_agent
    created_at / last_seen_at / expires_at / revoked_at


class ApiToken(Base):
    __tablename__ = "api_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    # May point at a service account rather than a person — that's how the SCIM
    # bearer token avoids dying with its creator. See §3.5.
    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.id"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)  # sha256
    scopes: Mapped[list] = mapped_column(JSON, default=list)  # [] = inherit account's permissions
    expires_at / last_used_at / revoked_at


# Audit events are NOT a table — they're an append-only JSONL file on the data
# volume with a 30-day TTL. See §6.4.
```

### 3.3 Why `is_break_glass` earns a column

The failure mode we're designing against: org turns on "require SSO," the IdP then has an outage or a misconfiguration, and nobody can log in to the tool that manages their fleet's security posture. Reserving one flagged local account that is *permanently* exempt from SSO enforcement is the standard answer (Okta and AWS both push this pattern for their own admin surfaces).

The cost of the exemption is that it must be impossible to use quietly: every break-glass authentication writes an audit event at high severity **and** streams to the SIEM immediately, so the use shows up in the customer's alerting rather than only in our UI.

### 3.4 OIDC account linking — decided: auto-link on verified email

When `alice@corp.com` first signs in through Okta and a local account with that email already exists, we link them automatically **only if the IdP asserts `email_verified: true`**. Resolution order:

1. Match `auth_identities` on `(issuer, subject)` → done, this is a returning user.
2. No match → look up `accounts` by the `email` claim.
   - Found **and** `email_verified` is true → create an `AuthIdentity` row joining the existing account. Audit as `auth.identity.linked`.
   - Found and `email_verified` is false or absent → **reject the login** and surface it to an admin. Do not link, do not silently create a duplicate.
   - Not found → JIT-provision a new account with the **Viewer** role, audited as `account.provisioned.jit`. Least privilege on auto-provisioning: anyone the IdP vouches for gets in, but an admin decides who becomes an Analyst or Auditor.

The `email_verified` gate is the whole point. Without it, anyone who can set an unverified email attribute in the IdP — or in *any* IdP we're configured to trust — inherits an existing LoonInspect account along with its roles. That's a direct path to the break-glass admin. The claim is cheap to check and turns a takeover into a failed login.

Two consequences to keep in mind when this ships: linking must be an audit event, since it's a privilege-transfer moment; and because §3.1 keys identities on `(issuer, subject)` rather than email, a later email change on either side doesn't unlink or re-link anything.

### 3.5 SCIM forward-compatibility

OIDC and SCIM look similar and are not. OIDC is *authentication* — user-initiated, login-time, JIT. SCIM is *provisioning* — Okta-initiated, out-of-band, full CRUD lifecycle that happens whether or not the person ever logs in. Four things follow from that, and they're all cheap now.

**1. The SCIM bearer token must belong to a service account, not a person.**

Okta authenticates to our SCIM endpoint with a bearer token. The obvious implementation — an admin creates a personal API token and pastes it into Okta — sets up a circular failure: that admin eventually leaves, Okta deprovisions them, deprovisioning disables their account, disabling their account kills their tokens, and **the now-dead token was the thing Okta used to tell us about the deprovisioning**. Provisioning stops silently, and it can't be repaired through the system that broke.

The fix is one boolean: `is_service_account`. Service accounts have no interactive login, are never IdP-managed, and can't be deprovisioned by the thing that authenticates through them. Retrofitting this means reassigning a live token's owner during an outage you can't see — exactly when you least want a migration.

Give that token a narrow `scopes` value rather than the Admin role, too. A leaked SCIM credential should be able to manage accounts and nothing else — not read Jamf connection credentials.

**2. `externalId` is not the OIDC `sub`.**

SCIM clients send `externalId` on create and expect it back on every response; it's how Okta correlates its user to ours across PATCH, PUT, and DELETE. In Okta it's *often* the same value as the OIDC `sub`, but that's a coincidence of one IdP, not a guarantee — and the SCIM identity may exist before any OIDC login has happened, so `auth_identities.subject` may be empty when SCIM first needs to correlate.

Hence `account.external_id` as its own column, unique per `external_source`, indexed. Without it, SCIM PATCH-by-externalId degrades to a table scan or an email match — and email matching is the same takeover vector §3.4 exists to close.

**3. SCIM `userName` is required and unique, and isn't necessarily the email.**

`userName` is SCIM's mandatory unique login identifier, and `filter=userName eq "..."` is a query Okta will actually send. Most deployments map it to email; some map it to `samAccountName` or a UPN that differs. If we assume `userName == email` and a customer's mapping disagrees, every sync creates duplicate accounts — data corruption that's tedious to unwind, worse than the migration would have been.

A nullable unique `username` column now costs nothing. What actually needs deciding before SCIM ships is the *mapping*, not the schema.

**4. Deactivation has to cascade, immediately.**

Okta deprovision arrives as `PATCH {"active": false}` (some configs send DELETE — map both to deactivate, never hard-delete, per §3.1). The response must be synchronous and complete: set `status='disabled'`, **revoke all sessions**, and **revoke all API tokens**. A deprovisioned employee holding a valid session cookie or a personal API token is precisely the scenario SCIM was bought to prevent, and "we mark them disabled and they expire within the hour" is not an answer anyone accepts. Session revocation is a `DELETE` against §3.2's session table — trivial, but only if it's designed as part of deactivation rather than remembered later.

**Also: SCIM-owned fields become read-only in our UI.** `external_source` already marks these accounts. Without the rule, an admin edits a display name locally, the next sync silently reverts it, and the UI looks broken rather than authoritative.

**Safely additive later — don't build now:**

- **Groups** (`/scim/v2/Groups` push). Needs its own tables plus a nullable `granted_via_group_id` on `account_role`. Low regret because §3.1 already models grants as rows with a `source`, so group-derived roles slot in beside manual ones instead of fighting them. Many Okta deployments only use attribute mapping and never push groups at all.
- **Multi-valued emails.** SCIM models emails as an array with a `primary` flag. Storing the primary and ignoring the rest is fine, and widening later is additive.
- **`meta.version` / ETags.** Optional in the spec; skip until something asks.

---

## 4. Authentication mechanics

### 4.1 Browser: opaque server-side session cookie

Not JWT. The reasoning:

- **Revocation.** A JWT can't be revoked without a denylist — and a denylist is a session table with extra steps.
- **Backchannel logout.** When OIDC lands, the IdP tells us "this session is over." That requires server-side session state to act on.
- **Cost is near zero here.** SQLite is already in the request path, sessions are single-digit-per-user, and there's no multi-service token-verification story to optimize for.
- No signing-key rotation ceremony to get wrong.

Cookie: `HttpOnly`, `SameSite=Lax`, `Secure` when `not settings.debug`, `Path=/`. Value is 32 bytes of `secrets.token_urlsafe`; only its SHA-256 is stored.

**Lifetime is operator-configurable, in seconds:**

```python
# core/config.py
# 0 = never idle-expire. Otherwise 60s .. 14d.
session_lifetime_seconds: int = 3600

@field_validator("session_lifetime_seconds")
def _check_session_lifetime(cls, v: int) -> int:
    if v == 0 or 60 <= v <= 1_209_600:
        return v
    raise ValueError("session_lifetime_seconds must be 0 (unlimited) or between 60 and 1209600 (14d)")
```

This is a **sliding idle timeout**, not an absolute one — `last_seen_at` refreshes on each authenticated request, and the session expires only after that much inactivity. At a 1-hour default an absolute timer would log people out mid-investigation every hour, which is the kind of thing that gets a security tool worked around rather than used.

`0` means unlimited: `expires_at` is stored as `NULL` and idle expiry never fires. `0` rather than an empty env var, because an unset variable has to fall back to the 1-hour default — "empty means unlimited" would turn a typo into a permanent session.

The 14-day ceiling applies to timed sessions only, enforced at startup, so a misconfigured deployment fails with a clear pydantic error instead of silently minting month-long sessions.

**Unlimited is never *unrevocable*.** Sessions still die on logout, admin revocation, account disable, and password change — that last one matters most, since it's the lever someone actually pulls after a laptop goes missing. What unlimited removes is only the passive timer, so the honest trade is: a stolen unlocked device stays authenticated until someone notices and acts. Reasonable for a single-operator homelab, and the wrong default for a fleet-security tool — which is why the default stays 3600 and the chosen value is logged at startup so it's visible in `docker compose logs`.

Same-origin makes this clean — `main.py` already serves the SPA and API from one port, and `config/api.ts` already sends `credentials: "include"`, so no CORS credential dance in production.

**Dev mode already works — verified.** `frontend/vite.config.ts` proxies `/api` → `127.0.0.1:8000`, and `config/env.ts` defaults `apiBaseUrl` to the relative `/api`. So the browser sees same-origin in dev exactly as it does in the container, and `SameSite=Lax` behaves identically in both. No `SameSite=None`, no HTTPS-in-dev requirement, no separate cookie config for the hot-reload workflow — which is the usual tax on cookie auth and we happen not to owe it. (`Secure` is skipped when `debug`, though browsers treat `localhost` as trustworthy anyway.)

### 4.2 CSRF

Cookie auth means CSRF is now in scope. `SameSite=Lax` blocks the classic cross-site form POST, but we're a security tool and shouldn't lean on one control:

- Double-submit token: a non-`HttpOnly` `csrf_token` cookie, echoed by the SPA in an `X-CSRF-Token` header, compared in constant time.
- Enforced **only on cookie-authenticated mutations**. Bearer-token requests are immune by construction and are exempt, which keeps the macOS client and CI simple.

### 4.3 Machine clients: personal API tokens

Format: `loon_pat_<token_id>_<secret>`. Lookup by the embedded id, then constant-time compare against the stored hash.

Hashing differs from passwords **on purpose**: token secrets are 32 bytes of CSPRNG output, so SHA-256 is correct and argon2 would be actively wrong — running a deliberately-slow KDF on every API request is a self-inflicted DoS. Passwords are low-entropy and get argon2id. Worth a comment in the code, since the inconsistency looks like a bug.

Tokens are shown exactly once at creation, inherit the creator's permissions (optionally narrowed by `scopes`), and support expiry + revocation. When the creator is disabled, their tokens stop working — checked at auth time, not by cascade.

Two rules added during implementation, neither in the original sketch:

**Scopes are intersected with the owner's live permissions on every request, never stored as a grant.** A token minted while its owner was an Admin loses that reach the moment the account is demoted, without anyone having to remember to re-issue it. Verified: the same token returned 200 on `/api/mdm/connections`, then 403 after the owner became a Viewer, then 200 again on restore.

**Minting a token requires an interactive session — a token cannot create another token.** Without this, a leaked token issues a replacement, and revoking the original stops containing the compromise. It's a three-line check that turns token revocation back into an actual containment action.

### 4.4 Default-deny enforcement

This is the load-bearing piece. Rather than adding `Depends(require_auth)` to each route — where the failure mode is a forgotten decorator on a route added six months from now — authentication is a **global dependency** on the app, with a small explicit allowlist:

```python
PUBLIC_PATHS = ("/api/health", "/api/auth/login", "/api/auth/setup", "/webhooks/", <static>)
```

A new router is protected the moment it's mounted. Making a route public is then a visible, reviewable diff against the allowlist.

"Public" here means *exempt from session auth*, not unauthenticated. `/webhooks/` is on the list because it authenticates with its own per-connection header credential (§4.7) — during pre-release that check is stubbed, which is the one knowingly-open path in this design.

### 4.5 Bootstrap (first run)

The container starts with zero accounts, which is the moment of maximum exposure: whoever reaches it first becomes admin.

Recommended: `/api/auth/setup` is live **only while `account_count == 0`**, and requires a claim token generated on first boot and printed to the container logs — the pattern Jupyter and Portainer use. Someone who can't read your `docker compose logs` can't claim the instance.

Plus `INITIAL_ADMIN_EMAIL` / `INITIAL_ADMIN_PASSWORD` env vars for automated deployments, which skip the wizard entirely.

### 4.6 Brute-force protection

DB-backed failed-attempt counter with exponential backoff, keyed on `(email, ip)`. DB rather than in-process because it survives restarts, and because each lockout is an audit event anyway. Failures return an identical response and timing regardless of whether the account exists.

### 4.6a Password policy

NIST SP 800-63B alignment, which is mostly about *removing* rules:

- **argon2id** with the library defaults; minimum 12 characters.
- **No composition rules** (no forced symbol/digit/case mixing) and **no forced expiry**. Both push users toward predictable mutations, and 800-63B explicitly advises against them.
- **Cap input at 128 characters before hashing.** Uncapped input to a memory-hard KDF is a cheap DoS — an unauthenticated endpoint that will happily argon2 a 10 MB request body is a gift. Easy to miss because it looks like a validation nicety rather than a control.
- Breach-list checking is skipped: it needs a bundled corpus or an outbound API call, and air-gapped installs are a target deployment.

### 4.7 Webhook authenticity — deferred, stubbed for pre-release

`/webhooks/jamf/{connection_id}` currently accepts any POST from anyone who can guess an integer. **Out of scope for this effort**; the real design lands in a later iteration. Recording the intended shape here so the auth model doesn't accidentally foreclose it:

LoonInspect generates a high-entropy header credential per connection. The admin pastes it into Jamf Pro's webhook configuration (Jamf Pro supports Header Authentication natively — a header name and static value). Inbound webhooks present it as `X-API-Key` or similar, and it's stored in the existing, currently-unused `MdmConnection.webhook_secret_encrypted`.

Three things that shape the eventual implementation, worth knowing now:

- **This authenticates the caller, not the payload.** Unlike an HMAC signature over the body, a static header value gives no body integrity and no replay protection. That's an acceptable trade for Jamf compatibility, but it means TLS is load-bearing rather than defense-in-depth — the value is replayable verbatim if intercepted.
- **Rotation needs two live values.** One column can't rotate without downtime: the moment you write the new secret, Jamf is still sending the old one until someone updates it by hand. Either accept a brief gap, or add a `previous_secret` + grace window. Worth deciding before it ships, since retrofitting it means a migration.
- **The secret must stay re-readable, unlike API tokens.** Admins need to paste it into Jamf Pro, possibly weeks after creating the connection, so the show-once rule from §4.3 can't apply. Gate re-reveal behind `CONNECTION_CREDENTIAL_READ` (Admin only) and audit each reveal — which the permission model in §5.1 already supports without additions.

Comparison must be constant-time, and the response must be identical whether the connection exists or the credential is wrong, so the enumerable integer in the path can't be used as an existence oracle.

---

## 5. Authorization

### 5.1 Permissions, not role strings

```python
class Permission(StrEnum):
    DEVICE_READ, APP_READ, VULN_READ
    CONNECTION_READ, CONNECTION_WRITE, CONNECTION_CREDENTIAL_READ
    FEATURE_FLAG_WRITE
    ACCOUNT_READ, ACCOUNT_WRITE
    AUDIT_READ
    TOKEN_CREATE
```

Endpoints declare `Depends(require(Permission.CONNECTION_WRITE))`. Roles are bundles:

| Permission | Viewer | Analyst | Auditor | Admin |
| --- | :-: | :-: | :-: | :-: |
| Device / app / vuln read | ✅ | ✅ | ✅ | ✅ |
| Connection read (config + health) | — | ✅ | ✅ | ✅ |
| Connection write | — | — | — | ✅ |
| **Connection credential read** | — | — | — | ✅ |
| Patch catalog sync | — | ✅ | — | ✅ |
| Feature flag write | — | — | — | ✅ |
| Account read | — | — | ✅ | ✅ |
| Account write | — | — | — | ✅ |
| Audit read | — | ✅ | ✅ | ✅ |
| Token create (own) | — | ✅ | ✅ | ✅ |

`PATCH_CATALOG_SYNC` was added during implementation and isn't in the original list: `POST /api/jamf-patch/sync` triggers an outbound refresh of Jamf's public catalog. Harmless in content, but it hits a third party, so it shouldn't be something a read-only role can fire in a loop. Auditor is denied it precisely because read-only has to mean read-only — that asymmetry with Analyst is deliberate.

**Auditor** is the read-only admin: full visibility into configuration, accounts, roles, and audit history, with no write permission anywhere. It's a strict subset of Admin, which makes it safe to hand to someone outside the team during a review.

The `CONNECTION_READ` / `CONNECTION_CREDENTIAL_READ` split is what makes Auditor work, and it lands on a specific line:

- `CONNECTION_READ` covers configuration and credential **metadata** — `last_successful_auth_at`, `credentials_rotated_at`, `credentials_fingerprint`. These already exist on `MdmConnection` and are exactly what an auditor needs to answer "are these credentials being rotated?"
- `CONNECTION_CREDENTIAL_READ` covers revealing **actual secret values** — principally the webhook header credential re-reveal from §4.7 — and triggering connection tests that exercise the live secret.

So an Auditor can verify rotation hygiene without ever being handed a secret, which is the whole point of the role. Admin-only remains the correct home for the second permission.

### 5.2 Forward-compat with IdP group mapping

Because grants live in `account_role` with a `source`, the later OIDC work is purely additive: a group→role mapping table, and a sync that reconciles only `source='oidc_group'` rows. Manual grants — including the break-glass admin's — are untouched by definition.

---

## 6. Logging

Right now the entire logging story is `print(f"[siem] {payload}")` in `mdm/service.py:30`. Audit can't be layered onto that, so the logging foundation lands **first**.

### 6.1 Three streams, deliberately not merged

| | Application log | Audit log | SIEM stream |
| --- | --- | --- | --- |
| Where | stdout (JSON) | JSONL file on the data volume | customer's SIEM (exists) |
| Lifetime | ephemeral, container-scoped | 30 days, rotated daily | customer-controlled |
| Audience | whoever runs the container | compliance, incident response, log shippers | detection engineering |
| Content | everything, incl. debug | security-relevant actions only | inventory deltas |

The mistake to avoid is making the audit log a log *level*. Application logs get sampled and dropped under pressure; audit records are evidence and have to survive independently of how noisy the app is that day.

### 6.2 The unifying thread: `request_id`

Middleware assigns a UUID per request, stored in a `contextvar` so it reaches every log call without threading a parameter through call stacks. It lands on both the application log line and the audit event — so an analyst pivots from an audit record → `request_id` → the full application-log trace for that request, which is the difference between "someone changed the Jamf credentials" and knowing exactly what the request did.

`contextvars` also carries the resolved actor, which is what lets `audit()` be a one-liner at call sites instead of plumbing the principal into every service function.

### 6.3 `actor_label` is denormalized on purpose

Each event carries `actor_id` (stable, for correlation) *and* `actor_label` — the email as it was at the moment of the action. When someone's email changes, or an IdP rewrites it during a domain migration, the historical record still reads correctly.

This matters more in a file than it would in a table: there's no join to resolve `actor_id` back to a human-readable name, and by the time anyone reads a 3-week-old line the account may have been renamed or disabled. Every event has to be self-describing on its own line.

### 6.4 The audit file

Append-only JSONL — one self-contained JSON object per line — written to the **data volume**:

```
/app/data/audit/audit.jsonl          # current day
/app/data/audit/audit.jsonl.2026-08-02   # rotated, kept 30 days
```

> ⚠️ **The path must be under `/app/data`.** That's the only thing `docker-compose.yml` persists (`looninspect-data:/app/data`, same volume as the SQLite DB). Audit written to `/app/logs` or the image filesystem is destroyed by the next `docker compose up --build` — which, given how often this app gets rebuilt during development, means the retention policy silently becomes "until the next rebuild."

**Rotation and TTL** come free from the stdlib:

```python
TimedRotatingFileHandler(
    path, when="midnight", utc=True,
    backupCount=settings.audit_retention_days,  # 30
)
```

`backupCount` *is* the TTL — the handler deletes the oldest file on each rotation, so 30 daily files is a rolling 30-day window with no cron, no cleanup job, and nothing to forget.

**Why a file rather than a table:**

- Every log shipper tails JSONL natively — Vector, Fluent Bit, Filebeat, Splunk UF. Mounting the volume is the entire integration, which is what makes "lots of other things can pick them up" true.
- Retention is a handler argument instead of a pruning job that has to be written, scheduled, and audited itself.
- Audit stays out of the DB backup/restore path, so restoring a database snapshot can't roll the audit trail backwards — a genuinely bad property for evidence.

**Details that are cheap now and painful to retrofit:**

- File mode `0600`, directory `0700`. The volume may be mounted by a sidecar shipper later.
- Flush on every write. Buffered audit that dies with the process is worse than useless, because it looks like the action never happened.
- If the write raises (disk full, permissions), log loudly to stderr and let the request proceed. The stricter posture — fail the request rather than act unlogged — is defensible for a security tool, but it turns a full disk into a total outage. Worth revisiting deliberately, not by default.
- **Single writer only.** The Dockerfile runs `fastapi run` with one worker today, which is what makes `TimedRotatingFileHandler` safe. Adding `--workers N` would have each process rotate independently and clobber the others. If workers ever get added, switch to `WatchedFileHandler` + external rotation.

**Known limitations — accepted for now, document them for users:**

The audit file is a local buffer and troubleshooting aid. It is explicitly **not** a compliance system of record, for four reasons:

1. **It's container-local.** `docker compose down -v`, a pruned volume, or a lost host takes the trail with it.
2. **It's not tamper-evident.** Anything that can mount the volume can rewrite or delete lines. No hash chain, no WORM storage, no signature.
3. **Retention is capped at 30 days** by design — shorter than most audit-retention obligations.
4. **It's single-node**, with no aggregation across deployments.

Users who need durable, tamper-resistant, or long-retention audit should forward events to a SIEM, which is the tool built for exactly those properties. **That integration is stubbed** — the config surface exists, the forwarding does not. Worth stating plainly in user-facing docs rather than letting people assume a file on a container volume satisfies an audit requirement; that assumption is only discovered to be wrong during an incident.

Example line:

```json
{"occurred_at":"2026-08-03T14:22:07Z","action":"connection.credentials.updated","outcome":"success",
 "actor_type":"account","actor_id":"9f2c...","actor_label":"kyle@corp.com","target_type":"mdm_connection",
 "target_id":"3","request_id":"7b1e...","ip":"10.0.0.4","metadata":{"changed":["client_secret"],"fingerprint":"a3f"}}
```

Config added to `core/config.py`:

```python
audit_log_path: str = "/app/data/audit/audit.jsonl"
audit_retention_days: int = Field(default=30, ge=1, le=3650)
log_level: str = "INFO"
log_format: str = "json"   # "console" when debug
```

### 6.5 Redaction

A central `redact()` applied to all audit metadata and log payloads, with a denylist keyed off the existing `CREDENTIAL_SCHEMAS` field names, so `client_secret` / `api_key` / `license_key` can't reach a log line or an audit event. Given this app's entire value proposition is encrypting those at rest, spilling them into a plaintext file on disk would be a genuine incident — and unlike a DB column, a file is trivially readable by anything that mounts the volume.

Credential *changes* are audited as `changed_fields: ["client_secret"]` — field names only, never values.

> **Correction to the original plan, and an open issue.** This section previously said to record "the existing 3-char fingerprint" alongside the changed fields. That turns out to be wrong: `MdmConnection.credentials_fingerprint` is literally `secret[:3]` — the first three characters of the plaintext secret, not a hash of it. Writing that into a long-lived plaintext file on a shared volume defeats the point of the audit log's redaction, so it is no longer recorded. `changed_fields` already answers "did the secret rotate?", which is all the fingerprint was there for.
>
> The larger issue is upstream and predates this work: `credentials_fingerprint` is returned by `GET /api/mdm/connections`, so **every role with `CONNECTION_READ` — Analyst and Auditor included — can read the first three characters of every Jamf client secret.** A truncated SHA-256 would serve the same "has this changed?" purpose with no leakage. Changing it touches stored values and the connections UI, so it's flagged rather than silently rewritten.

### 6.6 Reading and forwarding — out of scope for now

The file is the interface. The outbound event bus and the fetch API are yours to build, so this design deliberately stops at "events land on disk, correctly shaped."

One note for whenever that API arrives: reading JSONL means scanning files. At this app's event volume that's fine for a long time, and premature indexing would be exactly the complexity we're avoiding. The signal that it has stopped being fine is wanting to filter by actor or target across the full 30-day window in a UI — that's when a queryable index earns its keep, and the file remains the source of truth underneath it.

**SIEM forwarding of audit events is the documented answer to §6.4's limitations, and it is stubbed.** Existing `stream_event()` in `mdm/service.py` stays as-is for `device.inventory.changed` and is not extended to audit events in this phase. What Phase 3 should ship is the seam, not the implementation: audit events already carry a stable JSON shape, so the eventual forwarder is a consumer of the same payload the file receives — no re-modelling, no second event schema to keep in sync.

Until it exists, the supported aggregation path is tailing the JSONL off the mounted volume with any shipper (Vector, Fluent Bit, Filebeat, Splunk UF). That's worth putting in the user docs, since it's a real answer available today and costs us nothing to support.

---

## 7. Frontend

The existing `features/auth/index.ts` stub already has the right shape (`AuthStatus`, `AuthUser` with a string `id`) — it just has no implementation.

- **`AuthProvider`** (zustand, already a dependency) bootstraps via `GET /api/auth/me` on mount. `status: "unknown"` gates the first paint so a refresh doesn't flash the login screen at an authenticated user.
- **Route guard** wraps the `<App />` element in `routes.tsx`, preserving the attempted path for post-login redirect.
- **`apiRequest`** ([config/api.ts](../frontend/src/config/api.ts)) gains: `X-CSRF-Token` injection on mutations, `401` → clear state and bounce to login, `403` → a distinguishable permission error rather than the current generic `API request failed: ${status}` throw.
- **Permission-aware nav** hides Settings/Connections for non-admins. Presentational only — the server is the authority, and every endpoint enforces independently.
- New pages: Login, first-run Setup, Account settings (password, API tokens), Admin → Accounts. No audit UI — the audit file has no read API yet by design (§6.6).

---

## 8. Delivery phases

| Phase | Scope | Why here |
| --- | --- | --- |
| **0** ✅ | Structured logging, `request_id` middleware, contextvars, `redact()` | Audit depends on it; nothing else can be attributed without it |
| **1** ✅ | Accounts, identities, sessions, default-deny, CSRF, login UI, first-run claim | Closes the open-door problem — the actual point of the exercise |
| **1a** ✅ | Carry the unused SCIM columns (`username`, `external_id`, `is_service_account`) in the Phase 1 migration | Free now; a migration + data reconciliation later. §3.5 |
| **2** ✅ | Permissions, roles, per-endpoint enforcement, nav gating | Needs Phase 1's principal to enforce against |
| **3** ✅ | Audit events → JSONL file, 30d rotation, redaction | Needs both a principal and the logging foundation |
| **4** ✅ | API tokens + management UI | Unblocks the macOS client |
| **Later** | OIDC/Okta, SCIM, TOTP → WebAuthn | Additive by construction if §3.1 holds |
| **Deferred** | Webhook header auth (§4.7) | Separate iteration; stubbed for pre-release |

MFA was explicitly out of scope for v1. The model above doesn't block it: TOTP secrets become another `auth_identity` row (encrypted with the existing `EncryptedString`), and `session.auth_method` already carries what's needed for step-up.

---

## 9. New dependencies

| Package | Purpose | Note |
| --- | --- | --- |
| `argon2-cffi` | Password hashing | Direct, not via `passlib` — passlib is effectively unmaintained |
| *(none for OIDC yet)* | | `authlib` when Phase "Later" starts |

Everything else — session tokens, CSRF, HMAC, API tokens — is stdlib `secrets` / `hmac` / `hashlib`.

---

## 10. Open questions

None blocking. Everything below is decided.

### Resolved

- **Read-only admin** → yes, as the **Auditor** role: a strict subset of Admin with no write permissions and no access to secret values. See §5.1.
- **Session lifetime** → `session_lifetime_seconds`, sliding idle timeout, default 3600. `0` = unlimited; any other value is 60s–14d. See §4.1.
- **Audit retention** → 30 days, as daily-rotated JSONL on the data volume; `backupCount` enforces the TTL. Container-local storage is an accepted limitation, documented, with SIEM forwarding (stubbed) as the answer for durable retention. See §6.4.
- **Audit read API / outbound bus** → out of scope; the file is the interface. See §6.6.
- **OIDC account linking** → auto-link, gated on `email_verified`. See §3.4.
- **SCIM readiness** → three unused columns carried in the Phase 1 migration (`username`, `external_id`, `is_service_account`), plus deactivation cascading to sessions and tokens. Groups deferred as safely additive. See §3.5.
- **Webhook authentication** → per-connection static header credential (`X-API-Key`-style) generated by LoonInspect, pasted into Jamf Pro. Deferred to a later iteration; see §4.7.
- **Testing** → deferred to a later iteration, before public release. See §11.

---

## 11. Implementation notes worth not rediscovering

**Hiding a page is not the same as hiding its controls.** Phase 2's first pass gated the Settings *nav* and the *route*, and the Auditor still landed on a fully-populated Connections page with a live "Add connection" button. The API refused the write, so nothing was exposed — but a read-only role discovering its limits through a 403 is a UI bug, and the permissions payload exists specifically to prevent it. Any page reachable by more than one role needs its write controls gated separately from the route.

**The frontend `PERMISSIONS` map is hand-synced with `app/core/permissions.py`.** A typo there fails *open* in the UI — the control renders, the API still refuses, and the user gets a 403 instead of a hidden button. Not a security hole, but it makes the mistake invisible until someone hits it. Worth generating from the backend enum if this list grows.

**FastAPI's built-in docs bypass global dependencies.** `/docs`, `/redoc`, and `/openapi.json` are mounted as plain Starlette routes, not `APIRoute`s — so `FastAPI(dependencies=[...])` never runs for them, and the default-deny layer silently did not cover the one surface that enumerates the entire API. Fixed by disabling the built-ins (`docs_url=None`, etc.) and re-registering them as real routes in `main.py`. Worth re-checking whenever anything else gets mounted outside the router.

**SQLite gives back naive datetimes**, even from `DateTime(timezone=True)` — there's no timezone type to round-trip through. Comparing one against `datetime.now(timezone.utc)` raises `TypeError`, which took out session expiry, the sliding-window refresh, and the lockout check all at once. `app.core.auth.as_utc()` re-attaches UTC on read; every comparison against a stored timestamp has to go through it. This will come back in Phase 4 with token expiry.

**Objects built in Python have no loaded relationships.** `account.roles` on a freshly constructed `Account` triggers a lazy load, which under asyncio raises `MissingGreenlet` rather than quietly issuing a query. `lazy="selectin"` only helps when the object came from a query — after `create_account()` the relationship needs an explicit `await db.refresh(account, ["roles"])`.

**Two things hijack logging config, and both were found the hard way in Phase 0.**

*Alembic.* `migrations/env.py` calls `fileConfig(config.config_file_name)`, which applies `alembic.ini`'s `[loggers]` section **globally** — replacing the app's handlers with a console formatter and dropping the root level to WARNING. Because migrations run in-process at startup, every log line after the first migration silently changed format and level. Fixed by guarding the call behind `config.attributes.get("configure_logger", True)` and setting that flag to `False` in `core/database.py`. The alembic CLI is unaffected, since nothing sets the flag there.

*fastapi-cli.* `fastapi run` imports the app module to resolve the import string **before** uvicorn applies its own `dictConfig`. So a `configure_logging()` call at module import gets overwritten, and uvicorn's loggers come back with their own handlers and `propagate=False`. Fixed by calling `configure_logging()` a second time at the top of `lifespan()`, once uvicorn has finished. The function is idempotent by design for exactly this reason.

The general lesson for later phases: anything that calls `logging.config.fileConfig` or `dictConfig` after startup will silently take over the audit handler too. Worth checking whenever a library is added.

**Four log lines will never be JSON**, and that's accepted: `uv`'s build output, fastapi-cli's startup banner, and the two `INFO:     Started server process` / `Waiting for application startup` lines uvicorn emits between its own logging setup and lifespan. All are pre-application output containing no app data. Eliminating them would mean replacing `fastapi run` with a direct `uvicorn` invocation plus `--log-config`, which costs more than it's worth.

**Existing deployments get locked out on upgrade — intentionally.** Anyone already running LoonInspect has zero accounts, so their first request after upgrading lands on the setup flow. That's the correct behavior, but it means this upgrade isn't a no-op: the claim token in `docker compose logs` becomes required reading. Needs a README line before release, or it reads as a broken build.

**Create the audit directory at startup.** `/app/data/audit/` isn't in the image, and the volume mounts empty on first run. `mkdir(parents=True, exist_ok=True)` in `lifespan()` *before* the log handler attaches — otherwise first boot dies on a missing path, and it presents as a Docker problem rather than an application one.

**Expired sessions need reaping.** They accumulate indefinitely otherwise. APScheduler is already wired up in `main.py`; this is one more daily job beside the existing sweeps.

**New frontend pages need i18n entries.** Every existing page goes through `useLocale()` with `en.ts` and `de.ts`. Login, Setup, and Account settings need both, or they'll be the only untranslated screens in the app.

**CORS becomes near-vestigial — leave it, but watch it.** Prod is same-origin and dev goes through the Vite proxy, so `cors_origins` does no load-bearing work in either. The thing to prevent is a future `allow_origins=["*"]`: combined with the existing `allow_credentials=True`, that turns into a session-theft primitive.

**Testing is deferred** to a later iteration, ahead of public release. What that leaves uncovered in the meantime is worth naming: the default-deny allowlist (§4.4) is the one piece with no compile-time safety net — a new router is protected automatically, but nothing catches a mistaken *addition* to `PUBLIC_PATHS`. When tests do land, the highest-value one by a wide margin is a parametrized sweep over `app.routes` asserting every route either requires a principal or is explicitly allowlisted. It's roughly fifteen lines and it permanently closes the "someone shipped an unprotected endpoint" class of bug.
