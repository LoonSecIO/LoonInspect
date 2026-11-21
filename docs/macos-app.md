# LoonInspect as a macOS app

Status: **built, 1.2.0**, 2026-11-18 (packaged as 1.0.0 on 2026-11-10) · Apple silicon, macOS 13
or later · the files are under [`macos/`](../macos/README.md) · when it will not open or start,
[`troubleshooting.md`](troubleshooting.md) §25 · its limits, [KNOWN_ISSUES.md](../KNOWN_ISSUES.md)
§10 · built and checked on one Mac (macOS 27.3, Xcode 27.2, Swift 6.4): the update from 1.1.0
under [Validation (1.2.0)](#validation-120), the one from 1.0.0 under
[Validation (1.1.0)](#validation-110), the packaging under [Validation (1.0.0)](#validation-100).

It began as the packaging spike of 2026-10-06 (`spike/macos-app`, pull request #750), whose
question was whether LoonInspect could ship as a macOS application instead of a container. The
answer was yes, as a packaging job rather than a port, and this is that job finished: the same
shell, re-read and re-derived on a branch cut from `main` as [BRANCHING.md](BRANCHING.md) §3.1
asks, with the release names, a Developer ID signature and the hardened runtime on every file,
an icon, a disk image, the notarization step, and the words for when it fails.

## What it is

One app, one Mac. `LoonInspect.app` runs the backend, the frontend and PostgreSQL 17 the
container runs, unchanged, as child processes of a small Swift shell, with Postgres beside the
backend on a Unix socket instead of in a sidecar container. SQLite was never on the table:
row-level security, advisory locks and `SKIP LOCKED` need Postgres. The frontend's one
difference: in the app's window the first-run setup page asks for no claim token, because the
shell hands it this session's ([The first administrator](#the-first-administrator)).

It is for an operator who wants to look at a Jamf Pro instance from a laptop without a Docker
host. It runs while it is open and the Mac is awake, and not otherwise; a fleet whose events must
reach a SIEM every night runs the container (KNOWN_ISSUES.md §10).

### Using the app on this Mac

Open the release's disk image, drag **LoonInspect** to **Applications**, then launch it there.
Python, PostgreSQL and the web interface are bundled; the receiving Mac needs no Docker,
Homebrew, Xcode or separate database. The account created at setup belongs to this installation.

**Help › Using LoonInspect on This Mac** explains the local instance, network connections,
data location, updates and transfer. The startup screen names the phase in progress. A failure
offers **Show Logs** and **Quit**; after correcting the cause, quit and reopen the app.

Closing the window leaves collection running. **Window › Show LoonInspect** brings it back;
**Quit LoonInspect** stops collection and delivery, and sleep pauses them. The interface is
reachable only from this Mac. Jamf cannot send webhooks to its loopback address; use a reachable
server deployment for incoming webhooks and continuous operation.

Local storage does not mean no outbound traffic. LoonInspect contacts Jamf and the destinations
you configure; community sharing and configured AI have their own controls, the Fleet catalog,
while its flag is on, reads Fleet's repository on GitHub once a day, and the update check asks
LoonSec once a day whether a newer release exists ([Updates](#updates)). Setup preselects
the community-sharing choice. Review it there and under **Settings › Data Sharing** before
collecting production inventory. Connection secrets are encrypted in the database with a key
in login Keychain; the database itself is not encrypted by LoonInspect.

Copying the DMG to another Mac installs the software, not the existing instance's accounts,
connections or inventory. Those stay in Application Support and Keychain. Moving an existing
instance requires the matching database and secrets described under [Backup](#backup).

| Path in the bundle | Holds |
| --- | --- |
| `Contents/MacOS/LoonInspect` | The shell: the window, the menu, the supervisor (`macos/shell/`). |
| `Contents/Resources/backend` | Laid out as the image's `/app`: `app/` with the SPA in `app/static` and `build_info.json` stamped as the Dockerfile stamps it, `migrations/`, `alembic.ini`, `docs/baseline-rules.yml`. |
| `Contents/Resources/python` | CPython 3.12 from python-build-standalone and the runtime packages `uv.lock` names, installed as macOS arm64 wheels against the lockfile's hashes, bytecode compiled at build time. |
| `Contents/Resources/postgres` | PostgreSQL 17 from zonky's embedded-postgres-binaries (EnterpriseDB's build): `initdb`, `pg_ctl`, `postgres`, and no `psql` or `pg_dump`. |
| `Contents/Resources/launcher` | `loon_backend.py`: `app.serve` plus the watchdog. |
| `Contents/Resources/build-manifest.json` | The app version and build number, the commit and whether the tree was clean, the backend's `RELEASE`, the pinned runtimes, the identity it was signed as. |
| `Contents/Resources/LoonInspect.icns` | The icon, rendered at build time from `frontend/public/brand/loon-mark-reversed.svg` on a `lake` tile. |

## How it runs

```
LoonInspect                       Contents/MacOS, the Swift shell
├── postgres -D …/pgdata          Contents/Resources/postgres/bin, Unix socket only, no TCP
└── python3 loon_backend.py       Contents/Resources/python/bin, app.serve on 127.0.0.1:<port>
```

The app's own files are all in `~/Library/Application Support/LoonInspect`, mode 0700.

| Path | Holds |
| --- | --- |
| `pgdata/` | The database cluster. Marked excluded from Time Machine by the app itself ([Backup](#backup)). |
| `run/` | The socket (`.s.PGSQL.5432`), `port` (the chosen port, written for anyone who wants to reach the UI), and `shell.lock` (one instance at a time). |
| `logs/` | `shell.log`, `postgres.log`, `backend.log` (the container's JSON stdout, line for line) and `initdb.log`. Each is moved to `<name>.1` at a launch that finds it over 20 MB. |
| `data/` | The backend's `./data`: it runs with the support directory as its working directory, so the audit log lands here as it lands on the container's volume. |
| `preferred-port` | Last launch's port, which the next launch reuses if it is free, so the UI's origin and its per-origin browser storage survive a relaunch. |

The window adds the paths macOS and WebKit name after the bundle identifier for any app with a
web view: `~/Library/WebKit/io.loonsec.looninspect` (the page's site data),
`~/Library/Caches/io.loonsec.looninspect` (WebKit's HTTP cache),
`~/Library/Preferences/io.loonsec.looninspect.plist` (the window's frame and Check for Updates Daily), and the per-user
temporary and cache entries under `/var/folders` that WebKit's own processes make.

**The socket path.** `sockaddr_un.sun_path` is 104 bytes on macOS, terminator included, and
`/Users/<name>/Library/Application Support/LoonInspect/run/.s.PGSQL.5432` leaves about 30
characters for the account name. A longer home directory path gets the socket in
`/tmp/io.loonsec.looninspect.<uid>`, a 0700 directory of this user's, where Postgres puts its
own by default; the shell checks that directory is a directory and this user's before using it,
and `shell.log` says when it did. The lock, the port file and the logs stay in the support
directory either way.

**The secrets** are three generic passwords in the login keychain under the service
`LoonInspect`: `ENCRYPTION_KEY` (a Fernet key), `postgres-looninspect_app` and
`postgres-looninspect`. All three are generated on the first launch, and none is written to a
file: `initdb` reads the superuser's password from its stdin, a pipe, and the role's password
reaches single-user Postgres the same way. A later launch that finds the database but not the key
refuses to start and says why, rather than mint a new key that would leave every stored credential
unreadable (KNOWN_ISSUES.md §5). The items are made through `/usr/bin/security`, so they trust
`security` and any process of this user can read them without a prompt; why that is still so in
1.1.0 is under [What it leaves out](#what-it-leaves-out).

**First launch.** `initdb -U looninspect --pwfile=/dev/stdin --auth=scram-sha-256
--encoding=UTF8 --locale=C --locale-provider=builtin --builtin-locale=C.UTF-8`: the container's
superuser, a password on the pipe, the socket asking for a password inside a 0700 directory
(the container trusts every socket connection), and code-point ordering with Unicode case mapping
without macOS's libc locale tables, which is what the container's `en_US.utf8` under musl gives
too. The cluster is built as `pgdata.initdb` and renamed only when complete. Then what the image's
first boot does: `CREATE DATABASE looninspect`, and the two statements of
`ops/postgres/initdb/10-app-role.sh` (`CREATE ROLE looninspect_app … NOSUPERUSER NOCREATEDB
NOCREATEROLE NOBYPASSRLS`, `ALTER SCHEMA public OWNER TO looninspect_app`), in single-user mode
because the build has no `psql`, with `exit_on_error=on` (single-user mode otherwise exits 0 after
an error) and `log_min_error_statement=panic` (a failing `CREATE ROLE` would otherwise be logged
with its password). A quit during any of this stops the running tool, and the shell removes
`pgdata.initdb`; a launch after a crash removes it before starting over.

**Every launch.** The shell rotates any log over 20 MB, takes the instance lock, marks `pgdata`
excluded from Time Machine, stops a Postgres an earlier session left running (a `postmaster.pid`
naming a live process whose command line is this data directory), starts
`postgres -D pgdata -c listen_addresses= -c unix_socket_directories=<socket dir> -c port=5432`
(5432 names the socket file only; this Mac's other Postgres on `*:5432` never collided with it),
waits for `postmaster.pid` to read `ready`, picks the port, starts the backend with the
environment below, polls `/api/health` until it answers 200 behind a waiting page (or an error
page that names the log if it never does), and loads `http://127.0.0.1:<port>/`. Links that
leave the instance open in the default browser. Downloads ask where to save the file and report
completion or failure; cancelling the save dialog cancels that download.

| Setting | Container | App | Why |
| --- | --- | --- | --- |
| `HOST`, `PORT` | `0.0.0.0:8001` | `127.0.0.1:<free port>` | Nothing off the Mac can reach it. |
| `TLS_MODE` | `off` by default | `off` | Loopback only. |
| `DATABASE_URL` | `…@db:5432/looninspect` | `postgresql+asyncpg://looninspect_app:<pw>@/looninspect?host=<socket dir>` | asyncpg takes a `host` that starts with `/` as a socket directory. The space in "Application Support" stays literal: a `%20` would break Alembic's ConfigParser. |
| `DATABASE_MODE` | `bundled` | `bundled` | The same promise: the role was made right at first boot. |
| `ENCRYPTION_KEY` | `.env` | login keychain | Never in a file. |
| `SECURE_COOKIES` | `true` | `false` | Plain HTTP on 127.0.0.1 only, so no cookie crosses a network; WebKit's handling of Secure cookies over `http://127.0.0.1` is not one to lean on. |
| `UPDATE_CHECK` | `true` | **Check for Updates Daily**: `true` until it is turned off | The app's user has no `.env`; the menu item is the switch ([Updates](#updates)). |
| `INSTANCE_KIND` | `container` | `mac-app` | The update check's `kind`, which says the request comes from the app. |
| Everything else | compose's defaults, which equal `config.py`'s | `config.py`'s defaults | pydantic-settings reads a `.env` from the working directory, which here is the support directory. |

### The first administrator

The backend mints and logs a claim token while no account exists, as in the container, and
`INITIAL_ADMIN_*` is not used. The shell reads this session's token from `backend.log` and hands
it to its own window and nothing else: a `WKUserScript`, run at document start in the main frame
only, defines a read-only `window.looninspectSetupClaimToken` when the page's origin is
`http://127.0.0.1:<port>`. The setup page sends that token and draws no claim field and no
`docker compose logs` help; the display name field takes the focus. No URL, file, pasteboard or
shell log line carries the token. In a browser opened with **Open in Browser** the page is the
container's, token field included, and the token is in `logs/backend.log`.

The claim exchange is a container-era control. It is held by the shell for now, by Kyle's ruling
of 2026-10-06, and is to be gutted before a public release: a loopback-only backend mode without
a claim, or the shell creating the first account itself. That is a backend change, and it is not
in 1.1.0 ([What it leaves out](#what-it-leaves-out)).

**Quit.** From the menu, with ⌘Q, through AppleScript, at logout, or on SIGTERM, SIGINT or
SIGHUP: the backend first (SIGTERM, uvicorn's graceful shutdown, SIGKILL after 15 s), then
`pg_ctl stop -m fast`, and only then does the app exit. If the shell itself is killed, the
backend's watchdog notices within a second and takes both steps from inside the backend,
signalling only the postmaster this shell started and only while `postmaster.pid` still names it.
A second copy of the app refuses to start, says that one is already running, and leaves the
running one alone.

## Version, signature, release

**The version.** `CFBundleShortVersionString` in `macos/shell/Info.plist` is the app's release,
`1.2.0`, and the pull request that prepares a release moves it, as the one that prepares an image
release moves `RELEASE` in `backend/app/core/version.py`. They serve different purposes but the
release workflow requires them to agree (`1.2.0` in the app, `v1.2.0` in the backend): the app's
version names the bundle a Mac runs; the backend compares its release with the database's
`schema_release` (BRANCHING.md §1.1). `build-manifest.json` records both. `CFBundleVersion` is
the build number, `BUILD_NUMBER` or the UTC build minute, stamped by
`build-app.sh`; the page's build readout and the update check read `build_info.json`
(`YYYY.MM.DD+<sha>`), written as the Dockerfile writes it.

The app's 1.0.0 and the container's v1.0.0 share a name and not a commit. The container's is the
tag of 2026-09-20. The app was first packaged from `main` on 2026-11-10, 110 commits later, with
`RELEASE` still reading `v1.0.0`, so the 1.0.0 app carries everything `main` had by then,
including the schema's release record ([Updates](#updates) is where that matters). From 1.1.0 on
the app and the container are built from one tagged commit.

**The signature.** Every Mach-O file in the bundle, the shell, `python3.12`, every extension
module and dylib the wheels carry, every Postgres binary and library, is signed with the one
"Developer ID Application" identity in the keychain, the hardened runtime
(`--options runtime`) and a secure timestamp, inside out; the bundle is sealed last, and the
build fails if any file does not verify with the runtime flag. No entitlement is needed: each
process loads only libraries signed by the same team. Without a Developer ID in the keychain the
build signs ad-hoc with the same flags, so a development build fails where a release build would,
and runs on the Mac that built it and nowhere else. The `.pyc` files are compiled at build time
with `unchecked-hash`, so nothing writes into the sealed bundle at run time.

**Notarization** is the release step. It runs in the `macOS release` GitHub Action or locally
on a Mac with the signing identity. This command prompts for an app-specific password:

```sh
xcrun notarytool store-credentials LoonInspect --apple-id <Apple ID> --team-id 6CWZ5GA79H
NOTARY_PROFILE=LoonInspect macos/scripts/notarize.sh
```

`notarize.sh` refuses an ad-hoc build and a bundle built from a modified tree, submits the app as
a zip, staples the ticket to it, rebuilds and signs the disk image from the stapled app, submits
and staples that, and ends with `spctl` reading `accepted` for both. Until it has run, Gatekeeper
answers `rejected (Unnotarized Developer ID)` for the app on any Mac that did not build it, and
`troubleshooting.md` §25 step 1 reads that back to the operator.

**A release.** Build from the release commit, notarize, and put
`macos/build/LoonInspect-<version>-arm64.dmg` on the GitHub release while it is still a draft:
this repository's releases are immutable, so a published one takes no more files. The disk
image holds the app and an Applications link; a user drags one onto the other and opens it.
The GitHub Action does this when it is run from main with the release's tag: it builds,
notarizes and makes the draft release holding the files, and publishing that draft is the
release. A run without a tag saves workflow artifacts. CI requires the app version and backend
`RELEASE` to agree and validates main ancestry before importing signing credentials, and at
publication it checks that the release carries the files. Environment setup and the full flow
are in
[`macos/README.md`](../macos/README.md#github-actions).

### Finding text and searching records

**Edit → Find → Find in Page…** (⌘F) opens a native find bar. Type literal text; **Return** or
**⌘G** moves to the next match, **Shift-Return** or **⇧⌘G** moves back, and the search wraps at
both ends. **Match case** makes matching case-sensitive. **⌘E** uses selected page text.
**Escape** or **Done** closes the bar and returns focus to the page. Queries stay in memory
for this app session; page finding sends nothing to the backend or an AI provider.

Find searches the **loaded page text**, including content below the visible area. It does not
fetch another result page, expand a collapsed section, or search hidden/password fields.
**No matches on this page** does not mean there are no matching inventory records. Use
**Go to page search**, when offered, to focus the page's existing search controls. The handoff
preserves their text and filters and does not submit them.

**Go to AI search** appears only where the page already offers an available AI search:
the Changes Prompt bar or the Vulnerabilities AI lever, with its existing flag, consent,
and saved-provider gates satisfied. It focuses that prompt or explicitly selects the page's
AI mode. It does not copy the Find query, send page content, or submit a question. Review and
submit the question using the page's own controls. AI availability never changes what ⌘F does.

A route change rechecks the retained Find query. If loaded content changes after a result,
the bar says **Page content changed**; press Return to find in the updated content. Find is
unavailable while the native startup/recovery screen is showing.

### Updates

**The check.** About once a day the app asks LoonSec's update service, as the container does
(`troubleshooting.md` §10), whether a newer release exists: one `POST` to
`https://api.next.loonsec.io/v1/update` of five keys, the contract word (`v1`), the release, the
kind (`mac-app`, from the `INSTANCE_KIND` the shell sets), how far setup has got (`unclaimed`,
`claimed`, `connected` or `collecting`) and the day number LoonSec gave its last answered check,
once there is one. No instance identifier, no inventory. The banner and **Settings › Support › Updates** say when a
newer release exists, and from the app (`kind` `mac-app`) they print its own steps, the three
below, with a link to the release's page, where the disk image is: never a compose command. The
block's sentences are the app's where the container's would be false: *Checking is off* names
the menu item below, the backup is the copy of `pgdata` in [Backup](#backup), and the step back is
the one below. It asks only while the app is open and the Mac awake, so on the days the app is used;
nothing wakes it to check, and a check owed meanwhile is asked once the app runs again.

**The switch** is **LoonInspect › Check for Updates Daily**, on until it is turned off, which
sets `UPDATE_CHECK`. The choice is kept in the app's preferences (`CheckForUpdatesDaily` in
`io.loonsec.looninspect`), outside the bundle, so an update keeps it. Off, the backend asks
nothing. A change while the app runs restarts the backend at once on the same port: the window
reads *Restarting LoonInspect*, then reloads its page, and a collection run in progress stops as
at Quit. `defaults write io.loonsec.looninspect CheckForUpdatesDaily -bool false` is the same
switch, applied the same way by a running window and at start by `--headless`. An
`UPDATE_CHECK_URL` in the app's own environment is passed as it is and names only where the
check asks: the menu item still decides whether it asks. An `UPDATE_CHECK` there is passed too
and wins; the item is then dimmed and shows the stored choice, the one a launch without it uses.
With `UPDATE_CHECK=false`, or a URL naming a stand-in of your own, a test starts the app counted
nowhere ([`macos/README.md`](../macos/README.md#build-and-run)). `shell.log` says at every start
what the backend was told and from where (*update check: the backend is told …*).

**Taking an update** is by hand, with the newer disk image from the release page.

1. **Quit LoonInspect**, from the menu or with ⌘Q. Closing the window is not quitting: the
   backend and Postgres keep running, and the app must not be replaced under them.
2. **Open the newer disk image and drag LoonInspect onto Applications**, replacing the old app.
3. **Open it.** The launch runs the newer release's migrations, as the container's first start
   does, before the window loads.

What an update keeps: everything outside the bundle. The data directory, the three keychain
items, `preferred-port` and the preferences are the ones the older app made, so accounts, connections with their
credentials, settings, inventory, the port and Check for Updates Daily all carry over, and a browser session opened with
**Open in Browser** stays signed in because the origin did not move. What it replaces: the
bundle, and so the backend, the frontend, the runtimes and the shell.

**Stepping back** is the same three steps with the older disk image, and it obeys the image's
rule (`operations.md` §5): a build that finds a schema revision it does not carry reads the
database's release record, starts without migrating when its own `RELEASE` is at or above the
record, and refuses with a sentence naming both when it is below. 1.2.0's migration records that
v1.1.0 reads its schema, so 1.1.0 starts on a database 1.2.0 migrated and `backend.log` says *…which recorded
that v1.1.0 or later can read it; this image is v1.1.0 (build …), so it starts without
migrating*. The table 1.2.0 added stays, unread, and going forward again migrates nothing. 1.0.0
is below the record and refuses (*…so it will not start on it*); `troubleshooting.md` §25 step 5
is the refusal's step-through. An older app has no menu item and starts its backend with the
check off whatever the item said; the choice stays in the preferences, unread, for 1.2.0.

A Postgres major (17 to 18) would need `pg_upgrade` or a dump and restore, the same question the
container's database volume has. The backup before any of this is [Backup](#backup): a copy of
`pgdata` taken while the app is quit.

## Backup

The bundle ships no `pg_dump`, so `operations.md` §2 cannot be run against the app
(KNOWN_ISSUES.md §10). The backup that exists:

1. Quit the app. A copy of `pgdata` taken while Postgres runs is not a consistent database, which
   is why the app marks `pgdata` excluded from Time Machine (`tmutil isexcluded` reads
   `[Excluded]`).
2. Copy `~/Library/Application Support/LoonInspect/pgdata`.
3. Preserve the matching login Keychain items under service `LoonInspect`: `ENCRYPTION_KEY`,
   `postgres-looninspect_app`, and `postgres-looninspect`. Without `ENCRYPTION_KEY`, the stored
   connection credentials are unreadable (`operations.md`, "ENCRYPTION_KEY is not optional").
   The database passwords must also match the copied cluster. Keep these secrets in protected
   backup storage; an installer or a copy of `pgdata` does not contain them.

A restore puts the directory back with the app quit and all three matching Keychain items
available to the receiving macOS user. A restore into the original user account may retain those
items; copying files to another Mac does not transfer them. Do not replace a missing encryption
key with a new one: that cannot decrypt the original credentials. There is no built-in migration
assistant. Keep the original database and Keychain backup until the restored instance has been
verified. This procedure backs up the database; preserve `data/` and `logs/` separately if their
audit and diagnostic history is needed.

## What it leaves out

- **It runs only while it is open**, and a sleeping Mac pauses it (KNOWN_ISSUES.md §10). A
  login-item or LaunchAgent mode (`SMAppService`) is the likely answer, and it reopens what
  **Quit** means.
- **The setup claim exchange** stays, shell-held, by Kyle's ruling of 2026-10-06; gutting it is a
  backend change and a ruling, owed before a public release.
- **No update mechanism.** The app says that a newer release exists, and taking it is
  [by hand](#updates). Sparkle 2 (an EdDSA-signed appcast and a URL to host it) or a Homebrew
  cask would take it. Undecided.
- **No `pg_dump`.** EnterpriseDB's client binaries (zonky's own upstream) with a Back Up command
  in the app menu would give `operations.md` §2 to the app.
- **The keychain items trust `/usr/bin/security`**, so any process of the same user reads them
  without a prompt, the reach of a 0600 file without the copy on disk. An item that trusted only
  the app's Developer ID signature would prompt every other reader, but the same secrets sit in
  the backend's environment, which the same user can read with `ps -E`, as they sit in the
  container's; the move to `SecItem` is worth making once the backend takes them another way (a
  password-less URL and a passfile, a key read from a descriptor).
- **Intel.** The Postgres build is universal and python-build-standalone publishes x86_64; the
  wheels would need x86_64 builds, two bundles or a merged tree. Worth doing only if asked for.
- **Logs rotate at launch only.**
- **Size.** 11 MB is `fastapi[standard]`'s command line (fastapi-cli, typer, rich-toolkit and
  friends), which the running server never imports; 29 MB is ICU data EnterpriseDB's Postgres
  links and the builtin locale never uses. Dropping either is a dependency or a build of our own.
- **Export validation.** Downloads have a save dialog and completion/error feedback. The
  historical 1.0.0 validation below did not exercise the evidence report and data-sharing export
  end to end. JavaScript `alert` and `confirm` are not implemented; the frontend uses neither.

## Measurements

From the build of `edf7caa` on 2026-11-10 (a modified tree: this document's branch before its
commit), on one Mac: Apple silicon, macOS 27.3, Xcode 27.2, Swift 6.4, node 26.8.1, with the
Developer ID signature and the hardened runtime on every file. Each first launch started with no
support directory and no keychain items.

| What | Number |
| --- | --- |
| Bundle | 217 MB, 7,707 files; 137 Mach-O files signed; the disk image 75 MB (`UDZO`, zlib 9) |
| Build | 187 s end to end with the downloads, npm and wheel caches warm: 163 s to the signed bundle (the wheels 66 s, the signatures with their timestamps 78 s), 24 s for the disk image. The first build, with a cold wheel cache, took 157 s to the bundle. The spike's ad-hoc builds took 43 s; the timestamps are most of the difference. |
| First launch, headless, to `/api/health` 200 | 2.55 s, initdb and all migrations included |
| First launch, `open` to health 200, window on `/setup` | 1.14 s (the database already made by the headless run before it); the page reported 2.1 s later |
| Later launches to health 200 | 0.71 to 0.84 s headless; 0.97 s from `open` |
| Quit to no process left | 0.45 and 0.50 s through AppleScript; 0.37 to 0.47 s on SIGTERM headless |
| Shell SIGKILLed | Backend and Postgres both gone 0.45 s later, through the watchdog; Postgres logged a fast shutdown and *database system is shut down* |
| Memory at rest, sign-in page shown | Shell 99 MB RSS (WebKit's own processes not counted), backend 184 MB, the postmaster 23 MB |
| Support directory after setup | 50 MB |

## Validation (1.2.0)

The update from 1.1.0, walked on the Mac above on 2026-11-20 UTC, headless (#821). Both apps were
built by `macos/scripts/build-app.sh` and signed with the Developer ID: 1.1.0 from the `v1.1.0`
tag (`21521d89`, build `20261119.0328`, `backend_release: v1.1.0`), 1.2.0 from `main` at
`1048293a` (build `20261120.0339`, `backend_release: v1.2.0`). Each was copied over the one in
an Applications folder of the walk's own. It replaces the walk of 2026-11-18 (#812), whose
candidate had neither the migration nor the update check.

Every launch had `UPDATE_CHECK_URL` in the app's environment, naming a stand-in on `127.0.0.1`
that records each request and answers in the shape #819 gives. No development service answers
the update check yet, and nothing was sent to the production one. The Mac's lid was closed and
it slept in stretches; a figure a sleep fell across is not quoted.

- **A 1.1.0 instance, from nothing.** Set up through the API with the session's claim token: an
  administrator, the `jamf_patch` flag on, an exclusion pattern, a destination with a stored
  secret, and a patching rule confirmed from the Cyber Essentials entry. Its update status read
  `disabled`, as 1.1.0's shell makes it, and the stand-in saw nothing from it. Quit:
  nothing left running in 0.46 s. (Its first launch is not timed here; the same app was healthy
  1.9 s after launch in a dry run earlier the same day.)
- **The update.** The 1.2.0 app over the 1.1.0 app, same data directory and keychain items.
  Healthy 1.2 s after launch on the same port. `backend.log` shows the one migration 1.2.0 adds:
  `f794a1c3d5e7 -> e819a4c2f6b3` (the update check's row). `shell.log` said *update check: the
  backend is told INSTANCE_KIND=mac-app and UPDATE_CHECK=true, from Check for Updates Daily;
  UPDATE_CHECK_URL is passed from the app's environment*. The session cookie minted under 1.1.0
  still answered `/api/auth/me`. Of 50 answers read under each, 45 were the same; the other five
  were two clocks, the catalogue entry's link and read date in the catalogue and under the
  confirmed rule, and the update status, which now has something to say. The stored secret was
  read and used (the destination test reached name resolution, which is past the decrypt). The
  three keychain items were the same values (compared by digest).
- **The check.** Before any check the status read `kind: mac-app`, the once-only notice
  pending, and a next body of `{"contract":"v1","release":"v1.2.0","kind":"mac-app",
  "stage":"claimed"}`: an account, and no MDM connection. With `update_check_state.next_check_at`
  moved back in the app's own database, nothing arrived within 100 seconds the first time; made
  due again, the stand-in received exactly that body. (On a fresh launch of the same build a
  due check arrived after a minute both times it was tried, below.) The notice was then
  dismissed through its route.
- **The choice, across a relaunch.** `defaults write io.loonsec.looninspect
  CheckForUpdatesDaily -bool false`, which is what the menu item writes, then quit and open:
  `shell.log` said *UPDATE_CHECK=false, from Check for Updates Daily*, and the status read
  `disabled`, with the body the last check sent still shown and no next body.
  The same build, launched again from nothing with its waits counted in time the Mac was awake:
  a due check arrived after a minute (`"stage":"unclaimed"`); with the choice off, across a
  relaunch, a check was due for 201 seconds and the stand-in received nothing; with the choice
  on again, across another relaunch, the next due check arrived after a minute and carried
  `"last":20777`, the day the first had been given.
- **The step back.** The 1.1.0 app over the 1.2.0 app: healthy 1.0 s after launch, with
  *…its schema is at revision e819a4c2f6b3, which this image does not carry… so it starts
  without migrating* and `database ready, at a newer release's schema, nothing migrated`. The
  session was still signed in, and every answer read as it had before the update, the two
  clocks aside. This is the path the walk of 2026-11-18 could not reach.
- Afterwards the support directory, the three keychain items and the preference were removed;
  this walk had made them all.

**Not run:** the window and a click on the menu item (the preference was written directly),
notarization of 1.2.0 and a launch from a quarantined download (the release workflow does the
last two at publication), the check against LoonSec's own update service, the update on an
instance with inventory (the container's walk is in [the release notes](releases/v1.2.0.md)),
and a second Mac.

## Validation (1.1.0)

The update from 1.0.0, walked on the Mac above on 2026-11-15, headless unless said. Both apps
were built by `macos/scripts/build-app.sh` from clean trees and signed with the Developer ID:
1.0.0 from `main` at `a2d75cb` (the commit the notarized 1.0.0 workflow artifact of 2026-11-13
was built from), 1.1.0 from the release-prep branch at `e2300e4` (build `20261115.1442`,
`backend_release: v1.1.0`, 89 s end to end). Each was installed the way a user installs it: its
disk image mounted, and the app copied over the one in an Applications folder.

- **A 1.0.0 instance, from nothing.** First launch healthy in 2.66 s. Set up through the API with
  the session's claim token: an administrator, the `jamf_patch` flag on, an exclusion pattern,
  and a destination with a stored secret. Quit: nothing left running in 0.29 s.
- **The update.** The 1.1.0 app over the 1.0.0 app, same data directory and keychain items.
  Healthy in 1.67 s on the same port (`50722`). `backend.log` shows the two migrations 1.1.0
  adds to what 1.0.0 already had: `a4d7e1c9b2f3 -> c793a1f5d2e8` (promoted applications) and
  `c793a1f5d2e8 -> f794a1c3d5e7` (the Fleet catalog). The session cookie minted under 1.0.0 still
  answered `/api/auth/me`. Accounts, the destination, the flags, the sharing settings and the
  setup status read as they did under 1.0.0, and the two new flags listed, off. The stored secret
  was read and used (the destination test reached DNS resolution, which is past the decrypt).
  The three keychain items were the same values (compared by digest).
- **The step back.** The 1.0.0 app over the 1.1.0 app: healthy in 1.67 s, with the *starts
  without migrating* warning quoted under [Updates](#updates) and `database ready, at a newer
  release's schema, nothing migrated`. Every value read as it had before the update.
- **Forward again.** The 1.1.0 app: healthy in 1.67 s, no migration run.
- **Windowed.** `open` on the 1.1.0 app: healthy in 1.2 s, and the shell logged the window on
  `/login` with a password field. `osascript -e 'quit app "LoonInspect"'`: everything gone in
  0.48 s.
- An earlier pass the same day, with a 1.1.0 that differed from 1.0.0 only in its two version
  numbers, gave the same results with no migration to run.
- Afterwards the support directory, the three keychain items and the window's WebKit and cache
  entries were removed; this session had made them all.

**Not run:** notarization of 1.1.0 and a launch from a quarantined download (the release
workflow does both at publication, and a `v1.1.0-rc.1` prerelease is the way to see them before
the release); the update on an instance with real inventory (the container's walk of the same
migrations is in [the release notes](releases/v1.1.0.md)); a second Mac.

## Validation (1.0.0)

On the Mac above, on 2026-11-10, against the working tree that became this branch's commit; the
`spike/macos-app` checks of 2026-10-06 (a first launch cut short three ways, the role's
privileges over the socket, the window's form driven by script) were not repeated, since the code
they covered is the spike's, re-read and unchanged except as this document says.

**Build and signature**
- `macos/scripts/build-app.sh` from a clean `macos/build` (downloads cached), twice: the second run,
  after the fix below, exit 0 in 187 s, end to end through the disk image; 217 MB, 7,707 files. Every Mach-O file under `Contents/Resources` (137) and the bundle verify with
  `codesign --verify --strict`, and each reads `flags=0x10000(runtime)` under `Authority=Developer
  ID Application`. `codesign --verify --strict --deep` of the bundle: *valid on disk, satisfies its
  Designated Requirement*. `Info.plist`: `io.loonsec.looninspect`, `1.0.0`, build `20261110.1927`,
  `CFBundleIconFile` `LoonInspect`. The manifest records the commit, `tree: modified`, and
  `backend_release: v1.0.0`.
- `spctl --assess --type execute`: *rejected, source=Unnotarized Developer ID*, the verdict this
  document and troubleshooting §25 say to expect before `notarize.sh` has run.
- `package-dmg.sh`: a 75 MB image that `hdiutil verify` accepts, signed with the same identity
  and timestamp; mounted, it holds `LoonInspect.app` (verifies, `1.0.0`) and the `Applications`
  link. `spctl --assess --type open`: *rejected, Unnotarized Developer ID*, likewise.
- The first run of the build stopped at its own check with every file reported as lacking the
  runtime: `grep -q` under `pipefail` fails the pipeline when codesign dies of SIGPIPE. Fixed to
  read the whole output; the check then passed on the same bundle, 137 files, 0 failures.
- `shellcheck` (`koalaman/shellcheck:stable`) on the five scripts: clean. `ruff check` and
  `ruff format --check` (0.17.3, the lockfile's) on `macos/launcher`: clean. `swift build -c
  release`: no warnings. The icon renders at all ten sizes; `iconutil` wrote a 173 KB `.icns`.
- Frontend, on the host: `npm run typecheck` exit 0; `npm run lint` 0 errors and the 4 warnings
  `main` has; `vitest run` 56 files, 677 tests passed (`SetupPage.test.tsx` holds 3).
  `test_docs_index.py`'s five functions, called with the host's Python: pass.

**Launches**, headless unless said, from no support directory and no keychain items:
- First launch: health 200 in 2.55 s. `/api/auth/status` read `setupRequired: true` with the
  build stamp `2026.11.10+edf7caa`. `ps`: `postgres` and `python3` from the bundle, children of
  the shell. `lsof`: Postgres with no TCP socket; Python listening on `127.0.0.1` only.
  `tmutil isexcluded pgdata`: `[Excluded]`, the attribute on the directory. The socket in `run/`.
  The three keychain items under `LoonInspect` were made, and `grep -rlaF` found none of their
  values in any file under the support directory.
- SIGTERM: the shell exited 0 in 0.47 s; no process from the bundle left; no `postmaster.pid`.
- Second launch: health in 0.83 s, the same port. A second `--headless` meanwhile exited 1 with
  *Another LoonInspect is already running*, and the first stayed healthy.
- SIGKILL of the shell: the watchdog stopped the backend and Postgres within 0.45 s;
  `postgres.log` ends with a checkpoint and *database system is shut down*. The launch after it was
  healthy in 0.84 s.
- Windowed, unclaimed (`open`): health in 1.14 s; `shell.log` says the token was handed to the
  window, which reported `{"path":"/setup","passwordField":true,"claimField":false,"tokenHanded":true}`;
  a capture of the window shows the setup page with no claim field, the caret in the display
  name field, and the build stamp. `osascript -e 'quit app "LoonInspect"'`: everything gone in 0.50 s.
- Setup through the API with the token from this session's `backend.log`: `POST /api/auth/setup`
  201 (an address under a reserved domain was refused 422 first, as the validator should); `POST
  /api/auth/login` 200; `/api/auth/me` the administrator with role `admin`; `/api/system/version` 200.
- Relaunch: health in 0.72 s, `setupRequired: false`, the earlier session cookie still answered
  200 on `/api/auth/me`.
- Windowed, claimed: *no usable setup claim token in this session's backend log; none handed to
  the window*; the window reported `/login` with a password field and `tokenHanded: false`; a
  capture shows the sign-in page. Quit: gone in 0.45 s.
- Rotation: with `postgres.log` replaced by a 21 MB file, the next launch logged *rotated
  postgres.log (21 MB) to postgres.log.1*, `postgres.log.1` is that file, and the new
  `postgres.log` holds this session's lines.
- Afterwards the support directory, the three keychain items and the window's WebKit, cache
  and preferences entries were removed; this session had made them all.

**Not run:** notarization and stapling (`notarize.sh` needs the maintainer's notarytool profile,
which this Mac does not hold; the script is written to the documented commands and read, not
exercised); a second Mac, Intel, or a copy opened from the disk image under quarantine; the
socket fallback under `/tmp` (a changed `HOME` does not move Application Support, so the long
path could not be produced; the code is reviewed, not exercised); a file download from the
window; the first-launch-cut-short cases the spike ran; anything longer than a few minutes of
running; the backend suite (nothing under `backend/` changed).

## Identifying the app in a support report

The sidebar and My Account show the Mac app release. Settings → Support lists **App version**,
**App build**, and **Backend build** separately; Copy includes all three. App version and build
are the values in LoonInspect → About LoonInspect. The backend's date-plus-commit stamp remains
available for update checks and diagnostics. This information is available after sign-in.

An older package can report **Not recorded** for its app fields. Read those values in About
LoonInspect and include them with the backend build; a date-plus-commit stamp is not an app release.
