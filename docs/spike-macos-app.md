---
question: Can LoonInspect ship as a macOS application instead of a container?
owner: kylepazandak
opened: 2026-10-06
review-date: 2026-10-20
---

# LoonInspect as a macOS app: a packaging spike

Status: spike, 2026-10-06, branch `spike/macos-app`, a draft pull request that is not for merge
as is ([BRANCHING.md](BRANCHING.md) §3.1: a spike's code is never merged; this finding is what
moves on). Built and measured on one Mac: Apple silicon, macOS 27.2, Xcode 27 (Swift 6.4).

## The answer

Yes, as a packaging job rather than a port. An unsigned `LoonInspect.app` built from this
branch launches on this Mac, creates its database, runs all 73 migrations, and shows the
first-run setup page (and the sign-in page on every launch after setup) in its own window.
Quitting, even part-way through the first launch, leaves no process behind and no password in a
file. The backend is unchanged. The frontend's one change: in the app's window the setup page
asks for no claim token, because the shell hands it this session's. They run as they do in the
image, with PostgreSQL 17 beside them as a child process instead of a sidecar container.

| Measure | Result |
| --- | --- |
| Bundle on disk | 217 MB, 7,679 files (81 MB zipped with `ditto -c -k`) |
| First launch, `open` to `/api/health` 200 | 2.00 to 2.06 s over three runs, initdb and all 73 migrations included |
| Later launches, `open` to `/api/health` 200 | 1.03 to 1.08 s over three runs |
| Quit (`osascript -e 'quit app "LoonInspect"'`) to no process left | 0.43 to 0.66 s over seven quits |
| Clean build, `rm -rf macos/build` to a signed bundle | 43 s, downloads included (npm cache and the uv image already local) |

Nothing blocked the deliverable. What is left before anyone else can run it is signing,
notarization, an update story and the decisions in [Needs Kyle](#needs-kyle).

## What was built

All of it is under `macos/` ([macos/README.md](../macos/README.md)). Four other files changed:
the row for this document in [docs/README.md](README.md), which `test_docs_index.py` requires;
a `.dockerignore` entry that keeps `macos/` out of the image's build context, since a
local `macos/build` holds about 700 MB (downloads, a copy of the frontend with its
`node_modules`, the bundle and its zip); and `frontend/src/features/auth/SetupPage.tsx` with a
test beside it, for the claim token (see [How it runs](#how-it-runs)). Nothing under `backend/`
changed.

| Path | Job |
| --- | --- |
| `macos/scripts/fetch-runtime.sh` | Downloads two pinned artifacts into `macos/build/downloads` and checks each one's version and sha256. A mismatch, fresh or cached, stops the script. The pins: CPython 3.12.15 from python-build-standalone release 20261003 (`aarch64-apple-darwin-install_only`, the release's SHA256SUMS entry, which equals GitHub's asset digest), and zonky `embedded-postgres-binaries-darwin-arm64v8` 17.11.0 from Maven Central (its published `.sha256`). |
| `macos/scripts/build-app.sh` | Builds the bundle from the working tree. It copies an allowlist of paths, so a local `backend/.env` never rides along (INSPECT-0175). Then: frontend `npm ci && npm run build`; `uv export --frozen --no-dev --no-emit-project` run inside Docker; `pip install --require-hashes --no-deps --only-binary=:all:` into the bundled Python on the host, so every wheel is a macOS arm64 one; prune; compile bytecode; Postgres; `swift build -c release`; Info.plist; ad-hoc signature; a check that every Mach-O file verifies; sizes. |
| `macos/shell/` | The Swift shell, a SwiftPM executable with no Xcode project. The window is a `WKWebView`. The app menu has Open in Browser, Show Logs in Finder and Quit. The supervisor starts and stops the children. `--headless` does everything except the window. |
| `macos/launcher/loon_backend.py` | The backend's entry point: `app.serve.main()` and a watchdog. If the shell dies, the watchdog sends the backend the SIGTERM a normal quit would have sent and, after the backend's shutdown, sends Postgres the signal `pg_ctl stop -m fast` sends. |

The bundle's `Contents/Resources/backend` is laid out like the image's `/app`: `app/` with the
SPA in `app/static` and a `build_info.json` stamped as the Dockerfile stamps it
(`2026.10.06+4796bd0` for the build measured here), `migrations/`,
`alembic.ini`, and `docs/baseline-rules.yml`, where `app.baseline.catalogue` looks for it. The
other directories in `Contents/Resources` are `python/` (the interpreter and the 56 locked
packages that apply to macOS), `postgres/` (`bin`, `lib`, `share`) and `launcher/`.

## How it runs

```
LoonInspect                       Contents/MacOS, the Swift shell
├── postgres -D …/pgdata          Contents/Resources/postgres/bin, Unix socket only, no TCP
└── python3 loon_backend.py       Contents/Resources/python/bin, app.serve on 127.0.0.1:<port>
```

The app's own files are all in `~/Library/Application Support/LoonInspect-Spike`, mode 0700.
The `-Spike` suffix keeps it apart from any future real app.

| Path | Holds |
| --- | --- |
| `pgdata/` | The database cluster. |
| `run/` | The socket (`.s.PGSQL.5432`), `port` (the chosen port, written for anyone who wants to reach the UI), and `shell.lock` (one instance at a time). |
| `logs/` | `shell.log`, `postgres.log`, `backend.log` (the container's JSON stdout, line for line) and `initdb.log`. |
| `data/` | The backend's `./data`: the backend runs with this directory as its working directory, so the audit log lands here as it lands on the container's volume. |
| `preferred-port` | Last launch's port, which the next launch reuses if it is free. The UI's origin then stays the same, and so does its per-origin browser storage. |

The window adds three paths, which macOS and WebKit name after the bundle identifier as they do
for any app with a web view:

- `~/Library/WebKit/io.loonsec.looninspect.spike`, the page's site data, such as local storage.
- `~/Library/Caches/io.loonsec.looninspect.spike`, WebKit's HTTP cache.
- `~/Library/Preferences/io.loonsec.looninspect.spike.plist`, the window's frame.

After all of today's runs they held 0.8 MB, 1.9 MB and one setting, and none held a keychain
value. The reset in [macos/README.md](../macos/README.md) removes all three.

The secrets are three generic passwords in the login keychain under the service
`LoonInspect-Spike`: `ENCRYPTION_KEY` (a Fernet key), `postgres-looninspect_app` and
`postgres-looninspect`. All three are generated on first launch, and none is written to a file.
initdb reads the superuser's password from its stdin, a pipe, and the role's password reaches
single-user Postgres the same way. A later launch that finds the database but not the key
refuses to start and says why, rather than mint a new key that would leave every stored
credential unreadable (KNOWN_ISSUES.md §5).

The items trust `/usr/bin/security`, which made them (see below). Any process running as this
user can therefore read them with `security find-generic-password -w`, with no prompt, as the
test script did unattended. That is the reach of a 0600 file in the support directory, without
the copy on disk. A Developer ID build can make items that prompt every other reader
([Needs Kyle](#needs-kyle) 1).

**First launch.** `initdb` runs with these flags:

- `-U looninspect --pwfile=/dev/stdin --auth=scram-sha-256`. The superuser is the one the
  container creates, and its password arrives on initdb's stdin. The container trusts every
  socket connection (stock docker-entrypoint); here the socket asks for a password as well,
  inside a 0700 directory.
- `--encoding=UTF8 --locale=C --locale-provider=builtin --builtin-locale=C.UTF-8`. This
  gives code-point ordering and Unicode case mapping without macOS's libc locale tables. The
  container's `en_US.utf8` under musl orders by code point too, because musl has no collation.

The cluster is built as `pgdata.initdb` and renamed only when it is complete. Then comes what
the image's first boot does: the entrypoint's `CREATE DATABASE looninspect`, and the two
statements of `ops/postgres/initdb/10-app-role.sh`, `CREATE ROLE looninspect_app … NOSUPERUSER
NOCREATEDB NOCREATEROLE NOBYPASSRLS` and `ALTER SCHEMA public OWNER TO looninspect_app`. They
run in single-user mode, because zonky's build has no `psql`. That also means nothing can
connect while they run. Two flags are needed there: `exit_on_error=on`, because single-user mode
otherwise exits 0 after an error, and `log_min_error_statement=panic`, because a failing
`CREATE ROLE` is otherwise echoed into the log with its password (seen in a test, then fixed).

A quit during any of this stops the tool that is running: initdb answers SIGTERM by deleting
what it built, and single-user Postgres exits. No later step starts, and the shell removes
`pgdata.initdb` if it is still there. A launch after a crash removes it before starting over.

**Every launch.** The shell runs these steps:

1. Takes the instance lock.
2. Stops a Postgres left running by an earlier session, if `postmaster.pid` names a live
   process whose command line is this data directory's.
3. Starts `postgres -D pgdata -c listen_addresses= -c unix_socket_directories=<run> -c
   port=5432`. Here 5432 only names the socket file. This Mac's other Postgres, Splunk's on
   `*:5432`, was running throughout and never collided with it.
4. Waits until `postmaster.pid` reports `ready` for that PID, which is `pg_ctl -w`'s own test.
5. Picks the port.
6. Starts the backend with the environment below.
7. Polls `/api/health` until it answers 200, showing a waiting page meanwhile, or an error page
   that names the log if it never does.
8. Loads `http://127.0.0.1:<port>/`.

Links that leave the instance are meant to open in the default browser, and file downloads to
go to `~/Downloads`. Both are written; neither was exercised.

| Setting | Container | App | Why |
| --- | --- | --- | --- |
| `HOST`, `PORT` | `0.0.0.0:8001` | `127.0.0.1:<free port>` | Nothing off the Mac can reach it. |
| `TLS_MODE` | `off` by default | `off` | Loopback only. |
| `DATABASE_URL` | `…@db:5432/looninspect` | `postgresql+asyncpg://looninspect_app:<pw>@/looninspect?host=<run dir>` | asyncpg takes a `host` that starts with `/` as a socket directory. The space in "Application Support" stays literal, since a `%20` would break Alembic's ConfigParser (`migrations/env.py`). |
| `DATABASE_MODE` | `bundled` | `bundled` | Same promise: the role was made right at first boot. |
| `ENCRYPTION_KEY` | `.env` | login keychain | Never in a file. |
| `SECURE_COOKIES` | `true` | `false` | Plain HTTP on 127.0.0.1 only, so no cookie crosses a network. WebKit's handling of Secure cookies over `http://127.0.0.1` is not something to lean on, and Open in Browser may well be Safari. |
| `UPDATE_CHECK` | `true` | `false` | Its banner tells an operator to pull a new image. How an app updates is an open question (see below). |
| Everything else | compose's defaults, which equal `config.py`'s | `config.py`'s defaults | pydantic-settings reads `.env` from the working directory, which here is the support directory. Not tried. |

**The first administrator.** The backend mints and logs a claim token while no account exists,
as in the container, and `INITIAL_ADMIN_*` is not used. The shell reads this session's token
from `backend.log` and hands it to its own window and nothing else: a `WKUserScript`, run at
document start in the main frame only, defines a read-only `window.looninspectSetupClaimToken`
when the page's origin is `http://127.0.0.1:<port>`. The setup page sends that token and draws
no claim field and no `docker compose logs` help. No URL, file, pasteboard or shell log line
carries it. Setup is meant to happen in the app window: a browser opened with Open in Browser
gets no token and shows the container's page, whose token is in this session's
`logs/backend.log`.

**Quit.** Quitting from the menu, with ⌘Q, through AppleScript or at logout, or with SIGTERM,
SIGINT or SIGHUP, stops the backend first: SIGTERM, which uvicorn answers with its graceful
shutdown, and SIGKILL if that takes more than 15 s. Then `pg_ctl stop -m fast`, and only then
does the app exit. If the shell itself is killed (SIGKILL, a crash), the backend's watchdog
notices within a second and takes both steps from inside the backend. It sends SIGTERM to the
backend's own process. Once uvicorn is done, it sends Postgres SIGINT, which is what `pg_ctl
stop -m fast` sends. It signals only the postmaster this shell started, and only while
`postmaster.pid` still names it, because a newer launch may have stopped it and started its own
by then. If the shell dies before the backend has started, Postgres keeps running until the next
launch, which stops it first. A second copy of the app refuses to start, says that one is
already running, and leaves the running one alone.

## Measurements

From the clean build of commit `4796bd0`, on this Mac. Each first launch had no data
directory and no keychain items; the later launches followed the third.

| What | Number |
| --- | --- |
| Downloads | CPython 25.1 MB, zonky jar 62.1 MB (3 s for both here) |
| Build, clean | 43 s wall (41, 46 and 50 s on the three clean builds before it); the steps took 3 s (downloads), 6 s (frontend), 9 s (Python and wheels), 1 s (backend and bytecode), 6 s (Postgres), 7 s (Swift), 3 s (signature check), 7 s (sizes and zip) |
| Bundle | 217 MB: Python 136 MB (site-packages 97 MB; `.pyc` files across both, 46 MB); Postgres 70 MB, of which 29 MB is ICU data; backend 7.7 MB, of which the SPA is 1.7 MB; shell 324 KB |
| Zipped | 81 MB |
| First launch | 2.00, 2.06 and 2.04 s from `open` to health 200. The shell's clock for the third read 2.04 s in all: 0.16 s for AppKit to start and call the supervisor, 0.18 s keychain (three items made), 0.60 s initdb and role, 0.05 s Postgres start, 1.05 s backend. Of the backend's time, 0.09 s goes to uvicorn's binding line, 0.54 s more to imports and Alembic's setup, 0.25 s to the 73 migrations on the empty database, and up to 0.2 s to the shell's next look at `/api/health`. The window's page load finishes about 0.2 s after health. An earlier build's single sample was 2.76 s, with a 1.12 s initdb. |
| Later launches | 1.04, 1.03 and 1.08 s from `open` to health 200; 0.86 s headless. Postgres is ready 0.09 s into the supervisor's start, and uvicorn's startup completes at 0.77 s. |
| Quit | 0.43 to 0.66 s through AppleScript, over seven quits; 0.38 s on SIGTERM to the windowed app; 0.29 and 0.38 s headless; 0.33 s when quit 0.6 s into a later launch |
| First launch cut short | No process and nothing on disk left, 0.12 s after a SIGTERM during initdb, 0.20 s after one during single-user `CREATE DATABASE`, and 0.45 s after an AppleScript quit during initdb. The next launch was an ordinary first launch, healthy in 2.04 s. |
| Shell killed with SIGKILL | Backend gone 0.45 s later and Postgres 0.48 s later, both through the watchdog, which looks once a second. A relaunch at once after a second SIGKILL stopped the old Postgres itself and was healthy in 1.15 s. 4 s later its own Postgres still ran, so the old backend's watchdog had left it alone. |
| Memory at rest, setup page shown | Shell 106 MB RSS (WebKit's own processes not counted), backend 189 MB, Postgres 85 MB across 9 processes (shared buffers counted in each) |

## What worked, what blocked, what surprised

Worked first time:

- python-build-standalone 3.12.15 is relocatable as shipped, and `bin/python3.12` is static,
  so no `install_name_tool` was needed.
- The export lists 58 runtime packages. The 56 that apply to macOS (colorama and tzdata are
  Windows-only) all exist as macOS arm64 or pure-Python wheels whose hashes are in `uv.lock`.
  `--only-binary=:all:` built nothing from source. The plan expected psycopg and
  Python 3.14 to cost hours; the backend uses asyncpg, and the image runs 3.12.
- zonky's jar is EnterpriseDB's build, universal, `@rpath`-relocatable, and signed with EDB's
  Developer ID (hardened runtime, timestamped). `lipo -thin arm64` keeps each slice's signature,
  so Postgres in the bundle still verifies as EDB-signed.
- Same Postgres minor as today's `postgres:17-alpine` (17.11, read from the test database here).
- Alembic runs in-process through the socket URL; the 73 migrations take 0.25 s on an empty
  database.

Did not go as the plan said, and what was done:

- zonky ships `initdb`, `pg_ctl` and `postgres`, and no `psql`, `pg_isready` or `pg_dump`. The
  role is created in single-user mode. The role check below ran through the bundle's Python and
  asyncpg over the same socket, standing in for the task's "psql from the bundle". Backups need
  `pg_dump` (see Needs Kyle).
- The x86_64 slices of universal2 wheels (uvloop, greenlet) are not signed at all, so
  `codesign --verify` failed on them. Every Mach-O file is now thinned to arm64, which also saves
  space.
- Keychain access control lists trust the code signature that made an item. An ad-hoc
  signature is a hash of the binary, so a rebuilt shell would meet an "allow access" prompt
  that a `--headless` run cannot answer. The shell goes through `/usr/bin/security`, which Apple
  signs and which does not change. A value travels on `security -i`'s stdin, never in an
  argument `ps` could show. With a Developer ID this becomes plain `SecItem` calls.
- SIGTERM to the windowed app first hung the shell after its children had stopped. AppKit's
  `terminate:` waits for its reply in a nested run loop, and calling it from the signal
  source's main-queue block kept the main queue, where the reply is delivered, from ever
  running. Found in testing and fixed by running `terminate:` from the run loop instead.
- The host's node is v26.8.1, not 22. The frontend built cleanly with it, and the script warns
  whenever node is not 22, as the image and CI use.
- The setup page's claim-token help names `docker compose logs`, which is wrong inside an app.
  A menu item that copied the token came first. Now the shell hands the token to its window
  and the page draws no field there (Kyle, 2026-10-06), the spike's one frontend change.
- The verifier found the superuser's password left on disk. The first build wrote it to
  `run/initdb.pw` for `initdb --pwfile`, and only a `defer` on the start thread removed it. That
  never ran when a quit ended the process during initdb. Quitting 0.45 to 0.5 s into a first
  launch, twice, left the file (0600, the keychain's value) both times. initdb now reads the
  password from a pipe. The same review found `pgdata.initdb` left by such a quit, and Postgres
  left running after a SIGKILL of the shell. Both are handled now (see Quit), and the tests
  below check all three.

Where this deviates from the settled design, and why:

- The uv image is `ghcr.io/astral-sh/uv:0.9.30-python3.12-bookworm-slim`, pinned by the
  registry's index digest as well, not the floating `python3.12-alpine`. 0.9.30 is the
  Dockerfile's and CI's pin, so the export cannot drift with a new uv, and with the digest a
  re-pushed tag cannot change it either. The export is platform-neutral: markers plus every
  wheel's hash.
- Postgres is started directly (argv, no shell) rather than with `pg_ctl start`. A socket path
  with a space then needs no quoting, and Postgres is the shell's own child. It is stopped with
  `pg_ctl stop -m fast` as specified.
- No `install_name_tool` was needed anywhere. Nested code keeps its upstream signatures (EDB's,
  and the linker's ad-hoc ones), and only the bundle is signed ad-hoc. The script fails if any
  Mach-O file in the bundle does not verify.
- The backend is started through `macos/launcher/loon_backend.py` rather than `python -m
  app.serve`, for the watchdog. It calls the same `main()`. Its own SIGTERM handler runs after
  uvicorn's graceful shutdown, because uvicorn hands a signal it caught back to the handler it
  replaced. That is where it stops Postgres when the shell is gone.
- This document is at the path the plan named. [BRANCHING.md](BRANCHING.md) §3.1 names
  `docs/spikes/<slug>.md`; the front matter above is that section's.

## Needs Kyle

What each needs, as far as the spike could see:

1. **Developer ID signing.** This needs an Apple Developer Program membership and a "Developer
   ID Application" certificate in Kyle's keychain. Then everything is signed inside out, with
   `--options runtime --timestamp`: each Python Mach-O file (python3.12 and 26 extension
   modules) and the shell. EDB's Postgres binaries are already Developer ID signed with
   hardened runtime; whether notarization accepts another team's signatures inside the bundle
   is the first thing to try. Apple expects nested code in `Contents/Frameworks`,
   `Contents/Helpers` and similar, not `Contents/Resources`, so `python/` and `postgres/`
   probably move. Entitlements are to be found by testing; the likely candidate is none, since
   each process loads only its own team's libraries. The keychain items then move to
   `SecItem`, with an access list that trusts only the app's signature, so another process of
   the same user meets a prompt instead of reading them freely.
2. **Notarization.** `xcrun notarytool submit LoonInspect.zip --keychain-profile <profile>
   --wait`, then `xcrun stapler staple`. The profile comes from `notarytool store-credentials`
   with Kyle's App Store Connect API key or app-specific password. Without notarization a
   downloaded copy is quarantined, and Gatekeeper refuses it. This spike only ever ran a bundle
   built on this Mac, which carries no quarantine.
3. **Updates: Sparkle or not.** There are three options:
   - Sparkle 2, which needs an EdDSA-signed appcast and a URL to host it.
   - A banner from the existing GitHub release check, with words for an app.
   - A Homebrew cask.

   Whichever it is, the data directory survives a bundle swap and migrations run at start as
   they do now. A Postgres major (17 to 18) still needs `pg_upgrade` or a dump and restore, the
   same question the container's database volume has.
4. **Intel.** zonky's binaries are already universal, and python-build-standalone publishes
   x86_64. The wheels would need x86_64 builds, which means two arch-specific bundles or a
   merged Python tree. It is worth doing only if someone asks.
5. **Backups and a shell.** [operations.md](operations.md) §2's backup is `pg_dump` as the
   superuser. The app keeps that superuser's password in the keychain, but ships no `pg_dump`.
   Options are EDB's client binaries (zonky's own upstream), or a backup command in the app menu.
6. **Name, identifier, icon.** The spike's names are `io.loonsec.looninspect.spike`,
   `LoonInspect-Spike` and the generic icon. An icon from the loon mark is a brand decision
   ([frontend/public/brand/BRAND-USAGE.md](../frontend/public/brand/BRAND-USAGE.md)).
7. **Moving this finding.** The conversion step to `docs/spikes/macos-app.md` (BRANCHING.md
   §3.1), and whether the answer is "implementation" (a fresh `inspect-NNNN/` branch) or
   "documentation".
8. **The setup claim.** The claim exchange is a container-era AAA control; for the app it is
   held by the shell for now and needs gutting before public release (Kyle, 2026-10-06).
   Options: a loopback-only backend mode without a claim, or the shell creating the first
   account itself.

## Before it is a product

None of these needs Kyle's hands, but all of them are work:

- **It runs only while it is open and the Mac is awake.** The scheduler, the nightly sweep and
  SIEM delivery pause with it. A login-item or LaunchAgent mode (`SMAppService`) is the likely
  answer, which reopens what "Quit" means.
- **Logs grow without rotation.** The container leans on Docker's log driver.
- **Time Machine would copy a live `pgdata`**, and a copy taken that way is not consistent. The
  directory wants a backup exclusion, and backups should go through `pg_dump`.
- **macOS limits a socket path to 103 bytes.** Under `/Users/<name>` that leaves 32 characters
  for the name. The shell refuses a longer path with a sentence, and has no fallback directory
  yet.
- **Downloads are wired but untested.** These are the evidence report and the data-sharing
  export. JavaScript `alert` and `confirm` are not implemented; the frontend uses neither today.
- **The backend's environment is readable by the same user**, as in the container. It holds
  `DATABASE_URL` with the role's password, and the encryption key. A password-less URL and a
  passfile would need a backend hook.
- **Size.** 11 MB is what `fastapi[standard]` brings for the `fastapi` command line
  (fastapi-cli, fastapi-cloud-cli, typer, sentry-sdk, rignore, fastar, rich-toolkit,
  markdown-it), none of which the running server imports; dropping it is a backend dependency
  change. Another 29 MB is the ICU data that EDB's Postgres links but the builtin locale never
  uses; removing it needs a Postgres build of our own.
- **No CI job builds the app.** A macOS runner could run `build-app.sh` and the `--headless`
  checks below.
- **No troubleshooting entry.** A spike's failure sentences live in the shell, and each one
  names its log. A real app adds the step-through to
  [troubleshooting.md](troubleshooting.md) (CLAUDE.md).
- **Test hooks.** `LOON_SPIKE_SNAPSHOT` and `LOON_SPIKE_WINDOW_SCRIPT`, which the validation
  below uses to see and drive the window, come out.

## Validation

Everything here was run on this Mac on 2026-10-06, from the worktree of `spike/macos-app`. The
numbers above and the checks below are from a clean build of `4796bd0`, except the claim-token
checks at the end, which ran against a clean build of `b085bf8`.

- `rm -rf macos/build && macos/scripts/build-app.sh`, four times over the day: exit 0 each
  time. An earlier run failed on the unsigned x86_64 slices, which led to the thinning.
- `shellcheck` (`koalaman/shellcheck:stable` in Docker) on both scripts: clean.
- `ruff check` and `ruff format --check` (0.16.9, the lockfile's) on `macos/launcher` with
  `backend/pyproject.toml`'s settings: clean.
- `swift build -c release`: no warnings.
- A first launch cut short, three ways, each from no data directory and no keychain items:
  - SIGTERM to `--headless` while initdb ran
  - SIGTERM to `--headless` while single-user Postgres ran `CREATE DATABASE`
  - `osascript -e 'quit app "LoonInspect"'` while initdb ran

  Each time, `ps` found no process from the bundle, and `run/initdb.pw`, `pgdata.initdb` and
  `pgdata` were all absent. No file in the support directory held any of the three keychain
  values (`grep -rlaF`). The next launch made the database with one initdb.
- `open macos/build/LoonInspect.app` three times, each with no data directory and no keychain
  items. After the third:
  - `run/port` was written.
  - `curl /api/health` returned 200 `{"status":"ok"}`.
  - `curl /` and `curl /login` returned 200 `text/html`, the SPA (`<title>LoonInspect</title>`).
  - `/api/auth/status` returned `setupRequired: true`.
  - The window's own report read `{"path":"/setup","passwordField":true}`; a WebKit snapshot of
    the window showed the setup page.
  - `ps` showed `postgres` and `python3` running from `LoonInspect.app/Contents/Resources` as
    the shell's children.
  - `lsof` showed Postgres with no TCP socket, and Python listening on 127.0.0.1 only.
- Over the bundle's socket, with the bundle's Python and asyncpg:
  - As `looninspect_app`: `rolsuper`, `rolcreatedb`, `rolcreaterole` and `rolbypassrls` all
    `False`. `public` is owned by `looninspect_app`, and `alembic_version` is at
    `a4d7e1c9b2f3`, the repository's only head. There are 58 tables, 44 with FORCE ROW LEVEL
    SECURITY, and `client_addr` is null, which means a Unix socket.
  - As `looninspect`, with the keychain's password, which initdb had read from the pipe: a
    superuser, on 17.11, with `listen_addresses` empty.
  - A wrong password was refused for both roles.
  - No file under the support directory held a keychain value, and neither did the three
    WebKit and preferences paths.
- Persistence:
  - First-run setup through the API with the logged claim token returned 201.
  - Three relaunches through `open` followed. Each was healthy with `setupRequired: false`, and
    curl's session from before still authenticated. The window reported `/login` with a
    password field each time, and a snapshot of the first showed the sign-in page.
  - Signing in through the API with the administrator's password returned 200.
  - `initdb.log` holds one successful initdb.
- Quit, each followed by `ps`, which found no shell, `postgres` or `python3` from the bundle
  every time:
  - `osascript -e 'quit app "LoonInspect"'`, seven times
  - SIGTERM to the windowed app
  - SIGTERM to `--headless`, three times
  - quit 0.6 s into a later launch, which left no `postmaster.pid`
  - SIGKILL of the shell: the watchdog stopped the backend, then Postgres, whose log reads
    "received fast shutdown request" and then "database system is shut down".
- A SIGKILL of the shell followed at once by a relaunch: the new launch stopped the old
  Postgres and started its own, which was still running 4 s later.
- A second `--headless` while one ran: exit 1, "Another LoonInspect is already running", and
  the first was untouched.

**The claim token in the window**, `b085bf8`: `rm -rf macos/build && macos/scripts/build-app.sh`
exited 0 in 73 s (the wheels step took 25 s, against 9 s in the table's build), and the bundle
was again 217 MB and 7,679 files. The three launches below started with no support directory
and no keychain items.

- Frontend, on the host: `npm ci`, then `typecheck` exit 0, `lint` 0 errors (the 4 warnings
  main has), `test -- --run` 55 files and 656 tests (the new `SetupPage.test.tsx` holds 3), and
  `build`. Without a host token the page renders byte for byte as origin/main's does: 11,764
  bytes in English and 11,805 in German, compared once and not committed.
- `swift build -c release`: no warnings. The shell's binary has no pasteboard call left.
- First launch, healthy 2.88 s after `open` (initdb and the role took 1.10 s of it, against
  0.60 s in the table's runs): `shell.log` says the token was handed to the window, which reported
  `{"path":"/setup","passwordField":true,"claimField":false,"tokenHanded":true}`. A snapshot
  showed the setup page with no claim field and no `docker compose logs` help. `/` and `/setup`
  as curl fetches them held the token 0 times, and so did every process's command line.
- Second launch, still unclaimed: a new token was handed over. A test-only hook,
  `LOON_SPIKE_WINDOW_SCRIPT` (a file of JavaScript the window runs once), read the property's
  descriptor (`writable`, `configurable` and `enumerable` false; overwriting and deleting it
  failed) and an empty query string. It then filled in and submitted the page's own form with
  sharing unticked: `POST /api/auth/setup` answered 201 and the page moved to `/`. Sign-in
  through the API then returned 200, and `/api/auth/me` named the administrator.
- Third launch, claimed: nothing was handed over, and the window showed `/`, still signed in
  from setup. Sign-in through the API returned 200 again.
- Each of the backend's two tokens was in one file only, its own line in `logs/backend.log`, and
  in nothing under the WebKit, cache and preferences paths. `shell.log` records each handover
  without the value.
- Each `osascript` quit left no process from the bundle, after 0.61, 0.53 and 0.49 s.

Not run: anything on a second Mac, on Intel, or on a copy downloaded with quarantine; a
Developer ID signature or notarization; sign-in through the window itself (the session was made
with `curl`); Open in Browser during setup (a browser without the token gets the page's ordinary
branch, which the test and the byte comparison cover); a download; and anything longer than a
few minutes of running. At the end, the test data directory was taken out of `~/Library` and
the three keychain items were removed; this session created them (no support directory existed
before the claim-token run, so none was moved aside). The WebKit and preferences paths were
left, since earlier sessions created them. The built `macos/build/LoonInspect.app` is left in
place, so the next `open` is a first launch.

## Reproduce

```sh
macos/scripts/build-app.sh
open macos/build/LoonInspect.app        # or: …/Contents/MacOS/LoonInspect --headless
cat ~/Library/Application\ Support/LoonInspect-Spike/run/port
```

On a first launch the window's setup page asks only for the administrator's name, email and
password. To start over, see [macos/README.md](../macos/README.md).
