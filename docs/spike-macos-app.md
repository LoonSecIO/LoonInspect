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
first-run setup page (and the sign-in page on every launch after) in its own window. Quitting
leaves no process behind. The backend and the frontend are unchanged. They run as they do in
the image, with PostgreSQL 17 beside them as a child process instead of a sidecar container.

| Measure | Result |
| --- | --- |
| Bundle on disk | 217 MB, 7,679 files (81 MB zipped with `ditto -c -k`) |
| First launch, `open` to `/api/health` 200 | 2.97 s, with initdb and all 73 migrations included |
| Later launches, `open` to `/api/health` 200 | 1.08 to 1.25 s over three runs |
| Quit (`osascript -e 'quit app "LoonInspect"'`) to no process left | 0.45 to 0.60 s |
| Clean build, `rm -rf macos/build` to a signed bundle | 46 s (npm cache and the uv image already local) |

Nothing blocked the deliverable. What is left before anyone else can run it is signing,
notarization, an update story and the decisions in [Needs Kyle](#needs-kyle).

## What was built

All of it is under `macos/` ([macos/README.md](../macos/README.md)). Two other files changed:
the row for this document in [docs/README.md](README.md), which `test_docs_index.py` requires,
and one `.dockerignore` line that keeps `macos/` out of the image's build context, since a
local `macos/build` holds about 300 MB. Nothing under `backend/` or `frontend/` changed.

| Path | Job |
| --- | --- |
| `macos/scripts/fetch-runtime.sh` | Downloads two pinned artifacts into `macos/build/downloads` and checks each one's version and sha256. A mismatch, fresh or cached, stops the script. The pins: CPython 3.12.15 from python-build-standalone release 20261003 (`aarch64-apple-darwin-install_only`, the release's SHA256SUMS entry, which equals GitHub's asset digest), and zonky `embedded-postgres-binaries-darwin-arm64v8` 17.11.0 from Maven Central (its published `.sha256`). |
| `macos/scripts/build-app.sh` | Builds the bundle from the working tree. It copies an allowlist of paths, so a local `backend/.env` never rides along (INSPECT-0175). Then: frontend `npm ci && npm run build`; `uv export --frozen --no-dev --no-emit-project` run inside Docker; `pip install --require-hashes --no-deps --only-binary=:all:` into the bundled Python on the host, so every wheel is a macOS arm64 one; prune; compile bytecode; Postgres; `swift build -c release`; Info.plist; ad-hoc signature; a check that every Mach-O file verifies; sizes. |
| `macos/shell/` | The Swift shell, a SwiftPM executable with no Xcode project. The window is a `WKWebView`. The app menu has Open in Browser, Copy Setup Claim Token, Show Logs in Finder and Quit. The supervisor starts and stops the children. `--headless` does everything except the window. |
| `macos/launcher/loon_backend.py` | The backend's entry point: `app.serve.main()` and a watchdog. If the shell dies, the watchdog sends the backend the SIGTERM a normal quit would have sent. |

The bundle's `Contents/Resources/backend` is laid out like the image's `/app`: `app/` with the
SPA in `app/static` and a `build_info.json` stamped `2026.10.06+8687cdc`, `migrations/`,
`alembic.ini`, and `docs/baseline-rules.yml`, where `app.baseline.catalogue` looks for it. The
other directories in `Contents/Resources` are `python/` (the interpreter and the 56 locked
packages that apply to macOS), `postgres/` (`bin`, `lib`, `share`) and `launcher/`.

## How it runs

```
LoonInspect                       Contents/MacOS, the Swift shell
├── postgres -D …/pgdata          Contents/Resources/postgres/bin, Unix socket only, no TCP
└── python3 loon_backend.py       Contents/Resources/python/bin, app.serve on 127.0.0.1:<port>
```

Everything the app writes is in `~/Library/Application Support/LoonInspect-Spike`, mode 0700.
The `-Spike` suffix keeps it apart from any future real app.

| Path | Holds |
| --- | --- |
| `pgdata/` | The database cluster. |
| `run/` | The socket (`.s.PGSQL.5432`), `port` (the chosen port, written for anyone who wants to reach the UI), and `shell.lock` (one instance at a time). |
| `logs/` | `shell.log`, `postgres.log`, `backend.log` (the container's JSON stdout, line for line) and `initdb.log`. |
| `data/` | The backend's `./data`: the backend runs with this directory as its working directory, so the audit log lands here as it lands on the container's volume. |
| `preferred-port` | Last launch's port, which the next launch reuses if it is free. The UI's origin then stays the same, and so does its per-origin browser storage. |

The secrets are three generic passwords in the login keychain under the service
`LoonInspect-Spike`: `ENCRYPTION_KEY` (a Fernet key), `postgres-looninspect_app` and
`postgres-looninspect`. All three are generated on first launch; none is written to a file. A
later launch that finds the database but not the key refuses to start and says why, rather
than mint a new key that would leave every stored credential unreadable (KNOWN_ISSUES.md §5).

**First launch.** `initdb` runs with these flags:

- `-U looninspect --pwfile --auth=scram-sha-256`. The superuser is the one the container
  creates. The container trusts every socket connection (stock docker-entrypoint); here the
  socket asks for a password as well, inside a 0700 directory.
- `--encoding=UTF8 --locale=C --locale-provider=builtin --builtin-locale=C.UTF-8`. This
  gives code-point ordering and Unicode case mapping without macOS's libc locale tables. The
  container's `en_US.utf8` under musl orders by code point too, because musl has no collation.

The cluster is built as `pgdata.initdb` and renamed only when it is complete, so an
interrupted first launch leaves nothing that looks like a database. Then come what the image's
first boot does: the entrypoint's `CREATE DATABASE looninspect`, and the two statements of
`ops/postgres/initdb/10-app-role.sh`, `CREATE ROLE looninspect_app … NOSUPERUSER NOCREATEDB
NOCREATEROLE NOBYPASSRLS` and `ALTER SCHEMA public OWNER TO looninspect_app`. They run in
single-user mode, because zonky's build has no `psql`. That also means nothing can connect
while they run. Two flags are needed there: `exit_on_error=on`, because single-user mode
otherwise exits 0 after an error, and `log_min_error_statement=panic`, because a failing
`CREATE ROLE` is otherwise echoed into the log with its password (seen in a test, then fixed).

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

The first administrator is made the container's way: the backend logs a claim token while no
account exists. The setup page still says to run `docker compose logs app | grep "claim
token"`, which is wrong inside an app. The menu's Copy Setup Claim Token reads the token from
this session's part of `backend.log` instead. `INITIAL_ADMIN_*` is not used.

**Quit.** Quitting from the menu, with ⌘Q, through AppleScript or at logout, or with SIGTERM,
SIGINT or SIGHUP, stops the backend first with SIGTERM, then uvicorn's graceful shutdown;
after 15 s it sends SIGKILL instead. Then `pg_ctl stop -m fast`, and only after that does the
app exit. If the shell itself is killed (SIGKILL, a crash), the backend's watchdog stops the
backend within about a second. Postgres has no such watchdog: it keeps running until the next
launch, which stops it first. A second copy of the app refuses to start, says that one is
already running, and leaves the running one alone.

## Measurements

From the final clean build, on this Mac. The first launch had no data directory and no
keychain items; the later launches followed it.

| What | Number |
| --- | --- |
| Downloads | CPython 25.1 MB, zonky jar 62.1 MB (about 4 s here) |
| Build, clean | 46 s wall; the steps took 4 s (downloads), 6 s (frontend), 10 s (Python and wheels), 1 s (bytecode), 7 s (Postgres), 7 s (Swift), 4 s (signature check), 7 s (zip) |
| Bundle | 217 MB: Python 136 MB (site-packages 97 MB; `.pyc` files across both, 46 MB); Postgres 70 MB, of which 29 MB is ICU data; backend 7.7 MB, of which the SPA is 1.7 MB; shell 320 KB |
| Zipped | 81 MB |
| First launch | 2.97 s from `open` to health 200. The shell's clock: 0.18 s keychain (three items), 1.11 s initdb and role, 0.05 s Postgres start, 1.44 s backend start and 73 migrations and uvicorn bind. The window's page load finishes about 0.25 s after health. Headless: 3.27 s. |
| Later launches | 1.25, 1.13 and 1.08 s from `open` to health 200; 0.92 s headless |
| Quit | 0.45 to 0.60 s through AppleScript; 0.39 s on SIGTERM to the windowed app; 0.34 s headless; 0.42 s when quit while still starting |
| Shell killed with SIGKILL | Backend gone 1.29 s later through the watchdog; the next launch stopped the orphaned Postgres and was healthy in 1.20 s |
| Memory at rest, setup page shown | Shell 101 MB RSS (WebKit's own processes not counted), backend 188 MB, Postgres 87 MB across 9 processes (shared buffers counted in each) |

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
- Alembic runs in-process through the socket URL; 73 migrations take about 0.9 s.

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
- The setup page's claim-token help names `docker compose logs`. The menu item works around
  it; a real app needs the page to say something else, which is a frontend change.

Where this deviates from the settled design, and why:

- The uv image is `ghcr.io/astral-sh/uv:0.9.30-python3.12-bookworm-slim`, not the floating
  `python3.12-alpine`. 0.9.30 is the Dockerfile's and CI's pin, so the export cannot drift with
  a new uv. The export is platform-neutral: markers plus every wheel's hash.
- Postgres is started directly (argv, no shell) rather than with `pg_ctl start`. A socket path
  with a space then needs no quoting, and Postgres is the shell's own child. It is stopped with
  `pg_ctl stop -m fast` as specified.
- No `install_name_tool` was needed anywhere. Nested code keeps its upstream signatures (EDB's,
  and the linker's ad-hoc ones), and only the bundle is signed ad-hoc. The script fails if any
  Mach-O file in the bundle does not verify.
- The backend is started through `macos/launcher/loon_backend.py` rather than `python -m
  app.serve`, for the watchdog. It calls the same `main()`.
- This document is at the path the plan named. [BRANCHING.md](BRANCHING.md) §3.1 names
  `docs/spikes/<slug>.md`; the front matter above is that section's.

## Needs Kyle

What each needs, as far as the spike could see:

1. **Developer ID signing.** This needs an Apple Developer Program membership and a "Developer
   ID Application" certificate in Kyle's keychain. Then everything is signed inside out, with
   `--options runtime --timestamp`: each Python Mach-O file (python3.12 and about 60 `.so`) and
   the shell. EDB's Postgres binaries are already Developer ID signed with hardened runtime;
   whether notarization accepts another team's signatures inside the bundle is the first thing
   to try. Apple expects nested code in `Contents/Frameworks`, `Contents/Helpers` and similar,
   not `Contents/Resources`, so `python/` and `postgres/` probably move. Entitlements are to be
   found by testing; the likely candidate is none, since each process loads only its own team's
   libraries.
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

## Validation

Everything here was run on this Mac on 2026-10-06, from the worktree of `spike/macos-app`:

- `rm -rf macos/build && macos/scripts/build-app.sh`: exit 0, with the sizes and times above.
  An earlier run failed on the unsigned x86_64 slices, which led to the thinning.
- `shellcheck` (`koalaman/shellcheck:stable` in Docker) on both scripts: clean.
- `ruff check` and `ruff format --check` (0.16.9, the lockfile's) on `macos/launcher` with
  `backend/pyproject.toml`'s settings: clean.
- `swift build -c release`: no warnings.
- `open macos/build/LoonInspect.app` with no data directory and no keychain items:
  - `run/port` was written.
  - `curl /api/health` returned 200 `{"status":"ok"}`.
  - `curl /` returned 200 `text/html`, the SPA (`<title>LoonInspect</title>`).
  - `/api/auth/status` returned `setupRequired: true`.
  - The window's own report read `{"path":"/setup","passwordField":true}`; a WebKit snapshot of
    the window showed the setup page.
  - `ps` showed `postgres` and `python3` running from `LoonInspect.app/Contents/Resources` as
    the shell's children.
  - `lsof` showed Postgres with no TCP socket, and Python listening on 127.0.0.1 only.
- Over the bundle's socket, connected as `looninspect_app` with the bundle's Python and
  asyncpg:
  - The role: `rolsuper`, `rolcreatedb`, `rolcreaterole` and `rolbypassrls` all `False`.
  - The database: `public` owned by `looninspect_app`; `alembic_version` at `a4d7e1c9b2f3`,
    the repository's only head; 58 tables, 44 with FORCE ROW LEVEL SECURITY.
  - A wrong password was refused.
- Persistence:
  - First-run setup through the API with the logged claim token returned 201.
  - Quit, then three relaunches: each was healthy with `setupRequired: false`, the session from
    before still authenticated, and the window on `/login`.
  - `initdb.log` holds one initdb run.
- Quit, five ways, each followed by `ps`, which found no `postgres` or `python3` from the bundle
  every time:
  - `osascript -e 'quit app "LoonInspect"'`
  - SIGTERM to the windowed app, at once and after 3 s idle
  - SIGTERM to `--headless`
  - quit 0.6 s into a launch
  - SIGKILL of the shell, after which the next launch cleaned up
- A second `--headless` while one ran: exit 1, "Another LoonInspect is already running", and
  the first was untouched.

Not run: anything on a second Mac, on Intel, or on a copy downloaded with quarantine; a
Developer ID signature or notarization; sign-in through the window itself (the session was made
with `curl`); a download; and anything longer than a few minutes of running. At the end, the
test data directory and the three keychain items were removed. They were created by this
session. The built `macos/build/LoonInspect.app` is left in place, so the next `open` is a
first launch.

## Reproduce

```sh
macos/scripts/build-app.sh
open macos/build/LoonInspect.app        # or: …/Contents/MacOS/LoonInspect --headless
cat ~/Library/Application\ Support/LoonInspect-Spike/run/port
```

The menu's Copy Setup Claim Token fills the setup page's first field. To start over, see
[macos/README.md](../macos/README.md).
