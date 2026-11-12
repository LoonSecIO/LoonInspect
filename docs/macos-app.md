# LoonInspect as a macOS app

Status: **built, 1.0.0**, 2026-11-10 · Apple silicon, macOS 13 or later · the files are under
[`macos/`](../macos/README.md) · when it will not open or start,
[`troubleshooting.md`](troubleshooting.md) §25 · its limits, [KNOWN_ISSUES.md](../KNOWN_ISSUES.md)
§10 · built and checked on one Mac (macOS 27.3, Xcode 27.2, Swift 6.4), on the commit this
document names under [Validation](#validation-100).

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
`~/Library/Preferences/io.loonsec.looninspect.plist` (the window's frame), and the per-user
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
1.0.0 is under [What 1.0.0 leaves out](#what-100-leaves-out).

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
leave the instance open in the default browser; file downloads go to `~/Downloads`.

| Setting | Container | App | Why |
| --- | --- | --- | --- |
| `HOST`, `PORT` | `0.0.0.0:8001` | `127.0.0.1:<free port>` | Nothing off the Mac can reach it. |
| `TLS_MODE` | `off` by default | `off` | Loopback only. |
| `DATABASE_URL` | `…@db:5432/looninspect` | `postgresql+asyncpg://looninspect_app:<pw>@/looninspect?host=<socket dir>` | asyncpg takes a `host` that starts with `/` as a socket directory. The space in "Application Support" stays literal: a `%20` would break Alembic's ConfigParser. |
| `DATABASE_MODE` | `bundled` | `bundled` | The same promise: the role was made right at first boot. |
| `ENCRYPTION_KEY` | `.env` | login keychain | Never in a file. |
| `SECURE_COOKIES` | `true` | `false` | Plain HTTP on 127.0.0.1 only, so no cookie crosses a network; WebKit's handling of Secure cookies over `http://127.0.0.1` is not one to lean on. |
| `UPDATE_CHECK` | `true` | `false` | Its notice tells an operator to pull an image. How the app updates is below. |
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
in 1.0.0 ([What 1.0.0 leaves out](#what-100-leaves-out)).

**Quit.** From the menu, with ⌘Q, through AppleScript, at logout, or on SIGTERM, SIGINT or
SIGHUP: the backend first (SIGTERM, uvicorn's graceful shutdown, SIGKILL after 15 s), then
`pg_ctl stop -m fast`, and only then does the app exit. If the shell itself is killed, the
backend's watchdog notices within a second and takes both steps from inside the backend,
signalling only the postmaster this shell started and only while `postmaster.pid` still names it.
A second copy of the app refuses to start, says that one is already running, and leaves the
running one alone.

## Version, signature, release

**The version.** `CFBundleShortVersionString` in `macos/shell/Info.plist` is the app's release,
`1.0.0`, and the pull request that prepares a release moves it, as the one that prepares an image
release moves `RELEASE` in `backend/app/core/version.py`. The two are not the same number and
need not be: the app's names the bundle a Mac runs, the backend's is what the image inside it
compares with a database's `schema_release` (BRANCHING.md §1.1). `build-manifest.json` records
both. `CFBundleVersion` is the build number, `BUILD_NUMBER` or the UTC build minute, stamped by
`build-app.sh`; the page's build readout and the update check read `build_info.json`
(`YYYY.MM.DD+<sha>`), written as the Dockerfile writes it.

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

**A release.** Build from the release commit, notarize, attach
`macos/build/LoonInspect-<version>-arm64.dmg` to the GitHub release. The disk image holds the
app and an Applications link; a user drags one onto the other and opens it. The GitHub Action
builds and attaches these assets on release publication; manual runs from main save workflow
artifacts. CI requires the app version and backend `RELEASE` to agree and validates tag/main
ancestry before importing signing credentials. Environment setup and the full flow are in
[`macos/README.md`](../macos/README.md#github-actions).

**Updates.** There is no update mechanism in 1.0.0, and `UPDATE_CHECK` is off because its notice
tells an operator to pull an image. A newer version is a newer disk image dragged over the old
app; the data directory and the keychain items survive the swap, and the next launch runs the new
migrations as the container does. Stepping back obeys the same rule as the image: a build refuses
a database written by a later `RELEASE` than its own (`operations.md` §5), and
`troubleshooting.md` §25 step 5 says so. A Postgres major (17 to 18) would need `pg_upgrade` or a
dump and restore, the same question the container's database volume has.

## Backup

The bundle ships no `pg_dump`, so `operations.md` §2 cannot be run against the app
(KNOWN_ISSUES.md §10). The backup that exists:

1. Quit the app. A copy of `pgdata` taken while Postgres runs is not a consistent database, which
   is why the app marks `pgdata` excluded from Time Machine (`tmutil isexcluded` reads
   `[Excluded]`).
2. Copy `~/Library/Application Support/LoonInspect/pgdata`.
3. Keep the `ENCRYPTION_KEY` item from the login keychain with it
   (`security find-generic-password -s LoonInspect -a ENCRYPTION_KEY -w`). Without it the
   credentials in the copy are unreadable, exactly as a `pg_dump` without the key is not a backup
   (`operations.md`, "ENCRYPTION_KEY is not optional").

A restore is the directory put back, with the app quit, and the keychain item present. The
`postgres-looninspect_app` password must match too; it is in the same keychain, and a restore on
the same user account has it.

## What 1.0.0 leaves out

- **It runs only while it is open**, and a sleeping Mac pauses it (KNOWN_ISSUES.md §10). A
  login-item or LaunchAgent mode (`SMAppService`) is the likely answer, and it reopens what
  **Quit** means.
- **The setup claim exchange** stays, shell-held, by Kyle's ruling of 2026-10-06; gutting it is a
  backend change and a ruling, owed before a public release.
- **No update mechanism.** Sparkle 2 (an EdDSA-signed appcast and a URL to host it), the
  existing GitHub release check with words for an app, or a Homebrew cask. Undecided.
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
- **Downloads are wired and untested** in the app's window: the evidence report and the
  data-sharing export. JavaScript `alert` and `confirm` are not implemented; the frontend uses
  neither.

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
