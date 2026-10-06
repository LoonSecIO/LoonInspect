# macos/: LoonInspect as a macOS app (spike)

A packaging spike, not a product: an unsigned `LoonInspect.app` that runs the same backend,
frontend and PostgreSQL 17 the container runs, as child processes of a small Swift shell.
The findings, the numbers and what is left are in
[docs/spike-macos-app.md](../docs/spike-macos-app.md).

| Path | What it is |
| --- | --- |
| `scripts/fetch-runtime.sh` | Downloads CPython 3.12 (python-build-standalone) and PostgreSQL 17 (zonky, Maven Central), pinned by version and sha256, into `build/downloads`. |
| `scripts/build-app.sh` | Builds `build/LoonInspect.app` from this checkout: frontend, backend, locked wheels, Postgres, the shell, an ad-hoc signature. |
| `shell/` | The Swift shell (SwiftPM, no Xcode project): the window, the menu, and the supervisor that starts and stops Postgres and the backend. |
| `launcher/loon_backend.py` | The backend's entry in the bundle: `app.serve` plus a watchdog that stops it if the shell dies. |

Build and run (Apple silicon; needs Xcode's `swift`, `node`/`npm`, and Docker for `uv export`):

```sh
macos/scripts/build-app.sh
open macos/build/LoonInspect.app
macos/build/LoonInspect.app/Contents/MacOS/LoonInspect --headless   # everything but the window
```

The app keeps its database and logs in `~/Library/Application Support/LoonInspect-Spike`,
its secrets in the login keychain under the service `LoonInspect-Spike`, and the port it
chose in `run/port` there. The window's web view data, cache and frame are kept under the
bundle identifier, `io.loonsec.looninspect.spike`. To start over, quit it and remove them all:

```sh
rm -rf ~/Library/Application\ Support/LoonInspect-Spike \
  ~/Library/WebKit/io.loonsec.looninspect.spike ~/Library/Caches/io.loonsec.looninspect.spike
defaults delete io.loonsec.looninspect.spike
for a in ENCRYPTION_KEY postgres-looninspect_app postgres-looninspect; do
  security delete-generic-password -s LoonInspect-Spike -a "$a"; done
```

Nothing under `build/` is committed: the downloads, the bundle and the zip are all rebuilt.
