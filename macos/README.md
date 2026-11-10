# macos/: LoonInspect as a macOS app

`LoonInspect.app` runs the same backend, frontend and PostgreSQL 17 the container runs, as child
processes of a small Swift shell, on one Apple-silicon Mac. What it is, where its data lives, how
a release is cut and what 1.0.0 leaves out are in [docs/macos-app.md](../docs/macos-app.md); when
it will not open or start, [docs/troubleshooting.md](../docs/troubleshooting.md) §24.

| Path | What it is |
| --- | --- |
| `scripts/fetch-runtime.sh` | Downloads CPython 3.12 (python-build-standalone) and PostgreSQL 17 (zonky, Maven Central), pinned by version and sha256, into `build/downloads`. |
| `scripts/build-app.sh` | Builds `build/LoonInspect.app` from this checkout and signs every Mach-O file in it with the hardened runtime: frontend, backend, locked wheels, Postgres, the icon, the shell. Then `package-dmg.sh`. |
| `scripts/package-dmg.sh` | Puts the app on `build/LoonInspect-<version>-arm64.dmg` with an Applications link, and signs the image. |
| `scripts/notarize.sh` | Has Apple notarize the app and the image, staples both, and proves them with `spctl`. The release step. |
| `scripts/sign-identity.sh` | The identity the scripts sign with: `$SIGN_IDENTITY`, else the one Developer ID Application identity in the keychain, else ad-hoc. |
| `scripts/make-icon.swift` | Renders `LoonInspect.icns` from `frontend/public/brand/loon-mark-reversed.svg` at build time; no binary icon is committed. |
| `shell/` | The Swift shell (SwiftPM, no Xcode project): the window, the menu, and the supervisor that starts and stops Postgres and the backend. `Info.plist` holds the app's version. |
| `launcher/loon_backend.py` | The backend's entry in the bundle: `app.serve` plus a watchdog that stops it, and Postgres, if the shell dies. |

## Build and run

Apple silicon; needs Xcode's `swift`, `node`/`npm`, Docker (for `uv export` only), and the
network for the pinned downloads and the signature timestamps.

```sh
macos/scripts/build-app.sh
open macos/build/LoonInspect.app
macos/build/LoonInspect.app/Contents/MacOS/LoonInspect --headless   # everything but the window
```

The build signs with the one "Developer ID Application" identity in the login keychain, or
ad-hoc when there is none (`SIGN_IDENTITY=-` forces that). An ad-hoc build runs on the Mac that
built it and nowhere else. Either way every Mach-O file carries the hardened runtime, so a
development build fails where a release build would.

## Release

1. The version is `CFBundleShortVersionString` in `shell/Info.plist`; the pull request that
   prepares a release moves it. `CFBundleVersion` is stamped at build time (`BUILD_NUMBER`, or the
   UTC build minute).
2. Build from the release commit, with the Developer ID in the keychain: `macos/scripts/build-app.sh`.
   `Contents/Resources/build-manifest.json` records the commit, whether the tree was clean, and
   what was signed as what.
3. Notarize, once per release, with a notarytool profile stored once per Mac:

   ```sh
   xcrun notarytool store-credentials LoonInspect --apple-id <Apple ID> --team-id <team id> --password <app-specific password>
   NOTARY_PROFILE=LoonInspect macos/scripts/notarize.sh
   ```

   The script submits the app, staples it, rebuilds and signs the disk image from the stapled
   app, submits and staples that, and ends with `spctl` reading `accepted` for both. It refuses a
   bundle built from a modified tree.
4. Attach `build/LoonInspect-<version>-arm64.dmg` (and the `.zip` beside it, if wanted) to the
   GitHub release. Nothing under `build/` is committed.

## Where it keeps things, and how to start over

The app keeps its database and logs in `~/Library/Application Support/LoonInspect`, its three
secrets in the login keychain under the service `LoonInspect`, and the port it chose in
`run/port` there. The window's web view data, cache and frame are kept under the bundle
identifier, `io.loonsec.looninspect`. To start over, quit it and remove them all:

```sh
rm -rf ~/Library/Application\ Support/LoonInspect \
  ~/Library/WebKit/io.loonsec.looninspect ~/Library/Caches/io.loonsec.looninspect
defaults delete io.loonsec.looninspect
for a in ENCRYPTION_KEY postgres-looninspect_app postgres-looninspect; do
  security delete-generic-password -s LoonInspect -a "$a"; done
```

The database is gone with the first line, and so is everything the instance held: do that only
to start over. A backup is a copy of `pgdata` taken while the app is quit, plus the
`ENCRYPTION_KEY` keychain item, without which the stored credentials in that copy are
unreadable ([docs/macos-app.md](../docs/macos-app.md), "Backup").
