# macos/: LoonInspect as a macOS app

`LoonInspect.app` runs the same backend, frontend and PostgreSQL 17 the container runs, as child
processes of a small Swift shell, on one Apple-silicon Mac. What it is, where its data lives, how
a release is cut and what 1.0.0 leaves out are in [docs/macos-app.md](../docs/macos-app.md); when
it will not open or start, [docs/troubleshooting.md](../docs/troubleshooting.md) §25.

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

Apple silicon; needs Xcode's `swift`, Node 22 (`node`/`npm`), native **uv 0.9.30**, and the
network for pinned downloads and signature timestamps. Install the exact uv version with
a dedicated environment: `python3 -m venv /tmp/looninspect-build-tools` and
`/tmp/looninspect-build-tools/bin/pip install uv==0.9.30`, then add its `bin` to `PATH`.
The exporter runs offline with `--frozen`; wheel installation verifies the lockfile hashes.

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
   xcrun notarytool store-credentials LoonInspect --apple-id <Apple ID> --team-id 6CWZ5GA79H
   NOTARY_PROFILE=LoonInspect macos/scripts/notarize.sh
   ```

   The command prompts securely for an Apple app-specific password. For an App Store Connect
   API key instead, use `--key /absolute/path/AuthKey.p8 --key-id <key id>` and, for a team key
   only, `--issuer <issuer UUID>`. Do not put passwords or private keys into a commit or chat.

   The script submits the app, staples it, rebuilds and signs the disk image from the stapled
   app, submits and staples that, and ends with `spctl` reading `accepted` for both. It refuses a
   bundle built from a modified tree.
4. Attach `build/LoonInspect-<version>-arm64.dmg` (and the `.zip` beside it, if wanted) to the
   GitHub release. Nothing under `build/` is committed.

## GitHub Actions

[macOS release](../.github/workflows/macos-release.yml) builds on an Apple-silicon `macos-15`
runner with Xcode 26.3, Node 22 and uv 0.9.30. A manual run from **main** produces downloadable
workflow artifacts. Publishing a `vMAJOR.MINOR.PATCH` release (including prereleases) builds
its tagged commit and attaches the verified DMG, ZIP and `SHA256SUMS` to that release. The tag
must be on main and match both the app version and backend `RELEASE` (excluding a prerelease
suffix). Existing release assets are never overwritten. Keep the existing admin-only `v*`
tag ruleset. Old tags without this workflow do not start it retroactively.

Create the **macos-release** GitHub environment. Restrict its deployment branches/tags to
branch `main` and tags `v*`, and store these environment secrets:

| Secret | Value |
| --- | --- |
| `MACOS_CERTIFICATE_BASE64` | Base64 of a password-protected `.p12` containing the Developer ID Application certificate **and its private key**, team `6CWZ5GA79H`. |
| `MACOS_CERTIFICATE_PASSWORD` | The P12 export password. |
| `APPLE_API_KEY` | Contents of an App Store Connect API private `.p8` key. |
| `APPLE_API_KEY_ID` | That API key's ID. |
| `APPLE_API_ISSUER_ID` | Issuer UUID for a **team** API key; omit for an individual API key. |

Alternatively, omit the three API-key secrets and set `APPLE_ID` and
`APPLE_APP_SPECIFIC_PASSWORD`. The API-key path takes precedence if configured. The signing
certificate and the notary credentials are separate: a signing certificate alone cannot
submit to Apple. Use GitHub's secret form or `gh secret set --repo LoonSecIO/LoonInspect
--env macos-release NAME` with stdin; never commit these values.

The job imports the certificate and validated notary credentials into a temporary keychain,
selects the one signing identity for the expected team, and requires a clean checkout and a
Developer ID build. `SIGN_KEYCHAIN` and `NOTARY_KEYCHAIN` select that keychain without changing
the runner's default keychain. It removes the keychain and credential files on success or
failure. Pull requests run isolated script tests and a complete ad-hoc build without these secrets;
that unsigned-for-distribution build is never uploaded.

Only after both artifacts pass notarization, stapling and Gatekeeper assessment are they
uploaded. A separate job with `contents: write` attaches assets to a published release; the
signing job has `contents: read`. Apple submission responses and rejection logs are saved as a
separate diagnostic artifact even on failure. Artifacts expire after 14 days; release assets
remain with the release. See troubleshooting §25, **Maintainer: build or notarization fails**.

The local script saves a submission ID before its bounded wait (`NOTARY_TIMEOUT`, default
`1h` per submission). A timeout does not cancel Apple's work. Check that submission before
starting another run; rerunning the script submits again. `ALLOW_DIRTY=1` is a local test
escape hatch, never set by the workflow. Run the isolated script tests with
`python3 macos/tests/test_notarize.py`; they require macOS `plutil` but no credentials/network.

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
