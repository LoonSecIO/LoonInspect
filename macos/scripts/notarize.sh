#!/usr/bin/env bash
# Has Apple notarize the built app, staples the ticket, rebuilds the disk image from the stapled
# app, notarizes and staples that too, and proves both with spctl. The result is what a GitHub
# release carries: a LoonInspect-<version>-arm64.dmg that Gatekeeper opens on another Mac.
#
# Needs NOTARY_PROFILE, a notarytool keychain profile the maintainer stores once (macos/README.md):
#   xcrun notarytool store-credentials LoonInspect --apple-id <Apple ID> --team-id <team> --password <app-specific password>
# or the same with --key, --key-id and --issuer for an App Store Connect API key.
#
#   NOTARY_PROFILE=LoonInspect macos/scripts/notarize.sh
set -euo pipefail

macos=$(cd "$(dirname "$0")/.." && pwd)
build="$macos/build"
app="$build/LoonInspect.app"
die() { echo "notarize: $*" >&2; exit 1; }

[ -d "$app" ] || die "no $app; run macos/scripts/build-app.sh first"
[ -n "${NOTARY_PROFILE:-}" ] || die "NOTARY_PROFILE is not set. It names a notarytool keychain profile; macos/README.md says how to store one."
identity=$("$macos/scripts/sign-identity.sh")
[ "$identity" != - ] || die "the build is signed ad-hoc, and Apple notarizes Developer ID signatures only. Build again with a Developer ID Application identity in the keychain."
codesign -dvv "$app" 2>&1 | grep '^Authority=Developer ID Application' >/dev/null ||
  die "$app does not carry a Developer ID signature; run macos/scripts/build-app.sh with the identity in the keychain"
manifest="$app/Contents/Resources/build-manifest.json"
if [ "$(plutil -extract tree raw -o - "$manifest" 2>/dev/null)" != clean ] && [ -z "${ALLOW_DIRTY:-}" ]; then
  die "this bundle was built from a working tree with uncommitted changes (build-manifest.json says tree: modified). A release is built from a commit; commit, rebuild, and run this again, or set ALLOW_DIRTY=1 for a test."
fi
version=$(plutil -extract CFBundleShortVersionString raw -o - "$app/Contents/Info.plist")

submit() {  # <file> <log name>: submits, waits, and fails with Apple's log if the ticket is refused
  local file=$1 name=$2 result id status
  result="$build/notarize-$name.json"
  echo "notarize: submitting $(basename "$file") ($(du -h "$file" | cut -f1)) as profile $NOTARY_PROFILE; this takes minutes"
  xcrun notarytool submit "$file" --keychain-profile "$NOTARY_PROFILE" --wait --timeout 1h --output-format json >"$result"
  id=$(plutil -extract id raw -o - "$result")
  status=$(plutil -extract status raw -o - "$result")
  if [ "$status" != Accepted ]; then
    xcrun notarytool log "$id" --keychain-profile "$NOTARY_PROFILE" "$build/notarize-$name.log" || true
    die "Apple answered '$status' for $(basename "$file") (submission $id). Its log is $build/notarize-$name.log: each issue names the file and what it lacks (a signature, the hardened runtime, a secure timestamp)."
  fi
  echo "notarize: $(basename "$file") accepted (submission $id)"
}

# 1. The app, as a zip; the ticket is stapled to the bundle so a Mac offline still opens it.
zip="$build/LoonInspect-$version-arm64.zip"
rm -f "$zip"
ditto -c -k --keepParent "$app" "$zip"
submit "$zip" app
xcrun stapler staple "$app"
# The zip a release may also carry: the stapled app, not the copy Apple saw.
rm -f "$zip"
ditto -c -k --keepParent "$app" "$zip"

# 2. The disk image, rebuilt from the stapled app, then notarized and stapled itself.
"$macos/scripts/package-dmg.sh"
dmg="$build/LoonInspect-$version-arm64.dmg"
submit "$dmg" dmg
xcrun stapler staple "$dmg"

# 3. The proof: what Gatekeeper will say on a Mac that has never seen this build.
xcrun stapler validate "$app"
xcrun stapler validate "$dmg"
spctl --assess --type execute --verbose=2 "$app"
spctl --assess --type open --context context:primary-signature --verbose=2 "$dmg"
echo "notarize: done. Release assets: $dmg and $zip"
