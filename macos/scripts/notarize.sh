#!/usr/bin/env bash
# Notarizes and staples the signed app, then rebuilds, notarizes and staples its DMG.
# NOTARY_PROFILE names stored credentials; NOTARY_KEYCHAIN optionally selects CI's temporary
# keychain. Submission IDs are saved before waiting, including when Apple's wait times out.
# See macos/README.md for credentials and docs/troubleshooting.md for failures.
set -euo pipefail

macos=$(cd "$(dirname "$0")/.." && pwd)
build="$macos/build"
app="$build/LoonInspect.app"
die() { echo "notarize: $*" >&2; exit 1; }
field() { plutil -extract "$2" raw -o - "$1" 2>/dev/null || true; }

[ -d "$app" ] || die "no $app; run macos/scripts/build-app.sh first"
[ -n "${NOTARY_PROFILE:-}" ] || die "NOTARY_PROFILE is not set; store notarization credentials as described in macos/README.md."
auth=(--keychain-profile "$NOTARY_PROFILE")
[ -z "${NOTARY_KEYCHAIN:-}" ] || auth+=(--keychain "$NOTARY_KEYCHAIN")
identity=$("$macos/scripts/sign-identity.sh")
[ "$identity" != - ] || die "a Developer ID Application identity is required; import the signing certificate and rebuild (macos/README.md)."
codesign --verify --strict --deep "$app" || die "the app's signature is invalid; rebuild it before submitting to Apple."
signature=$(codesign -dvv "$app" 2>&1)
printf '%s\n' "$signature" | grep '^Authority=Developer ID Application' >/dev/null ||
  die "the app lacks a Developer ID signature; rebuild with the release signing certificate."
if [ -n "${EXPECTED_TEAM_ID:-}" ]; then
  printf '%s\n' "$signature" | grep -Fx "TeamIdentifier=$EXPECTED_TEAM_ID" >/dev/null ||
    die "the app was not signed by team $EXPECTED_TEAM_ID; check the imported certificate and SIGN_IDENTITY, then rebuild."
fi
manifest="$app/Contents/Resources/build-manifest.json"
if [ "$(field "$manifest" tree)" != clean ] && [ "${ALLOW_DIRTY:-0}" != 1 ]; then
  die "the bundle was built from a modified tree; commit all build inputs and rebuild. ALLOW_DIRTY=1 is for local tests only."
fi
version=$(plutil -extract CFBundleShortVersionString raw -o - "$app/Contents/Info.plist")
xcrun notarytool history "${auth[@]}" --output-format json >/dev/null ||
  die "Apple could not authenticate profile $NOTARY_PROFILE; check its credentials, team access and network, then store it again (macos/README.md)."

submit() {
  local file=$1 name=$2 result status_file id status recovery rc=0
  result="$build/notarize-$name.json"
  status_file="$build/notarize-$name-status.json"
  rm -f "$result" "$status_file" "$build/notarize-$name.log"
  echo "notarize: submitting $(basename "$file"); Apple may take several minutes"
  xcrun notarytool submit "$file" "${auth[@]}" --output-format json >"$result" || rc=$?
  id=$(field "$result" id)
  [ -n "$id" ] || die "Apple did not return a submission ID (exit $rc). Check the error above and $result for authentication or upload failure; retry after resolving it."
  echo "notarize: $(basename "$file") submission $id; saved in $result"
  rc=0
  xcrun notarytool wait "$id" "${auth[@]}" --timeout "${NOTARY_TIMEOUT:-1h}" --output-format json >"$status_file" || rc=$?
  status=$(field "$status_file" status)
  if [ "$status" != Accepted ]; then
    xcrun notarytool log "$id" "${auth[@]}" "$build/notarize-$name.log" || true
    if [ "$status" = Invalid ] || [ "$status" = Rejected ]; then
      die "Apple answered '$status' for $(basename "$file") (submission $id). Read $build/notarize-$name.log for the file and signing problem, then fix and rebuild."
    fi
    printf -v recovery '%q ' xcrun notarytool info "$id" "${auth[@]}"
    die "submission $id is not accepted (status '${status:-unavailable}', wait exit $rc). Apple may still be processing it. Check with: $recovery. Saved responses: $result and $status_file. See docs/troubleshooting.md before retrying."
  fi
  echo "notarize: $(basename "$file") accepted (submission $id)"
}

zip="$build/LoonInspect-$version-arm64.zip"
rm -f "$zip"
ditto -c -k --keepParent "$app" "$zip"
submit "$zip" app
xcrun stapler staple "$app"
rm -f "$zip"
ditto -c -k --keepParent "$app" "$zip"

"$macos/scripts/package-dmg.sh"
dmg="$build/LoonInspect-$version-arm64.dmg"
submit "$dmg" dmg
xcrun stapler staple "$dmg"

xcrun stapler validate "$app"
xcrun stapler validate "$dmg"
codesign --verify --strict --deep "$app"
codesign --verify --strict "$dmg"
spctl --assess --type execute --verbose=2 "$app"
spctl --assess --type open --context context:primary-signature --verbose=2 "$dmg"
(cd "$build" && shasum -a 256 "$(basename "$dmg")" "$(basename "$zip")" > SHA256SUMS)
echo "notarize: verified release assets: $dmg and $zip; checksums in $build/SHA256SUMS"
