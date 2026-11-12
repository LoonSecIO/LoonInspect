#!/usr/bin/env bash
# Prints the code-signing identity the other scripts use: $SIGN_IDENTITY if set, else the one
# "Developer ID Application" identity in the keychain, else "-" (ad-hoc: runs here, not for
# distribution). Two Developer ID identities is an error, since a guess would sign as the wrong team.
set -euo pipefail
if [ -n "${SIGN_IDENTITY:-}" ]; then
  printf '%s\n' "$SIGN_IDENTITY"
  exit 0
fi
query=(security find-identity -v -p codesigning)
[ -z "${SIGN_KEYCHAIN:-}" ] || query+=("$SIGN_KEYCHAIN")
found=$("${query[@]}" 2>/dev/null | sed -n 's/.*"\(Developer ID Application: [^"]*\)".*/\1/p' | sort -u)
case $(printf '%s\n' "$found" | grep -c . || true) in
  0) echo - ;;
  1) printf '%s\n' "$found" ;;
  *) echo "sign-identity: more than one Developer ID Application identity in the keychain; set SIGN_IDENTITY to one of:" >&2
     printf '  %s\n' "$found" >&2
     exit 1 ;;
esac
