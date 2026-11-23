#!/bin/bash
# LoonInspect 1.3.0: remove this macOS user's local installation and start fresh.
# Uses only macOS tools. --dry-run lists the scope without changing anything.
set -eu
set -o pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin

fail() { printf '\nSTOPPED: %s\n' "$*" >&2; exit 1; }
dry_run=false
case "${1:-}" in
  --dry-run) dry_run=true ;;
  '') ;;
  *) fail 'Usage: Uninstall-LoonInspect.command [--dry-run]' ;;
esac
[ "$#" -le 1 ] || fail 'Only --dry-run is supported.'
[ "$(uname -s)" = Darwin ] || fail 'Run this script on the Mac where you want to remove LoonInspect.'
user_uid=$(id -u)
[ "$user_uid" != 0 ] || fail 'Run as your normal macOS user, without sudo.'
user_root=${HOME:-}
[ -n "$user_root" ] && [ "$user_root" != / ] && [ -d "$user_root/Library" ] || fail 'The current user home folder is not valid.'
[ "$(stat -f %u "$user_root")" = "$user_uid" ] || fail 'The home folder does not belong to the current user.'
[ ! -L "$user_root" ] || fail 'The home folder is a symbolic link; review its location before uninstalling.'
bundle_id=io.loonsec.looninspect
support="$user_root/Library/Application Support/LoonInspect"
socket_dir="/tmp/io.loonsec.looninspect.$user_uid"
apps=("$user_root/Applications/LoonInspect.app" '/Applications/LoonInspect.app')
data_paths=(
  "$support"
  "$user_root/Library/WebKit/$bundle_id"
  "$user_root/Library/Caches/$bundle_id"
  "$user_root/Library/HTTPStorages/$bundle_id"
  "$user_root/Library/HTTPStorages/$bundle_id.binarycookies"
  "$user_root/Library/Cookies/$bundle_id.binarycookies"
  "$user_root/Library/Saved Application State/$bundle_id.savedState"
  "$user_root/Library/Preferences/$bundle_id.plist"
  "$socket_dir"
)
key_accounts=(ENCRYPTION_KEY postgres-looninspect_app postgres-looninspect)

# Do not traverse a redirected Library subfolder during recursive deletion.
for parent in "$user_root/Library" "$user_root/Applications" \
  "$user_root/Library/Application Support" "$user_root/Library/WebKit" \
  "$user_root/Library/Caches" "$user_root/Library/HTTPStorages" \
  "$user_root/Library/Cookies" "$user_root/Library/Saved Application State" \
  "$user_root/Library/Preferences" "$user_root/Library/Preferences/ByHost"; do
  [ ! -L "$parent" ] || fail "A parent folder is a symbolic link: $parent. Review it before uninstalling."
done
shopt -s nullglob
for path in "$user_root/Library/Preferences/ByHost/$bundle_id".*.plist; do
  data_paths+=("$path")
done
shopt -u nullglob
for app in "${apps[@]}"; do
  if [ -e "$app" ] || [ -L "$app" ]; then
    [ ! -L "$app" ] || fail "The app is a symbolic link: $app. Remove that link manually and rerun."
    actual_id=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$app/Contents/Info.plist" 2>/dev/null) || fail "Cannot identify $app. Move it to Trash manually and rerun."
    [ "$actual_id" = "$bundle_id" ] || fail "The app at $app has a different bundle identifier; it will not be removed."
  fi
done
if [ -e "$socket_dir" ] && [ ! -L "$socket_dir" ]; then
  [ "$(stat -f %u "$socket_dir")" = "$user_uid" ] || fail 'The temporary database socket folder belongs to another user.'
fi

printf '\nLoonInspect — complete local uninstall\n\n'
printf 'Mac: %s\nUser: %s\n\n' "$(hostname)" "$(id -un)"
printf '%s\n' \
  'This permanently deletes this user’s LoonInspect accounts, passwords,' \
  'Jamf connection credentials, inventory, patch plans, audit history,' \
  'AI settings, local browser state, and the three LoonInspect Keychain items.'
printf '\nApp copies to remove:\n'
printf '  %s\n' "${apps[@]}"
printf '\nLocal data to remove (where present):\n'
printf '  %s\n' "${data_paths[@]}"
printf '\nPreviously exported PDFs, downloaded installers, backups, other macOS users,\nand the remote Jamf server are outside this uninstall. No backup is created.\n'
if "$dry_run"; then
  printf '\nDRY RUN COMPLETE — nothing was changed or stopped.\n'
  exit 0
fi
printf '\nType ERASE LOONINSPECT to permanently remove this installation: '
IFS= read -r answer || fail 'No confirmation received. Nothing was changed.'
[ "$answer" = 'ERASE LOONINSPECT' ] || fail 'Cancelled. Nothing was changed.'

# The shell handles SIGTERM by stopping its backend and PostgreSQL in order.
shell_pids=$(ps -ww -U "$user_uid" -o pid=,command= | awk '/\/Contents\/MacOS\/LoonInspect([[:space:]]|$)/ {print $1}')
if [ -n "$shell_pids" ]; then
  printf '\nStopping LoonInspect and its local services…\n'
  while IFS= read -r pid; do
    kill -TERM "$pid" 2>/dev/null || true
  done <<< "$shell_pids"
fi
running_services() {
  ps -ww -U "$user_uid" -o pid=,command= | awk -v support="$support/pgdata" '
    /\/Contents\/MacOS\/LoonInspect([[:space:]]|$)/ ||
    /\.app\/Contents\/Resources\/launcher\/loon_backend\.py/ ||
    (index($0, support) && /\/postgres[[:space:]]+-D[[:space:]]/) {print $1}'
}
for ((attempt=0; attempt<60; attempt++)); do
  [ -n "$(running_services)" ] || break
  sleep 1
done
[ -z "$(running_services)" ] || fail 'A LoonInspect service is still running. Quit LoonInspect (or restart this Mac without reopening it), then rerun. No data was deleted.'

# Fail before deleting data if the Keychain is inaccessible. Never read secret values.
for account in "${key_accounts[@]}"; do
  if security find-generic-password -s LoonInspect -a "$account" >/dev/null 2>&1; then
    :
  else
    result=$?
    [ "$result" -eq 44 ] || fail "Cannot access the LoonInspect Keychain item $account (exit $result). Unlock your login Keychain and rerun. No data was deleted."
  fi
done

printf '\nRemoving local LoonInspect data…\n'
# Remove the database first; if removal fails, retain the keys needed to read it.
for path in "${data_paths[@]}"; do
  rm -rf -- "$path" || fail "Could not remove $path. Check its permissions and rerun."
done
if defaults read "$bundle_id" >/dev/null 2>&1; then
  defaults delete "$bundle_id" >/dev/null || fail 'Could not clear LoonInspect preferences. Rerun after checking this user’s Library permissions.'
fi
for account in "${key_accounts[@]}"; do
  if security delete-generic-password -s LoonInspect -a "$account" >/dev/null 2>&1; then
    :
  else
    result=$?
    [ "$result" -eq 44 ] || fail "Local data was removed, but Keychain item $account could not be removed (exit $result). Unlock your login Keychain and rerun before reinstalling."
  fi
done

for app in "${apps[@]}"; do
  rm -rf -- "$app" || fail "Local data was reset, but $app could not be removed. Move it to Trash in Finder (which can ask for administrator access), then rerun."
done
for path in "${data_paths[@]}" "${apps[@]}"; do
  [ ! -e "$path" ] && [ ! -L "$path" ] || fail "Something recreated $path. Quit all LoonInspect copies and rerun."
done
for account in "${key_accounts[@]}"; do
  if security find-generic-password -s LoonInspect -a "$account" >/dev/null 2>&1; then
    fail "Another Keychain item named $account remains. Rerun before reinstalling."
  else
    result=$?
    [ "$result" -eq 44 ] || fail 'Keychain cleanup could not be verified. Unlock your login Keychain and rerun.'
  fi
done
printf '\nUNINSTALL COMPLETE.\n\n'
printf 'Install LoonInspect 1.3.0 again from:\n%s\n\n' \
  'https://github.com/LoonSecIO/LoonInspect/releases/download/v1.3.0/LoonInspect-1.3.0-arm64.dmg'
printf 'Open the newly installed app. You should see first-time setup.\nCreate a new local administrator and reconnect Jamf.\n'
