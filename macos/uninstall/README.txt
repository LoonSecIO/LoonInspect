LoonInspect clean uninstall / local reset

Replacing or deleting LoonInspect.app preserves this Mac user's local accounts,
inventory, logs and Keychain secrets. Reinstalling normally reopens that instance.

For a deliberate permanent reset, open Terminal and drag LoonInspect-Uninstall
from this disk image into it. Press Return for a read-only preview. To proceed,
append --uninstall and press Return. Read the exact removal paths and type both
requested confirmations. Never use sudo. There is no unattended --yes mode.

The helper stops verified LoonInspect processes belonging to the current user,
waits for services to stop, removes the listed local runtime data and login
Keychain credentials, and removes matching, user-owned app bundles only from
/Applications and ~/Applications. It refuses symbolic-link paths, changed files,
unsafe ownership and services that will not stop. Failures identify the next check;
a failed removal can be partial, so preview again before retrying.

A backup needs a copy of pgdata taken while the app is quit AND its matching
ENCRYPTION_KEY, postgres-looninspect_app and postgres-looninspect login Keychain
items (service LoonInspect). This helper never creates a backup or exports secrets.
Move any needed backups and exported evidence OUTSIDE ALL previewed removal paths
before confirming. Sibling backup/export files, other users' data and remote Jamf
data are retained. Custom app locations, shared app bundles owned by another user,
credentials in other keychains and macOS-managed temporary WebKit caches are retained.

After reset, install/open the signed app and complete first-time setup with a new
account. Re-pair MCP clients with new tokens. This is not password recovery.
Full backup instructions: docs/macos-app.md, Backup, in the LoonInspect repository.
