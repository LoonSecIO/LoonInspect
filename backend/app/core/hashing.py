from __future__ import annotations

import hashlib

# Internal keys: app_hash groups the Applications page, version_hash drives inventory
# deltas. Their former wire role — the lookup key sent to the LoonSec Global API —
# moved to app.core.content_keys (v1, SHA-256; see docs/data-sharing.md). Changing
# these still reshuffles deltas on the next sync, so they stay stable, but they are
# no longer cross-codebase contract.

_SEPARATOR = ":"


def _md5(*parts: str) -> str:
    return hashlib.md5(_SEPARATOR.join(parts).encode("utf-8")).hexdigest()


def compute_app_hash(name: str, bundle_id: str) -> str:
    """Identifies the *application*, independent of version.

    md5("AppName:BundleID"). This is what groups Slack 4.0.1 and Slack 4.1.0 into one
    row on the Applications page.
    """
    return _md5(name, bundle_id)


def compute_version_hash(
    name: str, bundle_id: str, version: str, short_version: str | None = None
) -> str:
    """Identifies a specific *build* of an application — the internal per-build key.

    md5("AppName:BundleID:Version:ShortVersion"), with the short version omitted
    entirely when absent rather than joined as an empty segment. Jamf's inventory
    returns only one version field, so most records hash on three components; a source
    that supplies both (the HEC payload) hashes on four and produces a different,
    more precise key for the same install.
    """
    parts = [name, bundle_id, version]
    if short_version:
        parts.append(short_version)
    return _md5(*parts)
