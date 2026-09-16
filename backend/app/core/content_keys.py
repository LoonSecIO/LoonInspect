"""Canonical content keys for community data sharing — the v1 contract.

These keys are shared vocabulary between every shipped container and the LoonSec
cloud: prevalence uploads are keyed by them, feed lookups join on them, and the
reveal threshold counts distinct submitters per identical key. A drifting key is
therefore not a counting bug — it is a silent false negative in vulnerability
matching. The rules below are frozen in docs/data-sharing.md and asserted as
literal digests in tests/test_content_keys.py; they change only behind a new
version prefix, never in place.

The older MD5 pair in app.core.hashing remains the *internal* grouping and delta
key. The wire role it once described has moved here.
"""

from __future__ import annotations

import hashlib
import unicodedata

# U+001F joins fields. It cannot legitimately appear in any field, and is stripped
# if a hostile or broken source ever supplies it — a delimiter that can occur in
# data is two keys for one app waiting to happen.
_SEPARATOR = "\x1f"

_PREFIX = "v1:"

# Domain namespaces, so an OS tuple can never collide with an app tuple.
DOMAIN_APP_TITLE = "app.title"
DOMAIN_APP_FULL = "app.full"
DOMAIN_APP_BUNDLE = "app.bundle"
DOMAIN_OS = "os"
DOMAIN_HW = "hw"


def _canonical_field(value: str | None) -> str:
    """NFC-normalize and strip. None participates as the empty string — null and
    empty are deliberately indistinguishable (Jamf sends null short versions, the
    HEC payload sends real ones, and both must land on one key when equal)."""
    if value is None:
        return ""
    return unicodedata.normalize("NFC", value).strip().replace(_SEPARATOR, "")


def canonical_key(domain: str, *fields: str | None) -> str:
    payload = _SEPARATOR.join([domain, *[_canonical_field(f) for f in fields]])
    return _PREFIX + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def app_title_key(name: str, bundle_id: str) -> str:
    """The application's *identity*, independent of version — the disclosure-control
    and feed-join key."""
    return canonical_key(DOMAIN_APP_TITLE, name, bundle_id)


def app_full_key(name: str, bundle_id: str, version: str, short_version: str | None) -> str:
    """A specific build — the prevalence key."""
    return canonical_key(DOMAIN_APP_FULL, name, bundle_id, version, short_version)


def app_bundle_key(bundle_id: str | None, version: str) -> str | None:
    """The build *without its name* — the rename-proof prevalence key (#245).

    `key_title` and `key_full` both hash the display name, so an admin who renames an app
    — a rebranded Self Service, a white-labelled Electron build — mints keys only their
    own fleet has, and the corpus's reveal threshold counts one submitter forever
    (docs/data-sharing.md, the k-rule). Every rename of one bundle collapses onto one
    `app.bundle` key, so prevalence measures the software rather than the popularity of
    its default name.

    Returns None — never a key — when there is no bundle identifier to hash. This is the
    one place the empty-string rule of `_canonical_field` would do real harm rather than
    merely absorb a null: identity here is the bundle id alone, so every nameless app at
    one version would land on a single shared digest and be counted as one piece of
    software. An absent key is a row the corpus skips; a wrong key is a count that lies.
    Jamf's client already falls back to the app's name where `bundleId` is missing
    (`app.mdm.jamf.client`), which can leave the field blank as well as null, so both
    spellings of absence answer None.
    """
    if bundle_id is None or not _canonical_field(bundle_id):
        return None
    return canonical_key(DOMAIN_APP_BUNDLE, bundle_id, version)


def os_key(platform: str, os_version: str, os_build: str | None) -> str:
    return canonical_key(DOMAIN_OS, platform, os_version, os_build)


def hw_key(model_identifier: str, cpu_arch: str | None) -> str:
    return canonical_key(DOMAIN_HW, model_identifier, cpu_arch)
