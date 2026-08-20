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


def os_key(platform: str, os_version: str, os_build: str | None) -> str:
    return canonical_key(DOMAIN_OS, platform, os_version, os_build)


def hw_key(model_identifier: str, cpu_arch: str | None) -> str:
    return canonical_key(DOMAIN_HW, model_identifier, cpu_arch)
