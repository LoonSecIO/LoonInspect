"""`apply_hashes` is the single choke point where every ingest path is hashed.

The MDM clients deliberately do not hash their own output, so a scheduled sweep, a
manual sync, and an inbound webhook all arrive here and come out identical. If one path
ever hashed separately the three would drift and the same install would produce
different Global API lookup keys depending on how it was ingested.

The inventory delta itself is not covered here. It is computed inline inside
`process_sync` against a live session (`service.py:245-250`), so testing it needs
either a database or a refactor extracting it into a pure function — and doing that
refactor before any coverage exists is the wrong order. Tracked as follow-on work.
"""

from __future__ import annotations

from app.core.hashing import compute_app_hash, compute_version_hash
from app.mdm.service import apply_hashes
from app.schemas.payload import NormalizedApp


def _app(**overrides) -> NormalizedApp:
    fields = {"name": "Slack", "bundle_id": "com.tinyspeck.slackmacgap", "version": "4.0.1"}
    return NormalizedApp(**(fields | overrides))


def test_stamps_both_hashes() -> None:
    app = _app()
    assert app.app_hash is None and app.version_hash is None

    apply_hashes(app)

    assert app.app_hash == compute_app_hash("Slack", "com.tinyspeck.slackmacgap")
    assert app.version_hash == compute_version_hash("Slack", "com.tinyspeck.slackmacgap", "4.0.1")


def test_returns_the_same_object() -> None:
    """Callers use the return value and the mutation interchangeably; returning a copy
    would leave one of the two silently unhashed."""
    app = _app()
    assert apply_hashes(app) is app


def test_short_version_is_forwarded() -> None:
    """The HEC path supplies both version fields. If `apply_hashes` dropped the short
    version, a webhook-ingested app would hash to the three-part key and collide with
    the sweep-ingested one instead of being the more precise record it should be."""
    app = apply_hashes(_app(short_version="4001"))

    assert app.version_hash == compute_version_hash("Slack", "com.tinyspeck.slackmacgap", "4.0.1", "4001")
    assert app.version_hash != compute_version_hash("Slack", "com.tinyspeck.slackmacgap", "4.0.1")


def test_a_version_bump_changes_only_the_version_hash() -> None:
    """The property the Applications page depends on: one app row, many builds."""
    old = apply_hashes(_app(version="4.0.1"))
    new = apply_hashes(_app(version="4.1.0"))

    assert old.app_hash == new.app_hash
    assert old.version_hash != new.version_hash
