"""UUIDv7 (RFC 9562 §5.7): a small, dependency-free generator for one thing — the run
id, promoted to a wire correlation key (`jobID`) by #188 and no longer safe to mint as
`uuid.uuid4()`'s random hex (#225, split from #188's ruling on 2026-09-01).

`core/runs.py` minted the run id with `uuid.uuid4()`. `jobID` rides every event a run
produces, so `eventstats max(jobID) by serialNumber` — the natural latest-state idiom on
a fan-out sourcetype — is the search an analyst reaches for. Over random hex that search
is not wrong, exactly; it is meaningless, and it fails the way #188 exists to
prevent: a plausible answer, no error, silently sorting devices by nothing.

**Not `uuid.uuid7()`.** That lands in the standard library at Python 3.14. This repo
runs 3.12 in the image (`Dockerfile`) and declares `requires-python >=3.11`
(`pyproject.toml`), so the stdlib function does not exist at runtime here — this module
is the local helper #225 asked for rather than a dependency or a Python bump.

**Not ULID either**, per #188's own ruling: a 26-character Crockford base32 token would
put a second id shape on the wire beside `eventID` (a `uuid5`) for no gain UUIDv7 doesn't
already give. UUIDv7 keeps the exact 36-character hyphenated shape and 16-byte width
`uuid.uuid4()` already produced, so nothing downstream that stores, displays, or parses
a run id as a UUID changes format — only its ordering property is new.

**This is free today and a breaking change after the flip.** `eventID` is
`uuid5(jobID, jamfProID)` (docs/runs.md), so changing `jobID`'s generator changes every
derived event id too. Landing this before the flip, while the wire has no customers
depending on an `eventID`'s specific value, is what makes it free.
"""

from __future__ import annotations

import os
import time
import uuid

# RFC 9562 §4.1: the 4-bit version nibble (bits 79-76) and the 2-bit variant (bits
# 63-62, the "10" prefix identifying the RFC 4122 / RFC 9562 variant family).
_VERSION_NIBBLE = 0x7
_VARIANT_BITS = 0b10

_RAND_A_MASK = 0x0FFF  # 12 bits, RFC 9562's "pure random" construction (method 1).
_RAND_B_MASK = 0x3FFFFFFFFFFFFFFF  # 62 bits.
_TIMESTAMP_MASK = 0xFFFFFFFFFFFF  # 48 bits — good for ~8919 years past the epoch.


def _current_unix_ms() -> int:
    """The clock `uuid7()` reads, factored out as a seam for tests.

    Two ids minted in the same millisecond are not ordered relative to each other — RFC
    9562's pure-random construction (the one this module implements) does not promise
    that, only millisecond-resolution ordering. A test that wants to pin "ids sort in
    creation order" therefore has to control the clock rather than rely on real
    wall-clock gaps between two calls, which can land in the same millisecond and
    legitimately tie. Monkeypatching this module-level function is that control point.
    """
    return time.time_ns() // 1_000_000


def uuid7() -> uuid.UUID:
    """A time-ordered UUID: RFC 9562 version 7, the "pure random" construction (§5.7,
    method 1) — a 48-bit big-endian millisecond Unix timestamp, the version and variant
    nibbles, and 74 bits of `os.urandom`, the same CSPRNG source `uuid.uuid4()` itself
    draws from (CPython's `uuid4()` is `UUID(bytes=os.urandom(16))` with the version and
    variant bits overwritten — this is that same shape with the leading bytes replaced
    by a clock reading instead of more randomness).

    **Ordering holds at millisecond resolution, not below it.** Two ids minted in the
    same millisecond are unordered relative to each other, by the RFC's own definition
    of this construction — not a bug this module introduces. That is the right trade for
    a run id: runs are not minted faster than a handful per second even on a busy
    tenant's webhook burst, so a same-millisecond pair is rare, and when it happens the
    two runs' own `occurredAt` / window fields still carry the true order on the wire —
    the id only has to make `eventstats max(jobID) by serialNumber` meaningful, not
    serialize a race between two acquisitions.

    **Still effectively unguessable despite the visible timestamp.** `Run.id`'s own
    docstring (`app/models/schema.py`) records unguessability as the reason the run id is
    a UUID rather than a sequence — "a customer's Splunk search should not be able to
    guess a neighbouring run's id." A v7 id spends 48 of its 128 bits on a timestamp
    instead of randomness, dropping the random tail from `uuid4()`'s 122 bits to 74 (12
    in `rand_a`, 62 in `rand_b`). That is still 2**74 candidates even for an adversary who
    already knows the exact millisecond a neighbouring run started — itself not secret;
    it is what that run's own `occurredAt` already says — which is far beyond anything a
    rate-limited API has to defend against. The property survives the switch.
    """
    unix_ts_ms = _current_unix_ms() & _TIMESTAMP_MASK
    # 10 bytes covers both random fields: 2 for rand_a's 12 bits, 8 for rand_b's 62.
    rand = os.urandom(10)
    rand_a = int.from_bytes(rand[0:2], "big") & _RAND_A_MASK
    rand_b = int.from_bytes(rand[2:10], "big") & _RAND_B_MASK

    value = unix_ts_ms << 80
    value |= (_VERSION_NIBBLE << 12 | rand_a) << 64
    value |= (_VARIANT_BITS << 62) | rand_b
    return uuid.UUID(int=value)
