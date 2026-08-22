"""The diff engine: two observations of one subject in, a list of changes out. Pure.

Scalar sections are compared leaf by leaf on their canonical documents (dotted paths);
list sections are compared as entry sets, then added/removed entries are paired by the
kind's identity fields so a version bump reads as one `updated` rather than a removal
and an addition. Nothing here knows about policy or levels — that is applied afterwards
— so the engine can also back a "show me everything that changed" view.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class FieldChange:
    section: str
    field: str  # dotted path
    old: Any
    new: Any


@dataclass(frozen=True, slots=True)
class Entry:
    digest: str
    body: Mapping
    label: str | None = None


@dataclass(frozen=True, slots=True)
class EntryChange:
    section: str
    kind: str
    change: str  # added | removed | updated
    identity: dict
    old: Mapping | None
    new: Mapping | None
    label: str | None = None
    changed_fields: tuple[str, ...] = field(default=())


def flatten(document: Mapping | None, prefix: str = "") -> dict[str, Any]:
    """Dotted-path leaves of a canonical document. Lists are leaves (compared whole):
    the contract's scalar sections carry only lists of strings, and a smart group's
    criteria list is one thing that "moved" or did not."""
    out: dict[str, Any] = {}
    if not isinstance(document, Mapping):
        return out
    for key, value in document.items():
        path = f"{prefix}{key}"
        if isinstance(value, Mapping):
            out.update(flatten(value, f"{path}."))
        else:
            out[path] = value
    return out


def diff_scalar(section: str, old: Mapping | None, new: Mapping | None) -> list[FieldChange]:
    before, after = flatten(old), flatten(new)
    changes: list[FieldChange] = []
    for path in sorted(set(before) | set(after)):
        if before.get(path) != after.get(path):
            changes.append(FieldChange(section=section, field=path, old=before.get(path), new=after.get(path)))
    return changes


def _identity(body: Mapping, keys: Sequence[str]) -> dict:
    return {key: body.get(key) for key in keys}


def _identity_key(body: Mapping, keys: Sequence[str]) -> tuple:
    return tuple(_stable(body.get(key)) for key in keys)


def _stable(value: Any) -> Any:
    if isinstance(value, list):
        return tuple(_stable(v) for v in value)
    if isinstance(value, Mapping):
        return tuple(sorted((k, _stable(v)) for k, v in value.items()))
    return value


def diff_entries(
    section: str,
    kind: str,
    identity: Sequence[str],
    old: Iterable[Entry],
    new: Iterable[Entry],
) -> list[EntryChange]:
    old_by_digest = {entry.digest: entry for entry in old}
    new_by_digest = {entry.digest: entry for entry in new}
    gone = [entry for digest, entry in old_by_digest.items() if digest not in new_by_digest]
    came = [entry for digest, entry in new_by_digest.items() if digest not in old_by_digest]

    # Pair by identity: the same app at the same path with a different version is one
    # update. If several entries share an identity (two copies of one app at one path
    # cannot happen, but two EA values for one definition could), pair them in order.
    came_by_identity: dict[tuple, list[Entry]] = {}
    for entry in came:
        came_by_identity.setdefault(_identity_key(entry.body, identity), []).append(entry)

    changes: list[EntryChange] = []
    for entry in gone:
        key = _identity_key(entry.body, identity)
        candidates = came_by_identity.get(key)
        if candidates:
            partner = candidates.pop(0)
            changed = tuple(
                sorted(
                    name
                    for name in set(entry.body) | set(partner.body)
                    if name not in identity and entry.body.get(name) != partner.body.get(name)
                )
            )
            changes.append(
                EntryChange(
                    section=section, kind=kind, change="updated",
                    identity=_identity(partner.body, identity),
                    old=entry.body, new=partner.body,
                    label=partner.label or entry.label, changed_fields=changed,
                )
            )
        else:
            changes.append(
                EntryChange(
                    section=section, kind=kind, change="removed",
                    identity=_identity(entry.body, identity), old=entry.body, new=None, label=entry.label,
                )
            )
    for remaining in came_by_identity.values():
        for entry in remaining:
            changes.append(
                EntryChange(
                    section=section, kind=kind, change="added",
                    identity=_identity(entry.body, identity), old=None, new=entry.body, label=entry.label,
                )
            )
    # Deterministic order: by change kind then identity, so tests and event streams are stable.
    order = {"removed": 0, "updated": 1, "added": 2}
    changes.sort(key=lambda c: (order[c.change], repr(sorted(c.identity.items()))))
    return changes
