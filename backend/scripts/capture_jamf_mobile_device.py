#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["httpx>=0.27"]
# ///
"""Capture one tenant's mobile-device shapes, redacted, into tests/fixtures/jamf/ (#238).

Every mobile shape in `docs/mobile-devices.md` comes from Jamf's published reference and has
never been read against a tenant. This is the trip that fixes that; §6 there is the command.

Credentials come from the environment and nowhere else — not an argument (a secret on a command
line is in the shell history and in every `ps` on the box), not a file (a file gets committed).
Nothing written carries the host, the tenant or a token, and which file a device lands in is read
off its own `supervised` flag: the pair is the fixture (§4), and a mislabelled pair is worse than none.
"""

from __future__ import annotations

import json
import os
import re
import sys
from collections import Counter
from datetime import UTC, datetime
from typing import Any

import httpx

FIXTURES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests", "fixtures", "jamf")

# The reference's mobile section vocabulary, unverified: if it is refused, the script asks with none.
SECTIONS = (
    "GENERAL,HARDWARE,USER_AND_LOCATION,PURCHASING,SECURITY,APPLICATIONS,EBOOKS,NETWORK,SERVICE_SUBSCRIPTIONS,"
    "CERTIFICATES,PROFILES,USER_PROFILES,PROVISIONING_PROFILES,SHARED_USERS,EXTENSION_ATTRIBUTES"
)
# what | the privilege the reference names | candidate paths, tried in order. The Jamf Pro API and
# the Classic API take the same bearer token, so a classic spelling is a free candidate.
READS = tuple(
    rule.split("|")
    for rule in (
        "devices|Read Mobile Devices|/api/v2/mobile-devices",
        "inventory collection settings|Read Mobile Device Inventory Collection Settings"
        "|/api/v1/mobile-device-inventory-collection-settings /api/v2/mobile-device-inventory-collection-settings"
        " /JSSResource/mobiledeviceinventorycollection",
        "smart groups|Read Smart Mobile Device Groups|/api/v1/mobile-device-groups/smart-groups"
        " /api/v1/mobile-device-groups /api/v2/mobile-device-groups /JSSResource/mobiledevicegroups",
    )
)

# --- redaction ----------------------------------------------------------------------
#
# What the computer fixture scrubbed — names, usernames, serials, UDIDs, MACs, addresses, certificate
# identities — plus what only mobile carries: the cellular identifiers, the Managed Apple ID, the
# coordinates, and Lost Mode's phone, message and footnote. It over-redacts where it cannot judge (a
# public CA's subject name, every EA value) and it sweeps: an identifier under a key this table never
# heard of is replaced anyway, and the key printed.

_SWEEPS = (
    (re.compile(r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}"), "uuid"),
    (re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"), "mac"),
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"), "email"),
    # Narrow enough to miss a timestamp, a version and an IMEI: a leading `+`, or 3-3-4 separated.
    (re.compile(r"\+\d[\d\s().-]{6,}\d|(?<![\d.-])(?:\(\d{3}\)\s?|\d{3}[\s.-])\d{3}[\s.-]\d{4}(?![\d-])"), "phone"),
)
_TOKEN_RULES = (  # a substring of the key, lowercased and stripped of punctuation, most specific first
    "udid:uuid managementid:uuid serialnumber:serial macaddress:mac ipaddress:ipv4 ipv6:ipv6 ipv4:ipv4 "
    "email:email appleid:email username:user phonenumber:phone fingerprint:hex assettag:label "
    "latitude:geo longitude:geo lostmodephone:phone lostmodemessage:label lostmodefootnote:label"
)
_KEY_RULES = (  # whole-key matches, for keys too short or too common to match on a substring
    "imei:digits meid:digits iccid:digits eid:digits phone:phone realname:person fullname:person "
    "purchasingaccount:person purchasingcontact:person devicename:label displayname:label room:label "
    "building:label department:label position:label subjectname:label commonname:label issuer:label "
    "ponumber:label applecareid:label softwareupdatedeviceid:label"
)
_BY_TOKEN = tuple(rule.split(":") for rule in _TOKEN_RULES.split())
_BY_KEY = dict(rule.split(":") for rule in _KEY_RULES.split())
# A bare `name` is the device's or an org unit's only under these parents; elsewhere it labels an
# app, a group, a profile or a partition — shapes the contract reads, not identity.
_NAME_PARENTS = frozenset({"", "results", "general", "site", "location", "userandlocation", "hardware"})
_PUNCTUATION = re.compile(r"[^a-z0-9]")  # the Classic API spells the same field `serial_number`
_SHAPE_RULES = (  # kind → the placeholder it mints, keeping the shape a reader expects
    "uuid=A1B2C3D4-0000-4000-8000-{n:012X}|mac=02:00:00:00:00:{n:02X}|ipv4=203.0.113.{n}|ipv6=fe80::{n:x}|"
    "serial=LOONMOBILE{n:02d}|email=loonuser{n}@example.com|user=loonuser{n}|person=Loon User {n}|"
    "phone=+1-555-01{n:02d}"
)
_SHAPES = dict(rule.split("=") for rule in _SHAPE_RULES.split("|"))


def _kind(path: tuple[str, ...]) -> str | None:
    key = _PUNCTUATION.sub("", path[-1].lower())
    parent = _PUNCTUATION.sub("", path[-2].lower()) if len(path) > 1 else ""
    # An EA named "Device Owner" holds a username, a person or a number; its key says so nowhere.
    if parent == "extensionattributes" and key in ("value", "values"):
        return "label"
    if key == "name":
        return "label" if parent in _NAME_PARENTS else None
    if key in _BY_KEY:
        return _BY_KEY[key]
    return next((kind for token, kind in _BY_TOKEN if token in key), None)


def _placeholder(kind: str, n: int, original: Any) -> Any:
    if kind == "geo":  # a position is not a shape worth keeping, and it keeps the record's own type
        return "0.0" if isinstance(original, str) else 0.0
    width = len(str(original))
    if kind in ("digits", "hex"):  # an IMEI and a fingerprint keep their length: a shape is a fact
        return (str(n) if kind == "digits" else f"{n:x}").rjust(width, "0")[-width:]
    return _SHAPES.get(kind, "Redacted {n}").format(n=n)


class Scrub:
    """One capture's replacements: same value in, same placeholder out, so the fixture still joins
    device to user to group as the tenant did. Running it over its own output changes nothing."""

    def __init__(self) -> None:
        self.seen: dict[tuple[str, Any], Any] = {}
        self.counts: Counter[str] = Counter()
        self.swept: set[str] = set()

    def mint(self, kind: str, original: Any) -> Any:
        # Absent stays absent and a flag is a shape; everything else a rule names is replaced
        # whatever its type — a latitude is a float, and letting floats through was the leak.
        if original is None or original == "" or isinstance(original, bool):
            return original
        if (kind, original) not in self.seen:
            self.counts[kind] += 1
            placeholder = _placeholder(kind, self.counts[kind], original)
            self.seen[(kind, original)] = self.seen[(kind, placeholder)] = placeholder
        return self.seen[(kind, original)]

    def walk(self, value: Any, path: tuple[str, ...] = ()) -> Any:
        if isinstance(value, dict):
            return {key: self.walk(item, (*path, str(key))) for key, item in value.items()}
        if isinstance(value, list):
            return [self.walk(item, path) for item in value]
        kind = _kind(path) if path else None
        if kind:
            return self.mint(kind, value)
        if not isinstance(value, str):
            return value
        for pattern, sweep_kind in _SWEEPS:
            if pattern.search(value):
                self.swept.add(".".join(path) or "(root)")
                value = pattern.sub(lambda match, k=sweep_kind: str(self.mint(k, match.group(0))), value)
        return value


def redact(payload: Any, scrub: Scrub | None = None) -> tuple[Any, Scrub]:
    """The redacted copy, and the scrub that made it: counts for the summary, swept keys for the finding."""
    scrub = scrub or Scrub()
    return scrub.walk(payload), scrub


# --- the trip -----------------------------------------------------------------------


def _settings() -> tuple[str, str, str]:
    missing = [name for name in ("JAMF_URL", "JAMF_CLIENT_ID", "JAMF_CLIENT_SECRET") if not os.environ.get(name)]
    if missing:
        sys.exit(f"capture stopped: {', '.join(missing)} not set. Export all three for an API client on the tenant.")
    return os.environ["JAMF_URL"].rstrip("/"), os.environ["JAMF_CLIENT_ID"], os.environ["JAMF_CLIENT_SECRET"]


def _token(http: httpx.Client, base: str, client_id: str, secret: str) -> str:
    data = {"grant_type": "client_credentials", "client_id": client_id, "client_secret": secret}
    response = http.post(f"{base}/api/oauth/token", data=data)
    if response.status_code != 200:
        sys.exit(
            f"capture stopped: Jamf refused the API client credentials ({response.status_code}). Check JAMF_URL, and "
            "the client id and secret under Settings → System → API roles and clients. Nothing was written."
        )
    return response.json()["access_token"]


def _get(http: httpx.Client, base: str, token: str, path: str, params: dict | None = None) -> httpx.Response:
    return http.get(f"{base}{path}", params=params, headers={"Authorization": f"Bearer {token}"})


def _answer(http: httpx.Client, base: str, token: str, paths: str, params: dict | None = None) -> tuple[str, Any]:
    """The first candidate spelling that is not a 404 is the endpoint; if none answers, every
    status comes back in its place, because a spelling that 404s is a finding of its own."""
    tried = []
    for path in paths.split():
        response = _get(http, base, token, path, params)
        tried.append(f"{path} {response.status_code}")
        if response.status_code != 404:
            return path, response
    return ", ".join(tried), None


_RUN = Scrub()  # one scrub for the whole trip, so the two devices never redact to one UDID


def _write(name: str, payload: Any) -> None:
    """Redact, then write: nothing else writes a fixture, so no unscrubbed byte reaches disk."""
    redacted, _ = redact(payload, _RUN)
    target = os.path.join(FIXTURES, name)
    with open(target, "w") as handle:
        handle.write(json.dumps(redacted, indent=2, ensure_ascii=False) + "\n")
    print(f"  wrote {name} ({os.path.getsize(target)} bytes)")


def _flag(value: Any, wanted: str) -> bool | None:
    """A named boolean anywhere in a record: `supervised` sits in a type-specific block
    whose spelling nobody has read, so it is searched for rather than addressed."""
    items = value.items() if isinstance(value, dict) else enumerate(value) if isinstance(value, list) else ()
    for key, item in items:
        if str(key).lower() == wanted and isinstance(item, bool):
            return item
        found = _flag(item, wanted)
        if found is not None:
            return found
    return None


def _privileges(rows: list[tuple[str, str, int, str]], version: str) -> None:
    """The ledger, merged with its own previous run: a read that was 403 before and answers now
    is a privilege that was *needed* — evidence the reference cannot give. No host in this file."""
    target = os.path.join(FIXTURES, "mobile_privileges.txt")
    before: dict[str, str] = {}
    if os.path.exists(target):
        with open(target) as handle:
            before = {row[0]: row[2] for row in (line.split("\t") for line in handle) if len(row) > 2}
    lines = [
        f"# The API Role privileges the mobile capture needed (#238). Jamf Pro {version}, {datetime.now(UTC).date()}.",
        "# read <TAB> path <TAB> status <TAB> privilege. 'needed' marks one that answered only once the privilege",
        "# was ticked between two runs — the reference is a claim; that is a fact.",
    ]
    for what, path, status, privilege in rows:
        was = before.get(what, "")  # carried, not re-derived: a third run must not erase run two's evidence
        needed = " (needed)" if status == 200 and (was.startswith("403") or "(needed)" in was) else ""
        note = privilege if status != 403 else f"{privilege} — 403: tick it in the API Role and run again"
        lines.append(f"{what}\t{path}\t{status}{needed}\t{note}")
    with open(target, "w") as handle:
        handle.write("\n".join(lines) + "\n")
    print(f"  wrote mobile_privileges.txt ({len(rows)} reads)")


def _devices(http: httpx.Client, base: str, token: str, body: Any, rows: list[tuple[str, str, int, str]]) -> list[str]:
    """Every listed device's full detail (the first four; a demo tenant has two), named by supervision."""
    _write("mobile_devices_list_real.json", body)
    written: list[str] = []
    for device in (body.get("results", []) if isinstance(body, dict) else [])[:4]:
        device_id = str(device.get("id", "")) if isinstance(device, dict) else ""
        if not device_id:
            continue
        path = f"/api/v2/mobile-devices/{device_id}/detail"
        response = _get(http, base, token, path, {"section": SECTIONS})
        asked = "?section=<every>"
        if response.status_code == 400:
            # The endpoint may take no section parameter at all; nobody has asked. Ask again with none.
            response, asked = _get(http, base, token, path), "(the sectioned form was refused)"
        read = f"/api/v2/mobile-devices/{{id}}/detail {asked}"
        rows.append(("device detail", read, response.status_code, "Read Mobile Devices"))
        if response.status_code != 200:
            print(f"! device {device_id}: detail answered {response.status_code}")
            continue
        record = response.json()
        supervised = _flag(record, "supervised")
        if supervised is None:
            print(f"  device {device_id}: no `supervised` flag anywhere in the record — a finding for §4")
        name = "mobile_device_detail_unsupervised_real.json" if supervised is False else "mobile_device_detail_real.json"
        if name in written:
            print(f"  device {device_id}: that side of the supervised pair is already written; skipped")
            continue
        _write(name, record)
        written.append(name)
    return written


def main() -> int:
    base, client_id, secret = _settings()
    rows: list[tuple[str, str, int, str]] = []
    captured: list[str] = []
    with httpx.Client(timeout=30, headers={"Accept": "application/json"}) as http:
        token = _token(http, base, client_id, secret)
        answer = _get(http, base, token, "/api/v1/jamf-pro-version")
        version = answer.json().get("version", "unknown") if answer.status_code == 200 else "unknown"
        print(f"Jamf Pro {version}; writing into {FIXTURES}")

        for what, privilege, candidates in READS:
            params = {"page": 0, "page-size": 100, "sort": "id:asc"} if what == "devices" else None
            path, response = _answer(http, base, token, candidates, params)
            if response is None:
                rows.append((what, path, 404, f"{privilege} — every spelling 404s; the endpoint is elsewhere"))
                print(f"! {what}: no candidate answered ({path})")
                continue
            rows.append((what, path, response.status_code, privilege))
            if response.status_code != 200:
                print(f"! {what}: {path} answered {response.status_code}; needs {privilege!r}")
            elif what == "devices":
                captured = _devices(http, base, token, response.json(), rows)
            elif "collection" in what:
                _write("mobile_inventory_collection_settings_real.json", response.json())
            else:
                _write("mobile_smart_group_real.json", response.json())

    _privileges(rows, version)
    if not captured:
        sys.exit(
            "No mobile device record was captured. Enrol an iPad — supervised, and a second unsupervised if it is "
            "cheap — and run this again; docs/mobile-devices.md §4 says why the pair is the fixture."
        )
    unknown = f"; keys the table did not know: {', '.join(sorted(_RUN.swept))}" if _RUN.swept else ""
    print(f"redacted: {', '.join(f'{k} ×{v}' for k, v in sorted(_RUN.counts.items())) or 'nothing'}{unknown}")
    print("Read every written file before committing it: this fixtures directory is public.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
