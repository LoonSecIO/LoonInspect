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
import textwrap
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
# coordinates, Lost Mode's phone, message and footnote, and the secrets a device record keeps (AirPlay's
# password, the activation-lock bypass code — a secret is not an identifier, so no sweep can see one).
# It over-redacts where it cannot judge (a public CA's subject name, every EA value, every smart-group
# criterion value, every `name` a tenant rather than a vendor chose) and it sweeps: an identifier under
# a key this table never heard of is replaced anyway.
#
# A table holds what somebody thought of, which is why the scrub also *holds*: every other string written
# under a key no rule names is listed under the file it landed in. "Read every written file before
# committing it" is only as good as the list it is read against, and that list is the last defence.

_SWEEPS = (
    (re.compile(r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}"), "uuid"),
    (re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"), "mac"),
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"), "email"),
    # Narrow enough to miss a timestamp, a version and an IMEI: a leading `+`, or 3-3-4 separated.
    (re.compile(r"\+\d[\d\s().-]{6,}\d|(?<![\d.-])(?:\(\d{3}\)\s?|\d{3}[\s.-])\d{3}[\s.-]\d{4}(?![\d-])"), "phone"),
)
# A written string nobody needs to read again: a small number, a version, a date, an enum token, a flag.
# Bounded on purpose: a long run of digits is an ICCID or a phone number and a long mixed run of capitals
# and digits is a serial — neither is trivial, and the held list is the only thing that will say so.
# (An all-caps username such as KPAZANDAK is still indistinguishable from an enum token and stays off it.)
_TRIVIAL = re.compile(r"\s*|-?\d[\d.]{0,7}|\d[\d.:+TZ -]*[:T-][\d.:+TZ -]*|[A-Z][A-Z_]*|[A-Z][A-Z0-9_]{0,7}|true|false|null")
_TOKEN_RULES = (  # a substring of the key, lowercased and stripped of punctuation, most specific first
    "udid:uuid managementid:uuid serialnumber:serial macaddress:mac ipaddress:ipv4 ipv6:ipv6 ipv4:ipv4 "
    "email:email appleid:email username:user phonenumber:phone fingerprint:hex assettag:label "
    "latitude:geo longitude:geo lostmodephone:phone lostmodemessage:label lostmodefootnote:label "
    # Jamf spells the PreStage a device enrolled through `enrollmentMethodPrestage.profileName` and
    # `enrollmentMethod.objectName`, never `name`: a tenant-chosen name that a bare `name` rule never reaches.
    "displayname:label profilename:label objectname:label "
    # The secrets: AirPlay's password reached a fixture in full once, under a key the table did not name.
    "password:secret passphrase:secret passcode:secret bypasscode:secret unlockcode:secret "
    "recoverykey:secret privatekey:secret secret:secret token:secret credential:secret"
)
_KEY_RULES = (  # whole-key matches, for keys too short or too common to match on a substring
    "imei:digits meid:digits iccid:digits eid:digits phone:phone realname:person fullname:person "
    "purchasingaccount:person purchasingcontact:person devicename:label room:label pin:secret "
    "building:label department:label position:label subjectname:label commonname:label issuer:label "
    # An e-book's author and title are a person and a document the tenant loaded; a cellular line's `label`
    # is what the device's own user typed on the iPhone ("Kyle Personal"), not a carrier's word.
    "author:person title:label label:label "
    "ponumber:label applecareid:label softwareupdatedeviceid:label"
)
_BY_TOKEN = tuple(rule.split(":") for rule in _TOKEN_RULES.split())
_BY_KEY = dict(rule.split(":") for rule in _KEY_RULES.split())
# A bare `name` is the tenant's unless its parent says otherwise: an app, an e-book, a carrier and a
# criterion field are named by a vendor or by Jamf, while a device, a group, a site and a profile are named
# by whoever runs the tenant. An extension attribute is the one parent here whose `name` the tenant *does*
# author, and it is kept anyway: that vocabulary is what the fixture exists to show, and it lands on the
# held list, where the one person who can tell a carrier from a customer reads it before committing.
# The allowlist this replaces ran the other way round, and "Kyle's iPad" under `mobile_devices[].name` in a
# Classic group body was written out whole. A prestage name is not reached by any of this — Jamf spells it
# `profileName` and `objectName`, which is why those are key rules above.
_NAME_SHAPE_PARENTS = (  # the parents under which a `name` belongs to a vendor or to Jamf, not to the tenant
    "applications application ebooks ebook extensionattributes criteria criterion servicesubscriptions"
)
_NAME_SHAPES = frozenset(_NAME_SHAPE_PARENTS.split())
# An opaque value: what a smart-group criterion searches on, or what an EA holds, is whatever the tenant
# put there — a username, a serial, a device name — and the key says so nowhere.
_OPAQUE_VALUES = frozenset({"extensionattributes", "criteria", "criterion"})
_PUNCTUATION = re.compile(r"[^a-z0-9]")  # the Classic API spells the same field `serial_number`
_SHAPE_RULES = (  # kind → the placeholder it mints, keeping the shape a reader expects
    "uuid=A1B2C3D4-0000-4000-8000-{n:012X}|mac=02:00:00:00:00:{n:02X}|ipv4=203.0.113.{n}|ipv6=fe80::{n:x}|"
    "serial=LOONMOBILE{n:02d}|email=loonuser{n}@example.com|user=loonuser{n}|person=Loon User {n}|"
    "phone=+1-555-01{n:02d}|secret=redacted-secret-{n}"
)
_SHAPES = dict(rule.split("=") for rule in _SHAPE_RULES.split("|"))


def _kind(path: tuple[str, ...]) -> str | None:
    key = _PUNCTUATION.sub("", path[-1].lower())
    parent = _PUNCTUATION.sub("", path[-2].lower()) if len(path) > 1 else ""
    # An EA named "Device Owner" holds a username, a person or a number; a criterion's value likewise.
    if parent in _OPAQUE_VALUES and key in ("value", "values"):
        return "label"
    if key == "name":
        return None if parent in _NAME_SHAPES else "label"
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
        self.seen: dict[Any, Any] = {}  # keyed on the value, not on (kind, value): see mint()
        self.counts: Counter[str] = Counter()
        self.swept: set[str] = set()
        self.held: set[str] = set()  # written as the tenant wrote it, under a key no rule names

    def mint(self, kind: str, original: Any) -> Any:
        # Absent stays absent and a flag is a shape; everything else a rule names is replaced
        # whatever its type — a latitude is a float, and letting floats through was the leak.
        if original is None or original == "" or isinstance(original, bool):
            return original
        if kind == "secret" and not isinstance(original, str):
            return original  # `passcodePresent` and a grace period in seconds are shapes, not secrets
        if original not in self.seen:
            self.counts[kind] += 1
            placeholder = _placeholder(kind, self.counts[kind], original)
            # One placeholder per value whichever rule mints it first: a serial read as a device field and
            # again as a smart-group criterion has to land on the same string or the fixture stops joining.
            self.seen[original] = self.seen[placeholder] = placeholder
        return self.seen[original]

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
        where = ".".join(path) or "(root)"
        for pattern, sweep_kind in _SWEEPS:
            if pattern.search(value):
                self.swept.add(where)
                value = pattern.sub(lambda match, k=sweep_kind: str(self.mint(k, match.group(0))), value)
        if not _TRIVIAL.fullmatch(value):
            self.held.add(where)  # no rule named the key and no sweep explains what is left: a human reads it
        return value


def redact(payload: Any, scrub: Scrub | None = None) -> tuple[Any, Scrub]:
    """The redacted copy, and the scrub that made it: counts for the summary, swept and held keys to read."""
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
NOTES: list[str] = []  # what degraded quietly mid-run, repeated at the end where it is still on screen
_HELD_TOTAL: set[str] = set()


def _write(name: str, payload: Any) -> None:
    """Redact, then write: nothing else writes a fixture, so no unscrubbed byte reaches disk."""
    _RUN.held = set()  # held is per file: the same key in a second file is a second tenant's words
    redacted, _ = redact(payload, _RUN)
    target = os.path.join(FIXTURES, name)
    with open(target, "w") as handle:
        handle.write(json.dumps(redacted, indent=2, ensure_ascii=False) + "\n")
    print(f"  wrote {name} ({os.path.getsize(target)} bytes)")
    _HELD_TOTAL.update(_RUN.held)
    if _RUN.held:
        print(f"    {len(_RUN.held)} keys no rule names; their values are the tenant's own. Read them in {name}:")
        print(textwrap.fill(", ".join(sorted(_RUN.held)), 118, initial_indent="      ", subsequent_indent="      "))


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
    rows = list(dict.fromkeys(rows))  # `device detail` is one read asked once per device, not one read each
    before: dict[str, str] = {}
    if os.path.exists(target):
        with open(target) as handle:
            before = {f"{row[0]}\t{row[1]}": row[2] for row in (line.split("\t") for line in handle) if len(row) > 2}
    lines = [
        f"# The API Role privileges the mobile capture needed (#238). Jamf Pro {version}, {datetime.now(UTC).date()}.",
        "# read <TAB> path <TAB> status <TAB> privilege. 'needed' marks one that answered only once the privilege",
        "# was ticked between two runs — the reference is a claim; that is a fact.",
    ]
    for what, path, status, privilege in rows:
        was = before.get(f"{what}\t{path}", "")  # carried, not re-derived: run three must not erase run two
        needed = " (needed)" if status == 200 and (was.startswith("403") or "(needed)" in was) else ""
        note = privilege if status != 403 else f"{privilege} — 403: tick it in the API Role and run again"
        lines.append(f"{what}\t{path}\t{status}{needed}\t{note}")
    with open(target, "w") as handle:
        handle.write("\n".join(lines) + "\n")
    print(f"  wrote mobile_privileges.txt ({len(rows)} reads)")


def _devices(
    http: httpx.Client, base: str, token: str, body: Any, rows: list[tuple[str, str, int, str]]
) -> tuple[list[str], str]:
    """Every listed device's full detail (the first four; a demo tenant has two), named by supervision.
    The second return is why nothing was captured — the three reasons are different instructions."""
    _write("mobile_devices_list_real.json", body)
    listed = (body.get("results", []) if isinstance(body, dict) else [])[:4]
    written: list[str] = []
    refused: list[str] = []
    for device in listed:
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
            refused.append(f"{device_id} → {response.status_code}")
            continue
        record = response.json()
        supervised = _flag(record, "supervised")
        name = "mobile_device_detail_unsupervised_real.json" if supervised is False else "mobile_device_detail_real.json"
        if supervised is None:
            NOTES.append(
                f"device {device_id}: no `supervised` flag anywhere in the record, so {name} claims a side of the "
                "pair the record itself does not state — a finding for §4, and a caveat for the commit message."
            )
        if name in written:
            NOTES.append(f"device {device_id}: {name} was already written by another device; this record was dropped.")
            continue
        _write(name, record)
        written.append(name)
    if written:
        return written, ""
    if not listed:
        return [], (
            "The tenant has no mobile device enrolled: the list read answered 200 with an empty page. Enrol an iPad — "
            "supervised, and a second unsupervised if it is cheap — and run this again; docs/mobile-devices.md §4 "
            "says why the pair is the fixture."
        )
    if not refused:
        return [], (
            f"{len(listed)} device(s) were listed and not one carried an `id` to read a detail with. The list page's "
            "own shape is the finding; it is written to mobile_devices_list_real.json — read it."
        )
    return [], (
        f"{len(listed)} device(s) are enrolled, but every /api/v2/mobile-devices/{{id}}/detail read failed "
        f"({'; '.join(refused)}). The enrolment is not what is missing. A 403 wants 'Read Mobile Devices' ticked in "
        "the API Role; a 404 means the detail path is spelled differently than the reference says — which is #238's "
        "own premise — and mobile_privileges.txt records every spelling this run tried."
    )


def main() -> int:
    base, client_id, secret = _settings()
    rows: list[tuple[str, str, int, str]] = []
    captured: list[str] = []
    why = "The device list read is the first thing this script does, and it did not run."
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
                if what == "devices":
                    why = (
                        f"No mobile-device list endpoint answered: every candidate 404s ({path}). This says nothing "
                        "about what is enrolled — the read that would have asked never reached Jamf."
                    )
                continue
            rows.append((what, path, response.status_code, privilege))
            if response.status_code != 200:
                print(f"! {what}: {path} answered {response.status_code}; needs {privilege!r}")
                if what == "devices":
                    why = (
                        f"The device list read was refused: {path} answered {response.status_code}. Tick "
                        f"{privilege!r} in the API Role and run again — this says nothing about what is enrolled, "
                        "and mobile_privileges.txt now names the privilege."
                    )
            elif what == "devices":
                captured, why = _devices(http, base, token, response.json(), rows)
            elif "collection" in what:
                _write("mobile_inventory_collection_settings_real.json", response.json())
            else:
                _write("mobile_smart_group_real.json", response.json())

    _privileges(rows, version)
    if not captured:
        sys.stdout.flush()  # the reason is the last line the run says; a pipe must not reorder it above them
        sys.exit(f"No mobile device record was captured. {why}")
    swept = f"; swept out of keys no rule names: {', '.join(sorted(_RUN.swept))}" if _RUN.swept else ""
    print(f"redacted: {', '.join(f'{k} ×{v}' for k, v in sorted(_RUN.counts.items())) or 'nothing'}{swept}")
    if _HELD_TOTAL:
        print(f"held: {len(_HELD_TOTAL)} keys no rule names, listed above under every file each one appeared in.")
    for note in NOTES:
        print(f"! {note}")
    print("Read every written file before committing it: this fixtures directory is public.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
