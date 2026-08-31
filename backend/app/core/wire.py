"""Shaping the delivered event — the envelope half of the wire contract (#188, #189).

Splunk indexes four fields *beside* the event body: `time`, `host`, `source` and
`sourcetype`. They cost no licence volume (Splunk meters the event value, not the
envelope) and they are faster to search than a body field carrying the same string, so
by default anything that fits here is envelope-only and never duplicated into
`deviceMeta` — that is why the instance URL is `source` and not a key.

`host` is the one ruled exception (Kyle, 2026-08-31): the hostname ships in both places.
A Splunk admin can override `host` at the HEC input, and envelope fields need not
survive a summary index or an export into a case file, while the body always travels —
so the identity that joins outward to EDR, DHCP and identity logs is not left somewhere
a customer can quietly remove.

The catch is that `app.core.outbox._build_body` — the one place the HEC body is
assembled — receives only the destination and the frozen payload. No session, no Device,
no run. So the envelope's values have to be computed at *enqueue*, carried on the
payload under `ENVELOPE`, and lifted back out at delivery. `_build_body` removes the key
whatever the destination type, so it never reaches a customer's index or a generic
webhook receiver.
"""

from __future__ import annotations

from urllib.parse import urlparse

# Reserved payload key holding the envelope hints. Popped by `_build_body` before the
# body is sent, so it is a transport detail of the outbox and never part of the wire
# vocabulary a customer writes SPL against.
ENVELOPE = "_envelope"

# Ports that carry no information because they are the scheme's own default.
_DEFAULT_PORTS = {"https": 443, "http": 80}


def instance_label(base_url: str) -> str:
    """The MDM instance as Splunk's `source` names it (Kyle's ruling, 2026-08-31).

    Scheme dropped, non-default port kept: `https://acme.jamfcloud.com` becomes
    `acme.jamfcloud.com`, and `https://jamf.corp.local:8443` stays
    `jamf.corp.local:8443`.

    Both halves of that earn their place. The scheme is a constant — every Jamf Pro is
    https — and dropping it makes the value typable in SPL without quoting, since `//`
    forces a quoted term where a bare host does not. The port is the opposite: it is
    identifying, because `jamf.corp.local:8443` and `:8444` are two different servers,
    and merging them would union two fleets under one name. `:` is a Splunk minor
    segmenter, so keeping it costs nothing in searchability.

    Built from `.hostname` plus an explicit port rather than `.netloc`, which would
    carry `user:pass@` through into indexed metadata if anyone ever put credentials in a
    base URL. Lowercased because hostnames are case-insensitive while Splunk's `source`
    matching is not.
    """
    parsed = urlparse(base_url if "://" in base_url else f"https://{base_url}")
    host = (parsed.hostname or base_url).strip().lower()
    try:
        port = parsed.port
    except ValueError:
        # A malformed port ("https://host:notaport") — the host alone still identifies
        # the instance, and raising here would fail a sync over a cosmetic detail.
        port = None
    if port and port != _DEFAULT_PORTS.get(parsed.scheme):
        return f"{host}:{port}"
    return host


def envelope(*, occurred_at, host: str | None, source: str | None) -> dict[str, object]:
    """The envelope hints for one event, dropping anything absent.

    `time` is epoch seconds, which is what HEC expects. Setting it from the event's own
    `occurred_at` is what makes Splunk's `_time` mean *when the device changed* rather
    than when the outbox worker got around to delivering it — the v0 constraint recorded
    in docs/splunk-event-shaping.md, which trails occurrence by the 30s tick and, after a
    destination outage, by up to the full retention window.

    An empty `host` is dropped rather than sent: HEC falls back to the input's own
    default for a blank one, which would collapse every affected device onto a single
    phantom host where `dc(serialNumber)` counts them all as one.
    """
    hints: dict[str, object | None] = {
        "time": occurred_at.timestamp() if occurred_at else None,
        "host": host or None,
        "source": source or None,
    }
    return {key: value for key, value in hints.items() if value is not None}
