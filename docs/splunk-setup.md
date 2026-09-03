# Sending LoonInspect events to Splunk

Everything here is read out of the delivery code (`backend/app/core/outbox.py`,
`backend/app/core/wire.py`) rather than from memory of how HEC usually works. Where a
claim is about Splunk's own defaults rather than about LoonInspect, it says so.

One delivery is one HTTPS POST: `Content-Type: application/json`,
`Authorization: Splunk <token>`, a 10-second timeout, and each event wrapped as
`{"event": {…}}` with `time`, `host` and `source` beside it — plus `sourcetype`, for the
families that carry one (§6). A `device.inventory` snapshot is the one delivery that is
many events: it is split at delivery into one HEC event per section item and posted as
one request of all of them (§7). Deliveries are attempted on a 30-second tick, retried
with exponential backoff (30s doubling to a 1-hour cap) and dead-lettered after 10
attempts.

## 1. Turn HEC on — it ships disabled

Splunk Enterprise ships the HTTP Event Collector **disabled**, and the global switch is
separate from any individual token: both have to be on.

**Settings → Data inputs → HTTP Event Collector → Global Settings**

- *All Tokens*: **Enabled**
- *HTTP Port Number*: **8088** (Splunk's default)
- *Enable SSL*: leave it **ticked**. See §5 — the answer is not to untick it.

On Splunk Cloud, HEC is enabled per stack and reached on a different hostname from the
search head; take the URL from the token's own page rather than assuming the shape below.

## 2. Create a token, scoped to one index

**Settings → Data inputs → HTTP Event Collector → New Token**

- *Name*: anything — `LoonInspect`.
- *Source type*: set one explicitly, but know that most of what arrives ignores it.
  Since 2026-09-03 the events carry their own `sourcetype`, which overrides the input's:
  the `device.inventory` snapshot arrives as sub-events under the fourteen section strings
  (`loon:jamf:mac:app`, …), the change stream under its fifteen `:change` strings, and
  `run.completed` / `run.failed` under `loon:run` (§6). What still lands under the name
  you set here is `device.inventory.changed` — the delta family has no ruled string — and
  the test event. Set one anyway: it is what those get for ever, and it is where an event
  from a LoonInspect build that predates a family's stamp would land.
- *Allowed indexes* and *Default index*: **this is the only thing that decides where the
  events land.** LoonInspect never sends an `index` field — every HEC event object
  carries the three envelope hints `wire.envelope()` emits (`time`, `host` and `source`),
  its `sourcetype` where the family has one (§6), and nothing else.
- Select **exactly one** index and make it the default. A HEC token is a write
  credential; leaving every index selected means a compromised or fat-fingered token can
  write anywhere in your Splunk, and it buys nothing here because LoonInspect writes to
  one place.

Splunk shows the token value once. It is the only secret in this setup.

## 3. The URL

```
https://splunk.example.com:8088/services/collector
```

Scheme, host, port, path — all four. LoonInspect POSTs to the URL **exactly as entered**
and appends nothing to it (`_attempt_delivery` calls `client.post(destination.url, …)`).
The Elasticsearch destination type is the one that builds a path from an index; this one
does not. `/services/collector/event` is the same endpoint spelled out, and also works.

**Splunk Cloud** terminates HEC on its own hostname and on 443, not 8088. Copy the URL
from your stack.

### When LoonInspect runs in Docker and Splunk does not

Inside the container, `localhost` is the container. A Splunk running on the Docker host
is `host.docker.internal` on Docker Desktop (macOS and Windows):

```
https://host.docker.internal:8088/services/collector
```

On Linux Docker Engine that name does not exist by default, and this repo's
`docker-compose.yml` does not add it — you need `extra_hosts:
["host.docker.internal:host-gateway"]` on the `app` service, or the host's real address.
If Splunk is another container on the same compose network, use its service name.

## 4. The "Secret" field is the HEC token

Add the destination at **Settings → Destinations → Add destination**, type *Splunk HTTP
Event Collector*. The field labelled **Secret** takes the raw HEC token — the GUID Splunk
showed you, with no `Splunk ` prefix. `_build_headers` builds the header:

```python
headers["Authorization"] = f"Splunk {secret}"
```

Over the API it is the same object; `authType` is derived, so you do not have to send it,
and a contradicting one is refused rather than quietly stored:

```bash
curl -sX POST https://looninspect.example.com/api/destinations \
  -H "Authorization: Bearer $LOONINSPECT_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"Splunk","type":"splunk_hec",
       "url":"https://splunk.example.com:8088/services/collector",
       "authSecret":"'"$HEC_TOKEN"'"}'
```

The token is encrypted at rest with the instance's `ENCRYPTION_KEY` and there is **no
read path** for it: `GET /api/destinations` returns `hasSecret: true`, never the value.
Rotating it means sending a new `authSecret`; leaving the field blank on an edit keeps
the stored one.

## 5. TLS, and Splunk's stock self-signed certificate

Stock Splunk serves HEC over TLS with a **self-signed** certificate. LoonInspect delivers
through `httpx.AsyncClient()` and passes no `verify` argument, so httpx verifies the chain
against its bundled public roots. Against a stock HEC, therefore, **every delivery
fails**, and this is the error stored on the destination row and shown in the
destinations table:

```
[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate (_ssl.c:1010)
```

(reproduced against a self-signed HTTPS listener using the same client the outbox uses.)

There is no "skip certificate validation" setting. An unverified TLS session is encrypted
but unauthenticated, and whatever is on the other end of it is being handed a write
credential for your index on every request — so the fix is to make verification succeed,
not to stop asking.

Three ways forward, all of which keep verification on:

**a. Give HEC a certificate that already validates.** `serverCert` in the `[http]` stanza
of `$SPLUNK_HOME/etc/apps/splunk_httpinput/local/inputs.conf`, then restart Splunk. If it
chains to a public CA, nothing else here applies.

**b. Trust your internal CA inside the container.** httpx honours `SSL_CERT_FILE` and
`SSL_CERT_DIR` (verified in httpx 0.28.1, which is what the lockfile pins). Mount a
bundle into the `app` container and point the variable at it.

> **The bundle must contain the public roots as well as your CA.** `SSL_CERT_FILE`
> *replaces* the trust store for the whole process rather than adding to it, and the same
> client settings are used for every outbound call this app makes — the daily update
> check, Jamf Cloud, the sharing exchange. With only your own CA in the file, those start
> failing certificate verification. Both halves of that were tested.

Build the bundle by concatenating:

```bash
# -T matters: without it compose allocates a TTY and the PEM comes back with CRs in it.
docker compose exec -T app uv run --frozen --no-sync --no-dev \
  python -c "import certifi; print(open(certifi.where()).read())" > ca-bundle.pem
cat internal-ca.pem >> ca-bundle.pem
```

then mount it and set the variable on the `app` service:

```yaml
    environment:
      SSL_CERT_FILE: /app/data/ca-bundle.pem
    volumes:
      - ./ca-bundle.pem:/app/data/ca-bundle.pem:ro
```

**c. Put a TLS-terminating proxy in front of Splunk** with a certificate your
infrastructure already trusts, and point the destination at the proxy.

**What not to do:** unticking *Enable SSL* on the HEC input makes the error go away by
sending the token in clear text on every delivery. Anyone who can read one packet can
then write whatever they like into your index. It is a lab shortcut on a throwaway
instance, not a fix.

## 6. `sourcetype`, and the `props.conf` stanzas to hand your Splunk team

**Three families carry their own; two take the input's.** Every string is minted in
[`splunk-wire-vocabulary.md`](splunk-wire-vocabulary.md) §2 and stamped by
`core/outbox.py` on this destination type only; a `sourcetype` in the HEC body overrides
the input's for that event.

- `device.inventory` — the per-device snapshot — never arrives whole. It is split at
  delivery into one HEC event per section item, each under the registry's string for its
  section: the seven one-per-device sections as one event each (`loon:jamf:mac:general`,
  `:hardware`, `:operatingSystem`, `:userAndLocation`, `:purchasing`, `:security`,
  `:diskEncryption`) and the seven list sections as one event per item (`loon:jamf:mac:app`,
  `:ea`, `:group`, `:profile`, `:localUserAccount`, `:cert`, `:update`). Fourteen strings.
  What one sub-event looks like is in [`runs.md`](runs.md) §4.
- `device.change` — the change stream — is delivered under
  `loon:jamf:mac:<entity>:change`, one string per entity a change can name: the fourteen
  sections plus `computerGroup`. Fifteen strings.
- `run.completed` and `run.failed` arrive under `loon:run` — LoonInspect's own assertion
  about a run, with no vendor segment.
- `device.inventory.changed` and the test event send none and arrive under whichever
  sourcetype **you** set on the input (§2). The delta family has no ruled string, and a
  string once minted is a permanent stanza, so none was invented in passing.

The stanza below keys on the input's name and so covers the delta and the test event; the
same three lines belong under each of the thirty minted strings, and the section after it
says how to avoid writing them thirty times. It assumes you called the input
`loon:inspect`, so substitute your own.

```ini
# props.conf — LoonInspect events arriving over HEC.
# Key: the sourcetype set on the HEC input. It decides for device.inventory.changed and
# the test event only; the snapshot's sub-events, the change stream and the run family
# send their own strings and need the same three settings under each of them — a
# sourcetype stanza takes no wildcards.
[loon:inspect]

# The event body is a JSON object. Search-time extraction, so this line belongs on the
# search head. Without it, deviceMeta.serialNumber needs spath in every search.
KV_MODE = json

# Each JSON object in a POST is one event; there is nothing to merge. Index-time.
SHOULD_LINEMERGE = false

# One delta carries every app that changed on one device, so it is not small: measured
# from the real payload builder, the body is 509 bytes plus roughly 330 per changed app,
# which puts a device with ~30 app changes — an OS upgrade, a re-image — past the 10,000
# byte TRUNCATE default. A snapshot sub-event is small (an app is ~790 bytes, measured on
# the real fixture) but an extension-attribute sub-event carries Jamf's value list
# verbatim, and an EA is arbitrary script output. Truncation would cut the JSON mid-object
# and take the field extraction down with it. Index-time.
TRUNCATE = 0

# Deliberately NOT set:
#   TIME_PREFIX / TIME_FORMAT / DATETIME_CONFIG — the HEC "time" field already carries
#     when the device changed (see below); a props timestamp rule here could only make
#     _time worse.
#   INDEXED_EXTRACTIONS — would index every field a second time and charge you for it.
```

`KV_MODE` is search-time and `SHOULD_LINEMERGE`/`TRUNCATE` are index-time, so strictly
they live in different places in a distributed deployment. Handing the whole stanza over
is fine — each line is inert where it does not apply.

**The thirty-one-stanza question.** `[<sourcetype>]` accepts no wildcards, so covering
every minted string the same way means repeating these three lines under each of the
fourteen section strings, `loon:run`, and the fifteen `loon:jamf:mac:*:change` strings.
Two ways out, in order of preference:

1. **Key on `source` instead.** Every LoonInspect event carries the Jamf instance as
   `source`, and a `[source::...]` stanza is the kind that *does* accept wildcards — so
   `[source::acme.jamfcloud.com]` (or `[source::*.jamfcloud.com]`) is one stanza covering
   every family and every entity from that Jamf Pro.
2. **Check whether you need `KV_MODE` at all.** Splunk's default search-time extraction
   already reads pure-JSON events on recent versions; the line above is belt-and-braces.
   If `deviceMeta.serialNumber` resolves in a search against an unconfigured sourcetype on
   your version, the thirty stanzas are a convenience, not a requirement.

Neither claim has been tested against a real Splunk here, which is exactly why the count
is written down rather than glossed: it is the argument for shipping a LoonInspect TA, and
that is not built. What *was* tested (2026-09-03, a local Splunk Enterprise 10.4): the
whole 107-event request for the real fixture is accepted by
`/services/collector/event` as one POST.

**The size of a request, and the one setting.** All of a device's sub-events travel in
one POST — 84,135 bytes for a Mac with 83 apps, measured — and Splunk Cloud Platform
documents a 1 MB `max_content_length` for HEC (Splunk Enterprise ships
`[http_input] max_content_length = 838860800` in its default `limits.conf`; it was
1,000,000 before 7.x). A request over the input's limit is refused whole with HTTP 413.
`SPLUNK_HEC_MAX_REQUEST_BYTES` (default **900000**, 10% under that 1 MB) is the ceiling on
one request body: a device whose expansion exceeds it is sent as consecutive requests of
at most that many bytes, whole events only, in order, and the delivery succeeds only when
every request does. Raise it on Enterprise if you like; lower it if your HEC input's
`max_content_length` is smaller. It bounds requests, not events — a single event larger
than the ceiling is still sent, alone.

## 7. What arrives, and where `_time` comes from

`_time` is the event's own occurrence time, not the time Splunk received it: `time` in the
envelope is set at enqueue, on every family, from the instant the event is about — the
body's `occurredAt` on `device.inventory`, `device.inventory.changed` and `run.completed`,
its `windowEnd` on `run.failed`, and on `device.change` the same clock as the inventory
event of the same pull. A sweep's events carry the run's window, a webhook's carry Jamf's
`reportDate`.
This matters most on day one — events produced before any destination existed are held,
not discarded, so adding Splunk on Friday after Monday's baseline delivers four days of
events onto their own days rather than as one Friday spike.

`host` is the device hostname and `source` is the Jamf instance (`acme.jamfcloud.com`,
or `jamf.corp.local:8443` when the port is not the scheme's default).

**The body's field names are frozen.** The vocabulary — the sourcetype tree, the wrapper
keys, the casing law and the additive-only clauses — is
[`splunk-wire-vocabulary.md`](splunk-wire-vocabulary.md), ruled in
[#188](https://github.com/LoonSecIO/LoonInspect/issues/188) and frozen on 2026-09-01.
Its registry is generated from `app/core/wire_vocabulary.py`, and
`tests/test_wire_vocabulary.py` fails on drift in either direction, so the document and
the code cannot disagree. ([#90](https://github.com/LoonSecIO/LoonInspect/issues/90),
which this paragraph used to cite as still open, closed on 2026-09-03 with each of its
decision points forwarded to that ruling.) Where each shape is written down: the
`deviceMeta` block and the `run.completed` / `run.failed` payloads in [runs.md](runs.md)
§4 and §7; the per-device snapshot `device.inventory` — its section wrappers, and the
`app` item carrying `patch` and `vuln` beside Jamf's object — in [runs.md](runs.md) §4 and
`app/schemas/payload.py` (`InventorySnapshotEvent`); the change stream in
[change-log.md](change-log.md); the inventory delta's own keys — `addedApps` and
`removedApps`, each a list of app objects — in `app/schemas/payload.py`
(`InventoryChangedEvent`), the one place that serializes them.

One casing law covers all five families. Every key LoonInspect mints is camelCase with
the token `ID` uppercased — `occurredAt`, `jobID`, `connectionID`, `eventID` — and a
vendor's native key keeps the vendor's spelling, so an app's `bundleId` is Jamf's, inside
a snapshot's `app[].app` object as much as inside `addedApps`. `event` is the
discriminator on every family and `jobID` is the run id everywhere, so `event=device.*`,
`event=run.*` and a bare `jobID=$id$` each work across the whole feed.
`tests/test_wire_casing.py` holds that on the payloads the outbox actually stores, all
five families judged together, not on the source that built them.

What "frozen" licenses is §5 of the vocabulary document: new keys may appear and
consumers must ignore unknown keys; a key's name, type and meaning never change once
shipped; a shipped key is never removed; a sourcetype string, once minted, is permanent.
SPL written against these names today does not need revisiting. Since 2026-09-03 the
`device.inventory` snapshot arrives split by section under the section sourcetypes in the
registry (`loon:jamf:mac:app` and the rest) rather than under the one you set on the input
— the move `device.change` had already made (§6). So pin dashboards to the index and to
`source` (one Jamf instance's whole feed) or to `event`, not to the input's sourcetype
alone.

**What each destination type receives for the per-device snapshot** (`device.inventory`,
one per device per pass, ~28 KB for a Mac with 83 apps — [runs.md](runs.md) §4):

- A `splunk_hec` destination gets it **split**: one HEC event per section item — one for
  each of the seven one-per-device sections, one per app, per extension attribute, per
  group membership, per profile, per local user account, per certificate, per software
  update — 107 for that Mac, each carrying `event=device.inventory`, `jobID`, the whole
  `deviceMeta` block, its section's object under its wrapper key, and the snapshot's
  `time`, `host` and `source`, under `sourcetype=loon:jamf:mac:<wrapper>`. All of them in
  one POST (84,135 bytes for that Mac), so `app.name=X app.version=Y` is one app, as it
  should be — the multivalue-pairing hazard [splunk-event-shaping.md](splunk-event-shaping.md)
  describes is why the split exists.
- A generic webhook, and the `runreveal` preset, get the bare document, whole.
- An Elastic destination gets one `create` document per snapshot with `@timestamp` from
  `occurredAt`, nested `app[]` and all. Per-app expansion for Elastic is not v0.

**Selecting one device's pass, and deduplicating a retry.** `deviceMeta.eventID` is one
id per device per pull, on every sub-event of that pull; a retry after a lost response
re-sends a device's sub-events together, so the dedup key on a fan-out sourcetype is the
pull plus the item — `| dedup deviceMeta.eventID app.bundleId app.path app.version` on
`loon:jamf:mac:app`, and each section's own identity on its sourcetype — never
`deviceMeta.eventID` alone, which collapses a device's whole pass to one arbitrary row.

**What an absent sub-event means.** A section outside the webhook collection's aperture
is not read and fans out nothing; a section read and genuinely empty fans out nothing
too. On the wire the two look the same: `loon:jamf:mac:general` with no
`loon:jamf:mac:cert` for the same `deviceMeta.eventID` is *either* zero certificates *or*
certificates not read. Under the nightly sweep — the whole contract — "zero" is the right
reading; under a webhook collection scoped to a few sections it is not, and nothing on the
sub-event says which (a key that would is a #189 decision, not taken). If you scope the
webhook collection, know that its snapshots are partial by design.

**Volume is a subscription knob, not a wire change.** Null or empty `subscribed_events`
means every event, so a destination on the default receives the snapshot from the day it
ships; a destination subscribed only to `device.inventory.changed` never receives one,
and one subscribed only to `device.inventory` gets the state without the deltas. The
field is on the API (`subscribedEvents` on `POST`/`PATCH /api/destinations`); the UI
carries it but has no editor for it yet.

## 8. Prove it end to end

Press **Test** on the destination. That button sends one synthetic event down the same
`_attempt_delivery` the scheduler uses — a pass means real deliveries will work, which a
bespoke ping could not tell you. Three things about the test event specifically:

- It carries no envelope, so it lands at **receipt** time under the input's default
  `host`. Real events do not.
- It is never stored and never retried.
- It ignores subscriptions, so it arrives even at a destination subscribed only to
  other event types.

Then look in Splunk. A bare term search works before the props stanza is in place:

```
index=your_index "destination.test"
```

and after a sync has produced something real — one snapshot per device, split into its
sub-events under the section sourcetypes, and a delta for every device whose app list
moved:

```
index=your_index event=device.inventory | stats count by sourcetype
index=your_index sourcetype=loon:jamf:mac:app | stats dc(deviceMeta.serialNumber) AS macs, count AS apps
index=your_index sourcetype=loon:jamf:mac:app deviceMeta.eventID=<one id> | stats count
index=your_index "device.inventory.changed" | head 5
```

The first shows one row per section present plus `loon:run` for the sweep's own event;
the third returns that device's app count for that pull, and the same search under
`sourcetype=loon:jamf:mac:general` returns 1.

## 9. When nothing arrives

The destinations table is the first place to look: it shows the last delivery error
verbatim (first 500 characters of what Splunk said), pending and failed counts, and last
success/failure times. Every failed attempt is also logged, not just the tenth.

| What you see | What it usually is |
| --- | --- |
| `[SSL: CERTIFICATE_VERIFY_FAILED] …` | §5. The certificate, not the token. |
| `HTTP 401` / `HTTP 403` | The token — wrong value, disabled token, or the global *All Tokens* switch still off. |
| `HTTP 400` naming the index | The token is not allowed to write the index it was asked for. |
| `HTTP 413` | One request exceeded the HEC input's `max_content_length`. Lower `SPLUNK_HEC_MAX_REQUEST_BYTES` (§6) below that limit; the snapshot is then sent as more, smaller requests. |
| Connection refused / timeout | Reachability. From inside the container, not from your laptop — see §3. |
| No error, and no `device.inventory.changed` | Nothing changed. A sweep where no app changed on any device emits no delta, by design — one `device.inventory` snapshot per device and the sweep's own `run.completed` event still arrive. No snapshot either means the destination is subscribed to other event types only. |
| Events stop after a while | Ten failed attempts dead-letter a delivery; fix the cause and the *next* events flow, but the dead-lettered ones are not retried. |

Two timing facts worth knowing before you go looking for a bug:

- A destination added after the baseline sweep still receives it. Events are held while
  no destination is enabled, for `event_outbox_retention_days` (default **7**).
- A backlog drains oldest-first, at most 1,000 deliveries per 30-second tick, so a week
  of held events on a large fleet arrives over minutes rather than at once — 40,000
  events to one destination is about twenty minutes. A failed delivery re-queues behind
  whatever is due before its next attempt, so arrival order is not occurrence order.
  `_time` is each event's own and does not depend on when it arrives.
