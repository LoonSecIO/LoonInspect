# Sending LoonInspect events to Splunk

Everything here is read out of the delivery code (`backend/app/core/outbox.py`,
`backend/app/core/wire.py`) rather than from memory of how HEC usually works. Where a
claim is about Splunk's own defaults rather than about LoonInspect, it says so.

One delivery is one HTTPS POST: `Content-Type: application/json`,
`Authorization: Splunk <token>`, a 10-second timeout, and the event wrapped as
`{"event": {…}}` with `time`, `host` and `source` beside it. Deliveries are attempted on
a 30-second tick, retried with exponential backoff (30s doubling to a 1-hour cap) and
dead-lettered after 10 attempts.

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
- *Source type*: set one explicitly. It names every event except the change stream:
  `device.change` carries its own `sourcetype` and overrides the input's, and nothing
  else sends one (§6). Whatever you set here is what those other events get for ever.
- *Allowed indexes* and *Default index*: **this is the only thing that decides where the
  events land.** LoonInspect never sends an `index` field — `_build_body` adds only the
  three envelope hints, and `wire.envelope()` emits only `time`, `host` and `source`.
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

## 6. `sourcetype`, and a `props.conf` stanza to hand your Splunk team

**One family carries its own; everything else takes the input's.**

- `device.change` — the change stream — is delivered under
  `loon:jamf:mac:<entity>:change`, one string per entity a change can name. There are
  fifteen: the fourteen inventory sections plus `computerGroup`, listed in
  [`splunk-wire-vocabulary.md`](splunk-wire-vocabulary.md) §2. A `sourcetype` in the HEC
  body overrides the input's for those events only.
- `device.inventory.changed`, `run.completed` and `run.failed` send none, so they arrive
  under whichever sourcetype **you** set on the input (§2). The reason, from
  `core/outbox.py`:

> Every other family is still deliberately unstamped. The ruled section tree names
> fan-out sub-events (`loon:jamf:mac:app`) that are not built, and minting a string for a
> shape that is about to change would create a permanent props.conf stanza for it.

The stanza below keys on the input's name and so covers those three families; it assumes
you called it `loon:inspect`, so substitute your own.

```ini
# props.conf — LoonInspect events arriving over HEC.
# Key: the sourcetype set on the HEC input. It decides for every family but the change
# stream, which sends its own (above) and needs the same three settings under each of its
# fifteen strings — a sourcetype stanza takes no wildcards.
[loon:inspect]

# The event body is a JSON object. Search-time extraction, so this line belongs on the
# search head. Without it, deviceMeta.serialNumber needs spath in every search.
KV_MODE = json

# One POST is one event; there is nothing to merge. Index-time.
SHOULD_LINEMERGE = false

# One event carries every app that changed on one device, so it is not small: measured
# from the real payload builder, the body is 509 bytes plus roughly 330 per changed app,
# which puts a device with ~30 app changes — an OS upgrade, a re-image — past the 10,000
# byte TRUNCATE default. Truncation would cut the JSON mid-object and take the field
# extraction down with it. Index-time.
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

**The change stream, and the sixteen-stanza question.** `[<sourcetype>]` accepts no
wildcards, so covering `device.change` the same way means repeating these three lines
under each of the fifteen `loon:jamf:mac:*:change` strings. Two ways out, in order of
preference:

1. **Key on `source` instead.** Every LoonInspect event carries the Jamf instance as
   `source`, and a `[source::...]` stanza is the kind that *does* accept wildcards — so
   `[source::acme.jamfcloud.com]` (or `[source::*.jamfcloud.com]`) is one stanza covering
   every family and every entity from that Jamf Pro.
2. **Check whether you need `KV_MODE` at all.** Splunk's default search-time extraction
   already reads pure-JSON events on recent versions; the line above is belt-and-braces.
   If `deviceMeta.serialNumber` resolves in a search against an unconfigured sourcetype on
   your version, the fifteen stanzas are a convenience, not a requirement.

Neither claim has been tested against a real Splunk here, which is exactly why the count
is written down rather than glossed: it is the argument for shipping a LoonInspect TA, and
that is not built.

## 7. What arrives, and where `_time` comes from

`_time` is the event's own occurrence time, not the time Splunk received it: `time` in the
envelope is set from `occurredAt` at enqueue. A sweep's events carry the run's window, a
webhook's carry Jamf's `reportDate`. This matters most on day one — events produced before
any destination existed are held, not discarded, so adding Splunk on Friday after
Monday's baseline delivers four days of events onto their own days rather than as one
Friday spike.

`host` is the device hostname and `source` is the Jamf instance (`acme.jamfcloud.com`,
or `jamf.corp.local:8443` when the port is not the scheme's default).

The body's field names — `deviceMeta`, `addedApps`, and the rest — are documented in
[runs.md](runs.md) §4. **Treat them as not yet frozen:** the casing rules are ruled for
the inventory event but still open for the other producers (#188, #90). Today that
difference is visible on the wire — `device.inventory.changed` is camelCase
(`occurredAt`), while `run.completed` is still snake_case (`occurred_at`) — and it is
expected to be reconciled before 1.0. Pin dashboards to the index and the sourcetype,
and expect to revisit field-level SPL.

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

and after a sync has produced something real:

```
index=your_index "device.inventory.changed" | head 5
```

## 9. When nothing arrives

The destinations table is the first place to look: it shows the last delivery error
verbatim (first 500 characters of what Splunk said), pending and failed counts, and last
success/failure times. Every failed attempt is also logged, not just the tenth.

| What you see | What it usually is |
| --- | --- |
| `[SSL: CERTIFICATE_VERIFY_FAILED] …` | §5. The certificate, not the token. |
| `HTTP 401` / `HTTP 403` | The token — wrong value, disabled token, or the global *All Tokens* switch still off. |
| `HTTP 400` naming the index | The token is not allowed to write the index it was asked for. |
| Connection refused / timeout | Reachability. From inside the container, not from your laptop — see §3. |
| No error, and no `device.inventory.changed` | Nothing changed. A sweep where no app changed on any device emits no inventory event at all, by design — the sweep's own `run.completed` event still arrives. |
| Events stop after a while | Ten failed attempts dead-letter a delivery; fix the cause and the *next* events flow, but the dead-lettered ones are not retried. |

Two timing facts worth knowing before you go looking for a bug:

- A destination added after the baseline sweep still receives it. Events are held while
  no destination is enabled, for `event_outbox_retention_days` (default **7**).
- `deliver_pending` has no `ORDER BY`, so a drained backlog arrives in arbitrary order.
  `_time` is still correct for each event; only arrival order is unspecified.
