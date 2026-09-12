# Pointing Jamf Pro's webhooks at LoonInspect

Status: **built**, 2026-09-12 ([#406](https://github.com/LoonSecIO/LoonInspect/issues/406)) ·
What LoonInspect does is read out of the code — the receiver in `backend/app/api/webhooks.py`,
the fetch in `backend/app/mdm/service.py` (`ingest_webhook`), and the panel in
`frontend/src/features/mdm/WebhookSetupPanel.tsx`. What Jamf Pro does is Jamf's, and says so:
its form is taken from Jamf's documentation
([Webhooks](https://docs.jamf.com/10.34.0/jamf-pro/documentation/Webhooks.html)), and its
labels move between versions, so check them against your own Jamf Pro as you go.

Webhooks are the real-time half. The scheduled device sweep still reads every Mac on its
schedule; a webhook reads one Mac the moment Jamf Pro says it changed, so what an operator
sees between sweeps is current. Skip this whole document and LoonInspect still works — it
is only ever as fresh as the last sweep.

One webhook is one HTTPS `POST` from Jamf Pro to `/webhooks/jamf/<connection id>`, carrying
the header `X-API-Key: <secret>` and a JSON body naming an event and a computer. LoonInspect
checks the secret before it reads the body, reads the event name and the computer's Jamf
id, then **fetches** that computer's inventory from Jamf Pro — a computer webhook carries
no application list — and answers once the reading is written. Two events do that:
`ComputerInventoryCompleted` and `ComputerAdded` (`REACTIVE_WEBHOOK_EVENTS` in
`backend/app/mdm/jamf/client.py`). Every other event is answered `200 ignored`, named in an
info line in the container log, and costs no API call and no run (#76).

## 1. Before you start: can Jamf Pro reach it?

Jamf Pro calls LoonInspect, never the other way round, so the question is whether *Jamf
Pro* can open the address, not whether you can.

- **Jamf Cloud calls from the internet.** LoonInspect needs a name (or address) and a port
  that the internet can reach. A laptop, `localhost`, a private address or a name only your
  network resolves will not work, and the setup panel says so when it sees one. An
  on-premises Jamf Pro can call a private address on its own network.
- **A firewall or security group in front of LoonInspect must admit Jamf.** Jamf publishes
  the addresses Jamf Cloud calls out from in
  [Permitting Inbound/Outbound Traffic with Jamf Cloud](https://docs.jamf.com/technical-articles/Permitting_InboundOutbound_Traffic_with_Jamf_Cloud.html).
  Admit those on LoonInspect's port and nothing else changes.
- **HTTPS, always.** Jamf Pro does not sign its webhooks, so the header is the whole
  authentication, and anyone who reads one callback can replay it
  ([auth-design.md](auth-design.md) §4.7). Over plain `http` it crosses the network
  readable; the panel warns when the address is `http`.
- **The certificate.** Whether Jamf Pro accepts a certificate it does not trust — the
  self-signed one a fresh LoonInspect serves — was **not** tested for this guide. Use a
  certificate from a public CA where you can. If webhooks never arrive at all
  ([troubleshooting.md](troubleshooting.md) §7, step 1), the certificate is the next thing
  to rule out after reachability.

## 2. In LoonInspect: Set up

**Settings › Connections.** Below the connections table, each Jamf Pro connection has its
**Collections**, and one of them is named **Webhook** — every Jamf connection is created
with it. Click **Set up** on that row.

1. **Turn on.** Receiving starts off, and a connection that is not receiving refuses every
   webhook. Turning it on without a secret makes one in the same save, and shows its
   header once.
2. **Copy the address** (panel item 1). It is the address your browser reached LoonInspect
   by, plus `/webhooks/jamf/<id>`. If you opened LoonInspect by a name Jamf Pro cannot use,
   the panel says so: open it by the name Jamf Pro will use, and the address follows.
3. **Copy the header** (panel item 2), now. It reads `{"X-API-Key":"…"}` — a JSON object,
   because that is what Jamf Pro's Header Authentication takes. LoonInspect shows it
   **once**: it is stored encrypted, and no page and no API response returns it again. If
   you lose it, Rotate (§6).

The secret is 32 random bytes made in your browser. If you would rather use your own,
**Use a secret of my own** takes one and shows its header once in the same way; a generated
one is stronger than anything typed. Basic authentication with the secret as the password
also works on the receiving side, but Header Authentication is what the panel hands you,
and what this guide sets up.

## 3. In Jamf Pro: the first webhook

**Settings › Global › Webhooks › New.** (Jamf's documentation calls the section *Global
Management*.)

| Field | Value |
| --- | --- |
| Display Name | anything, e.g. `LoonInspect — inventory completed` |
| Webhook URL | the address from Set up |
| Authentication Type | **Header Authentication** |
| Header Authentication | the header from Set up, pasted exactly as it is shown |
| Connection Timeout | 5 seconds |
| Read Timeout | **5 seconds or more** — see below |
| Content Type | **JSON** |
| Webhook Event | `ComputerInventoryCompleted` |

**Save.**

- **The header is pasted as-is.** Jamf takes key-value pairs in JSON, so
  `{"X-API-Key":"…"}` is the whole of it — not wrapped in another object, and not
  `X-API-Key: …` on one line. Jamf refuses a few header names inside that object
  (`Content-Type`, `User-Agent`, `Accept-Encoding`, `Content-Length`, `Host`); `X-API-Key`
  is not one of them. A header that does not reach LoonInspect is logged as `no_header`
  ([troubleshooting.md](troubleshooting.md) §7).
- **JSON, not XML.** LoonInspect reads JSON only. An XML webhook is refused with a `422`
  and a log line naming this setting.
- **Why the read timeout.** LoonInspect answers once it has read the Mac from Jamf Pro and
  written the reading. Measured 2026-09-12 against a Jamf Cloud instance, the reads a
  webhook waits on took 0.7–1.0 seconds, before any writing. Jamf's own API example sets a
  2-second read timeout, which leaves little room on a busy instance or a Mac with a large
  inventory; 5 seconds does. The connection timeout covers only opening the connection,
  and Jamf's example 5 seconds is fine.

## 4. The second webhook: `ComputerAdded`

**New** again, with every field the same except **Webhook Event**: `ComputerAdded`. A
Jamf webhook carries one event, and LoonInspect acts on these two, so it is two webhooks.

Do **not** add `ComputerCheckIn`. A check-in fires every time each Mac checks in, and
LoonInspect drops it on purpose (#76): it would be traffic that reads nothing. Any other
event is dropped the same way and named in the container log.

## 5. See it work

On a test Mac, run `sudo jamf recon`. That submits inventory, and Jamf Pro fires
`ComputerInventoryCompleted`. Within seconds:

- **Set up** shows *Last webhook run* with the time — close the panel and open it again to
  re-read it;
- the Overview's status strip counts it in *+N webhook sweeps since*;
- `GET /api/runs?trigger=webhook&pageSize=5` lists it ([troubleshooting.md](troubleshooting.md)
  §0 shows how to call the API).

Nothing? [troubleshooting.md](troubleshooting.md) §7 walks it from the container log.

## 6. Rotating the secret

**Rotate** on Set up makes a new secret and shows its header once. It is one secret, not
two: the old one stops working the moment you confirm, and every Jamf webhook is refused
until the new header is pasted into it. There is no changeover window
([auth-design.md](auth-design.md) §4.7).

1. **Rotate** in LoonInspect, and copy the new header.
2. In Jamf Pro, open each LoonInspect webhook — both of them — paste the new header into
   Header Authentication, and **Save**.

Webhooks that arrive between the two steps are refused and logged as `wrong_secret`; the
next sweep reads what they would have. Rotate is also the whole answer to a lost header:
LoonInspect cannot show the old one again, so a new one is the only way back.

## 7. Turning it off

**Turn off** on Set up. Every webhook is then refused (logged as `receiving_off`), and the
secret is kept for when you turn it back on. Remove or disable the webhooks in Jamf Pro
too, or Jamf Pro goes on calling an address that refuses it.

Disabling the **Webhook collection** is not the off switch, which is why the row no longer
offers it. The collection decides only what each webhook reads: switch it off and webhooks
keep arriving, and each reads every section instead of the collection's.

## 8. What the Webhook collection controls

**Edit** on the Webhook row sets the sections a webhook reads, and the extension attributes
it leaves out of the hash, exactly as a device sweep's do. A narrower collection makes each
webhook cheaper against Jamf Pro — and makes each webhook's snapshot partial by design:
[splunk-setup.md](splunk-setup.md) §7 says what a section outside the aperture looks like
on the wire. The sweep keeps its own sections and is unaffected.
