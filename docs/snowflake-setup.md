# Snowflake destination

**Status:** implemented in development; live gate pending, 2026-11-23 (#848).

The native destination writes whole LoonInspect events to Snowflake using Snowpipe
Streaming Named Channels. It stores inventory snapshots, changes and run events in
one table, with a deduplicated analyst view. You control the Snowflake account,
access grants, retention and costs.

**Validation status:** the adapter has synthetic transport and disposable-Postgres
recovery tests. A usable customer test account has not yet been verified. The live
SQL, ingestion, reconciliation and performance exercise below remains a release gate
for #848. Signing up for a portal alone does not establish that those checks passed.

## 1. Find the account and open a SQL workspace

Sign in to **Snowsight**, Snowflake's own web console. Open the account selector,
then **View account details**. Copy the organization-account identifier, for example
`EXAMPLE-TEST`; this is different from your human username. In a SQL worksheet or
workspace you can also run:

```sql
SELECT CURRENT_ORGANIZATION_NAME() || '-' || CURRENT_ACCOUNT_NAME() AS ACCOUNT_IDENTIFIER;
```

LoonInspect derives the HTTPS account URL from that identifier. This first adapter
supports public `snowflakecomputing.com` account URLs and ordinary unquoted object
names. PrivateLink, other sovereign-domain endpoints, proxy-only networks and quoted
case-sensitive identifiers are not supported by this adapter. Your SQL service may
only give you query access: an account administrator must create the objects and
service user if your role cannot do so. [Snowflake account identifiers](https://docs.snowflake.com/en/user-guide/admin-account-identifier).

## 2. Create the table, pipe and roles

In a **new disposable account or unused namespace**, open
[`sql/snowflake-setup.sql`](sql/snowflake-setup.sql), review it, and run it as an account
administrator. It uses `CREATE`, without replacing existing tables or users. If a
name already exists, stop and review that object or choose a fresh set of names.
Change the form values to match any names you change in the SQL.

The script creates:

- `LOONINSPECT.PUBLIC.LOON_EVENTS_RAW`: original public event in `PAYLOAD VARIANT`,
  source/tenant/event identity, event type, occurrence time and application queue time.
- `LOON_EVENTS_PIPE`: the streaming pipe the destination writes to.
- `LOON_EVENTS`, `LOON_MAC_OS_OBSERVATIONS`, and `LOON_MAC_OS_LATEST`: read views.
- `LOON_WRITER`: a service user and a role with database/schema USAGE, table INSERT
  and pipe OPERATE. It has no SELECT, UPDATE, DELETE, object creation or warehouse
  grant. LoonInspect never needs ACCOUNTADMIN.
- `LOON_ANALYST`: SELECT on the views and USAGE on a small auto-suspending query
  warehouse. Grant this role to the human or BI user that will run the queries.

The warehouse is for analyst queries; streaming ingestion is billed separately.
Review your trial credits or account budget before loading a fleet. These grants
follow [Snowflake's streaming access requirements](https://docs.snowflake.com/en/user-guide/snowpipe-streaming/snowpipe-streaming-access-control).

`LOADED_AT` is Snowflake's row commit timestamp, exposed by the view. The raw table
has `ROW_TIMESTAMP = TRUE` from creation. Do not replace it with CURRENT_TIMESTAMP
in the pipe: that can be the pipe's compile time. Inventory report dates and event
occurrence times retain their own meaning; missing dates stay missing.
[Row timestamp behavior](https://docs.snowflake.com/en/user-guide/data-engineering/row-timestamps).

## 3. Create and register the writer key

On a trusted local machine, create a dedicated directory accessible only to you.
In that directory run these commands; they generate files locally and make no
network request:

```sh
umask 077
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out loon_writer_key.pem
openssl pkey -in loon_writer_key.pem -pubout -out loon_writer_public.pem
```

Register the **public** key in a Snowflake SQL worksheet. Replace the placeholder
with the base64 body from `loon_writer_public.pem`, excluding its BEGIN/END lines
and line breaks:

```sql
USE ROLE ACCOUNTADMIN;
ALTER USER LOON_WRITER SET RSA_PUBLIC_KEY = '<PUBLIC_KEY_BODY>';
```

The **private** `loon_writer_key.pem` goes only into LoonInspect's destination form.
Do not put it in chat, a GitHub issue, SQL history, or a support bundle. This adapter
accepts unencrypted PEM RSA keys of at least 2048 bits and encrypts the value in
LoonInspect's database with the existing credential-encryption key. It never returns
that stored secret. Protect the local key file and retain it with your credential
backup. [Snowflake key-pair setup and rotation](https://docs.snowflake.com/en/user-guide/key-pair-auth).

## 4. Add and test the destination

In **Settings → Destinations → Add destination**, choose **Snowflake**. Enter:

| Field | Value with the supplied SQL |
| --- | --- |
| Organization-account identifier | Value from Account details / the SQL above |
| Service user | `LOON_WRITER` |
| Database | `LOONINSPECT` |
| Schema | `PUBLIC` |
| Pipe | `LOON_EVENTS_PIPE` |
| Writer role | `LOON_WRITER` |
| RSA private key | Complete contents of `loon_writer_key.pem`, including PEM lines |

Choose the event types to deliver, enable the destination, and save. **All event
types** includes future event families; a selected list stays explicit. Use **Test**.
The test is a real durable `destination.test` event targeted only to this destination,
even if it is not in the subscription list. A green result requires Snowflake's
committed checkpoint and matching row counts. Amber means queued or unresolved,
not a successful load. Enable the destination for background retries.

Copy the displayed **test source event key** into query 1 in
[`sql/snowflake-queries.sql`](sql/snowflake-queries.sql). Run it as `LOON_ANALYST`, using
`LOON_READ_WH`. Confirm exactly one view row with the test event. If your human user
cannot select that role, ask the account administrator to grant it to that user.
The app does not need the analyst's password or the warehouse name.

## 5. Establish a current baseline and query observations

Use the existing **Re-emit inventory** action and choose this destination. Include
`device.inventory` in its subscriptions and select operating-system inventory in
the collection. Wait for the re-emit run and the destination queue to settle. Query
2 counts events and distinct source/tenant/connection/device identities for that
run's `jobID`; compare its device count with the run. A successful re-emit run alone
means the events were queued, not that Snowflake accepted them.

Re-emit sends the currently stored snapshot with its original evidence dates. It
cannot reconstruct a historical observation the app never retained. Subsequent
sweeps and webhooks provide future history. Query 3 gives latest known OS/build;
query 4 preserves dated observations including older ones that arrived late. Query
5 counts computers whose tracked OS version changed exactly to `27.2.1` within a
half-open UTC window. It counts computers, not people. Query 6 exposes missing dates,
unread OS sections and missing builds. Inventory without an OS section remains a row
with `OS_SECTION_OBSERVED=false` and unknown OS fields, rather than disappearing.

Latest-state ordering uses source report time, then event occurrence time as a tie-break.
Event occurrence can mean a sweep window start or a webhook report time; it is not
necessarily collection time. `QUEUED_AT` records the durable source event's creation
time in the application, separately from both occurrence and warehouse commit time.
An undated observation cannot replace a dated observation as the latest dated
evidence. A device with only undated inventory stays present and explicitly marked
unknown. No missing report date, OS build, or collection is interpreted as compliance.

## 6. Retry, retention and operational boundaries

Each scheduler tick flushes available rows; it does not wait for a full batch.
Batches are at most **250 events and 3 MiB of encoded NDJSON**, including newlines.
One row larger than that limit is a visible dead letter, never truncated. A tick selects
at most 1,000 due deliveries and handles at most four Snowflake destinations. It can
first recover an already-frozen batch whose retry is due, even when older queued rows
filled the selection. New batches use only the selected rows. Consecutive resolved
batches share a 20-second per-destination network drain budget across discovery, DNS,
authentication and channel requests (local database commits and brief polling waits
can finish afterward).
It stops when a batch remains unresolved. The normal
scheduler checks every 30 seconds, while network work, a backlog or disabled workers
can extend latency. These are configured bounds, not measured throughput claims.

Before any request, the app commits the immutable batch and membership. Before
append it commits the previous checkpoint and cumulative row counters. Recovery
reopens the same Named Channel with `fail_on_uncommitted_rows=true`; it never drops
pending channel data. The batch becomes delivered only when its checkpoint commits
and the exact number of rows was inserted without rejection. If all rows were
rejected, they become dead letters with a next action. Mixed results remain unresolved
and replay one event at a time to identify rejected rows. Stable source keys and
`LOON_EVENTS` remove accepted replay duplicates. Use that view for counts.

An unresolved acknowledgement stays queued until reconciled; it does not exhaust
ten attempts and get purged. Fix the visible destination error, then automatic
retries continue with a bounded delay up to five minutes. Newer queued events do not
bring an unresolved batch's scheduled retry forward. Definitively rejected or
oversized events use ordinary dead-letter retention and **Redrive** after the cause
is fixed. Pending queues can consume local storage during a prolonged outage.
Disabling stops delivery while retaining the queue. Deleting a destination removes
its local delivery/recovery state, so it is not a retry remedy.

Source namespace and per-event UUIDs are persisted in the database, shared across
destinations, and retained in backups. Older retained events receive their UUID on
first export, so upgrading does not rewrite the retained outbox. Sibling changes sharing `deviceMeta.eventID`
still get different source keys. Keep the complete database and its matching
credential-encryption key together. Restore one active writer, rather than running
two writable clones of the same lineage. A channel expired after 30 idle days may
receive retained bytes again; the analyst view still deduplicates their stable keys.
Changing account/database/schema/pipe/role/user requires another destination and a
new baseline; key rotation is allowed in place. Restore/channel disagreements hold
the batch for investigation rather than silently declaring it delivered.

The REST adapter uses the app's existing HTTP and cryptography dependencies, keeping
native SDK packaging out of the macOS app. Snowflake's Python SDK does support macOS
ARM; REST was selected for control of the existing async outbound and recovery path,
not because SDK support is absent. The live exercise must establish whether REST's
lightweight-workload profile meets this fleet's volume.
[REST protocol](https://docs.snowflake.com/en/user-guide/snowpipe-streaming/snowpipe-streaming-high-performance-rest-api),
[recovery guidance](https://docs.snowflake.com/en/user-guide/snowpipe-streaming/snowpipe-streaming-high-performance-error-handling).

## 7. Required live acceptance exercise

Keep #848 open until these are recorded against a real disposable Snowflake target:

1. Run the supplied setup SQL; configure the app safely; query its exact test key.
2. Re-emit a known current fleet to this destination and reconcile the run's device
   count with query 2, including pending and failed delivery counts.
3. Capture one real OS change and two dated observations of the same Mac. Confirm
   latest state and retained history. Deliver an older observation late and confirm
   it does not replace newer evidence; keep missing evidence explicitly unknown.
4. On a disposable target only, induce a row rejection and interrupt/restart the
   sender after append. Confirm accepted, rejected and unresolved counts, stable
   replay keys and deduplicated counts. Do not drop a production channel to test this.
5. Record application-queue-to-commit lag for sparse events and a representative sweep,
   queue drain time, row/byte throughput and Snowflake cost. Synthetic tests do not
   establish these measurements or permission availability in a real account.

The app configuration, error surface, and supplied SQL are reviewable locally.
No live account credentials or customer writes were used to validate this change.

posture_snapshot: none
