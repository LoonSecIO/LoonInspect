# AI Activity

Open **AI Activity** from the Overview, Settings navigation, or Settings → AI.
The page needs system read access. Provider setup is a separate link; its write
controls still require system write access. History remains readable when AI
inference is disabled. Reading or refreshing Activity never asks an AI provider.

## Read the three answers

**How much?** Historical usage defaults to the last 30 inclusive UTC days. Choose
7, 30 or 90 days, or a custom range of at most 90 days. Inference attempts, actual
provider dispatches, useful results, failures and average request/local-wait times
appear first. A dispatch means the request reached the HTTP transport; it does not prove the
provider received it. An attempt can time out waiting for a local slot without
dispatching.
A response is useful only when its requesting feature accepts it. Retries and
fallback attempts are separate calls; cache hits are logical work without a call.

**Which service and purpose?** Service rows show identity and a safe label recorded
at call time. OpenAI-compatible describes a protocol: it can mean OpenAI, Ollama,
or another service. Old ambiguous rows remain legacy/unknown. Changing today’s
configuration never renames earlier calls. Optional service label/type controls
in Provider setup describe future calls without changing the endpoint or protocol.
Never put a credential or URL in the label. Unsaved provider tests have a distinct
“test endpoint” label so a test cannot masquerade as the saved production service.

Service, purpose, requested-or-reported model, outcome and protocol filters compose.
They are retained in the URL, including when navigating Back/Forward or refreshing.
Select a service, purpose or day to drill down. The daily chart, summaries and groups
use the same filters; each finalized attempt belongs to its UTC completion day.
Logical-work arrivals use their arrival day, while useful, failed, cancelled and
expired work use their completion day; work spanning midnight can appear in
different arrival and completion windows.
Detailed groups include requested versus reported model, token reporting coverage,
and separate waiting, request and total durations. Empty model reports are unknown.
Token sums cover only reports received from providers; these are not invoice totals.
Averages do not imply percentiles, and averages with different coverage need not add.

**Is it keeping up?** Live workload always covers current work across all services,
regardless of the selected historical period. It displays the server’s verdict,
evidence rule, next check, current waiting/running counts, oldest wait, and arrivals
versus useful completions in one recent window. Backlog alone does not establish
that processing is falling behind. Open its coverage details for inventory,
interactive requests and patch investigations. Research before inference has only
partial coverage. Work from other applications is outside this page’s visibility.
Interrupted interactive work remains stalled until its deadline and a 120-second
grace period have passed. Scheduled maintenance then marks it expired and records
its unfinished attempts as interrupted. A stalled maintenance worker can delay
that cleanup; refreshing this page does not perform it.

## Freshness and incomplete evidence

The live panel refreshes every 15 seconds while the tab is visible; returning to the
tab requests a fresh reading. Manual refresh is available. A failed read immediately
removes the prior health verdict and counts. A reading at least 45 seconds old is
also unavailable, even while its replacement request is still pending. The timestamp
then names the last successful reading, not current health. Check connectivity and
retry. A permission refusal asks for system read access, rather than reporting zero.

History is read when its range/filters change or Refresh history is pressed. Old
results clear as soon as the selection changes. No calls in a period, no matching
filters, disabled inference, unreadable readings and recording failures have distinct
messages. A recording failure makes the retained totals incomplete; do not use them
to conclude that no work happened or that processing is healthy.

Unknown tokens, durations, dispatches and useful results remain **Unknown**, with
reporting coverage shown as measured attempts / all attempts. Detailed measurement
begins when instrumentation first records it. Legacy daily rows cannot establish
minute-level workload history. The page displays that start, the earliest retained
daily measurement and retention. See [troubleshooting](troubleshooting.md) for the
server’s failure categories and recovery checks.

posture_snapshot: none
