"""The evidence artefact as one printable, self-contained HTML document (#473, #219 R5 5.6).

An auditor does not receive JSON. This renders #472's object — contract in docs/compliance-evidence.md §6 — as a
file that opens with **no network**: no CDN, no font, no stylesheet, because it will be opened a year from now on a
machine that cannot reach us. The bundle travels *inside* the page rather than beside it, where the two could be
separated. **No server-side PDF**: until a real assessor says a printed page is not acceptable, that is a fact we
do not have. **The fleet is untrusted input** (docs/ai-threat-model.md) — text through `_t`, the bundle through
`_bundle` — so a Mac named `</script>` closes nothing. Pure and synchronous, which is what lets the failure
sentences, the half of this surface that only shows up on a bad day, be tested at all.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from html import escape
from typing import Any

from app.baseline.report import REFUSAL
from app.core.config import settings
from app.mdm.jamf.contract import CONTRACT_VERSION

BUNDLE_ID = "evidence-bundle"
TITLE = "Evidence report"

#: Every sentence this surface prints about itself, together because they are its diagnosability contract:
#: docs/troubleshooting.md §17 steps through each, and one reworded there and not here is how that document decays.
#: Each says what happened, why, and the next check, in the operator's vocabulary (docs/diagnosability.md §2).
NO_OBSERVATION = (
    "No observation in this window. This connection has observations, but none between {start} and {as_of}, so no Mac "
    "is named below and the sum is empty. Check when the last device sweep ran — Settings › Connections, the run "
    "panel under the connection — and ask again for a window that reaches it."
)
NO_LEDGER_SAID = (
    "No observation ledger for this connection. Nothing has ever been written for it, so there is nothing to report "
    "on: only a device sweep writes the ledger, and a connection that has run only catalog refreshes or webhook runs "
    "has none. Run a device sweep from Settings › Connections, then ask again."
)
COLLECTOR_GAP = (
    "Part of this window was not collected. {days} of it read no observation — stretches where nothing reported at "
    "all, which is the collector not running rather than a fleet in a good state. Read the run history for those "
    "dates under Settings › Connections. The days are counted below by Mac rather than folded away."
)
STALE_TAIL = (
    "This report is dated later than the last collection it could read. The newest collection is {collected} and the "
    "report runs to {as_of}: the stretch between them counts as not observed, not as the last known state carried "
    "forward. If a sweep should have run since {collected}, that is the thing to check."
)
OLD_WINDOW = (
    "The runs behind the oldest part of this window are gone, and that is expected. Runs are kept {retention} days "
    "while the observation ledger is never purged, so a window opening {start} stays answerable long after the run "
    "that collected it stopped being listed. The evidence below is unaffected; only the run row is missing."
)
UNKNOWN_CONTRACT = (
    "Every verdict reads not reported, because these observations were recorded under contract version {seen} while "
    "this build's rules are written against {known}. A field path is a path into a contract, so the rules are left "
    "unapplied rather than guessed at. Use a build whose rules know {seen}, or report the pair."
)
CATALOGUE_UNREADABLE = (
    "The evidence report cannot be rendered: the baseline rule catalogue could not be read, and a partial catalogue "
    "prints as a passing fleet. {detail} Nothing about the fleet is wrong — report this with the build from "
    "Settings › Support."
)

_CSS = """
:root{color-scheme:light}
*{box-sizing:border-box}
body{margin:0;padding:24px;background:#fff;color:#111;
  font:13px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}
main{max-width:64rem;margin:0 auto}
h1{font-size:19px;margin:0 0 2px}
h2{font-size:12px;margin:20px 0 6px;text-transform:uppercase;letter-spacing:.07em;color:#444}
p{margin:0 0 6px}
.refusal{font-weight:600;border-left:3px solid #111;padding-left:9px;margin:10px 0}
dl{display:grid;grid-template-columns:max-content 1fr;gap:1px 14px;margin:0}
dt{color:#555}
dd{margin:0}
table{width:100%;border-collapse:collapse;margin:0 0 10px}
th,td{border:1px solid #bbb;padding:4px 6px;text-align:left;vertical-align:top}
th{background:#f1f1f1;font-weight:600}
td.n{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
/* Every character prints; nothing gets overflow:hidden or an ellipsis, a truncated digest on paper being
   not evidence. `hash` may break anywhere, `nb`/`ts` never (a split rule id or timestamp is unreadable
   when the column could be wider), `mono` breaks a token only when it cannot fit a line of its own. All
   three came from printing the page. */
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:11px;
  overflow-wrap:break-word;hyphens:none}
.hash{overflow-wrap:anywhere}
.nb,.ts{white-space:nowrap}
.note{border:1px solid #111;padding:7px 10px;margin:0 0 8px}
.note b{display:block}
/* The document is one row of one table so the refusal can be that table's repeating `thead` — measured
   against Chrome, the only construction that repeats on every page without printing over the content.
   `position:fixed` was tried five ways and every one failed. On screen the row is hidden: the refusal is
   already in the header block. */
.sheet>thead{display:none}
.sheet>thead>tr>th{background:none;border:0;border-bottom:.5pt solid #000;padding:0 0 3px;
  font-weight:400;font-size:9px}
.sheet>tbody>tr>td{border:0;padding:6px 0 0}
@media print{
  @page{size:A4 portrait;margin:14mm 12mm 14mm}
  body{padding:0;font-size:10px;background:#fff;color:#000}
  .sheet>thead,thead{display:table-header-group}
  tr,.note,dl,dd{break-inside:avoid}
  h1,h2,header{break-after:avoid}
  a{color:#000;text-decoration:none}
}
"""


def _t(value: Any) -> str:
    """Untrusted text into HTML. `quote=True`, because these land in attributes as well as in cells."""
    return escape("" if value is None else str(value), quote=True)


def _bundle(report: dict[str, Any]) -> str:
    """The object as a `<script type="application/json">` body. `<` becomes `\\u003c`, a valid JSON escape, so no
    value can spell `</script` and end the block early, whatever a Mac is called."""
    text = json.dumps(report, separators=(",", ":"))
    return text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def _when(value: Any) -> str:
    """To the minute; the columns say UTC once in their heading. The seconds went after a printed fixture showed the
    interval column wrapping one token per line."""
    return str(value)[:16].replace("T", " ") if value else "—"


def _when_said(value: Any) -> str:
    """With its clock spelled out, for the header and the sentences, where no column carries it."""
    return f"{_when(value)} UTC" if value else "—"


def _range(start: Any, end: Any) -> str:
    """Both ends, each unbreakable: a timestamp split over two lines is one a reader has to reassemble."""
    return f'<span class="ts">{_t(_when(start))}</span> → <span class="ts">{_t(_when(end))}</span>'


def _span_said(span: dict[str, Any]) -> str:
    """ "under one reporting interval", never "0 days": a zero meaning we saw it once must not wear the costume of a
    zero meaning it never happened (#472 §4), least of all on a page someone files."""
    days = span.get("days")
    return f"{days:g} days" if days else "under one reporting interval"


def _cell(value: Any, klass: str = "") -> str:
    return f'<td class="{klass}">{_t(value)}</td>' if klass else f"<td>{_t(value)}</td>"


def _table(headers: tuple[str, ...], body: list[list[str]], klass: str = "") -> str:
    head = "".join(f"<th>{_t(header)}</th>" for header in headers)
    rows = "".join("<tr>" + "".join(cells) + "</tr>" for cells in body)
    return f'<table class="{klass}"><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table>'


def notices(report: dict[str, Any], *, heartbeat: datetime | None, now: datetime | None = None) -> list[str]:
    """What this report has to say about itself, before a reader infers it wrong. Each is a state an empty or ugly
    table would otherwise be read as — #150's rule, that failure is not emptiness, applied to a page someone files.
    Derived from the object and the heartbeat alone, so the sentences are testable without a fleet."""
    window = report["header"]["method"]["window"]
    if heartbeat is None:
        return [NO_LEDGER_SAID]
    said: list[str] = []
    if not report["rows"]:
        said.append(NO_OBSERVATION.format(start=_when_said(window["start"]), as_of=_when_said(window["asOf"])))
    unknown = [version for version in report["header"]["contractVersions"] if version != CONTRACT_VERSION]
    if unknown:
        said.append(UNKNOWN_CONTRACT.format(seen=", ".join(unknown), known=CONTRACT_VERSION))
    gap = report["totals"].get("fleet", {}).get("notObservedParts", {}).get("noObservation")
    if gap and report["rows"]:
        said.append(COLLECTOR_GAP.format(days=_span_said(gap)))
    newest = max((row["collectedTo"] for row in report["rows"] if row.get("collectedTo")), default=None)
    if newest and str(window["asOf"]) > str(newest):
        said.append(STALE_TAIL.format(collected=_when_said(newest), as_of=_when_said(window["asOf"])))
    retention = settings.run_retention_days
    if str(window["start"]) < ((now or datetime.now(UTC)) - timedelta(days=retention)).isoformat():
        said.append(OLD_WINDOW.format(retention=retention, start=_when_said(window["start"])))
    return said


def _header_html(report: dict[str, Any]) -> str:
    """The five header items of #472, in its order. `notVisible` is the one a later session trims for space. It does
    not get trimmed: a page of technical evidence with no framework claim on it is read as a framework claim by
    whoever receives it unless it says otherwise in its own header."""
    head = report["header"]
    method, absent = head["method"], head["notVisible"]
    window, connection, catalogue = method["window"], method["connection"], method["catalogue"]
    pairs = (
        ("Connection", f"{connection['name']} — {connection['provider']}, #{connection['connectionID']}"),
        ("Read from", f"the {method['source']}"),
        ("Window", f"{_when_said(window['start'])} → {_when_said(window['asOf'])}"),
        ("Rule catalogue", f"version {catalogue['version']}, {catalogue['rules']} rules"),
        ("Contract version", ", ".join(head["contractVersions"]) or "—"),
        ("Clock", head["clock"]["statement"]),
        ("Not visible from here", f"{', '.join(absent['controls'])} — {absent['statement']}"),
    )
    items = "".join(f"<dt>{_t(key)}</dt><dd>{_t(value)}</dd>" for key, value in pairs)
    return (
        f"<header><h1>{TITLE}</h1><p>{_t(method['statement'])}</p><dl>{items}</dl>"
        f'<p class="refusal">{_t(head["refusal"])}</p></header>'
    )


def _totals_html(report: dict[str, Any]) -> str:
    """met + unmet + not observed = the window, where a reader cannot miss it, with `notReported` — a field the
    aperture never collected — beside the third rather than inside it."""
    titles = {rule["ruleID"]: rule["title"] for rule in report["rules"]}
    fleet = report["totals"].get("fleet")
    buckets = list(report["totals"]["byRule"].items()) + ([("Every rule, every Mac", fleet)] if fleet else [])
    body = [
        [
            _cell(titles.get(key, key)),
            *(_cell(_span_said(total[state]), "n") for state in ("met", "unmet", "notObserved")),
            _cell(" · ".join(f"{k}: {_span_said(v)}" for k, v in total.get("notObservedParts", {}).items()) or "—"),
            _cell(_span_said(total["window"]), "n"),
        ]
        for key, total in buckets
    ]
    said = (
        "<p>Met plus unmet plus not observed is the window, exactly. Not observed is every stretch this report "
        "cannot answer for, and its pieces are named beside it rather than folded in. A rule nothing could be "
        "counted for is absent here rather than a row of zeros.</p>"
    )
    headers = ("Rule", "Met", "Unmet", "Not observed", "of which", "= the window")
    return f"<h2>The three-way sum</h2>{said}{_table(headers, body, 'sum')}"


def _devices_html(report: dict[str, Any]) -> str:
    """The lineage triple beside the name: a repair keeps the serial and changes the UDID, so neither alone
    identifies a Mac over its life."""
    body = [
        [
            _cell(device.get("name") or "—"),
            _cell(device["deviceID"], "mono nb"),
            _cell(device.get("udid") or "—", "mono"),
            _cell(device.get("serialNumber") or "—", "mono nb"),
            _cell(device.get("managementID") or "—", "mono"),
        ]
        for device in report["devices"]
    ]
    return f"<h2>The Macs in this window</h2>{_table(('Mac', 'Jamf id', 'UDID', 'Serial', 'Management id'), body)}"


def _row_html(row: dict[str, Any], names: dict[str, str]) -> list[str]:
    """One (Mac, rule, interval). The field read and the digest it hashes to are the artefact's whole value over a
    spreadsheet, so they share the last cell rather than being cut for width."""
    read = _t(row.get("witnessed", {}).get("statement", "—"))
    digest = row.get("sectionDigest")
    seen = f'<div class="mono hash">{_t(digest)}</div>' if digest else ""
    collected = _range(row["collectedFrom"], row.get("collectedTo")) if row.get("collectedFrom") else "—"
    return [
        _cell(names.get(row["deviceID"], row["deviceID"])),
        _cell(row["ruleID"], "mono nb"),
        _cell(row["state"]),
        f"<td>{_range(row['from'], row['to'])}</td>",
        _cell(row["duration"], "n"),
        f"<td>{collected}</td>",
        f"<td><div>{read}</div>{seen}</td>",
    ]


def render_evidence_page(report: dict[str, Any], *, heartbeat: datetime | None, now: datetime | None = None) -> str:
    """The whole artefact as one file. `heartbeat` is the ledger's own clock, which the object does not carry and the
    sentences need; `now` is injectable so the run-retention sentence is testable."""
    names = {device["deviceID"]: device.get("name") or device["deviceID"] for device in report["devices"]}
    said = "".join(
        f'<div class="note"><b>Read this first</b>{_t(sentence)}</div>'
        for sentence in notices(report, heartbeat=heartbeat, now=now)
    )
    headers = ("Mac", "Rule", "State", "Interval, device time (UTC)", "For", "Collected (UTC)", "What was read")
    window = report["header"]["method"]["window"]
    title = f"{TITLE} — {report['header']['method']['connection']['name']}, {str(window['start'])[:10]}"
    body = (
        f"{_header_html(report)}{said}{_totals_html(report)}{_devices_html(report)}"
        f"<h2>Every interval</h2>{_table(headers, [_row_html(row, names) for row in report['rows']])}"
        "<h2>The bundle</h2><p>The machine-readable object this page was rendered from travels inside it: "
        f'<code class="mono">document.getElementById("{BUNDLE_ID}").textContent</code>, parsed as JSON. It carries '
        "each rule's predicate and every field this page shows. Its contract is docs/compliance-evidence.md.</p>"
        f'<script type="application/json" id="{BUNDLE_ID}">{_bundle(report)}</script>'
    )
    return (
        '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{_t(title)}</title><style>{_CSS}</style></head><body><main>"
        f'<table class="sheet"><thead><tr><th class="running">{_t(REFUSAL)}</th></tr></thead>'
        f"<tbody><tr><td>{body}</td></tr></tbody></table></main></body></html>"
    )


def page_filename(report: dict[str, Any]) -> str:
    """The window and `as_of` in the name, so two reports do not collide in a downloads folder."""
    window = report["header"]["method"]["window"]
    connection = report["header"]["method"]["connection"]["connectionID"]
    return f"evidence-{connection}-{str(window['start'])[:10]}-to-{str(window['asOf'])[:10]}.html"
