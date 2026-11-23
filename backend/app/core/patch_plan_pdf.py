"""Render the exact saved plan revision into a paginated, source-attributed audit report."""

from io import BytesIO
from pathlib import Path
from xml.sax.saxutils import escape

import reportlab
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import CondPageBreak, LongTable, Paragraph, SimpleDocTemplate, Spacer, TableStyle


def render_pdf(plan):
    buffer = BytesIO()
    fonts = Path(reportlab.__file__).parent / "fonts"
    if "PlanSans" not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont("PlanSans", str(fonts / "Vera.ttf")))
        pdfmetrics.registerFont(TTFont("PlanSansBold", str(fonts / "VeraBd.ttf")))
        pdfmetrics.registerFontFamily("PlanSans", normal="PlanSans", bold="PlanSansBold")
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("Plan", fontName="PlanSans", fontSize=9, leading=13, spaceAfter=7, splitLongWords=True))
    styles.add(ParagraphStyle("PlanSmall", parent=styles["Plan"], fontSize=7.5, leading=10, textColor=colors.HexColor("#475569")))
    styles.add(
        ParagraphStyle(
            "PlanTitle", parent=styles["Plan"], fontName="PlanSansBold", fontSize=24, leading=29, spaceAfter=18, keepWithNext=True
        )
    )
    styles.add(
        ParagraphStyle(
            "PlanHeading",
            parent=styles["Plan"],
            fontName="PlanSansBold",
            fontSize=13,
            leading=18,
            spaceBefore=13,
            keepWithNext=True,
        )
    )
    styles.add(ParagraphStyle("PlanCell", parent=styles["Plan"], fontSize=8, leading=11, spaceAfter=0, alignment=TA_LEFT))

    def p(value, style="Plan"):
        return Paragraph(escape(str(value if value is not None else "Not recorded")).replace("\n", "<br/>"), styles[style])

    def table(rows, widths):
        result = LongTable([[p(cell, "PlanCell") for cell in row] for row in rows], colWidths=widths, repeatRows=1, hAlign="LEFT")
        result.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 7),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                    ("LINEBELOW", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
                ]
            )
        )
        return result

    snapshot, research = plan["snapshot"], plan.get("research") or {}
    apps = snapshot["applications"]

    def evidence_summary(app):
        sources = list(dict.fromkeys(o["source"] for o in app["options"]))
        investigation = next((r for r in research.get("applications", []) if r["appHash"] == app["appHash"]), None)
        if investigation and investigation["status"] in {"candidate", "needs_review"}:
            sources.append("Installomator (review required)")
        return ", ".join(sources) or "Needs investigation"

    story = [
        p("LOONINSPECT / PATCH PLANNING", "PlanSmall"),
        Spacer(1, 12),
        p(plan["title"], "PlanTitle"),
        p(snapshot["organization"], "PlanHeading"),
        p(snapshot["status"]),
        p(
            f"Prepared by: {plan['createdBy']}\nInventory snapshot: {snapshot['asOf']}\n"
            f"Plan ID: {plan['id']}\nRevision: {plan['revision']}"
        ),
        p(
            f"{len(apps)} application{'s' if len(apps) != 1 else ''} with documented plans covering "
            f"{snapshot['applicationDevices']} distinct Macs. "
            f"The selected device scope contains {snapshot['scopedDevices']} Macs."
        ),
        p("Plan coverage", "PlanHeading"),
        table(
            [["Application / bundle ID", "Macs", "Plan status", "Source evidence"]]
            + [
                [
                    f"{app['name']}\n{app['bundleId']}",
                    str(app["devices"]),
                    app["status"].replace("_", " "),
                    evidence_summary(app),
                ]
                for app in apps
            ],
            [190, 40, 110, 164],
        ),
        p("Device scope", "PlanHeading"),
        *[p(line) for line in snapshot["scopeDescription"]],
        p("Inventory sources", "PlanHeading"),
    ]
    for source in snapshot["sources"]:
        story.append(
            p(
                f"{source['mdm']} - {source['name']} (connection {source['connectionId']}); {source['devices']} Macs. "
                f"Inventory dates: {source['oldestInventoryAt'] or 'unknown'} to {source['newestInventoryAt'] or 'unknown'}. "
                f"Unknown dates: {source['unknownInventoryDates']}."
            )
        )
    review = snapshot.get("operatorReview") or {}
    story.append(p("Operator review and rollout ownership", "PlanHeading"))
    for key, label in [
        ("owner", "Owner"),
        ("window", "Maintenance window"),
        ("pilot", "Pilot scope"),
        ("recovery", "Recovery plan"),
        ("exceptions", "Exceptions / follow-up"),
        ("approval", "Approval reference"),
    ]:
        story.append(p(f"{label}: {review.get(key) or 'Not recorded - requires review'}"))
    if review.get("recordedAt"):
        story.append(p(f"Recorded by {review['recordedBy']} at {review['recordedAt']}", "PlanSmall"))
    story += [
        p("Evidence limitations", "PlanHeading"),
        *[p(line) for line in snapshot["limitations"]],
        p("Report integrity", "PlanHeading"),
        p(f"SHA-256 of the saved report data: {plan['sha256']}", "PlanSmall"),
        p(
            "The checksum identifies this report's data revision. It is not a digital signature or proof of deployment.",
            "PlanSmall",
        ),
    ]
    for app in apps:
        investigation = next((item for item in research.get("applications", []) if item["appHash"] == app["appHash"]), None)
        story += [
            CondPageBreak(240),
            p(app["name"], "PlanTitle"),
            p(app["bundleId"], "PlanSmall"),
            p(
                f"{app['devices']} Macs / proposed target: {app['targetVersion'] or 'requires verification'} / "
                f"{app['status'].replace('_', ' ')}"
            ),
            table(
                [["Installed version", "Macs", "Compared with proposed target"]]
                + [
                    [
                        v["version"] + (f" ({v['shortVersion']})" if v.get("shortVersion") else ""),
                        str(v["devices"]),
                        v["relation"].replace("_", " "),
                    ]
                    for v in app["versions"]
                ],
                [230, 64, 210],
            ),
            p("Patch methods and provenance", "PlanHeading"),
        ]
        if not app["options"]:
            story.append(p("No catalog-backed method has been established. Investigate the vendor installer and Installomator."))
        for option in app["options"]:
            story += [
                p(f"{option['source']}: {option['title']} - {option['status'].replace('_', ' ')}", "PlanHeading"),
                p(f"Target: {option['targetVersion']}. {option['detail']}"),
                p(
                    f"Source: {option['url']}\nRead: {option['observedAt'] or 'unknown'}\nRevision: {option['sourceRevision']}",
                    "PlanSmall",
                ),
            ]
        story += [
            p("Proposed Jamf rollout", "PlanHeading"),
            *[p(f"{i}. {step}") for i, step in enumerate(app["steps"], 1)],
            p("Open review items at plan creation", "PlanHeading"),
            *[p(f"- {gap}") for gap in app["gaps"]],
        ]
        if investigation:
            story += [
                p("Background investigation", "PlanHeading"),
                p(investigation["detail"]),
                p(f"Status: {investigation['status']}. Checked: {investigation.get('checkedAt', 'unknown')}", "PlanSmall"),
            ]
            for key in ("url", "revision", "sha256", "label", "signingTeam"):
                if investigation.get(key):
                    story.append(p(f"{key}: {investigation[key]}", "PlanSmall"))
        ai = research.get("ai") or {}
        priorities = (ai.get("priorities") or {}).get(app["appHash"], [])
        if priorities:
            story += [
                p("AI-assisted review priorities", "PlanHeading"),
                p(
                    "Review rollout steps "
                    + ", ".join(str(index) for index in priorities)
                    + " first (see Proposed Jamf rollout)."
                ),
            ]
    story += [
        p("Investigation and AI provenance", "PlanHeading"),
        p(f"Investigation status: {plan['researchStatus']}"),
        p(research.get("detail", "Background investigation has not been requested.")),
    ]
    ai = research.get("ai") or {}
    labels = {
        "status": "AI status",
        "provider": "Provider",
        "requestedModel": "Requested model",
        "reportedModel": "Reported model",
        "completedAt": "Completed at",
        "promptSha256": "Prompt SHA-256",
        "detail": "Result",
    }
    if ai:
        story.append(p("\n".join(f"{label}: {ai[key]}" for key, label in labels.items() if ai.get(key)), "PlanSmall"))

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("PlanSans", 7)
        canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.drawString(54, 29, f"LoonInspect | {plan['id'][:8]} | revision {plan['revision']} | Draft plan")
        canvas.drawRightString(558, 29, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=(612, 792),
        rightMargin=54,
        leftMargin=54,
        topMargin=45,
        bottomMargin=49,
        title=plan["title"],
        author=plan["createdBy"],
        subject="Application patch plan and evidence",
    )
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()
