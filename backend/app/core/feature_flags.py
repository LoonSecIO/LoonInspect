from __future__ import annotations

# The master AI switch (INSPECT-0112). A registry key rather than anything richer:
# the flag turns the AI feature area on; whether any byte may leave the pod for
# inference is a separate consent on the data-sharing settings, checked by the gate
# in app.core.ai — which is also where the standing doctrine lives.
AI_FEATURES_FLAG = "ai_features"

# Promoted applications (#793). The flag turns the area on: off, nothing can be promoted and the
# exchange body is what it was before the area existed. Whether anything leaves at all is still
# the data-sharing tier's decision, read where the exchange is built (app.core.sharing).
APP_PROMOTION_FLAG = "app_promotion"

# Fleet's maintained-apps catalogue (#794). The one registry key that also decides an outbound
# call: while no organization on this instance has it on, nothing asks GitHub for the catalogue
# (`app.core.fleet_catalog`), and the tab under Devices > Applications is not listed.
FLEET_MAINTAINED_APPS_FLAG = "fleet_maintained_apps"

FEATURE_FLAG_REGISTRY: dict[str, dict[str, str]] = {
    "jamf_patch": {
        "label": "Jamf Patch feed",
        "description": (
            "Show the Jamf Patch tab under Devices › Applications, even without a "
            "connection that has the Jamf Pro capability enabled."
        ),
    },
    # The override on the data gate (#529), in `jamf_patch`'s voice: the entry follows the
    # corpus, and this is what lists it anyway — a lab, a demo or a design partner ahead of
    # its first epoch. It does not open the route, which is open either way, and it does not
    # make anything answer: the page still reads the banner and its *why* block.
    "vulnerabilities": {
        "label": "Posture › Vulnerabilities",
        "description": ("Show Posture › Vulnerabilities even before a vulnerability corpus is answering for this organization."),
    },
    # `patch_policy` (#614) was here until 2026-11-24, when it was promoted and removed: Posture ›
    # Patch policy is listed for every app:read holder (docs/feature-flags.md). A row an
    # organization stored for it is ignored, as every key outside this registry is.
    APP_PROMOTION_FLAG: {
        "label": "Promote applications",
        "description": (
            "Let an administrator promote an installed application under Settings › Data Sharing. "
            "While sharing is on, each exchange then sends that application's name, bundle ID and "
            "versions in plain text beside its hashes, without waiting for five organizations to "
            "report it. Off, nothing is promoted and the exchange is unchanged."
        ),
    },
    FLEET_MAINTAINED_APPS_FLAG: {
        "label": "Fleet catalog (maintained apps)",
        "description": (
            "Show Devices › Applications › Fleet catalog: the Mac apps Fleet maintains, with Fleet's latest "
            "version beside what this organization has installed. While this is on, the instance asks GitHub "
            "once a day for the catalog in Fleet's repository (fleetdm/fleet), reads the version history of "
            "the titles installed here from the same repository, slowly, and sends nothing about this "
            "organization. The catalog's files are under the licence in that repository's ee/ folder, which "
            "says production use needs a Fleet subscription."
        ),
    },
    AI_FEATURES_FLAG: {
        "label": "AI features",
        "description": (
            "Master switch for every AI-assisted feature; nothing AI runs while it "
            "is off. Off-pod inference additionally requires the AI-inference "
            "consent under Settings › Data Sharing, and every permitted call is "
            "written to the share log."
        ),
    },
}
