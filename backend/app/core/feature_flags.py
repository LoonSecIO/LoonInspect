from __future__ import annotations

# The master AI switch (INSPECT-0112). A registry key rather than anything richer:
# the flag turns the AI feature area on; whether any byte may leave the pod for
# inference is a separate consent on the data-sharing settings, checked by the gate
# in app.core.ai — which is also where the standing doctrine lives.
AI_FEATURES_FLAG = "ai_features"

FEATURE_FLAG_REGISTRY: dict[str, dict[str, str]] = {
    "jamf_patch": {
        "label": "Jamf Patch feed",
        "description": (
            "Show the Jamf Patch tab under Devices › Applications, even without a "
            "connection that has the Jamf Pro capability enabled."
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
