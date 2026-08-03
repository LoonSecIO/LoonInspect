from __future__ import annotations

FEATURE_FLAG_REGISTRY: dict[str, dict[str, str]] = {
    "jamf_patch": {
        "label": "Jamf Patch feed",
        "description": (
            "Show the Jamf Patch tab under Devices › Applications, even without a "
            "connection that has the Jamf Pro capability enabled."
        ),
    },
}
