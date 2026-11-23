"""The permissions and disclosure shown before granting an external MCP connection."""

from app.core.permissions import Permission

MCP_ACCESS_FLAG = "mcp_access"
DISCLOSURE = (
    "Connected assistants can retrieve this organization's fleet data within the permissions you grant: "
    "device names, identifiers, serials, users, inventory and application details, vulnerability evidence, "
    "changes, alerts, run diagnostics, connection names and reports. The selected client may send those "
    "results to its model provider. LoonInspect cannot verify the client's downstream provider or model. "
    "Every permitted tool result records its connection and disclosed field categories in the share log; "
    "credentials and account-management tools are never exposed. Sync permissions also allow requests to Jamf."
)
SCOPE_DESCRIPTIONS = {
    Permission.MCP_CONNECT: ("Connect an assistant", "Use the MCP endpoint with this explicitly scoped credential."),
    Permission.DEVICE_READ: ("Devices", "Names, serials, users, hardware, software inventory and device history."),
    Permission.APP_READ: ("Applications", "Installed applications, versions, affected devices and changes."),
    Permission.VULN_READ: ("Vulnerabilities", "CVE records, assessment states, evidence and affected inventory."),
    Permission.CONNECTION_READ: ("Sync history", "Connection names, run status, actor labels and diagnostic log lines."),
    Permission.SYSTEM_READ: ("Instance status", "Build, update and source status."),
    Permission.DESTINATION_READ: ("Delivery status", "Event delivery counts and failures."),
    Permission.AUDIT_READ: ("Reports", "Posture history and compliance evidence, including device identities."),
    Permission.DEVICE_SYNC: ("Refresh inventory", "Request a device refresh or inventory sweep from Jamf."),
    Permission.PATCH_CATALOG_SYNC: (
        "Refresh patch catalog",
        "Request the public Jamf patch catalog; cold refreshes take minutes.",
    ),
}
ALLOWED_SCOPES = frozenset(p.value for p in SCOPE_DESCRIPTIONS)


def validate_grant(scopes: list[str], expires_in_days: int | None) -> None:
    """MCP grants are finite and explicit, including when created through the ordinary token API."""
    if Permission.MCP_CONNECT.value not in scopes:
        return
    if not expires_in_days or not set(scopes) <= ALLOWED_SCOPES:
        raise ValueError("MCP connections need an expiry and only the fleet permissions shown in AI connections.")
