from __future__ import annotations

import json

from app.mdm.credentials import JamfCredentials
from app.mdm.jamf.client import JamfClient
from app.models.schema import MdmConnection


def get_mdm_client(connection: MdmConnection) -> JamfClient:
    """The connection's client. Jamf only (#79): the `provider` column and the
    credential-schema registry remain the seam a second provider plugs into; until one
    exists, pretending to dispatch here only hid that every caller was Jamf-shaped."""
    raw = json.loads(connection.credentials_encrypted) if connection.credentials_encrypted else {}
    credentials = JamfCredentials.model_validate(raw)
    return JamfClient(
        base_url=connection.base_url,
        client_id=credentials.client_id,
        client_secret=credentials.client_secret,
        user_agent_override=connection.user_agent_override,
    )
