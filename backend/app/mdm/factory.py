from __future__ import annotations

import json

from app.mdm.base import MdmClient
from app.mdm.credentials import CREDENTIAL_SCHEMAS
from app.mdm.jamf.client import JamfClient
from app.mdm.simplemdm.client import SimpleMdmClient
from app.models.schema import MdmConnection
from app.schemas.payload import MdmProvider


def _credentials(connection: MdmConnection) -> dict:
    if not connection.credentials_encrypted:
        return {}
    return json.loads(connection.credentials_encrypted)


def get_mdm_client(connection: MdmConnection) -> MdmClient:
    provider = MdmProvider(connection.provider)
    schema_cls = CREDENTIAL_SCHEMAS.get(provider)
    credentials = schema_cls.model_validate(_credentials(connection)) if schema_cls else None

    if provider == MdmProvider.jamf:
        return JamfClient(
            base_url=connection.base_url,
            client_id=credentials.client_id,
            client_secret=credentials.client_secret,
            user_agent_override=connection.user_agent_override,
        )
    if provider == MdmProvider.simplemdm:
        return SimpleMdmClient()
    raise NotImplementedError(f"MDM provider '{connection.provider}' is not implemented yet")
