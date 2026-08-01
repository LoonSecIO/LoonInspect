from __future__ import annotations

from app.mdm.base import MdmClient
from app.mdm.jamf.client import JamfClient
from app.mdm.simplemdm.client import SimpleMdmClient
from app.models.schema import MdmConnection
from app.schemas.payload import MdmProvider


def get_mdm_client(connection: MdmConnection) -> MdmClient:
    if connection.provider == MdmProvider.jamf.value:
        return JamfClient(
            base_url=connection.base_url,
            client_id=connection.client_id or "",
            client_secret=connection.client_secret_encrypted or "",
        )
    if connection.provider == MdmProvider.simplemdm.value:
        return SimpleMdmClient()
    raise NotImplementedError(f"MDM provider '{connection.provider}' is not implemented yet")
