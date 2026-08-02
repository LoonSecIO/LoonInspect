from __future__ import annotations

import json

from app.mdm.credentials import JamfCredentials
from app.mdm.patch.base import PatchProvider
from app.mdm.patch.jamf import JamfPatchProvider
from app.mdm.patch.loonsecio import LoonSecIoClient
from app.models.schema import MdmConnection
from app.schemas.connections import PatchManagementProvider


def get_patch_provider(connection: MdmConnection) -> PatchProvider | None:
    if connection.patch_management_provider == PatchManagementProvider.jamf.value:
        raw = json.loads(connection.credentials_encrypted) if connection.credentials_encrypted else {}
        credentials = JamfCredentials.model_validate(raw)
        return JamfPatchProvider(
            base_url=connection.base_url,
            client_id=credentials.client_id,
            client_secret=credentials.client_secret,
        )
    if connection.patch_management_provider == PatchManagementProvider.loonsecio.value:
        return LoonSecIoClient(
            license_key=connection.loonsecio_license_key_encrypted,
            data_sharing_enabled=connection.loonsecio_data_sharing_enabled,
        )
    return None
