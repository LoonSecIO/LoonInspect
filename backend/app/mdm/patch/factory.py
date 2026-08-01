from __future__ import annotations

from app.mdm.patch.base import PatchProvider
from app.mdm.patch.jamf import JamfPatchProvider
from app.mdm.patch.loonsecio import LoonSecIoClient
from app.models.schema import MdmConnection
from app.schemas.connections import PatchManagementProvider


def get_patch_provider(connection: MdmConnection) -> PatchProvider | None:
    if connection.patch_management_provider == PatchManagementProvider.jamf.value:
        return JamfPatchProvider(
            base_url=connection.base_url,
            client_id=connection.client_id,
            client_secret=connection.client_secret_encrypted,
        )
    if connection.patch_management_provider == PatchManagementProvider.loonsecio.value:
        return LoonSecIoClient(
            license_key=connection.loonsecio_license_key_encrypted,
            data_sharing_enabled=connection.loonsecio_data_sharing_enabled,
        )
    return None
