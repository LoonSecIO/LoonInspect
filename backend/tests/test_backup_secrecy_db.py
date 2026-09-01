"""What a `pg_dump` of this database gives away.

docs/operations.md §1 makes an operational promise on the strength of this: that a
database backup taken without `ENCRYPTION_KEY` is useless to whoever holds it, so the
dump can be handled as ordinary (sensitive) data rather than as a credential store, and
that an operator who kept the dump and lost the key has lost their connections.

test_crypto.py pins `EncryptedString` in isolation — that the type decorator encrypts
what it is handed. That is a different claim from this one. It says nothing about which
columns use it, and a new secret-bearing column declared `String` instead would leave
every existing test green while putting a Jamf client secret in every backup in
plaintext for ever. This reads the bytes Postgres actually stored, through raw SQL that
the ORM's type decorator never touches, and looks for the plaintext in *every column of
the row* rather than only the one it was written to.

Rejected: asserting against the output of a real `pg_dump`. It needs the binary in the
test image and a superuser connection, and it would prove strictly less — a dump is a
serialisation of exactly these bytes, so if the row is clean the dump is.

Needs a real Postgres like every session test; gated on RUN_DB_TESTS. See
test_tenancy_sweep.py for the local invocation pattern.
"""

from __future__ import annotations

import json
import os

import pytest
import pytest_asyncio
from sqlalchemy import delete, text

# One event loop for the whole module — the engine's pooled connections belong to
# whichever loop first used them.
pytestmark = [
    pytest.mark.skipif(
        not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"
    ),
    pytest.mark.asyncio(loop_scope="session"),
]

# Long and distinctive so a substring hit means what it looks like: a short value could
# collide with base64 or a uuid and make an absence assertion pass for the wrong reason.
CLIENT_SECRET = "jamf-client-secret-vvq-7d41e0b9a2"
WEBHOOK_SECRET = "jamf-webhook-secret-vvq-19c3f8de55"
LICENSE_KEY = "loonsecio-license-vvq-6b02a7c4f1"
DESTINATION_SECRET = "splunk-hec-token-vvq-3e95d0a6bc"

ALL_SECRETS = (CLIENT_SECRET, WEBHOOK_SECRET, LICENSE_KEY, DESTINATION_SECRET)


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def stored() -> None:
    """One connection and one destination, written the way the API writes them."""
    from app.core.bootstrap import bootstrap_tenants
    from app.core.database import init_db, session_for_tenant, unscoped_session
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Destination, MdmConnection

    await init_db()
    async with unscoped_session() as db:
        await bootstrap_tenants(db)

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        # Re-runnable locally: the previous run's rows would trip the unique constraint
        # on (tenant_id, name) and turn a failure here into a fixture mystery.
        await db.execute(delete(Destination).where(Destination.name == "vvq destination"))
        await db.execute(delete(MdmConnection).where(MdmConnection.name == "vvq connection"))
        db.add(
            MdmConnection(
                name="vvq connection",
                provider="jamf",
                base_url="https://jamf.vvq.example.com",
                credentials_encrypted=json.dumps(
                    {"clientId": "vvq-client-id", "clientSecret": CLIENT_SECRET}
                ),
                webhook_secret_encrypted=WEBHOOK_SECRET,
                loonsecio_license_key_encrypted=LICENSE_KEY,
            )
        )
        db.add(
            Destination(
                name="vvq destination",
                type="splunk_hec",
                url="https://splunk.vvq.example.com:8088/services/collector",
                auth_type="splunk_hec",
                auth_secret_encrypted=DESTINATION_SECRET,
            )
        )
        await db.commit()


async def _row_as_text(table: str, name: str) -> str:
    """Every column of the row, as the bytes Postgres holds.

    `text()` carries no type decorator, so nothing on this path decrypts — which is the
    whole point. `row_to_json` rather than naming columns: a column added later is
    covered by this test on the day it is added, without anyone remembering to add it.
    """
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        result = await db.execute(
            text(f"SELECT row_to_json(t)::text FROM {table} t WHERE t.name = :name"),
            {"name": name},
        )
        return result.scalar_one()


@pytest.mark.parametrize(
    ("table", "name"),
    [
        pytest.param("mdm_connections", "vvq connection", id="mdm_connections"),
        pytest.param("destinations", "vvq destination", id="destinations"),
    ],
)
async def test_no_secret_is_stored_in_the_clear(stored: None, table: str, name: str) -> None:
    """The claim the runbook rests on. A dump of this row hands its holder ciphertext."""
    row = await _row_as_text(table, name)

    for secret in ALL_SECRETS:
        assert secret not in row, (
            f"{table}.{name} holds {secret!r} in the clear — a pg_dump of this database "
            "is now a credential leak, and docs/operations.md §1 is wrong"
        )


async def test_the_stored_bytes_are_fernet_tokens_this_key_can_read(stored: None) -> None:
    """The other half: unreadable without the key, and readable *with* it.

    Without this a column that stored nothing at all, or stored a hash, would satisfy
    the test above while quietly losing the credential — the failure would surface at
    the next sweep instead of here.
    """
    from cryptography.fernet import Fernet, InvalidToken

    from app.core.crypto import get_encryption_key

    row = json.loads(await _row_as_text("mdm_connections", "vvq connection"))
    token = row["credentials_encrypted"]

    assert token.startswith("gAAAAA"), "not a Fernet token: the column is storing something else"
    assert json.loads(Fernet(get_encryption_key()).decrypt(token.encode()))["clientSecret"] == (
        CLIENT_SECRET
    )

    with pytest.raises(InvalidToken):
        Fernet(Fernet.generate_key()).decrypt(token.encode())
