"""credentials_fingerprint is a truncated hash, not the secret's first three characters (#316)

`mdm_connections.credentials_fingerprint` was `secret[:3]`: three characters of the
plaintext Jamf client secret, stored beside the ciphertext and returned by
`GET /api/mdm/connections` to every role with `CONNECTION_READ` — Analyst and Auditor
included, the two roles the README defines as having no access to secret values. The
field exists to answer "did the secret change?", and the first twelve hex characters of
SHA-256 over the secret answer that without disclosing anything
(`app.mdm.credentials.credential_fingerprint`).

Two things happen here. The column widens from three characters to twelve. And every
stored value is cleared rather than re-derived: the plaintext exists only inside
`credentials_encrypted`, and a migration that decrypts is a migration that fails, at
boot, whenever `ENCRYPTION_KEY` is absent or rotated — a worse failure than a blank
fingerprint. Cleared rows read as "no fingerprint yet" in the UI, and the next credential
save stamps the hash. `credentials_rotated_at` is untouched, so "when were these last
rotated?" keeps its answer throughout.

The clear walks tenants and binds each in turn, the same dance as a9d4c7e1f3b8: the table
is behind FORCEd row-level security with no owner bypass, and an unbound UPDATE raises
rather than touching zero rows (the baseline migration documents why).

Revision ID: 88a6f0da5041
Revises: d4a1e8c73b29
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "88a6f0da5041"
down_revision: Union[str, Sequence[str], None] = "d4a1e8c73b29"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

CLEAR = "UPDATE mdm_connections SET credentials_fingerprint = NULL WHERE credentials_fingerprint IS NOT NULL"


def _for_each_tenant(statement: str) -> None:
    bind = op.get_bind()
    tenant_ids = bind.execute(sa.text("SELECT id FROM tenants")).scalars().all()
    for tenant_id in tenant_ids:
        bind.execute(sa.text("SELECT set_config('looninspect.tenant_id', :tid, true)"), {"tid": str(tenant_id)})
        bind.execute(sa.text(statement))


def upgrade() -> None:
    # Widen first: a stored three-character prefix fits either width, so the order is
    # only about never holding a hash in a column that cannot take one.
    op.alter_column(
        "mdm_connections", "credentials_fingerprint", type_=sa.String(12), existing_type=sa.String(3), existing_nullable=True
    )
    _for_each_tenant(CLEAR)


def downgrade() -> None:
    # A twelve-character hash cannot narrow to three, and the prefix it replaced cannot be
    # recovered, so the column goes back empty; the pre-#316 write sites re-stamp it on
    # the next credential save exactly as this migration's upgrade relies on.
    _for_each_tenant(CLEAR)
    op.alter_column(
        "mdm_connections", "credentials_fingerprint", type_=sa.String(3), existing_type=sa.String(12), existing_nullable=True
    )
