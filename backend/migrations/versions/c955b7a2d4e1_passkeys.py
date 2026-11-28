"""Passkeys (#955): a passkey's columns on auth_identities, and the challenge table that makes an answer single-use.

`auth_identities` gains what a `webauthn` row needs, all nullable, so every `local` and `totp` row reads as
before and `uq_auth_identity_provider_subject` keeps its columns: a passkey's `subject` is the SHA-256 of
its credential id, and the id itself goes in `credential_id`, whole, because WebAuthn allows 1,023 bytes
and `subject` holds 255 characters (trap 3). The check constraint refuses a longer one at the database
too; the route refuses it first, with a sentence. Then the COSE public key, the signature counter, the
transports, the two backup flags, the host the passkey was made at and the name its owner gave it.

`passkey_challenges` holds each challenge handed out until its one answer deletes it (trap 4): a synced
passkey's counter stays zero, so nothing else stops a replay. Tenant-scoped and under row-level security
like every table that is not one of the three credential indexes; a sign-in's challenge lands in the
tenant an unauthenticated request is bound to, as the lockout counter does.

Additive only: an earlier release neither reads nor writes any of it. Downgrade drops the table and the
columns, and with them every passkey; each account still signs in with its password.

Revision ID: c955b7a2d4e1
Revises: c614b3d2e8f4
Create Date: 2026-11-28
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "c955b7a2d4e1"
down_revision = "c614b3d2e8f4"
branch_labels = None
depends_on = None

_PREDICATE = "tenant_id = current_setting('looninspect.tenant_id')::uuid"


def _columns() -> list[sa.Column]:
    """New objects on every call: a Column belongs to the first table it is added to, and the round trip
    upgrades twice in one process."""
    return [
        sa.Column("credential_id", sa.LargeBinary(), nullable=True),
        sa.Column("public_key", sa.LargeBinary(), nullable=True),
        sa.Column("sign_count", sa.BigInteger(), nullable=True),
        sa.Column("transports", postgresql.JSONB(), nullable=True),
        sa.Column("backup_eligible", sa.Boolean(), nullable=True),
        sa.Column("backed_up", sa.Boolean(), nullable=True),
        sa.Column("rp_id", sa.String(length=253), nullable=True),
        sa.Column("name", sa.String(length=64), nullable=True),
    ]


def upgrade() -> None:
    for column in _columns():
        op.add_column("auth_identities", column)
    op.create_check_constraint(
        "ck_auth_identities_credential_id_length",
        "auth_identities",
        "credential_id IS NULL OR octet_length(credential_id) <= 1023",
    )

    op.create_table(
        "passkey_challenges",
        sa.Column("challenge_hash", sa.String(length=64), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.Uuid(),
            sa.ForeignKey("tenants.id", ondelete="RESTRICT"),
            nullable=False,
            server_default=sa.text("current_setting('looninspect.tenant_id')::uuid"),
        ),
        sa.Column("purpose", sa.String(length=16), nullable=False),
        sa.Column("account_id", sa.String(length=36), nullable=True),
        sa.Column("session_id", sa.String(length=36), nullable=True),
        sa.Column("rp_id", sa.String(length=253), nullable=False),
        sa.Column("origin", sa.String(length=512), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_passkey_challenges_tenant_id", "passkey_challenges", ["tenant_id"])
    op.create_index("ix_passkey_challenges_expires_at", "passkey_challenges", ["expires_at"])
    op.execute("ALTER TABLE passkey_challenges ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE passkey_challenges FORCE ROW LEVEL SECURITY")
    op.execute(f"CREATE POLICY tenant_isolation ON passkey_challenges USING ({_PREDICATE}) WITH CHECK ({_PREDICATE})")


def downgrade() -> None:
    op.drop_table("passkey_challenges")
    op.drop_constraint("ck_auth_identities_credential_id_length", "auth_identities", type_="check")
    for column in reversed(_columns()):
        op.drop_column("auth_identities", column.name)
