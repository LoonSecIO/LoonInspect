"""An image older than its database (#672): the stamp the newer release left decides whether it starts.

A synthetic migration one past this image's head plays the newer release. Alembic runs it beside the
real scripts, and each test's teardown runs its downgrade, so the database is back at head afterwards.
The sentences are the ones docs/troubleshooting.md section 4 and docs/operations.md section 5 quote.
"""

from __future__ import annotations

import asyncio
import logging
import os

import pytest
import pytest_asyncio
from alembic import command
from alembic.script import ScriptDirectory
from alembic.util import CommandError
from sqlalchemy import text

from app.core import database
from app.core.version import RELEASE, get_app_version

needs_db = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

AHEAD = "ffff06720001"
DOCS = database._BACKEND_DIR.parent / "docs"
NEWER = """import sqlalchemy as sa
from alembic import op

revision = "{ahead}"
down_revision = "{head}"


def upgrade():
    op.create_table("newer_release_0672", sa.Column("id", sa.Integer(), primary_key=True))
    {record}


def downgrade():
    {restore}
    op.drop_table("newer_release_0672")
"""


def _stamp(release: str) -> str:
    return f"op.execute(\"UPDATE schema_release SET min_readable_release = '{release}'\")"


def _quoted_in(phrase: str, *documents: str) -> bool:
    """docs/diagnosability.md rule 4: the words ship with their step-through, so rewording one fails here."""
    return all(phrase in " ".join((DOCS / name).read_text().split()) for name in documents)


def test_this_images_release_is_one_a_stamp_compares_with():
    assert database.release_key(RELEASE) is not None
    assert database.release_key("v2.10.0") > database.release_key("v2.9.1") > database.release_key("v2.9.0")
    assert database.release_key("2.0.0") is database.release_key("v2.0.0-rc.1") is None


@pytest_asyncio.fixture(loop_scope="session")
async def newer(tenant_ready, tmp_path, monkeypatch):
    """(upgrade, stamp): moves the database one synthetic migration past head, recording what it is given;
    `stamp` is what head recorded. This image is v2.0.0 for the test."""
    monkeypatch.setattr(database, "RELEASE", "v2.0.0")
    async with database.engine.connect() as connection:
        head = await connection.scalar(text("SELECT version_num FROM alembic_version"))
        stamp = await connection.scalar(text("SELECT min_readable_release FROM schema_release"))
    config = database._alembic_config()
    versions = database._BACKEND_DIR / "migrations" / "versions"
    config.set_main_option("version_locations", os.pathsep.join([str(versions), str(tmp_path)]))

    async def upgrade(record: str, restore: str) -> None:
        (tmp_path / f"{AHEAD}_newer.py").write_text(NEWER.format(ahead=AHEAD, head=head, record=record, restore=restore))
        await asyncio.to_thread(command.upgrade, config, "head")

    yield upgrade, stamp
    if (tmp_path / f"{AHEAD}_newer.py").exists():
        await asyncio.to_thread(command.downgrade, config, head)


@needs_db[0]
@needs_db[1]
async def test_the_database_holds_the_stamp_the_newest_migration_declares(tenant_ready):
    """What the contract check reads, a migration's MIN_READABLE_RELEASE, is what its upgrade() wrote."""
    scripts = ScriptDirectory.from_config(database._alembic_config()).walk_revisions()  # newest first
    declared = next(script.module.MIN_READABLE_RELEASE for script in scripts if hasattr(script.module, "MIN_READABLE_RELEASE"))
    async with database.engine.connect() as connection:
        assert await connection.scalar(text("SELECT min_readable_release FROM schema_release")) == declared


@needs_db[0]
@needs_db[1]
@pytest.mark.parametrize("recorded", ["v2.0.0", "v1.0.0"])
async def test_an_image_at_or_above_the_stamp_starts_without_migrating(newer, recorded, caplog):
    upgrade, stamp = newer
    await upgrade(_stamp(recorded), _stamp(stamp))
    with caplog.at_level(logging.WARNING, logger=database.__name__):
        assert await database.init_db() is False
    line = caplog.text.replace(f"(build {get_app_version()})", "(build …)")
    phrase = f"which recorded that {recorded} or later can read it; this image is v2.0.0 (build …), so it starts without"
    assert f"(its schema is at revision {AHEAD}, which this image does not carry), {phrase}" in line
    assert _quoted_in(phrase.replace(recorded, "v2.0.0"), "operations.md")
    async with database.engine.connect() as connection:
        assert await connection.scalar(text("SELECT version_num FROM alembic_version")) == AHEAD


@needs_db[0]
@needs_db[1]
async def test_an_image_below_the_stamp_refuses_with_a_sentence_naming_both(newer, caplog):
    upgrade, stamp = newer
    await upgrade(_stamp("v2.1.0"), _stamp(stamp))
    with pytest.raises(RuntimeError) as refused, caplog.at_level(logging.ERROR, logger=database.__name__):
        await database.init_db()
    sentence = str(refused.value)
    phrase = "which recorded that only v2.1.0 or later can read it; this image is v2.0.0 (build …), so it will not start on it"
    assert phrase in sentence.replace(f"(build {get_app_version()})", "(build …)")
    assert _quoted_in(phrase, "troubleshooting.md", "operations.md")
    assert "Start an image of v2.1.0 or later" in sentence and "restore the backup taken before that upgrade" in sentence
    # Logged as a line of its own, and raised without Alembic's traceback chained to it.
    assert sentence in caplog.text and refused.value.__suppress_context__


@needs_db[0]
@needs_db[1]
async def test_a_database_with_no_stamp_keeps_alembics_refusal(newer):
    """A v1.x database has no schema_release table; nothing says what can read it, so nothing starts on it."""
    upgrade, _ = newer
    await upgrade(
        'op.rename_table("schema_release", "schema_release_0672")', 'op.rename_table("schema_release_0672", "schema_release")'
    )
    with pytest.raises(CommandError, match=f"Can't locate revision identified by '{AHEAD}'"):
        await database.init_db()
