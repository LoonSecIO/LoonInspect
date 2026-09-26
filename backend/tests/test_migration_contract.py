"""The expand/contract check (#655): .github/scripts/check_migration_contract.py."""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / ".github" / "scripts" / "check_migration_contract.py"
_spec = importlib.util.spec_from_file_location("check_migration_contract", SCRIPT)
contract = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(contract)

SCHEMA = """
class Widget(Base):
    __tablename__ = "widgets"
    id: Mapped[int] = mapped_column(primary_key=True)
    colour: Mapped[str] = mapped_column("color", String(16))
    parts: Mapped[list[Part]] = relationship()
"""
# Adds, drops only a table the release never had, renames only an index and a constraint, contracts only in downgrade().
EXPAND = """# release-note: plan a window
def upgrade():
    op.add_column("widgets", sa.Column("size", sa.Integer(), nullable=True))
    op.drop_table("gadgets")
    op.execute(f"ALTER INDEX ix_a RENAME TO ix_b; ALTER TABLE {TABLE} ADD CHECK (size > 0), RENAME CONSTRAINT ck_a TO ck_b")


def downgrade():
    op.drop_column("widgets", "color")
"""


def test_the_oracle_is_what_sqlalchemy_says_the_models_are():
    from app.models.schema import Tenant  # every model's table is on Tenant's metadata

    expected = {table.name: {column.name for column in table.columns} for table in Tenant.metadata.tables.values()}
    assert contract.oracle((SCRIPT.parents[2] / contract.SCHEMA).read_text()) == expected


@pytest.mark.parametrize(
    ("statement", "sentence"),
    [
        ('op.alter_column("widgets", "color", new_column_name="hue")', "renames column widgets.color, which v1.0.0 still reads"),
        ('op.rename_table(old_table_name="widgets", new_table_name="things")', "renames table widgets"),
        ("_helper()", "drops table widgets"),
        ('op.execute("ALTER TABLE widgets DROP color")', "runs SQL that says 'ALTER TABLE widgets DROP color'"),
        ('op.execute(f"ALTER TABLE {name} ADD size int, DROP color")', "says 'ALTER TABLE {} ADD size int, DROP color'"),
        ("op.execute(SQL)\nSQL = 'ALTER TABLE widgets RENAME color TO hue'", "says 'ALTER TABLE widgets RENAME color'"),
        ('for name in ("color",): op.drop_column("widgets", name)', "not a string literal"),
    ],
)
def test_each_contraction_is_refused_with_its_sentence(statement, sentence):
    source = f"def _helper():\n    op.drop_table('widgets')\n\n\ndef upgrade():\n    {statement}\n"
    [(_, refused)] = contract.refusals("c2.py", source, contract.oracle(SCHEMA), "v1.0.0")
    assert sentence in refused


@pytest.mark.skipif(shutil.which("git") is None, reason="builds a git repository")
def test_the_script_fails_a_contracting_migration_and_passes_an_expanding_one(tmp_path):
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    env |= {f"GIT_{who}_{what}": "t@t.invalid" for who in ("AUTHOR", "COMMITTER") for what in ("NAME", "EMAIL")}
    script = tmp_path / ".github" / "scripts" / SCRIPT.name

    def git(*args: str) -> None:
        subprocess.run(["git", *args], cwd=tmp_path, env=env, check=True)

    def commit_and_check(path: str, text: str) -> subprocess.CompletedProcess[str]:
        (tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / path).write_text(text)
        for args in (("add", "."), ("commit", "-qm", path)):
            git(*args)
        return subprocess.run([sys.executable, script], cwd=tmp_path, env=env, capture_output=True, text=True)

    git("init", "-q")
    commit_and_check(f".github/scripts/{SCRIPT.name}", SCRIPT.read_text())
    commit_and_check(contract.SCHEMA, SCHEMA)
    git("tag", "v1.0.0")
    passed = commit_and_check(f"{contract.VERSIONS}/b1_expand.py", EXPAND)
    assert passed.returncode == 0, passed.stdout + passed.stderr
    git("tag", "v1.1.0-rc.1")  # a prerelease: its notes, and the check below, still count from v1.0.0
    notes = subprocess.check_output([sys.executable, script, "--notes", "v1.1.0-rc.1"], cwd=tmp_path, env=env, text=True)
    assert "**Before you update:**\n- `b1`: plan a window\n\n1 migration(s) since v1.0.0 run" in notes, notes

    failed = commit_and_check(f"{contract.VERSIONS}/c2_contract.py", 'def upgrade():\n    op.drop_column("widgets", "color")\n')
    assert failed.returncode == 1
    assert "c2_contract.py,line=2::c2_contract.py drops column widgets.color, which v1.0.0 still reads" in failed.stdout
