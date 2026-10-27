"""Normalize legacy file_type values to canonical 'file'

Revision ID: 0002_normalize_file_types
Revises: 0001_phase1_schema
Create Date: 2026-10-27

Data normalization migration:
  - Converts legacy 'regular' and 'regular_file' values in `files.file_type`
    to canonical 'file'.
  - Preserves 'directory', 'symlink', and all other values (including NULLs).
  - Downgrade is an intentional no-op to prevent data corruption.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0002_normalize_file_types"
down_revision: Union[str, None] = "0001_phase1_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Normalize legacy 'regular' and 'regular_file' file_type values to 'file'.

    Only updates rows where file_type is 'regular' or 'regular_file'.
    Preserves 'directory', 'symlink', and all other values or NULLs.
    """
    files_table = sa.table(
        "files",
        sa.column("file_type", sa.String),
    )
    op.execute(
        files_table.update()
        .where(files_table.c.file_type.in_(["regular", "regular_file"]))
        .values(file_type="file")
    )


def downgrade() -> None:
    """Downgrade behavior: No-op.

    This data migration normalizes legacy `regular` and `regular_file` values
    to canonical `file`. Reversing this transformation is intentionally not
    performed because:
      1. Irreversible mapping (many-to-one):
         Both 'regular' and 'regular_file' collapse to 'file'. A downgrade cannot
         distinguish whether a 'file' record was originally 'regular',
         'regular_file', or newly created as canonical 'file' without an
         external mapping table.
      2. Data corruption risk:
         Indiscriminately converting all canonical 'file' records back to a
         single legacy value (e.g. 'regular') would corrupt data by mutating
         records legitimately created with canonical 'file' by newer collectors,
         APIs, or seed routines.
      3. Backward compatibility:
         The canonical value 'file' is fully supported by all application models,
         schemas, and views. Retaining canonical 'file' on downgrade preserves
         data integrity without breaking application behavior.

    Therefore, downgrade is an intentional no-op to protect data integrity.
    """
    pass
