"""Index completed integration exports created before scope-independent indexing."""

from uuid import UUID, uuid5

import sqlalchemy as sa
from alembic import op

revision = "0008_backfill_artifact_index"
down_revision = "0007_integration_workspace"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    tasks = conn.execute(
        sa.text(
            "SELECT t.id FROM tasks t JOIN workflow_metadata w ON t.id = w.task_id "
            "WHERE t.kind = 'greenfield' AND t.status = 'succeeded' "
            "AND w.workspace IS NOT NULL"
        )
    )
    # These are the six deterministic exports in the 0007 Greenfield format.
    for task_id in tasks.scalars():
        conn.execute(
            sa.text(
                "INSERT INTO integration_artifacts(id, task_id, name) "
                "VALUES (:id, :task, :name) ON CONFLICT(id) DO NOTHING"
            ),
            [
                {"id": str(uuid5(UUID(task_id), name)), "task": task_id, "name": name}
                for name in (
                    "bom.json",
                    "bom.csv",
                    "bom.md",
                    "topology.mmd",
                    "inventory.yaml",
                    "assumptions.md",
                )
            ],
        )


def downgrade() -> None:
    # The backfilled rows are valid 0007 data, including rows indexed before upgrade.
    pass
