"""Record the last reconciled checkpoint and its execution evidence."""

import sqlalchemy as sa
from alembic import op

revision = "0004_checkpoint_projection"
down_revision = "0003_agent_workflows"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("workflow_metadata", sa.Column("checkpoint_id", sa.String(36)))
    op.add_column("workflow_metadata", sa.Column("checkpoint_digest", sa.String(64)))
    op.add_column("workflow_metadata", sa.Column("verified_result", sa.Text()))
    op.add_column("workflow_metadata", sa.Column("recovery_code", sa.String(64)))


def downgrade() -> None:
    for column in (
        "recovery_code",
        "verified_result",
        "checkpoint_digest",
        "checkpoint_id",
    ):
        op.drop_column("workflow_metadata", column)
