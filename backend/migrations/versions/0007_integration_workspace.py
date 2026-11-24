"""Persist integration workspace and artifact ownership."""

import sqlalchemy as sa
from alembic import op

revision = "0007_integration_workspace"
down_revision = "0006_audit_fingerprints"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("workflow_metadata", sa.Column("workspace", sa.String(64)))
    op.create_table(
        "integration_artifacts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "task_id",
            sa.String(36),
            sa.ForeignKey("workflow_metadata.task_id"),
            nullable=False,
        ),
        sa.Column("name", sa.String(32), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("integration_artifacts")
    op.drop_column("workflow_metadata", "workspace")
