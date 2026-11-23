"""Add workflow metadata, audit and execution receipts."""

import sqlalchemy as sa
from alembic import op

revision = "0003_agent_workflows"
down_revision = "0002_network_core"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("network_revisions", sa.Column("execution_key", sa.String(64)))
    op.create_index(
        "uq_network_execution_key", "network_revisions", ["execution_key"], unique=True
    )
    op.create_table(
        "workflow_metadata",
        sa.Column(
            "task_id", sa.String(36), sa.ForeignKey("tasks.id"), primary_key=True
        ),
        sa.Column("thread_id", sa.String(36), nullable=False, unique=True),
        sa.Column("owner", sa.String(64), nullable=False),
        sa.Column("idempotency_key", sa.String(64), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("correlation_id", sa.String(36), nullable=False),
        sa.Column("initial_request_id", sa.String(36), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("pending", sa.Text()),
        sa.UniqueConstraint("owner", "idempotency_key"),
    )
    op.create_table(
        "workflow_events",
        sa.Column("sequence", sa.Integer(), primary_key=True),
        sa.Column("id", sa.String(36), nullable=False, unique=True),
        sa.Column("task_id", sa.String(36), sa.ForeignKey("tasks.id"), nullable=False),
        sa.Column("step", sa.String(64), nullable=False),
        sa.Column("code", sa.String(64)),
        sa.Column("actor", sa.String(64), nullable=False),
        sa.Column("request_id", sa.String(36), nullable=False),
        sa.Column("at", sa.String(40), nullable=False),
    )
    op.create_index("ix_workflow_events_task_id", "workflow_events", ["task_id"])
    op.create_table(
        "workflow_approvals",
        sa.Column(
            "task_id", sa.String(36), sa.ForeignKey("tasks.id"), primary_key=True
        ),
        sa.Column(
            "audit_event_id",
            sa.String(36),
            sa.ForeignKey("workflow_events.id"),
            unique=True,
            nullable=False,
        ),
        sa.Column("payload", sa.Text(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("workflow_approvals")
    op.drop_index("ix_workflow_events_task_id", table_name="workflow_events")
    op.drop_table("workflow_events")
    op.drop_table("workflow_metadata")
    op.drop_index("uq_network_execution_key", table_name="network_revisions")
    op.drop_column("network_revisions", "execution_key")
