"""Create Foundation storage."""

import sqlalchemy as sa
from alembic import op

revision = "0001_foundation"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tasks",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("kind", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
    )
    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("occurred_at_us", sa.BigInteger(), nullable=False),
        sa.Column("actor", sa.String(64)),
        sa.Column("request_id", sa.String(36), nullable=False),
        sa.Column("outcome", sa.Integer(), nullable=False),
    )
    op.create_index(
        "ix_audit_events_occurred_at_us", "audit_events", ["occurred_at_us"]
    )


def downgrade() -> None:
    op.drop_index("ix_audit_events_occurred_at_us", table_name="audit_events")
    op.drop_table("audit_events")
    op.drop_table("tasks")
