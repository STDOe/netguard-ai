"""Persist revisioned demo networks and correlate mutation audit events."""

import sqlalchemy as sa
from alembic import op

revision = "0002_network_core"
down_revision = "0001_foundation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "networks",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("current_revision", sa.Integer(), nullable=False),
    )
    op.create_table(
        "network_revisions",
        sa.Column(
            "network_id", sa.String(36), sa.ForeignKey("networks.id"), primary_key=True
        ),
        sa.Column("revision", sa.Integer(), primary_key=True),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("operation", sa.String(16), nullable=False),
        sa.Column("policy_version", sa.String(80), nullable=False),
        sa.Column("restored_from", sa.Integer()),
    )
    for name, field_type in (
        ("event_type", sa.String(48)),
        ("network_id", sa.String(36)),
        ("revision", sa.Integer()),
        ("policy_version", sa.String(80)),
    ):
        op.add_column("audit_events", sa.Column(name, field_type))


def downgrade() -> None:
    for name in ("policy_version", "revision", "network_id", "event_type"):
        op.drop_column("audit_events", name)
    op.drop_table("network_revisions")
    op.drop_table("networks")
