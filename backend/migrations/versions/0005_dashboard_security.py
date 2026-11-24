"""Persist audit reports, normalized honeypot events and web sessions."""

import sqlalchemy as sa
from alembic import op

revision = "0005_dashboard_security"
down_revision = "0004_checkpoint_projection"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "security_audit_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "network_id", sa.String(36), sa.ForeignKey("networks.id"), nullable=False
        ),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("snapshot_hash", sa.String(64)),
        sa.Column("policy_version", sa.String(80)),
        sa.Column("policy_hash", sa.String(64)),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("score", sa.Text(), nullable=False),
    )
    op.create_index(
        "ix_security_audit_runs_network_id", "security_audit_runs", ["network_id"]
    )
    op.create_table(
        "security_audit_findings",
        sa.Column(
            "run_id",
            sa.String(36),
            sa.ForeignKey("security_audit_runs.id"),
            primary_key=True,
        ),
        sa.Column("position", sa.Integer(), primary_key=True),
        sa.Column("payload", sa.Text(), nullable=False),
    )
    op.create_table(
        "honeypot_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("received", sa.Integer(), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
    )
    op.create_index("ix_honeypot_events_received", "honeypot_events", ["received"])
    op.create_table(
        "web_sessions",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("expires", sa.Integer(), nullable=False),
        sa.Column("binding", sa.String(64), nullable=False),
    )
    op.create_index("ix_web_sessions_expires", "web_sessions", ["expires"])


def downgrade() -> None:
    op.drop_table("web_sessions")
    op.drop_table("honeypot_events")
    op.drop_table("security_audit_findings")
    op.drop_table("security_audit_runs")
