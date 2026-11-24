"""Preserve complete audit provenance for new reports."""

import sqlalchemy as sa
from alembic import op

revision = "0006_audit_fingerprints"
down_revision = "0005_dashboard_security"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("security_audit_runs", sa.Column("profile_hash", sa.String(64)))
    op.add_column("security_audit_runs", sa.Column("findings_hash", sa.String(64)))


def downgrade() -> None:
    op.drop_column("security_audit_runs", "findings_hash")
    op.drop_column("security_audit_runs", "profile_hash")
