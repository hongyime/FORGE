"""Add workflow_history table for forensic traceability.

Revision ID: 0002_add_workflow_history
Revises: 0001_baseline
Create Date: 2026-05-27

Append-only audit trail. Every successful ``StateStore.save_checkpoint``
appends one row capturing the before/after stage and version, plus a UTC
timestamp. Forensic replay reads rows in ``recorded_at`` order.

Index ``ix_workflow_history_workflow_id`` makes per-workflow history lookups
O(log N) for big audit trails.
"""
from __future__ import annotations

from typing import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "0002_add_workflow_history"
down_revision: str | None = "0001_baseline"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "workflow_history",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("workflow_id", sa.String(64), nullable=False),
        sa.Column("event_type", sa.String(32), nullable=False),
        sa.Column("from_stage_index", sa.Integer, nullable=True),
        sa.Column("to_stage_index", sa.Integer, nullable=True),
        sa.Column("from_version", sa.Integer, nullable=True),
        sa.Column("to_version", sa.Integer, nullable=False),
        sa.Column("actor", sa.String(128), nullable=True),
        sa.Column("detail", sa.Text, nullable=True),
        sa.Column("recorded_at", sa.Float, nullable=False),
    )
    op.create_index(
        "ix_workflow_history_workflow_id",
        "workflow_history",
        ["workflow_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_workflow_history_workflow_id", table_name="workflow_history")
    op.drop_table("workflow_history")
