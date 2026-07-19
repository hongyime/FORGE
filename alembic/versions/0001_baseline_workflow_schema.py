"""Baseline workflow schema (matches what init_schema() historically created).

Revision ID: 0001_baseline
Revises:
Create Date: 2026-05-27

This migration is the canonical baseline for forge state. It captures EXACTLY
the tables that ``StateStore.init_schema()`` created before alembic was
introduced, so existing deployments can be safely stamped at this revision
via ``forge.workflow.migrate_bootstrap`` and then upgraded forward.

Tables created here:
  * ``workflows``                - workflow checkpoint rows (optimistic-locked)
  * ``agent_loop_heartbeat``     - single-row liveness probe

The ``workflow_history`` table ships in ``0002_add_workflow_history``.
"""
from __future__ import annotations

from typing import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "0001_baseline"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "workflow_state",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("definition_name", sa.String(255), nullable=False),
        sa.Column("definition_version", sa.String(64), nullable=False),
        sa.Column("current_stage_index", sa.Integer, nullable=False),
        sa.Column("stage_statuses", sa.Text, nullable=False),
        sa.Column("intermediate_results", sa.Text, nullable=False),
        sa.Column("started_at", sa.Float, nullable=False),
        sa.Column("updated_at", sa.Float, nullable=False),
        sa.Column("is_complete", sa.Boolean, nullable=False),
        sa.Column("failure_reason", sa.Text, nullable=True),
        sa.Column("checkpoint_valid", sa.Boolean, nullable=False),
        sa.Column("version", sa.Integer, nullable=False),
        sa.Column("resumed_at", sa.Float, nullable=True),
    )
    op.create_table(
        "agent_loop_heartbeat",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("timestamp", sa.Float, nullable=False),
    )


def downgrade() -> None:
    op.drop_table("agent_loop_heartbeat")
    op.drop_table("workflow_state")
