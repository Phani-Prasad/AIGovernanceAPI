"""
Add eval columns to audit_logs — one-time migration script.

Run this ONCE if you have an existing ai_governance.db that was
created before the model evaluation feature was added.

Usage:
    python migrate_eval_columns.py

Safe to run multiple times — checks if columns already exist before adding.
"""
import asyncio
import sys

from sqlalchemy import text
from core.database import engine


EVAL_COLUMNS = [
    ("hallucination_score", "FLOAT"),
    ("hallucination_flagged", "BOOLEAN DEFAULT 0"),
    ("bias_score",           "FLOAT"),
    ("bias_flagged",         "BOOLEAN DEFAULT 0"),
    ("eval_mode",            "VARCHAR(50)"),
]


async def migrate():
    print("AI Governance — Eval Columns Migration")
    print("=" * 45)

    async with engine.begin() as conn:
        # Get existing columns in audit_logs
        if "sqlite" in str(engine.url):
            result = await conn.execute(text("PRAGMA table_info(audit_logs)"))
            existing = {row[1] for row in result.fetchall()}
        else:
            # PostgreSQL
            result = await conn.execute(text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = 'audit_logs'"
            ))
            existing = {row[0] for row in result.fetchall()}

        added = 0
        for col_name, col_type in EVAL_COLUMNS:
            if col_name in existing:
                print(f"  SKIP  {col_name} (already exists)")
            else:
                await conn.execute(text(
                    f"ALTER TABLE audit_logs ADD COLUMN {col_name} {col_type}"
                ))
                print(f"  ADD   {col_name} {col_type}")
                added += 1

    print()
    print(f"Done — {added} column(s) added, {len(EVAL_COLUMNS) - added} skipped.")


if __name__ == "__main__":
    asyncio.run(migrate())
