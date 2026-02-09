#!/usr/bin/env python3
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

ALLOWLIST_TABLES = {
    "dbmate_schema_migrations",
    "schema_migrations",
}

CREATE_TABLE_RE = re.compile(r"create\s+table\s+(if\s+not\s+exists\s+)?([a-zA-Z0-9_\."]+)", re.IGNORECASE)


def run(cmd):
    return subprocess.check_output(cmd, cwd=ROOT, text=True).strip()


def main():
    base = os.environ.get("MIGRATION_GUARD_BASE")
    if not base:
        try:
            base = run(["git", "merge-base", "origin/main", "HEAD"])
        except Exception:
            base = "HEAD~1"

    diff = run(["git", "diff", "--name-status", f"{base}...HEAD"])
    if not diff:
        print("migration-guard: no changes")
        return 0

    added = []
    for line in diff.splitlines():
        status, path = line.split("\t", 1)
        if status != "A":
            continue
        if not path.startswith("migrations/"):
            continue
        if path.endswith(".down.sql"):
            continue
        if not path.endswith(".sql"):
            continue
        added.append(path)

    if not added:
        print("migration-guard: no new migrations")
        return 0

    errors = []
    for rel in added:
        path = ROOT / rel
        down_path = path.with_suffix("").with_suffix(".down.sql")
        if not down_path.exists():
            errors.append(f"missing down migration for {rel}: expected {down_path.relative_to(ROOT)}")

        sql = path.read_text(encoding="utf-8", errors="ignore")
        lowered = sql.lower()

        tables = []
        for match in CREATE_TABLE_RE.finditer(sql):
            raw = match.group(2).strip()
            raw = raw.strip('"')
            if "." in raw:
                raw = raw.split(".")[-1]
            tables.append(raw)

        for table in tables:
            if table in ALLOWLIST_TABLES:
                continue
            if f"alter table {table} enable row level security" in lowered:
                continue
            if f"alter table {table} force row level security" in lowered:
                continue
            errors.append(f"{rel}: table '{table}' created without RLS enable/force")

    if errors:
        print("migration-guard failed:\n" + "\n".join(errors))
        return 1

    print("migration-guard: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
