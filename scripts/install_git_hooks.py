#!/usr/bin/env python3
"""Enable the versioned iDO Git hooks for this checkout."""

from __future__ import annotations

import stat
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / ".githooks"


def main() -> int:
    if not (ROOT / ".git").exists():
        print("Run this setup from a normal iDO Git checkout.", file=sys.stderr)
        return 1
    for hook in ("pre-commit", "pre-push"):
        hook_path = HOOKS / hook
        if not hook_path.is_file():
            print(f"Missing hook: {HOOKS / hook}", file=sys.stderr)
            return 1
        hook_path.chmod(hook_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    result = subprocess.run(
        ["git", "config", "--local", "core.hooksPath", ".githooks"],
        cwd=ROOT,
    )
    if result.returncode:
        return result.returncode
    print("iDO Git hooks enabled for this checkout:")
    print("  pre-commit: staged Python/JavaScript syntax, conflict markers, secrets, and local-data files")
    print("  pre-push: the same checks on commits being sent to the remote")
    print("Hooks require Python 3.11+. Node.js enables inline JavaScript syntax checks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
