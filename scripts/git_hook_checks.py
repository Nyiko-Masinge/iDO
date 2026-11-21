#!/usr/bin/env python3
"""Fast, dependency-free checks for staged files and outgoing commits."""

from __future__ import annotations

import argparse
import ast
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONFLICT_MARKER = re.compile(r"^(<<<<<<<|=======|>>>>>>>)", re.MULTILINE)
PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
AWS_ACCESS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
GITHUB_TOKEN = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")
SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token)"
    r"\b\s*[:=]\s*(['\"])([^'\"\r\n]{8,})\1"
)
PLACEHOLDERS = {
    "change-me",
    "change-this-before-first-run",
    "change_this",
    "changeme",
    "example",
    "placeholder",
    "your-secret-here",
    "your_api_key",
    "your_password",
    "secret",
}
class HookError(RuntimeError):
    pass


def git(*args: str, input_text: str | None = None, check: bool = True) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        input=input_text,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise HookError(detail or f"git {' '.join(args)} failed")
    return result.stdout


def staged_paths() -> list[str]:
    raw = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        check=True,
    ).stdout
    return [part.decode("utf-8", "surrogateescape") for part in raw.split(b"\0") if part]


def blob_at(revision: str, path: str) -> bytes | None:
    spec = f":{path}" if revision == ":" else f"{revision}:{path}"
    result = subprocess.run(
        ["git", "show", spec],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    return result.stdout if result.returncode == 0 else None


def is_sensitive_path(path: str) -> str | None:
    normalized = path.replace("\\", "/").lower()
    name = normalized.rsplit("/", 1)[-1]
    if normalized.startswith("data/") or "/data/" in normalized:
        return "local data directory"
    if name.endswith((".db", ".sqlite", ".sqlite3")):
        return "local database file"
    if name == ".env" or (name.startswith(".env.") and name not in {".env.example", ".env.template"}):
        return "environment file"
    if name in {"id_rsa", "id_ed25519", "credentials.json", "secrets.json"}:
        return "credential file"
    return None


def secret_findings(text: str) -> list[str]:
    findings: list[str] = []
    if PRIVATE_KEY.search(text):
        findings.append("private key material")
    if AWS_ACCESS_KEY.search(text):
        findings.append("AWS access key pattern")
    if GITHUB_TOKEN.search(text):
        findings.append("GitHub token pattern")
    for match in SECRET_ASSIGNMENT.finditer(text):
        value = match.group(2).strip()
        if value.lower() not in PLACEHOLDERS and not value.startswith(("${", "os.getenv", "os.environ")):
            findings.append("hard-coded credential assignment")
            break
    return findings


def check_python(path: str, text: str, errors: list[str]) -> None:
    try:
        ast.parse(text, filename=path)
    except SyntaxError as exc:
        errors.append(f"{path}:{exc.lineno}: Python syntax error: {exc.msg}")


def check_javascript(path: str, text: str, errors: list[str]) -> None:
    if not shutil.which("node"):
        print("iDO hook: Node.js is not installed; inline JavaScript syntax check skipped.")
        return

    blocks = re.findall(r"<script(?:\s[^>]*)?>([\s\S]*?)</script\s*>", text, re.IGNORECASE)
    if path.lower().endswith(".js"):
        blocks = [text]
    if not blocks:
        return
    for index, block in enumerate(blocks, start=1):
        with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8", delete=False) as temp:
            temp.write(block)
            temp_path = Path(temp.name)
        try:
            result = subprocess.run(
                ["node", "--check", str(temp_path)],
                cwd=ROOT,
                text=True,
                encoding="utf-8",
                errors="replace",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if result.returncode:
                detail = result.stderr.strip().splitlines()
                errors.append(f"{path}: JavaScript block {index} syntax error: {detail[-1] if detail else 'invalid syntax'}")
        finally:
            temp_path.unlink(missing_ok=True)


def check_content(path: str, content: bytes | None, errors: list[str]) -> None:
    if content is None:
        return
    sensitive = is_sensitive_path(path)
    if sensitive:
        errors.append(f"{path}: blocked {sensitive}; keep it out of Git")
        return

    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return

    if CONFLICT_MARKER.search(text):
        errors.append(f"{path}: unresolved merge-conflict marker found")
    for finding in secret_findings(text):
        errors.append(f"{path}: possible {finding}; remove it or use an environment variable")

    suffix = Path(path).suffix.lower()
    if suffix == ".py":
        check_python(path, text, errors)
    elif suffix in {".html", ".js"}:
        check_javascript(path, text, errors)


def check_paths(revision: str, paths: list[str], errors: list[str]) -> None:
    for path in paths:
        check_content(path, blob_at(revision, path), errors)


def check_staged(errors: list[str]) -> None:
    paths = staged_paths()
    if not paths:
        print("iDO hook: no staged files to check.")
        return
    check_paths(":", paths, errors)


def check_pushes(errors: list[str]) -> None:
    lines = sys.stdin.read().splitlines()
    checked: set[tuple[str, str]] = set()
    for line in lines:
        fields = line.split()
        if len(fields) != 4:
            continue
        _local_ref, local_sha, _remote_ref, remote_sha = fields
        if local_sha and set(local_sha) == {"0"}:
            continue
        rev_args = ["rev-list", local_sha]
        if remote_sha and set(remote_sha) != {"0"}:
            rev_args.append(f"^{remote_sha}")
        commits = git(*rev_args).splitlines()
        for commit in commits:
            paths = git(
                "diff-tree", "--root", "-r", "--first-parent", "--no-commit-id",
                "--name-only", "--diff-filter=ACMR", "-z", commit,
            )
            for raw_path in paths.split("\0"):
                if not raw_path:
                    continue
                key = (commit, raw_path)
                if key in checked:
                    continue
                checked.add(key)
                check_content(raw_path, blob_at(commit, raw_path), errors)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--staged", action="store_true", help="check staged file contents")
    mode.add_argument("--push", action="store_true", help="check outgoing commits from pre-push input")
    args = parser.parse_args()

    errors: list[str] = []
    try:
        if args.staged:
            check_staged(errors)
        else:
            check_pushes(errors)
    except (HookError, OSError, subprocess.SubprocessError) as exc:
        print(f"iDO hook could not complete: {exc}", file=sys.stderr)
        return 2

    if errors:
        print("iDO hook checks failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        print("Fix the listed files, stage the corrections, and retry.", file=sys.stderr)
        print("Emergency bypass (not recommended): git -c core.hooksPath=/dev/null commit", file=sys.stderr)
        return 1

    print("iDO hook checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
