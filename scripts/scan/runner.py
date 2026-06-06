#!/usr/bin/env python3
"""Synup modular code scanner — entry point.

Runs a set of independently-toggleable checks (secrets, sensitive_files,
malware, dangerous_code) over a file or directory and exits non-zero when any
high/critical finding is present.

Usage:
  scan/runner.py [path] [--min-severity warn|high|critical] [--json]
                 [--report FILE] [--config FILE] [--disable a,b] [--list-checks]

Config: a `.synup-scan.json` in the working dir (repo root) is auto-loaded.
Inline: add a `synup-ignore` comment to a line to suppress its findings.
"""
from __future__ import annotations

import argparse
import fnmatch
import json as _json
import os
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # put scripts/ on path

from scan.base import (Finding, INLINE_IGNORE, SEVERITY_ORDER, iter_files,  # noqa: E402
                       relpath, sev_ge)
from scan.config import Config  # noqa: E402
from scan.checks import ALL, REGISTRY  # noqa: E402

RED = "\033[0;31m"; YEL = "\033[1;33m"; GRN = "\033[0;32m"; CYA = "\033[0;36m"; BLD = "\033[1m"; RST = "\033[0m"


def _allowed(rel: str, globs) -> bool:
    return any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(rel, g.rstrip("/") + "/*") for g in globs)


def scan(root: Path, cfg: Config, disabled_checks: set[str]) -> list[Finding]:
    enabled = [m for m in ALL if m.NAME not in disabled_checks]
    findings: list[Finding] = []
    for path in iter_files(root):
        rel = relpath(path, root)
        if _allowed(rel, cfg.allow):
            continue
        try:
            text = path.read_bytes().decode("utf-8", errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        for mod in enabled:
            try:
                results = mod.check(path, rel, text, lines, cfg.disabled_rules(mod.NAME))
            except Exception as e:  # a buggy rule must never break the whole scan
                results = [Finding("info", mod.NAME, f"check error: {e}", rel, 0)]
            for f in results:
                if f.line and 0 < f.line <= len(lines) and INLINE_IGNORE.search(lines[f.line - 1]):
                    continue  # inline-suppressed
                findings.append(f)
    return findings


def report_text(findings, files_note, out=sys.stdout):
    by_sev = defaultdict(list)
    for f in findings:
        by_sev[f.severity].append(f)
    totals = {s: len(by_sev.get(s, [])) for s in SEVERITY_ORDER}
    print(f"\n{BLD}=== Synup Code Scan ==={RST}", file=out)
    print(f"{files_note}", file=out)
    print(f"Findings : {len(findings)}  "
          f"({RED}critical:{totals['critical']} high:{totals['high']}{RST} "
          f"{YEL}warn:{totals['warn']}{RST} info:{totals['info']})", file=out)
    for sev in ("critical", "high", "warn", "info"):
        items = by_sev.get(sev, [])
        if not items:
            continue
        color = {"critical": RED, "high": RED, "warn": YEL, "info": CYA}[sev]
        print(f"\n{color}{BLD}[{sev.upper()}]{RST}", file=out)
        for f in items:
            loc = f"{f.file}:{f.line}" if f.line else f.file
            print(f"  {loc}  [{f.check}/{f.detail or f.rule}]  {f.rule}", file=out)
            if f.snippet:
                print(f"    {f.snippet}", file=out)
    if not findings:
        print(f"\n{GRN}No findings. Scan clean.{RST}", file=out)


def report_json(findings, file_count, out=sys.stdout):
    _json.dump({
        "files_scanned": file_count,
        "total_findings": len(findings),
        "findings": [vars(f) for f in findings],
    }, out, indent=2)
    out.write("\n")


def main() -> int:
    ap = argparse.ArgumentParser(description="Synup modular code scanner")
    ap.add_argument("path", nargs="?", default=".")
    ap.add_argument("--min-severity", choices=list(SEVERITY_ORDER), default=None,
                    help="minimum severity to report (default: warn, or config)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--report", metavar="FILE")
    ap.add_argument("--config", metavar="FILE", help="path to .synup-scan.json (default: ./.synup-scan.json)")
    ap.add_argument("--disable", default="", help="comma-separated checks to skip")
    ap.add_argument("--list-checks", action="store_true")
    args = ap.parse_args()

    if args.list_checks:
        for m in ALL:
            print(m.NAME)
        return 0

    root = Path(args.path).resolve()
    if not root.exists():
        print(f"Error: path not found: {root}", file=sys.stderr)
        return 2

    cfg_path = Path(args.config) if args.config else Config.discover(Path.cwd())
    cfg = Config.load(cfg_path)

    disabled_checks = set(cfg.disable)
    disabled_checks |= {c.strip() for c in args.disable.split(",") if c.strip()}
    unknown = disabled_checks - set(REGISTRY)
    if unknown:
        print(f"{YEL}warning: unknown checks in disable list: {', '.join(sorted(unknown))}{RST}", file=sys.stderr)

    min_sev = args.min_severity or cfg.min_severity or "warn"

    findings = [f for f in scan(root, cfg, disabled_checks) if sev_ge(f.severity, min_sev)]

    files_note = (f"Path     : {root}\n"
                  f"Checks   : {', '.join(m.NAME for m in ALL if m.NAME not in disabled_checks) or '(none)'}")

    if args.json:
        if args.report:
            with open(args.report, "w") as fh:
                report_json(findings, -1, fh)
        report_json(findings, -1)
    else:
        if args.report:
            with open(args.report, "w") as fh:
                report_text(findings, files_note, fh)
        report_text(findings, files_note)

    return 1 if any(sev_ge(f.severity, "high") for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
