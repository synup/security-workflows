#!/usr/bin/env python3
"""Synup modular code scanner — entry point.

Runs a set of independently-toggleable checks (secrets, sensitive_files,
malware, dangerous_code) over a file or directory and exits non-zero when any
high/critical finding is present.

Usage:
  scan/runner.py [path] [--min-severity warn|high|critical] [--json]
                 [--report FILE] [--config FILE] [--disable a,b] [--list-checks]
                 [--files-from FILE|-]

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


# Parallel scanning: files are scanned in a process pool (the checks are
# CPU-bound regex work, so threads wouldn't help under the GIL). Small scans
# (pre-commit, incremental post-* hooks) stay serial — spawning workers costs
# more than it saves for a handful of files.
PARALLEL_MIN_FILES = 64

_W_ENABLED: list = []          # per-process state, set by _init_worker / serial path
_W_RULES: dict = {}


def _init_worker(enabled_names, disabled_rules):
    global _W_ENABLED, _W_RULES
    _W_ENABLED = [m for m in ALL if m.NAME in enabled_names]
    _W_RULES = disabled_rules


def _scan_one(path: Path, rel: str) -> list[Finding] | None:
    """Scan one file with the enabled checks. None = unreadable (not counted)."""
    try:
        text = path.read_bytes().decode("utf-8", errors="replace")
    except OSError:
        return None
    lines = text.splitlines()
    # One pass over the file: almost no file has a `synup-ignore`, so skip the
    # per-finding line lookup (very slow on huge one-line JSON/minified files).
    has_ignore = INLINE_IGNORE.search(text) is not None
    out: list[Finding] = []
    for mod in _W_ENABLED:
        try:
            results = mod.check(path, rel, text, lines, _W_RULES.get(mod.NAME, set()))
        except Exception as e:  # a buggy rule must never break the whole scan
            results = [Finding("info", mod.NAME, f"check error: {e}", rel, 0)]
        for f in results:
            if has_ignore and f.line and 0 < f.line <= len(lines) and INLINE_IGNORE.search(lines[f.line - 1]):
                continue  # inline-suppressed
            out.append(f)
    return out


def _default_jobs() -> int:
    env = os.environ.get("SYNUP_SCAN_JOBS", "")
    if env.isdigit() and int(env) > 0:
        return int(env)
    return os.cpu_count() or 1


def scan(root: Path, cfg: Config, disabled_checks: set[str], progress: bool = False,
         only: list[str] | None = None, jobs: int | None = None):
    enabled_names = [m.NAME for m in ALL if m.NAME not in disabled_checks]
    disabled_rules = {m.NAME: cfg.disabled_rules(m.NAME) for m in ALL}
    files = []
    for path in iter_files(root, only):
        rel = relpath(path, root)
        if not _allowed(rel, cfg.allow):
            files.append((path, rel))

    jobs = jobs or _default_jobs()
    live = progress and sys.stderr.isatty()
    results: list = [None] * len(files)
    done = 0

    def tick(rel):
        nonlocal done
        done += 1
        if progress:
            if live:
                sys.stderr.write(f"\r\033[K  {CYA}scanning…{RST} {done}/{len(files)} files  {_trunc(rel, 48)}")
                sys.stderr.flush()
            elif done % 250 == 0:                         # non-tty (CI/log): periodic line
                sys.stderr.write(f"  scanning… {done}/{len(files)} files\n"); sys.stderr.flush()

    ran_parallel = False
    if jobs > 1 and len(files) >= PARALLEL_MIN_FILES:
        try:
            from concurrent.futures import ProcessPoolExecutor, as_completed
            with ProcessPoolExecutor(max_workers=jobs, initializer=_init_worker,
                                     initargs=(enabled_names, disabled_rules)) as ex:
                # biggest files first so one huge file doesn't finish last alone
                order = sorted(range(len(files)), key=lambda i: -_size(files[i][0]))
                futs = {ex.submit(_scan_one, *files[i]): i for i in order}
                for fut in as_completed(futs):
                    i = futs[fut]
                    results[i] = fut.result()
                    tick(files[i][1])
            ran_parallel = True
        except Exception as e:  # no fork/spawn allowed, broken pool… → serial
            if progress:
                sys.stderr.write(f"\r\033[K  {YEL}parallel scan unavailable ({e}); scanning serially{RST}\n")
            results = [None] * len(files); done = 0
    if not ran_parallel:
        _init_worker(enabled_names, disabled_rules)
        for i, (path, rel) in enumerate(files):
            results[i] = _scan_one(path, rel)
            tick(rel)

    if live:
        sys.stderr.write(f"\r\033[K  {GRN}scanned {len(files)} files{RST}\n"); sys.stderr.flush()
    findings = [f for r in results if r for f in r]          # stable: original file order
    nfiles = sum(1 for r in results if r is not None)
    return findings, nfiles


def _size(p: Path) -> int:
    try:
        return p.stat().st_size
    except OSError:
        return 0


SEV_COLOR = {"critical": RED, "high": RED, "warn": YEL, "info": CYA}
SEV_RANK = {"critical": 0, "high": 1, "warn": 2, "info": 3}


def _trunc(s, n):
    s = " ".join((s or "").split())          # collapse whitespace/newlines
    return s if len(s) <= n else s[: n - 1] + "…"


def report_text(findings, path_str, checks_str, files_scanned=0, out=sys.stdout):
    bar = "─" * 78
    n = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_ORDER}
    nfiles = len({f.file for f in findings})
    blocked = (n["critical"] + n["high"]) > 0

    # ---- header banner ----
    print(f"\n{BLD}┌{bar}┐{RST}", file=out)
    if not findings:
        print(f"{BLD}│{RST}  {GRN}✓ CLEAN{RST} — no findings  ({files_scanned} files scanned)", file=out)
        print(f"{BLD}└{bar}┘{RST}", file=out)
        return
    verdict = f"{RED}✗ BLOCKED{RST}" if blocked else f"{YEL}⚠ WARNINGS ONLY{RST}"
    summary = (f"{RED}{n['critical']} critical{RST} · {RED}{n['high']} high{RST} · "
               f"{YEL}{n['warn']} warn{RST} · {n['info']} info   in {nfiles} of {files_scanned} files")
    print(f"{BLD}│{RST}  Synup Code Scan   {verdict}", file=out)
    print(f"{BLD}│{RST}  {summary}", file=out)
    print(f"{BLD}└{bar}┘{RST}", file=out)

    # ---- one block per file (worst severity first), aligned table ----
    by_file = defaultdict(list)
    for f in findings:
        by_file[f.file].append(f)
    worst = lambda items: min(SEV_RANK[i.severity] for i in items)
    for fname in sorted(by_file, key=lambda k: (worst(by_file[k]), k)):
        rows = sorted(by_file[fname], key=lambda i: (SEV_RANK[i.severity], i.line))
        print(f"\n{BLD}▎ {fname}{RST}", file=out)
        print(f"  {'SEVERITY':<8}  {'RULE':<30}  {'LINE':>4}  MATCH", file=out)
        print(f"  {'─'*8}  {'─'*30}  {'─'*4}  {'─'*34}", file=out)
        for f in rows:
            c = SEV_COLOR[f.severity]
            sev = f"{c}{f.severity.upper():<8}{RST}"
            rid = _trunc(f"{f.check}/{(f.detail or f.rule).split()[0]}", 30).ljust(30)
            ln = (str(f.line) if f.line else "—").rjust(4)
            print(f"  {sev}  {rid}  {ln}  {_trunc(f.snippet or f.rule, 60)}", file=out)

    # ---- footer guidance ----
    print(f"\n{BLD}{bar}{RST}", file=out)
    if blocked:
        print(f"  Fix the {RED}critical/high{RST} findings, then {BLD}git add{RST} + commit again.", file=out)
    print(f"  Browse/curate checks: {YEL}synup-scan --list-rules{RST}   ·   "
          f"per-repo config: {YEL}synup-scan --init{RST}", file=out)
    print(f"  Scanned: {path_str}   Checks: {checks_str}", file=out)


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
    ap.add_argument("--progress", action="store_true", help="show a live file-by-file progress counter")
    ap.add_argument("--jobs", "-j", type=int, default=None,
                    help="worker processes for large scans (default: CPU count, or $SYNUP_SCAN_JOBS; 1 = serial)")
    ap.add_argument("--files-from", metavar="FILE",
                    help="scan only the NUL- or newline-separated paths (relative to `path`) "
                         "listed in FILE ('-' = stdin) instead of walking the whole tree")
    ap.add_argument("--list-checks", action="store_true", help="list check names")
    ap.add_argument("--list-rules", action="store_true",
                    help="list every check + rule (id, severity, blocks?) — the menu for .synup-scan.json")
    ap.add_argument("--init", action="store_true",
                    help="write a documented .synup-scan.json template to the current dir")
    args = ap.parse_args()

    if args.list_checks:
        for m in ALL:
            print(m.NAME)
        return 0

    if args.list_rules:
        print(f"{BLD}Synup scan — available checks & rules{RST}  "
              f"(BLOCKS = high/critical fail the commit; warn = reported only)\n")
        for m in ALL:
            print(f"{BLD}{m.NAME}{RST}   (disable whole check: \"disable\": [\"{m.NAME}\"])")
            for rid, sev, desc in m.catalog():
                tag = f"{RED}BLOCKS{RST}" if sev in ("high", "critical") else f"{YEL}warn  {RST}"
                print(f"   {tag}  [{sev:8}] {m.NAME}.{rid:22} {desc}")
            print()
        print("Disable one rule:  \"<check>\": { \"disable_rules\": [\"<rule>\"] }")
        print("Skip paths:        \"allow\": [\"glob/**\"]      Inline: add `synup-ignore` to a line.")
        return 0

    if args.init:
        dest = Path.cwd() / ".synup-scan.json"
        if dest.exists():
            print(f"{YEL}{dest} already exists — not overwriting.{RST}", file=sys.stderr)
            return 1
        tmpl = {
            "_README": "Synup scan config. Run `runner.py --list-rules` to see every option. "
                       "Add a check name to 'disable' to turn it off; add a rule id under "
                       "'<check>.disable_rules' to turn off one rule; 'allow' skips path globs.",
            "disable": [],
            "min_severity": "high",
            "allow": [],
        }
        for m in ALL:
            tmpl[m.NAME] = {"disable_rules": []}
        tmpl["_available"] = {m.NAME: [rid for rid, _, _ in m.catalog()] for m in ALL}
        dest.write_text(_json.dumps(tmpl, indent=2) + "\n", encoding="utf-8")
        print(f"{GRN}wrote {dest}{RST}  — edit it, then commit it to your repo.")
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

    only = None
    if args.files_from:
        raw = sys.stdin.read() if args.files_from == "-" else Path(args.files_from).read_text(encoding="utf-8")
        only = [p for p in (raw.split("\0") if "\0" in raw else raw.splitlines()) if p]

    all_findings, files_scanned = scan(root, cfg, disabled_checks, progress=args.progress, only=only, jobs=args.jobs)
    findings = [f for f in all_findings if sev_ge(f.severity, min_sev)]

    path_str = str(root)
    checks_str = ", ".join(m.NAME for m in ALL if m.NAME not in disabled_checks) or "(none)"

    if args.json:
        if args.report:
            with open(args.report, "w") as fh:
                report_json(findings, files_scanned, fh)
        report_json(findings, files_scanned)
    else:
        if args.report:
            with open(args.report, "w") as fh:
                report_text(findings, path_str, checks_str, files_scanned, fh)
        report_text(findings, path_str, checks_str, files_scanned)

    return 1 if any(sev_ge(f.severity, "high") for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
