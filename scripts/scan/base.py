"""Shared types and helpers for all checks."""
from __future__ import annotations

import math
import os
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

# ---------- severity ----------
SEVERITY_ORDER = {"info": 0, "warn": 1, "high": 2, "critical": 3}


def sev_ge(a: str, b: str) -> bool:
    return SEVERITY_ORDER.get(a, 0) >= SEVERITY_ORDER.get(b, 0)


# ---------- finding ----------
@dataclass
class Finding:
    severity: str          # info | warn | high | critical
    check: str             # which check module produced it (e.g. "secrets")
    rule: str              # human-readable rule name
    file: str              # path relative to scan root
    line: int              # 1-based; 0 = whole-file (e.g. sensitive filename)
    snippet: str = ""
    detail: str = ""


# ---------- file enumeration config ----------
SKIP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".ttf", ".woff", ".woff2", ".eot", ".otf",
    ".pdf", ".zip", ".gz", ".tar", ".tgz", ".bz2", ".xz", ".7z",
    ".mp3", ".mp4", ".wav", ".mov", ".avi", ".webm",
    ".bin", ".exe", ".dll", ".so", ".dylib", ".class", ".jar", ".war",
    ".pyc", ".pyo", ".o", ".a",
}
SKIP_DIRS = {
    ".git", "node_modules", "tmp", "log", "logs", "storage",
    "vendor", ".bundle", "__pycache__", "dist", "build", "coverage",
    "public/packs", "public/assets", "public/packs-test", ".next", ".venv", "venv",
}
SKIP_FILENAMES = {
    "scan_malware.py", "scan_report.txt", "malware_scan_report.txt",
}
LIKELY_MINIFIED = re.compile(r"\.min\.(js|css)$|/(vendor|dist|build)/")
MAX_FILE_BYTES = 5 * 1024 * 1024

# Inline suppression: put `synup-ignore` in a comment on the offending line.
INLINE_IGNORE = re.compile(r"synup-ignore\b", re.IGNORECASE)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = defaultdict(int)
    for ch in s:
        counts[ch] += 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def iter_files(root: Path) -> Iterable[Path]:
    """Yield scannable files under root (or root itself if it's a file)."""
    if root.is_file():
        if root.name in SKIP_FILENAMES:
            return
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        # prune skip dirs in-place for speed
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.is_symlink() or not p.is_file():
                continue
            if fn in SKIP_FILENAMES or p.suffix.lower() in SKIP_EXT:
                continue
            try:
                if p.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield p


def relpath(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def clip(s: str, n: int = 200) -> str:
    s = s.strip()
    return s[:n] + "…" if len(s) > n else s


def is_minified(path_str: str) -> bool:
    return bool(LIKELY_MINIFIED.search(path_str))
