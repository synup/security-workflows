"""SAST-lite: high-signal dangerous code patterns.

Intentionally conservative to keep false positives low. For deep SAST, the CI
Semgrep job (security-ci.yml) does the heavy lifting. Disable per-rule or the
whole check via .synup-scan.json if it's noisy for your repo.
"""
from __future__ import annotations

import re
from pathlib import Path

from ..base import Finding, clip, line_of

NAME = "dangerous_code"

RULES = [
    # --- injection ---
    ("py_shell_injection", "high", "Shell command built from interpolation (command injection)",
        re.compile(r"(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen|check_output))\s*\([^)]*(?:f[\"']|%\s|\+\s*\w|\.format\()")),
    ("subprocess_shell_true", "warn", "subprocess(..., shell=True)",
        re.compile(r"subprocess\.(?:call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True")),
    ("js_child_process_concat", "high", "child_process exec with string concatenation",
        re.compile(r"(?:child_process\.)?exec(?:Sync)?\s*\(\s*[`\"'][^`\"']*[`\"']\s*\+|\bexec(?:Sync)?\s*\(\s*`[^`]*\$\{")),
    ("sql_concat", "high", "SQL query built by string concatenation/format (SQLi)",
        re.compile(r"(?i)(?:select|insert|update|delete)\b[^\n;]{0,120}(?:\"\s*\+|\'\s*\+|%\s*\(|\.format\(|`[^`]*\$\{)")),
    # --- unsafe deserialization ---
    ("py_pickle", "high", "pickle.loads — unsafe deserialization",
        re.compile(r"\bpickle\.loads?\s*\(")),
    ("py_yaml_load", "high", "yaml.load without SafeLoader",
        re.compile(r"\byaml\.load\s*\((?![^)]*Safe)")),
    ("ruby_yaml_load", "warn", "YAML.load (use YAML.safe_load)",
        re.compile(r"\bYAML\.load(?!_file|_stream|_documents|s)\b")),
    ("ruby_send_user", "warn", "send() with user-controlled method name",
        re.compile(r"\.send\s*\(\s*(?:params|args|request|input)\b")),
    ("ruby_kernel_exec", "warn", "Kernel.exec/system or backtick with interpolation",
        re.compile(r"(?:Kernel\.(?:exec|system)|`[^`]*#\{|%x\{[^}]*#\{)")),
    ("js_node_serialize", "high", "node-serialize unserialize (RCE-prone)",
        re.compile(r"\bunserialize\s*\(")),
    # --- dynamic eval ---
    ("py_eval_exec", "high", "eval()/exec() on dynamic input",
        re.compile(r"\b(?:eval|exec)\s*\(\s*(?!['\"]\s*\))")),
    # --- weak crypto / TLS ---
    ("weak_hash", "warn", "Weak hash (MD5/SHA1) — avoid for passwords/signatures",
        re.compile(r"(?:hashlib\.(?:md5|sha1)|MessageDigest\.getInstance\(\s*[\"'](?:MD5|SHA-1)|createHash\(\s*[\"'](?:md5|sha1))", re.IGNORECASE)),
    ("weak_cipher", "warn", "Weak cipher (DES/RC4/ECB)",
        re.compile(r"\b(?:DES|RC4|ARC4)\b|/ECB/", re.IGNORECASE)),
    ("tls_verify_off", "high", "TLS certificate verification disabled",
        re.compile(r"(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*(?:0|false)|InsecureSkipVerify\s*:\s*true|_create_unverified_context)", re.IGNORECASE)),
    # --- debug / misconfig ---
    ("flask_debug", "warn", "Flask/Express debug mode in code",
        re.compile(r"(?:app\.run\([^)]*debug\s*=\s*True|DEBUG\s*=\s*True)")),
    ("disable_host_check", "warn", "Host/CSRF/SSRF protection disabled",
        re.compile(r"(?:ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*|csrf\s*:\s*false|WebSecurity\s*:\s*false)", re.IGNORECASE)),
]


def check(path: Path, rel: str, text: str, lines, disabled_rules):
    out: list[Finding] = []
    for rule_id, sev, desc, pat in RULES:
        if rule_id in disabled_rules:
            continue
        for m in pat.finditer(text):
            ln = line_of(text, m.start())
            out.append(Finding(sev, NAME, desc, rel, ln,
                               clip(lines[ln - 1] if ln <= len(lines) else m.group()), detail=rule_id))
    return out
