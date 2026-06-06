"""Hardcoded secrets / credentials detection."""
from __future__ import annotations

import re
from pathlib import Path

from ..base import Finding, clip, line_of, shannon_entropy

NAME = "secrets"

# (rule_id, severity, description, pattern)
RULES = [
    ("aws_access_key",   "critical", "AWS access key id",            re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b")),
    ("gcp_api_key",      "critical", "Google API key",               re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("gcp_oauth",        "high",     "Google OAuth access token",     re.compile(r"\bya29\.[0-9A-Za-z\-_]{20,}\b")),
    ("github_pat",       "critical", "GitHub token",                 re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b")),
    ("github_fine_pat",  "critical", "GitHub fine-grained PAT",      re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("slack_token",      "critical", "Slack token",                  re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("slack_webhook",    "high",     "Slack webhook URL",            re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9]+")),
    ("stripe_secret",    "critical", "Stripe secret/restricted key", re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b")),
    ("stripe_pub",       "warn",     "Stripe publishable key (public, but flag)", re.compile(r"\bpk_live_[0-9a-zA-Z]{24,}\b")),
    ("twilio_sid",       "high",     "Twilio account/API SID",       re.compile(r"\b(?:AC|SK)[0-9a-fA-F]{32}\b")),
    ("sendgrid",         "critical", "SendGrid API key",             re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b")),
    ("mailgun",          "high",     "Mailgun API key",              re.compile(r"\bkey-[0-9a-zA-Z]{32}\b")),
    ("npm_token",        "critical", "npm access token",             re.compile(r"\bnpm_[0-9A-Za-z]{36}\b")),
    ("pypi_token",       "critical", "PyPI upload token",            re.compile(r"\bpypi-AgEIcHlwaS[A-Za-z0-9_\-]{50,}")),
    ("openai",           "critical", "OpenAI API key",               re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b")),
    ("anthropic",        "critical", "Anthropic API key",            re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{30,}\b")),
    ("telegram_bot",     "high",     "Telegram bot token",           re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b")),
    ("square",           "critical", "Square access token",          re.compile(r"\bsq0atp-[0-9A-Za-z\-_]{22}\b")),
    ("shopify",          "critical", "Shopify access token",         re.compile(r"\bshp(?:at|ca|pa|ss)_[0-9a-fA-F]{32}\b")),
    ("private_key",      "critical", "Private key block",            re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("jwt",              "warn",     "JSON Web Token",               re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("db_uri_creds",     "high",     "DB connection string with credentials",
        re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|rediss)://[^:@\s/]+:[^@\s/]+@", re.IGNORECASE)),
    ("npmrc_token",      "critical", "npm registry auth token",      re.compile(r"//[^\s]+/:_authToken=[A-Za-z0-9_\-\.]+")),
]

# Generic "<secret-ish name> = '<value>'" with an entropy gate (catches custom secrets).
GENERIC = re.compile(
    r"""(?ix)
    \b(?P<key>(?:api|access|secret|private|auth|client)[_-]?(?:key|token|secret)?|password|passwd|pwd|token|secret|credential)\b
    \s*[:=]\s*
    (?P<q>['"])(?P<val>[^'"\n]{12,})(?P=q)
    """
)
GENERIC_ENTROPY = 3.5
PLACEHOLDER = re.compile(r"(?i)(example|placeholder|change[_-]?me|your[_-]|xxx+|\*\*\*|<[^>]+>|dummy|sample|test|redacted|\$\{)")


def check(path: Path, rel: str, text: str, lines, disabled_rules):
    out: list[Finding] = []
    for rule_id, sev, desc, pat in RULES:
        if rule_id in disabled_rules:
            continue
        for m in pat.finditer(text):
            ln = line_of(text, m.start())
            snippet = lines[ln - 1] if ln <= len(lines) else m.group()
            out.append(Finding(sev, NAME, desc, rel, ln, clip(snippet), detail=rule_id))

    if "generic" not in disabled_rules:
        for m in GENERIC.finditer(text):
            val = m.group("val")
            if PLACEHOLDER.search(val):
                continue
            if shannon_entropy(val) < GENERIC_ENTROPY:
                continue
            ln = line_of(text, m.start())
            out.append(Finding("high", NAME, f"Hardcoded secret in '{m.group('key')}' assignment",
                               rel, ln, clip(lines[ln - 1] if ln <= len(lines) else m.group()),
                               detail="generic"))
    return out


def catalog():
    return [(r[0], r[1], r[2]) for r in RULES] + [
        ("generic", "high", "Hardcoded secret in a secret-ish assignment (entropy-gated)"),
    ]
