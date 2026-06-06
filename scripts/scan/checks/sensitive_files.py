"""Block committing files that should never be in version control."""
from __future__ import annotations

import fnmatch
import re
from pathlib import Path

from ..base import Finding

NAME = "sensitive_files"

# (rule_id, severity, description, matcher) — matcher tested against basename and rel path.
# Each pattern is a shell glob; matched case-insensitively against the basename.
BLOCK = [
    ("dotenv",        "high",     "Environment file with secrets (.env)",      [".env", ".env.*"]),
    ("private_key",   "critical", "Private key file",                          ["*.pem", "*.key", "*.pkcs8", "*.pkcs12"]),
    ("ssh_key",       "critical", "SSH private key",                           ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"]),
    ("pkcs12",        "critical", "PKCS#12 / keystore",                        ["*.p12", "*.pfx", "*.keystore", "*.jks"]),
    ("putty_key",     "critical", "PuTTY private key",                         ["*.ppk"]),
    ("npmrc",         "high",     ".npmrc (may contain auth token)",           [".npmrc"]),
    ("pypirc",        "high",     ".pypirc (PyPI credentials)",                [".pypirc"]),
    ("netrc",         "high",     ".netrc (host credentials)",                 [".netrc", "_netrc"]),
    ("htpasswd",      "high",     ".htpasswd (password hashes)",               [".htpasswd"]),
    ("gcp_sa",        "high",     "GCP service-account key JSON",              ["*service-account*.json", "*serviceaccount*.json", "gcp-key*.json"]),
    ("aws_creds",     "critical", "AWS credentials file",                      ["credentials", "aws_credentials"]),
    ("kube",          "high",     "Kubeconfig (cluster credentials)",          ["kubeconfig", "*.kubeconfig"]),
    ("pkcs8",         "critical", "DER/keystore",                              ["*.der"]),
    ("ovpn",          "high",     "OpenVPN profile (may embed keys)",          ["*.ovpn"]),
    ("keepass",       "high",     "KeePass database",                          ["*.kdbx"]),
    ("pgp_secret",    "critical", "PGP/GPG secret keyring",                    ["secring.*", "*.gpg", "*.asc"]),
    ("tfstate",       "high",     "Terraform state (often contains secrets)",  ["*.tfstate", "*.tfstate.backup"]),
    ("docker_cfg",    "high",     "Docker registry credentials",               [".dockercfg", "config.json"]),
    ("git_creds",     "critical", "Stored git credentials",                    [".git-credentials"]),
    ("wp_config",     "high",     "WordPress config (DB creds)",               ["wp-config.php"]),
    ("rails_secrets", "high",     "Rails secrets/master key",                  ["master.key", "secrets.yml"]),
    ("history",       "high",     "Shell history (may contain secrets)",       [".bash_history", ".zsh_history", ".mysql_history", ".psql_history"]),
]

# Filenames that look sensitive but are safe to commit.
ALLOW = [
    ".env.example", ".env.sample", ".env.template", ".env.dist", ".env.defaults",
    "*.pub",
]


def _matches(name: str, globs) -> bool:
    return any(fnmatch.fnmatch(name, g) for g in globs)


def check(path: Path, rel: str, text: str, lines, disabled_rules):
    name = Path(rel).name.lower()
    if _matches(name, [a.lower() for a in ALLOW]):
        return []
    out: list[Finding] = []
    for rule_id, sev, desc, globs in BLOCK:
        if rule_id in disabled_rules:
            continue
        if _matches(name, [g.lower() for g in globs]):
            out.append(Finding(sev, NAME, desc, rel, 0,
                               snippet=f"committing '{rel}'", detail=rule_id))
            break  # one finding per file is enough
    return out


def catalog():
    return [(b[0], b[1], b[2]) for b in BLOCK]
