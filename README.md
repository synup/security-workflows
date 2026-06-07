# security-workflows

Centralized security scanning + git hooks for the Synup org.

This repo gives every developer **two layers of protection**:

| Layer | What | Where it runs |
|-------|------|---------------|
| **Local pre-commit hook** | Blocks a commit if staged changes contain malware/secrets | Your machine, before the commit is created |
| **CI workflow** | Re-scans changed files on every PR and blocks the merge | GitHub Actions |

Plus **SSH commit signing** so every commit is verified (✓ Verified badge on GitHub).

---

## For developers — one-time setup

Run this once per machine. It installs the hook globally (covers **every** repo you
have now or clone later) and sets up commit signing:

```bash
curl -sSL https://raw.githubusercontent.com/synup/security-workflows/master/install.sh | bash
```

…or from a clone, with your repos directory so it can detect husky projects:

```bash
git clone https://github.com/synup/security-workflows.git
cd security-workflows
./install.sh --root ~/Documents/synup-projects
```

That's it. The next time you `git commit`, staged changes are scanned and the commit
is signed automatically.

### Verify it works

```bash
cd <any-repo>
echo 'AKIA1234567890ABCDEF' > leak.txt && git add leak.txt && git commit -m test
#  → ✗ COMMIT BLOCKED — malware/secret scan found high/critical issues
rm leak.txt

git commit --allow-empty -m "signed?" && git log --show-signature -1
#  → shows "Good \"git\" signature ..."
```

### Keeping up to date

Re-run the installer any time to pull the latest scanner rules and hooks:

```bash
~/.synup/security-workflows/install.sh   # or curl one-liner again
```

---

## What it does

### `install.sh`
1. Clones/updates this repo into `~/.synup/security-workflows`.
2. Sets `git config --global core.hooksPath ~/.synup/security-workflows/hooks`
   — one global hook for all repos. The hook **chains** to any existing
   `.git/hooks/pre-commit` or `.husky/pre-commit`, so project hooks keep working.
3. Configures SSH commit signing (`gpg.format=ssh`, `commit.gpgsign=true`) and
   registers the key on GitHub as a **Signing Key** (signing-only — it can't be used
   to push). It picks the most secure key available:
   - **Secure Enclave (preferred):** if [Secretive](https://github.com/maxgoedjen/secretive)
     is installed with a key, that key is used — the private key never leaves the
     Apple chip and can't be copied off disk. Signing is routed through Secretive's
     agent **only** (via `gpg.ssh.program`), so your normal SSH auth/push agent is
     untouched.
   - **Passphrased file key (fallback):** generates a *dedicated*
     `~/.ssh/synup_signing_ed25519` and prompts you for a passphrase (so the key file
     alone is useless if copied), and the macOS Keychain caches the passphrase so you
     aren't retyping it.

| Flag | Effect |
|------|--------|
| `--root DIR` | Where to look for husky repos (default: current dir) |
| `--no-signing` | Skip commit-signing setup |
| `--no-hooks` | Skip git hook setup |
| `--inject-husky` | Auto-add the scan to husky repos' `.husky/pre-commit` |

### `hooks/pre-commit`
Materializes the **staged** content of your commit into a temp dir and runs
`scripts/scan/runner.py --min-severity high`. Any high/critical finding blocks the
commit.

Escape hatches (use rarely):
```bash
git commit --no-verify                 # skip all hooks
SYNUP_SKIP_MALWARE_SCAN=1 git commit   # skip only the malware scan
SYNUP_HOOK_STRICT=1                     # block even on scanner infra errors (default: warn+allow)
```

**Throttled auto-update.** The hook keeps its scanner rules fresh on its own: at most
once every 24h it kicks off a **detached background `git pull`** of
`~/.synup/security-workflows`. It never blocks or fails a commit — the current commit
uses the cached scanner and the next commit picks up any update. (CI always fetches the
latest scanner anyway, so the PR gate is never stale.)

```bash
SYNUP_HOOK_UPDATE_INTERVAL=3600 git commit   # check at most hourly instead of daily
SYNUP_HOOK_UPDATE_INTERVAL=0    git commit   # disable auto-update for this commit
SYNUP_HOOK_NO_UPDATE=1          git commit   # same: skip the update check
```

### `scripts/scan/` — modular scanner
The scanner is split into one file per check under `scripts/scan/checks/`, so checks
can be toggled and extended independently:

| Check | File | Detects |
|-------|------|---------|
| `secrets` | `checks/secrets.py` | AWS/GCP/GitHub/Slack/Stripe/Twilio/SendGrid/npm/PyPI/OpenAI/Anthropic tokens, private keys, DB URIs with creds, JWTs, generic high-entropy `KEY=…` |
| `sensitive_files` | `checks/sensitive_files.py` | committing `.env`, `*.pem`, `id_rsa`, `*.p12`, `.npmrc`, GCP SA json, etc. (`.env.example`/`*.pub` allowed) |
| `malware` | `checks/malware.py` | reverse shells, crypto miners, web shells, obfuscation, supply-chain markers, hidden payloads |
| `dangerous_code` | `checks/dangerous_code.py` | command/SQL injection, unsafe deserialization (`pickle`/`yaml.load`), `eval`, weak crypto, TLS verification off |

Run it manually any time:
```bash
python3 ~/.synup/security-workflows/scripts/scan/runner.py .                  # scan a repo
python3 ~/.synup/security-workflows/scripts/scan/runner.py file.js --json
python3 ~/.synup/security-workflows/scripts/scan/runner.py . --disable dangerous_code
python3 ~/.synup/security-workflows/scripts/scan/runner.py --list-checks
```
(`scripts/scan_malware.py` is the original self-contained scanner, kept unchanged so
the existing CI workflow keeps working as-is — see below.)

#### Configuring which scans run — `.synup-scan.json`
Each repo controls its own scans with a **`.synup-scan.json` at its root** (committed to the
repo, shared with the team). It is **never overwritten** by the hook's auto-update — that only
refreshes `~/.synup`, not your project repos.

**You don't need to read any code to know what's available.** Discover everything from the CLI:
```bash
S=~/.synup/security-workflows/scripts/scan/runner.py
python3 "$S" --list-checks    # the 4 check names
python3 "$S" --list-rules     # EVERY check + rule: id, severity, and whether it BLOCKS
python3 "$S" --init           # write a starter .synup-scan.json (with the full option list inside)
```
`--list-rules` prints the full menu; `--init` drops a ready-to-edit `.synup-scan.json` whose
`_available` block lists every check + rule id you can put under `disable` / `disable_rules`.
(`.synup-scan.example.json` is the same, committed for reference.)

Then edit it — turn off a whole check, a single rule, or skip paths:
```json
{
  "disable": ["dangerous_code"],
  "allow": ["test/fixtures/*", "docs/*"],
  "secrets": { "disable_rules": ["jwt", "stripe_pub"] },
  "min_severity": "high"
}
```
Or suppress one line inline with a `synup-ignore` comment.

### Fully offline — no dependencies
The scanner is **pure Python standard library** — nothing to `pip install`, no binaries,
no network at scan time. A commit check runs entirely locally in milliseconds. (The only
network use is the hook's optional **background** daily `git pull` to refresh rules, which
never blocks a commit and can be disabled with `SYNUP_HOOK_UPDATE_INTERVAL=0`.)

### Existing CI — `.github/workflows/malware-scan.yml` (unchanged)
The pre-existing reusable CI workflow is **left exactly as-is** — it runs the original
self-contained `scan_malware.py` on changed PR files (no external tools) and comments +
blocks on high/critical findings. Consumers keep calling it unchanged:
```yaml
# .github/workflows/security.yml in the consuming repo
name: Security
on: pull_request
jobs:
  malware:
    uses: synup/security-workflows/.github/workflows/malware-scan.yml@master
```
> Note: the **local hook** uses the newer modular scanner (`scripts/scan/`), which has
> broader coverage (secrets, sensitive-files, dangerous-code) than the CI's legacy
> `scan_malware.py`. Migrating CI to the modular scanner is a deliberate, separate step.

---

## Husky / JS repos

Husky sets a **local** `core.hooksPath` (e.g. `.husky/_`) that overrides the global
one, so the global hook is bypassed there. The installer detects these and either
warns you or, with `--inject-husky`, inserts this block at the **top** of
`.husky/pre-commit` — so the malware scan **runs first** and blocks the commit before
husky's own hooks (lint-staged, etc.) run (commit the change so teammates get it):

```sh
#!/usr/bin/env sh
# >>> synup malware scan >>>
"$HOME/.synup/security-workflows/hooks/pre-commit" || exit $?
# <<< synup malware scan <<<
. "$(dirname -- "$0")/_/husky.sh"   # ← your existing husky hook continues below
npx lint-staged
```

Both run, ours first. Re-running `--inject-husky` is idempotent and will reposition an
older bottom-injected block to the top.

---

## Uninstall

```bash
~/.synup/security-workflows/uninstall.sh                # removes hooks + disables signing
~/.synup/security-workflows/uninstall.sh --keep-signing # keep signing on
```
