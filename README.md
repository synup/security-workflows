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
`scripts/scan_malware.py --min-severity high`. Any high/critical finding blocks the
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

### `scripts/scan_malware.py`
Standalone scanner. Detects reverse shells, crypto miners, obfuscated payloads,
web shells, hardcoded credentials (AWS/GitHub/Slack tokens, private keys), and
supply-chain markers. Run it manually any time:

```bash
python3 ~/.synup/security-workflows/scripts/scan_malware.py .            # scan a repo
python3 ~/.synup/security-workflows/scripts/scan_malware.py file.js --json
```

### `.github/workflows/malware-scan.yml`
Reusable CI workflow. Add it to any repo with a thin caller:

```yaml
# .github/workflows/security.yml in the consuming repo
name: Security
on: pull_request
jobs:
  malware-scan:
    uses: synup/security-workflows/.github/workflows/malware-scan.yml@master
```

---

## Husky / JS repos

Husky sets a **local** `core.hooksPath` (e.g. `.husky/_`) that overrides the global
one, so the global hook is bypassed there. The installer detects these and either
warns you or, with `--inject-husky`, appends this to `.husky/pre-commit` (commit the
change so teammates get it):

```sh
# >>> synup malware scan >>>
"$HOME/.synup/security-workflows/hooks/pre-commit" || exit $?
# <<< synup malware scan <<<
```

---

## Uninstall

```bash
~/.synup/security-workflows/uninstall.sh                # removes hooks + disables signing
~/.synup/security-workflows/uninstall.sh --keep-signing # keep signing on
```
