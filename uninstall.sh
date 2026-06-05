#!/usr/bin/env bash
#
# Synup org git-hooks uninstaller — reverses install.sh.
# Keeps your SSH keys; only unsets the git config it added.
#
# Usage: ./uninstall.sh [--keep-signing]
set -euo pipefail

SYNUP_HOME_DIR="${SYNUP_HOME:-$HOME/.synup}"
HOOKS_DIR="$SYNUP_HOME_DIR/security-workflows/hooks"
KEEP_SIGNING=0
[ "${1:-}" = "--keep-signing" ] && KEEP_SIGNING=1

GRN='\033[0;32m'; YEL='\033[1;33m'; RST='\033[0m'
ok()   { printf "%b\n" "${GRN}✓${RST} $*"; }
warn() { printf "%b\n" "${YEL}!${RST} $*"; }

# Only unset hooksPath if it points at ours (don't clobber husky/custom setups).
current="$(git config --global core.hooksPath 2>/dev/null || true)"
if [ "$current" = "$HOOKS_DIR" ]; then
  git config --global --unset core.hooksPath && ok "removed global core.hooksPath"
else
  warn "core.hooksPath is '$current' (not ours) — left untouched"
fi

if [ "$KEEP_SIGNING" = 0 ]; then
  git config --global --unset commit.gpgsign 2>/dev/null || true
  git config --global --unset tag.gpgsign 2>/dev/null || true

  # Only tear down signing config that WE created — never clobber a pre-existing,
  # non-synup signing setup the developer may have configured themselves.
  sk="$(git config --global user.signingkey 2>/dev/null || true)"
  asf="$(git config --global gpg.ssh.allowedSignersFile 2>/dev/null || true)"
  prog="$(git config --global gpg.ssh.program 2>/dev/null || true)"
  ours=0
  case "$sk"  in *synup_signing_ed25519*|*secretive_signing.pub*) ours=1 ;; esac
  case "$asf" in "$SYNUP_HOME_DIR"/*) ours=1 ;; esac

  if [ "$ours" = 1 ]; then
    git config --global --unset user.signingkey            2>/dev/null || true
    git config --global --unset gpg.format                 2>/dev/null || true
    git config --global --unset gpg.ssh.allowedSignersFile 2>/dev/null || true
    case "$prog" in "$SYNUP_HOME_DIR"/*) git config --global --unset gpg.ssh.program 2>/dev/null || true ;; esac
    # Drop now-empty sections so ~/.gitconfig is left tidy.
    git config --global --remove-section gpg      2>/dev/null || true
    git config --global --remove-section 'gpg.ssh' 2>/dev/null || true
    git config --global --remove-section user      2>/dev/null || true
    ok "removed signing config (gpg.format, user.signingkey, allowedSignersFile)"
  elif [ -n "$sk" ]; then
    warn "user.signingkey is '$sk' (not ours) — left untouched"
    ok "disabled commit/tag signing"
  else
    ok "disabled commit/tag signing"
  fi

  # Remove the keychain block we may have appended to ~/.ssh/config (idempotent).
  SSHCFG="$HOME/.ssh/config"
  if [ -f "$SSHCFG" ] && grep -qF "synup signing keychain" "$SSHCFG"; then
    tmp="$(mktemp)"
    awk '/# >>> synup signing keychain >>>/{skip=1} skip!=1{print} /# <<< synup signing keychain <<</{skip=0}' "$SSHCFG" > "$tmp"
    cat "$tmp" > "$SSHCFG"   # '>' preserves the file's perms/inode (keeps 600)
    rm -f "$tmp"
    ok "removed Secretive/keychain block from ~/.ssh/config"
  fi
else
  warn "signing config kept (--keep-signing)"
fi

ok "Uninstalled. Your repos and SSH key FILES are untouched (only git/ssh config was reverted)."
warn "Husky repos with an injected scan line: remove the '# >>> synup malware scan >>>' block manually."
