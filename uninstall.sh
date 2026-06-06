#!/usr/bin/env bash
#
# Synup org git-hooks uninstaller — reverses install.sh.
# Keeps your SSH keys; only unsets the git config it added.
#
# Usage: ./uninstall.sh [--keep-signing] [--root DIR]
#   --root DIR  Where to look for husky repos to clean (default: current dir)
set -euo pipefail

SYNUP_HOME_DIR="${SYNUP_HOME:-$HOME/.synup}"
HOOKS_DIR="$SYNUP_HOME_DIR/security-workflows/hooks"
KEEP_SIGNING=0
ROOT_DIR="$PWD"
MARK_START="# >>> synup malware scan >>>"
MARK_END="# <<< synup malware scan <<<"

while [ $# -gt 0 ]; do
  case "$1" in
    --keep-signing) KEEP_SIGNING=1; shift ;;
    --root)         ROOT_DIR="$2"; shift 2 ;;
    *)              echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

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

# --- remove our injected scan block from husky repos' .husky/pre-commit ---
# Mirrors install.sh --inject-husky. Strips only our marked block (idempotent),
# leaving the rest of the husky hook intact.
husky_cleaned=0
while IFS= read -r hk; do
  [ -n "$hk" ] || continue
  grep -qF "$MARK_START" "$hk" 2>/dev/null || continue
  tmp="$(mktemp)"
  awk -v s="$MARK_START" -v e="$MARK_END" \
    'index($0,s){skip=1} skip!=1{print} index($0,e){skip=0}' "$hk" > "$tmp"
  cat "$tmp" > "$hk"; rm -f "$tmp"
  ok "removed scan block from ${hk#"$ROOT_DIR"/}"
  husky_cleaned=1
done < <(find "$ROOT_DIR" -name node_modules -prune -o -path '*/.husky/pre-commit' -print 2>/dev/null)
[ "$husky_cleaned" = 1 ] && warn "commit those .husky/pre-commit change(s) so teammates' repos update too"

ok "Uninstalled. Your repos and SSH key FILES are untouched (only git/ssh config was reverted)."
