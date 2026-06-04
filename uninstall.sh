#!/usr/bin/env bash
#
# Synup org git-hooks uninstaller — reverses install.sh.
# Keeps your SSH keys; only unsets the git config it added.
#
# Usage: ./uninstall.sh [--keep-signing]
set -euo pipefail

HOOKS_DIR="${SYNUP_HOME:-$HOME/.synup}/security-workflows/hooks"
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
  ok "disabled commit/tag signing (your keys are kept; user.signingkey left as-is)"
else
  warn "signing config kept (--keep-signing)"
fi

ok "Uninstalled. Your repos and SSH keys are untouched."
warn "Husky repos with an injected scan line: remove the '# >>> synup malware scan >>>' block manually."
