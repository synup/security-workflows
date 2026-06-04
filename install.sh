#!/usr/bin/env bash
#
# Synup org git-hooks + commit-signing installer
# ------------------------------------------------------------------
# Run once per developer machine. It:
#   1. Clones/updates security-workflows into ~/.synup/security-workflows
#   2. Points git's global core.hooksPath at the org pre-commit hook
#      (malware/secret scan on every commit, all current + future repos)
#   3. Sets up SSH-based commit signing and registers the key on GitHub
#   4. Flags any husky repos that bypass the global hook
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/synup/security-workflows/master/install.sh | bash
#   # or, from a clone:  ./install.sh [options]
#
# Options:
#   --root DIR        Directory to scan for husky repos (default: $PWD)
#   --no-signing      Skip SSH commit-signing setup
#   --no-hooks        Skip git hook setup
#   --inject-husky    Auto-add the scan to husky repos' .husky/pre-commit
#   -h, --help        Show this help
# ------------------------------------------------------------------
set -euo pipefail

REPO_URL="https://github.com/synup/security-workflows.git"
INSTALL_DIR="${SYNUP_HOME:-$HOME/.synup}/security-workflows"
HOOKS_DIR="$INSTALL_DIR/hooks"
ALLOWED_SIGNERS="${SYNUP_HOME:-$HOME/.synup}/allowed_signers"

ROOT_DIR="$PWD"
DO_SIGNING=1
DO_HOOKS=1
INJECT_HUSKY=0

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; CYA='\033[0;36m'; BLD='\033[1m'; RST='\033[0m'
info()  { printf "%b\n" "${CYA}▸${RST} $*"; }
ok()    { printf "%b\n" "${GRN}✓${RST} $*"; }
warn()  { printf "%b\n" "${YEL}!${RST} $*"; }
err()   { printf "%b\n" "${RED}✗${RST} $*" >&2; }
step()  { printf "\n%b\n" "${BLD}$*${RST}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --root)          ROOT_DIR="$2"; shift 2 ;;
    --no-signing)    DO_SIGNING=0; shift ;;
    --no-hooks)      DO_HOOKS=0; shift ;;
    --inject-husky)  INJECT_HUSKY=1; shift ;;
    -h|--help)       sed -n '2,30p' "$0"; exit 0 ;;
    *)               err "unknown option: $1"; exit 2 ;;
  esac
done

command -v git >/dev/null 2>&1 || { err "git is required"; exit 1; }

# ------------------------------------------------------------------
step "1/4  Fetching security-workflows → $INSTALL_DIR"
# ------------------------------------------------------------------
mkdir -p "$(dirname "$INSTALL_DIR")"
if [ -d "$INSTALL_DIR/.git" ]; then
  git -C "$INSTALL_DIR" pull --ff-only --quiet && ok "updated existing checkout"
else
  git clone --quiet "$REPO_URL" "$INSTALL_DIR" && ok "cloned"
fi
chmod +x "$HOOKS_DIR"/* 2>/dev/null || true
# Seed the hook's update timestamp so the next commit doesn't immediately re-pull.
printf '%s\n' "$(date +%s)" > "${SYNUP_HOME:-$HOME/.synup}/.synup_hook_last_update" 2>/dev/null || true

# ------------------------------------------------------------------
if [ "$DO_HOOKS" = 1 ]; then
step "2/4  Wiring global git hooks (core.hooksPath)"
# ------------------------------------------------------------------
  existing="$(git config --global core.hooksPath 2>/dev/null || true)"
  if [ -n "$existing" ] && [ "$existing" != "$HOOKS_DIR" ]; then
    warn "core.hooksPath was already set to: $existing"
    warn "overwriting with: $HOOKS_DIR  (back it up if it was intentional)"
  fi
  git config --global core.hooksPath "$HOOKS_DIR"
  ok "core.hooksPath → $HOOKS_DIR"
  info "applies to every current and future repo on this machine"

  # --- husky repos bypass the global hook (they set a local core.hooksPath) ---
  step "    Checking for husky repos under $ROOT_DIR"
  husky_repos=()
  while IFS= read -r gitdir; do
    repo="$(dirname "$gitdir")"
    local_hp="$(git -C "$repo" config --local core.hooksPath 2>/dev/null || true)"
    [ -n "$local_hp" ] && husky_repos+=("$repo")
  done < <(find "$ROOT_DIR" -maxdepth 3 -name .git -type d 2>/dev/null)

  if [ ${#husky_repos[@]} -eq 0 ]; then
    ok "no husky/local-hooksPath repos found"
  else
    SNIPPET_MARK="# >>> synup malware scan >>>"
    SNIPPET="$SNIPPET_MARK
\"$HOOKS_DIR/pre-commit\" || exit \$?
# <<< synup malware scan <<<"
    for repo in "${husky_repos[@]}"; do
      hk="$repo/.husky/pre-commit"
      if [ "$INJECT_HUSKY" = 1 ]; then
        mkdir -p "$repo/.husky"
        if [ -f "$hk" ] && grep -qF "$SNIPPET_MARK" "$hk"; then
          ok "husky already wired: ${repo#"$ROOT_DIR"/}"
        else
          printf "%s\n" "$SNIPPET" >> "$hk"; chmod +x "$hk"
          ok "injected scan into ${repo#"$ROOT_DIR"/}/.husky/pre-commit (commit this change)"
        fi
      else
        warn "husky repo bypasses global hook: ${repo#"$ROOT_DIR"/}"
        warn "  add this to its .husky/pre-commit (or re-run with --inject-husky):"
        printf "%b\n" "    ${CYA}\"$HOOKS_DIR/pre-commit\" || exit \$?${RST}"
      fi
    done
  fi
fi

# ------------------------------------------------------------------
if [ "$DO_SIGNING" = 1 ]; then
step "3/4  Configuring SSH commit signing"
# ------------------------------------------------------------------
  if [ "$(git config --global commit.gpgsign 2>/dev/null)" = "true" ] \
     && [ -n "$(git config --global user.signingkey 2>/dev/null)" ]; then
    ok "commit signing already configured (key: $(git config --global user.signingkey))"
  else
    # Pick an existing SSH key or create a dedicated signing key.
    KEY=""
    for cand in "$HOME/.ssh/id_ed25519" "$HOME/.ssh/id_rsa"; do
      [ -f "$cand.pub" ] && { KEY="$cand"; break; }
    done
    if [ -z "$KEY" ]; then
      KEY="$HOME/.ssh/synup_signing_ed25519"
      info "no SSH key found — generating $KEY"
      ssh-keygen -t ed25519 -f "$KEY" -N "" -C "synup-signing-$(whoami)@$(hostname)" >/dev/null
      ok "generated signing key"
    else
      info "reusing existing SSH key: $KEY.pub"
    fi

    git config --global gpg.format ssh
    git config --global user.signingkey "$KEY.pub"
    git config --global commit.gpgsign true
    git config --global tag.gpgsign true

    # allowed_signers lets you locally `git log --show-signature` verify.
    email="$(git config --global user.email 2>/dev/null || echo "$(whoami)@synup.com")"
    mkdir -p "$(dirname "$ALLOWED_SIGNERS")"
    grep -qsF "$(cut -d' ' -f1-2 < "$KEY.pub")" "$ALLOWED_SIGNERS" 2>/dev/null || \
      printf '%s namespaces="git" %s\n' "$email" "$(cat "$KEY.pub")" >> "$ALLOWED_SIGNERS"
    git config --global gpg.ssh.allowedSignersFile "$ALLOWED_SIGNERS"
    ok "signing enabled (gpg.format=ssh, commit.gpgsign=true)"

    # Register the public key with GitHub as a *signing* key.
    if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
      if gh ssh-key add "$KEY.pub" --type signing --title "synup-signing-$(hostname)" >/dev/null 2>&1; then
        ok "uploaded signing key to GitHub"
      else
        warn "could not auto-upload to GitHub (key may already exist, or token lacks 'admin:ssh_signing_key')"
        warn "  add it manually: https://github.com/settings/ssh/new  (Key type: Signing Key)"
      fi
    else
      warn "gh CLI not authenticated — add the key as a Signing Key here:"
      warn "  https://github.com/settings/ssh/new"
      printf "%b\n" "    ${CYA}$(cat "$KEY.pub")${RST}"
    fi
  fi
fi

# ------------------------------------------------------------------
step "4/4  Done"
# ------------------------------------------------------------------
ok "Synup security hooks installed."
info "Test it:    cd <any-repo> && echo 'AKIA1234567890ABCDEF' > t.txt && git add t.txt && git commit -m test"
info "            (the commit should be blocked; then: rm t.txt)"
info "Verify sig: git log --show-signature -1"
info "Update later: re-run this installer (it pulls the latest scanner + hooks)."
