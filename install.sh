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
#   --root DIR              Directory to scan for husky repos (default: $PWD)
#   --no-signing            Skip SSH commit-signing setup
#   --no-hooks              Skip git hook setup
#   --inject-husky          Auto-add the scan to husky repos' .husky/pre-commit
#   --reconfigure-signing   Re-run signing setup even if already configured
#                           (e.g. to switch an existing key to Secretive)
#   --signing-method M      secretive | passphrase  (skip the prompt; pick M)
#   -h, --help              Show this help
# ------------------------------------------------------------------
set -euo pipefail

# Override REPO_URL/REPO_REF (and SYNUP_HOME) to test a fork/branch before merge, e.g.:
#   SYNUP_HOME=/tmp/synup-test SYNUP_REPO_URL=https://github.com/<you>/security-workflows.git \
#   SYNUP_REPO_REF=add-precommit-hooks-and-signing ./install.sh
REPO_URL="${SYNUP_REPO_URL:-https://github.com/synup/security-workflows.git}"
REPO_REF="${SYNUP_REPO_REF:-}"
SYNUP_HOME_DIR="${SYNUP_HOME:-$HOME/.synup}"
INSTALL_DIR="$SYNUP_HOME_DIR/security-workflows"
HOOKS_DIR="$INSTALL_DIR/hooks"
ALLOWED_SIGNERS="$SYNUP_HOME_DIR/allowed_signers"

ROOT_DIR="$PWD"
DO_SIGNING=1
DO_HOOKS=1
INJECT_HUSKY=0
RECONFIGURE_SIGNING=0
SIGNING_METHOD="${SYNUP_SIGNING_METHOD:-}"   # secretive | passphrase | "" (prompt/auto)

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; CYA='\033[0;36m'; BLD='\033[1m'; RST='\033[0m'
info()  { printf "%b\n" "${CYA}▸${RST} $*"; }
ok()    { printf "%b\n" "${GRN}✓${RST} $*"; }
warn()  { printf "%b\n" "${YEL}!${RST} $*"; }
err()   { printf "%b\n" "${RED}✗${RST} $*" >&2; }
step()  { printf "\n%b\n" "${BLD}$*${RST}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --root)                 ROOT_DIR="$2"; shift 2 ;;
    --no-signing)           DO_SIGNING=0; shift ;;
    --no-hooks)             DO_HOOKS=0; shift ;;
    --inject-husky)         INJECT_HUSKY=1; shift ;;
    --reconfigure-signing)  RECONFIGURE_SIGNING=1; shift ;;
    --signing-method)       SIGNING_METHOD="$2"; shift 2 ;;
    -h|--help)              sed -n '2,34p' "$0"; exit 0 ;;
    *)               err "unknown option: $1"; exit 2 ;;
  esac
done

command -v git >/dev/null 2>&1 || { err "git is required"; exit 1; }

# ------------------------------------------------------------------
step "1/4  Fetching security-workflows → $INSTALL_DIR"
# ------------------------------------------------------------------
mkdir -p "$(dirname "$INSTALL_DIR")"
if [ -d "$INSTALL_DIR/.git" ]; then
  git -C "$INSTALL_DIR" remote set-url origin "$REPO_URL" 2>/dev/null || true
  git -C "$INSTALL_DIR" fetch --quiet origin
  if [ -n "$REPO_REF" ]; then
    git -C "$INSTALL_DIR" checkout --quiet "$REPO_REF"
    git -C "$INSTALL_DIR" pull --ff-only --quiet origin "$REPO_REF" && ok "updated to $REPO_REF"
  else
    git -C "$INSTALL_DIR" pull --ff-only --quiet && ok "updated existing checkout"
  fi
else
  git clone --quiet "$REPO_URL" "$INSTALL_DIR" && ok "cloned"
  [ -n "$REPO_REF" ] && { git -C "$INSTALL_DIR" checkout --quiet "$REPO_REF" && ok "checked out $REPO_REF"; }
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
fi

# --- husky repos set a local core.hooksPath that overrides the global hook ---
# Runs whenever hooks are being set up OR --inject-husky is requested, so the
# flag still works alongside --no-hooks.
if [ "$DO_HOOKS" = 1 ] || [ "$INJECT_HUSKY" = 1 ]; then
  step "Checking for husky repos under $ROOT_DIR"
  husky_repos=()
  while IFS= read -r gitdir; do
    [ -n "$gitdir" ] || continue
    repo="$(dirname "$gitdir")"                       # works for .git dir OR worktree .git file
    local_hp="$(git -C "$repo" config --local core.hooksPath 2>/dev/null || true)"
    [ -n "$local_hp" ] && husky_repos+=("$repo")
  done < <(find "$ROOT_DIR" -name node_modules -prune -o -name .git -print 2>/dev/null)

  if [ ${#husky_repos[@]} -eq 0 ]; then
    if [ "$INJECT_HUSKY" = 1 ]; then
      warn "--inject-husky: no husky repos found under '$ROOT_DIR'."
      warn "  Point --root at the folder that CONTAINS your repos, e.g.:"
      warn "    --root ~/Documents/synup-projects"
    else
      ok "no husky/local-hooksPath repos found"
    fi
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
  # --- shared: trust the key locally + register it on GitHub as a SIGNING key ---
  register_signing_pub() {
    local pubfile="$1"
    git config --global gpg.format ssh
    git config --global user.signingkey "$pubfile"
    git config --global commit.gpgsign true
    git config --global tag.gpgsign true

    # allowed_signers lets you locally `git log --show-signature` verify.
    local email; email="$(git config --global user.email 2>/dev/null || echo "$(whoami)@synup.com")"
    mkdir -p "$(dirname "$ALLOWED_SIGNERS")"
    grep -qsF "$(cut -d' ' -f1-2 < "$pubfile")" "$ALLOWED_SIGNERS" 2>/dev/null || \
      printf '%s namespaces="git" %s\n' "$email" "$(cat "$pubfile")" >> "$ALLOWED_SIGNERS"
    git config --global gpg.ssh.allowedSignersFile "$ALLOWED_SIGNERS"

    # Register on GitHub as a *signing* key (cannot be used to push).
    if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
      if gh ssh-key add "$pubfile" --type signing --title "synup-signing-$(hostname)" >/dev/null 2>&1; then
        ok "registered signing key on GitHub"
      else
        warn "couldn't auto-upload to GitHub (key may already exist, or token lacks 'admin:ssh_signing_key')"
        warn "  add it manually at https://github.com/settings/ssh/new  (Key type: Signing Key)"
      fi
    else
      warn "gh not authenticated — add this as a Signing Key at https://github.com/settings/ssh/new :"
      printf "%b\n" "    ${CYA}$(cat "$pubfile")${RST}"
    fi
  }

  if [ "$(git config --global commit.gpgsign 2>/dev/null)" = "true" ] \
     && [ -n "$(git config --global user.signingkey 2>/dev/null)" ] \
     && [ "$RECONFIGURE_SIGNING" != 1 ]; then
    ok "commit signing already configured (key: $(git config --global user.signingkey))"
    info "to switch it (e.g. to Secretive), re-run with --reconfigure-signing"
  else
    # --reconfigure-signing: clear our prior signing config so detection starts
    # clean and can switch key types (e.g. file key → Secure Enclave). Guarded
    # so we only drop config we created, never a developer's own setup.
    if [ "$RECONFIGURE_SIGNING" = 1 ]; then
      prog="$(git config --global gpg.ssh.program 2>/dev/null || true)"
      case "$prog" in "$SYNUP_HOME_DIR"/*) git config --global --unset gpg.ssh.program 2>/dev/null || true ;; esac
      info "reconfiguring signing (clearing previous synup signing config)…"
    fi

    SE_SOCK="$HOME/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh"
    SE_PUB=""
    if [ -S "$SE_SOCK" ]; then
      # Match any SSH public-key type. Secure Enclave keys are ECDSA P-256
      # (ecdsa-sha2-nistp256), so a plain '^ssh-' match misses them.
      SE_PUB="$(SSH_AUTH_SOCK="$SE_SOCK" ssh-add -L 2>/dev/null | grep -m1 -E '^(ssh-|ecdsa-|sk-)' || true)"
    fi

    # Can we open the controlling terminal to prompt? (-e /dev/tty isn't enough —
    # the node exists even when it's not usable, e.g. in CI.)
    HAVE_TTY=0
    if ( exec 3<>/dev/tty ) 2>/dev/null; then HAVE_TTY=1; fi

    # ---- choose the signing method: --signing-method/env > prompt > auto ----
    case "$SIGNING_METHOD" in
      secretive|passphrase) METHOD="$SIGNING_METHOD" ;;
      ""|auto)              METHOD="" ;;
      *) warn "unknown --signing-method '$SIGNING_METHOD' — ignoring"; METHOD="" ;;
    esac
    if [ -z "$METHOD" ] && [ "$HAVE_TTY" = 1 ]; then
      if [ -n "$SE_PUB" ]; then se_tag="detected ✓ — recommended"; def=1; else se_tag="not set up; needs Secretive app + a key"; def=2; fi
      printf "\nChoose your commit-signing method:\n" > /dev/tty
      printf "  1) Secure Enclave via Secretive  [%s]\n" "$se_tag" > /dev/tty
      printf "  2) Passphrase-protected key file\n" > /dev/tty
      printf "Enter choice [%s]: " "$def" > /dev/tty
      IFS= read -r choice < /dev/tty; [ -z "$choice" ] && choice="$def"
      case "$choice" in
        1) METHOD=secretive ;;
        2) METHOD=passphrase ;;
        *) warn "invalid choice — using passphrase"; METHOD=passphrase ;;
      esac
    fi
    [ -z "$METHOD" ] && { [ -n "$SE_PUB" ] && METHOD=secretive || METHOD=passphrase; }   # non-interactive auto
    if [ "$METHOD" = secretive ] && [ -z "$SE_PUB" ]; then
      if [ -d "/Applications/Secretive.app" ]; then
        warn "Secretive is installed but has no key yet — create one in the app, then re-run with --reconfigure-signing."
      else
        warn "Secretive not detected (install it + create a key first: https://github.com/maxgoedjen/secretive )."
      fi
      warn "Using a passphrased file key for now."
      METHOD=passphrase
    fi

    # ---------- Path A: Secure Enclave via Secretive (key never touches disk) ----------
    if [ "$METHOD" = secretive ]; then
      info "Using Secure Enclave (Secretive) — private key stays in the chip, can't be copied off disk"
      SE_PUBFILE="${SYNUP_HOME:-$HOME/.synup}/secretive_signing.pub"
      printf '%s\n' "$SE_PUB" > "$SE_PUBFILE"

      # Point git's signer at Secretive's agent for SIGNING ONLY, so your normal
      # SSH auth/push agent is left untouched.
      WRAPPER="${SYNUP_HOME:-$HOME/.synup}/ssh-keygen-secretive"
      cat > "$WRAPPER" <<EOF
#!/bin/sh
# Routes git's SSH signing through Secretive's Secure Enclave agent only.
SSH_AUTH_SOCK="$SE_SOCK" exec "$(command -v ssh-keygen)" "\$@"
EOF
      chmod +x "$WRAPPER"
      git config --global gpg.ssh.program "$WRAPPER"
      register_signing_pub "$SE_PUBFILE"
      ok "signing enabled via Secure Enclave (Secretive)"

    # ---------- Path B: dedicated, passphrase-protected file key ----------
    else
      info "Using a dedicated passphrase-protected key file"

      KEY="$HOME/.ssh/synup_signing_ed25519"
      git config --global --unset gpg.ssh.program 2>/dev/null || true

      if [ -f "$KEY.pub" ]; then
        info "reusing existing dedicated signing key: $KEY.pub"
      elif [ "$HAVE_TTY" = 1 ]; then
        # Prompt for a passphrase on the controlling terminal (works under curl|bash).
        PASS=""; PASS2="x"
        while [ "$PASS" != "$PASS2" ]; do
          printf "Enter a passphrase for your new signing key: " > /dev/tty
          IFS= read -rs PASS < /dev/tty; printf "\n" > /dev/tty
          printf "Confirm passphrase: " > /dev/tty
          IFS= read -rs PASS2 < /dev/tty; printf "\n" > /dev/tty
          [ "$PASS" != "$PASS2" ] && warn "passphrases didn't match — try again"
        done
        if [ -z "$PASS" ]; then
          warn "empty passphrase — the key file will be usable by anyone who copies it!"
        fi
        ssh-keygen -t ed25519 -f "$KEY" -N "$PASS" -C "synup-signing-$(whoami)@$(hostname)" >/dev/null
        unset PASS PASS2
        ok "generated passphrased signing key"
        # Cache the passphrase in the macOS Keychain so you aren't retyping it.
        if [ "$(uname)" = "Darwin" ]; then
          ssh-add --apple-use-keychain "$KEY" </dev/tty 2>/dev/null || true
          SSHCFG="$HOME/.ssh/config"; touch "$SSHCFG"; chmod 600 "$SSHCFG"
          if ! grep -qsF "synup signing keychain" "$SSHCFG"; then
            { printf '\n# >>> synup signing keychain >>>\nHost *\n  AddKeysToAgent yes\n  UseKeychain yes\n# <<< synup signing keychain <<<\n'; } >> "$SSHCFG"
          fi
        fi
      else
        warn "no terminal available for a passphrase prompt — generating WITHOUT a passphrase."
        warn "  add one afterwards with:  ssh-keygen -p -f $KEY"
        ssh-keygen -t ed25519 -f "$KEY" -N "" -C "synup-signing-$(whoami)@$(hostname)" >/dev/null
      fi
      register_signing_pub "$KEY.pub"
      ok "signing enabled via file key ($KEY.pub)"
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
