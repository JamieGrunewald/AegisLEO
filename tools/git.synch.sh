#!/usr/bin/env bash:
set -euo pipefail

# Simple Git helper for AegisLEO
# Usage:
#   ./git-sync.sh pull
#   ./git-sync.sh push "your commit message"
#   ./git-sync.sh status
#   ./git-sync.sh branch

REPO_DIR="${REPO_DIR:-$HOME/projects/satellite-lab}"

if [[ ! -d "$REPO_DIR/.git" ]]; then
  echo "[ERROR] Git repo not found at: $REPO_DIR"
  exit 1
fi

cd "$REPO_DIR"

current_branch() {
  git rev-parse --abbrev-ref HEAD
}

ensure_clean_remote() {
  echo "[INFO] Fetching remote state..."
  git fetch origin
}

do_pull() {
  local branch
  branch="$(current_branch)"
  echo "[INFO] Repo: $REPO_DIR"
  echo "[INFO] Branch: $branch"
  ensure_clean_remote
  echo "[INFO] Pulling latest changes from origin/$branch ..."
  git pull --no-rebase origin "$branch"
  echo "[OK] Pull complete."
}

do_push() {
  local msg="${1:-}"
  local branch
  branch="$(current_branch)"

  if [[ -z "$msg" ]]; then
    echo "[ERROR] Commit message required."
    echo "Usage: ./git-sync.sh push \"your commit message\""
    exit 1
  fi

  echo "[INFO] Repo: $REPO_DIR"
  echo "[INFO] Branch: $branch"

  ensure_clean_remote

  echo "[INFO] Staging changes..."
  git add -A

  if git diff --cached --quiet; then
    echo "[INFO] No staged changes to commit."
  else
    echo "[INFO] Committing..."
    git commit -m "$msg"
  fi

  echo "[INFO] Pulling latest remote changes before push..."
  git pull --no-rebase origin "$branch"

  echo "[INFO] Pushing to origin/$branch ..."
  git push -u origin "$branch"
  echo "[OK] Push complete."
}

do_status() {
  echo "[INFO] Repo: $REPO_DIR"
  git status
  echo
  git remote -v
}

do_branch() {
  echo "[INFO] Current branch: $(current_branch)"
}

case "${1:-}" in
  pull)
    do_pull
    ;;
  push)
    shift
    do_push "${1:-}"
    ;;
  status)
    do_status
    ;;
  branch)
    do_branch
    ;;
  *)
    cat <<'EOF'
Usage:
  ./git-sync.sh pull
  ./git-sync.sh push "your commit message"
  ./git-sync.sh status
  ./git-sync.sh branch

Optional:
  REPO_DIR=/path/to/repo ./git-sync.sh pull
EOF
    exit 1
    ;;
esac
