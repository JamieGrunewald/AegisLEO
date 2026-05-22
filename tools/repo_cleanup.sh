#!/usr/bin/env bash
set -Eeuo pipefail

# AegisLEO repo cleanup helper
# Default behavior: DRY RUN
# Use --apply to make changes

DRY_RUN=1
MOVE_LIBOQS=0
RENAME_LEGACY_FLOW=0
QUARANTINE_DUP_SIGS=1

ROOT_DIR="$(pwd)"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
QUARANTINE_DIR="${ROOT_DIR}/_cleanup_quarantine_${TIMESTAMP}"

log() {
  printf '[*] %s\n' "$1"
}

warn() {
  printf '[!] %s\n' "$1"
}

run_cmd() {
  local cmd="$1"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    printf '[DRY-RUN] %s\n' "$cmd"
  else
    printf '[APPLY]   %s\n' "$cmd"
    eval "$cmd"
  fi
}

usage() {
  cat <<'EOF'
Usage:
  bash tools/repo_cleanup.sh [options]

Options:
  --apply                 Apply changes. Without this, script is dry-run only.
  --move-liboqs           Move liboqs-python into third_party/liboqs-python
  --rename-legacy-flow    Rename receiver/transmitter legacy files
  --no-quarantine-sigs    Do not quarantine duplicate pq_sign modules
  -h, --help              Show this help

What it does:
  - removes __pycache__ directories and .pyc files
  - renames:
      adversary/replay_attach.py -> adversary/replay_attack.py
      tools/telemetry_visuallizer.py -> tools/telemetry_visualizer.py
  - optionally quarantines duplicate signature modules:
      ccsds/pq_sign.py
      crypto/pq_sign.py
    while keeping crypto/mldsa_signatures.py as the preferred implementation
  - optionally renames legacy receiver/transmitter files (--rename-legacy-flow)
    Note: legacy rename was completed during initial cleanup; this flag is a no-op
    on the current repo state but is retained for future refactoring cycles.
  - optionally moves liboqs-python into third_party/ (--move-liboqs)
    Note: liboqs-python is no longer vendored; install from source per docs/pqc_design.md.

Recommended first run:
  bash tools/repo_cleanup.sh

Then inspect output, and if it looks good:
  bash tools/repo_cleanup.sh --apply
EOF
}

ensure_quarantine_dir() {
  if [[ "${DRY_RUN}" -eq 0 ]]; then
    mkdir -p "${QUARANTINE_DIR}"
  fi
}

backup_and_move() {
  local src="$1"
  local dst="$2"

  if [[ ! -e "$src" ]]; then
    warn "Source not found, skipping: $src"
    return 0
  fi

  if [[ -e "$dst" ]]; then
    warn "Destination already exists, skipping move: $src -> $dst"
    return 0
  fi

  run_cmd "mv \"$src\" \"$dst\""
}

quarantine_file() {
  local src="$1"
  if [[ ! -e "$src" ]]; then
    warn "File not found, skipping quarantine: $src"
    return 0
  fi

  ensure_quarantine_dir
  local base
  base="$(basename "$src")"
  local dst="${QUARANTINE_DIR}/${base}"

  if [[ -e "$dst" ]]; then
    dst="${QUARANTINE_DIR}/${TIMESTAMP}_${base}"
  fi

  run_cmd "mv \"$src\" \"$dst\""
}

cleanup_python_artifacts() {
  log "Removing Python cache artifacts"
  run_cmd "find \"$ROOT_DIR\" -type d -name '__pycache__' -prune -exec rm -rf {} +"
  run_cmd "find \"$ROOT_DIR\" -type f \\( -name '*.pyc' -o -name '*.pyo' \\) -delete"
}

fix_typos() {
  log "Fixing obvious filename typos"

  if [[ -f "${ROOT_DIR}/adversary/replay_attach.py" ]]; then
    backup_and_move \
      "${ROOT_DIR}/adversary/replay_attach.py" \
      "${ROOT_DIR}/adversary/replay_attack.py"
  fi

  if [[ -f "${ROOT_DIR}/tools/telemetry_visuallizer.py" ]]; then
    backup_and_move \
      "${ROOT_DIR}/tools/telemetry_visuallizer.py" \
      "${ROOT_DIR}/tools/telemetry_visualizer.py"
  fi
}

quarantine_duplicate_signature_modules() {
  if [[ "${QUARANTINE_DUP_SIGS}" -eq 0 ]]; then
    log "Skipping duplicate signature module quarantine"
    return 0
  fi

  log "Quarantining duplicate signature modules"
  log "Preferred implementation remains: crypto/mldsa_signatures.py"

  if [[ -f "${ROOT_DIR}/ccsds/pq_sign.py" ]]; then
    quarantine_file "${ROOT_DIR}/ccsds/pq_sign.py"
  fi

  if [[ -f "${ROOT_DIR}/crypto/pq_sign.py" ]]; then
    quarantine_file "${ROOT_DIR}/crypto/pq_sign.py"
  fi
}

rename_legacy_secure_flow() {
  if [[ "${RENAME_LEGACY_FLOW}" -eq 0 ]]; then
    log "Skipping receiver/transmitter legacy-flow renames"
    return 0
  fi

  log "Renaming secure files into primary paths and preserving old versions as legacy"

  # Groundstation
  if [[ -f "${ROOT_DIR}/groundstation/receiver.py" && -f "${ROOT_DIR}/groundstation/receiver_secure.py" ]]; then
    if [[ ! -f "${ROOT_DIR}/groundstation/receiver_legacy.py" ]]; then
      backup_and_move \
        "${ROOT_DIR}/groundstation/receiver.py" \
        "${ROOT_DIR}/groundstation/receiver_legacy.py"
    else
      warn "groundstation/receiver_legacy.py already exists, skipping legacy rename"
    fi

    if [[ ! -f "${ROOT_DIR}/groundstation/receiver.py" ]]; then
      backup_and_move \
        "${ROOT_DIR}/groundstation/receiver_secure.py" \
        "${ROOT_DIR}/groundstation/receiver.py"
    else
      backup_and_move \
        "${ROOT_DIR}/groundstation/receiver_secure.py" \
        "${ROOT_DIR}/groundstation/receiver_secure.promote_me_manually.py"
    fi
  fi

  # Satellite
  if [[ -f "${ROOT_DIR}/satellite/transmitter.py" && -f "${ROOT_DIR}/satellite/transmitter_secure.py" ]]; then
    if [[ ! -f "${ROOT_DIR}/satellite/transmitter_legacy.py" ]]; then
      backup_and_move \
        "${ROOT_DIR}/satellite/transmitter.py" \
        "${ROOT_DIR}/satellite/transmitter_legacy.py"
    else
      warn "satellite/transmitter_legacy.py already exists, skipping legacy rename"
    fi

    if [[ ! -f "${ROOT_DIR}/satellite/transmitter.py" ]]; then
      backup_and_move \
        "${ROOT_DIR}/satellite/transmitter_secure.py" \
        "${ROOT_DIR}/satellite/transmitter.py"
    else
      backup_and_move \
        "${ROOT_DIR}/satellite/transmitter_secure.py" \
        "${ROOT_DIR}/satellite/transmitter_secure.promote_me_manually.py"
    fi
  fi
}

move_liboqs_into_third_party() {
  if [[ "${MOVE_LIBOQS}" -eq 0 ]]; then
    log "Skipping liboqs-python move"
    return 0
  fi

  log "Moving liboqs-python into third_party/"

  if [[ -d "${ROOT_DIR}/liboqs-python" ]]; then
    run_cmd "mkdir -p \"${ROOT_DIR}/third_party\""
    if [[ -d "${ROOT_DIR}/third_party/liboqs-python" ]]; then
      warn "third_party/liboqs-python already exists, skipping move"
    else
      run_cmd "mv \"${ROOT_DIR}/liboqs-python\" \"${ROOT_DIR}/third_party/liboqs-python\""
    fi
  else
    warn "liboqs-python directory not found, skipping"
  fi
}

print_post_steps() {
  cat <<EOF

Cleanup pass complete.

Suggested next steps:
  1. Review git diff
  2. Run tests:
       pytest tests -v
  3. Search for stale imports:
       grep -RIn "replay_attach\\|telemetry_visuallizer\\|pq_sign" .
  4. If you renamed legacy flows, verify imports for:
       groundstation.receiver
       satellite.transmitter

Quarantine directory:
  ${QUARANTINE_DIR}

EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --apply)
        DRY_RUN=0
        shift
        ;;
      --move-liboqs)
        MOVE_LIBOQS=1
        shift
        ;;
      --rename-legacy-flow)
        RENAME_LEGACY_FLOW=1
        shift
        ;;
      --no-quarantine-sigs)
        QUARANTINE_DUP_SIGS=0
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        warn "Unknown option: $1"
        usage
        exit 1
        ;;
    esac
  done
}

main() {
  parse_args "$@"

  log "Repo root: ${ROOT_DIR}"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    warn "Running in DRY-RUN mode. No files will be changed."
  else
    warn "Running in APPLY mode. Files will be modified."
  fi

  cleanup_python_artifacts
  fix_typos
  quarantine_duplicate_signature_modules
  rename_legacy_secure_flow
  move_liboqs_into_third_party
  print_post_steps
}

main "$@"
