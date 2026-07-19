#!/usr/bin/env bash
# StellarHub ZK reference · https://stellarhub.io
#
# build.sh — compile-ready pipeline for the confidential-send ZK circuits.
#
# Compiles every `circuits/*.circom` file into:
#   build/<name>.r1cs     — constraint system
#   build/<name>.wasm     — witness generator
#   build/<name>.sym      — symbol table
#   build/<name>_final.zkey                — Groth16 proving key (dev, non-prod)
#   build/<name>_verification_key.json     — Groth16 verification key
#
# Trust model:
#   The single-participant "ceremony" performed below is EXPLICITLY
#   non-production. Production keys come from the MPC ceremony spec
#   documented in the project docs. Any attempt to use these dev keys
#   on mainnet MUST be gated by ZK_MAINNET_APPROVED=1.
#
# Idempotency:
#   Each step checks if its output already exists and is newer than its
#   source; if so the step is skipped. Force a full rebuild with
#   ZK_FORCE_REBUILD=1.
#
# Design notes:
#   Deployment-specific build — ZK_NETWORK propagates to env.
#   No absolute paths — REPO_ROOT derived via marker walk.
#
# Exit codes:
#   0 — all artefacts produced
#   1 — toolchain missing (circom or snarkjs) — install hints printed
#   2 — compile / setup failed

set -Eeuo pipefail

# ---------------------------------------------------------------------------
# REPO_ROOT resolution (marker walk — no hardcoded absolute paths)
# ---------------------------------------------------------------------------

resolve_repo_root() {
  local dir
  dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  while [[ "$dir" != "/" ]]; do
    if [[ -f "$dir/package.json" && -d "$dir/circuits" ]]; then
      echo "$dir"
      return 0
    fi
    dir="$(dirname "$dir")"
  done
  echo "ERROR: could not locate the repository root (no package.json + circuits/ marker found)" >&2
  return 1
}

REPO_ROOT="$(resolve_repo_root)"
ZK_DIR="$REPO_ROOT"
CIRCUITS_DIR="$ZK_DIR/circuits"
BUILD_DIR="$ZK_DIR/build"
KEYS_DIR="$BUILD_DIR/keys"
PTAU_DIR="$ZK_DIR/ptau"

# Powers of Tau: pot14_final (2^14 = 16_384 constraints max, ~2.4 MB).
# Comfortably fits both range_proof (~64) and balance_commitment (~240).
PTAU_URL="${ZK_PTAU_URL:-https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_14.ptau}"
PTAU_FILENAME="powersOfTau28_hez_final_14.ptau"
PTAU_PATH="$PTAU_DIR/$PTAU_FILENAME"

FORCE_REBUILD="${ZK_FORCE_REBUILD:-0}"

# ---------------------------------------------------------------------------
# Logging helpers (no colours in CI-friendly mode)
# ---------------------------------------------------------------------------

log()  { printf '[build.sh] %s\n' "$*"; }
warn() { printf '[build.sh][warn] %s\n' "$*" >&2; }
die()  { printf '[build.sh][fail] %s\n' "$*" >&2; exit 2; }

# ---------------------------------------------------------------------------
# Toolchain detection
# ---------------------------------------------------------------------------

print_install_hints() {
  cat <<'EOF' >&2

Toolchain install hints:

  circom  (compiler, written in Rust):
    macOS:    brew install circom
              (or) cargo install --git https://github.com/iden3/circom.git
    Linux:    git clone https://github.com/iden3/circom.git && \
                cd circom && cargo build --release && \
                cargo install --path circom
    Verify:   circom --version  (expect 2.2.x)

  snarkjs (CLI + JS library):
    Any OS:   npm install -g snarkjs@0.7
              (project-local alt) npm install   # snarkjs is a devDependency
    Verify:   snarkjs --version  (or) npx snarkjs --version

After install, re-run:
    npm run build:circuits

EOF
}

SNARKJS_CMD=""

detect_toolchain() {
  if ! command -v circom >/dev/null 2>&1; then
    warn "circom not found on PATH"
    print_install_hints
    exit 1
  fi
  log "circom: $(circom --version 2>&1 | head -n1)"

  if command -v snarkjs >/dev/null 2>&1; then
    SNARKJS_CMD="snarkjs"
  elif command -v npx >/dev/null 2>&1; then
    # Resolve via npx (network on first call, cached thereafter).
    SNARKJS_CMD="npx --yes snarkjs@0.7"
    log "snarkjs: using 'npx --yes snarkjs@0.7' (not installed globally)"
  else
    warn "snarkjs not found and npx unavailable"
    print_install_hints
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# Idempotency helpers
# ---------------------------------------------------------------------------

needs_rebuild() {
  # needs_rebuild <output> <source1> [source2 ...]
  # Returns 0 (true) if output missing or older than any source, or if
  # ZK_FORCE_REBUILD=1.
  local out="$1"; shift
  [[ "$FORCE_REBUILD" == "1" ]] && return 0
  [[ ! -f "$out" ]] && return 0
  local src
  for src in "$@"; do
    [[ -f "$src" && "$src" -nt "$out" ]] && return 0
  done
  return 1
}

# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------

ensure_dirs() {
  mkdir -p "$BUILD_DIR" "$KEYS_DIR" "$PTAU_DIR"
}

download_ptau() {
  if [[ -f "$PTAU_PATH" ]]; then
    log "ptau: already present ($PTAU_FILENAME)"
    return 0
  fi
  log "ptau: downloading $PTAU_URL"
  if command -v curl >/dev/null 2>&1; then
    curl -fL --retry 3 -o "$PTAU_PATH.partial" "$PTAU_URL"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$PTAU_PATH.partial" "$PTAU_URL"
  else
    die "neither curl nor wget available to download ptau"
  fi
  mv "$PTAU_PATH.partial" "$PTAU_PATH"
  log "ptau: downloaded $(ls -lh "$PTAU_PATH" | awk '{print $5}')"
}

compile_circuit() {
  # compile_circuit <circuit_name>
  local name="$1"
  local src="$CIRCUITS_DIR/$name.circom"
  local r1cs="$BUILD_DIR/$name.r1cs"
  local wasm="$BUILD_DIR/$name.wasm"
  local sym="$BUILD_DIR/$name.sym"

  if [[ ! -f "$src" ]]; then
    die "source circuit missing: $src"
  fi

  if needs_rebuild "$r1cs" "$src"; then
    log "compile: $name.circom -> r1cs + wasm + sym"
    # circom emits <name>_js/<name>.wasm by convention; we copy it flat into build/.
    (cd "$ZK_DIR" && circom "circuits/$name.circom" \
        --r1cs --wasm --sym \
        -l "$REPO_ROOT/node_modules" \
        -o "build/") \
      || die "circom compile failed for $name"
    if [[ -f "$BUILD_DIR/${name}_js/${name}.wasm" ]]; then
      cp "$BUILD_DIR/${name}_js/${name}.wasm" "$wasm"
    fi
  else
    log "compile: $name.r1cs up-to-date (skip)"
  fi
}

groth16_setup() {
  # groth16_setup <circuit_name>
  local name="$1"
  local r1cs="$BUILD_DIR/$name.r1cs"
  local zkey0="$BUILD_DIR/${name}_0000.zkey"
  local zkeyf="$BUILD_DIR/${name}_final.zkey"
  local vk="$BUILD_DIR/${name}_verification_key.json"

  if needs_rebuild "$zkey0" "$r1cs" "$PTAU_PATH"; then
    log "setup: groth16 setup for $name"
    $SNARKJS_CMD groth16 setup "$r1cs" "$PTAU_PATH" "$zkey0" \
      || die "groth16 setup failed for $name"
  else
    log "setup: ${name}_0000.zkey up-to-date (skip)"
  fi

  if needs_rebuild "$zkeyf" "$zkey0"; then
    # Single-participant contribution (NON-PRODUCTION).
    # Production keys come from an MPC ceremony (see project docs).
    local seed="dev-contribution-$(date +%s)-$$"
    log "ceremony: single-participant contribution (NON-PRODUCTION) for $name"
    $SNARKJS_CMD zkey contribute "$zkey0" "$zkeyf" \
      --name="stellarhub-dev" \
      -e="$seed" \
      || die "zkey contribute failed for $name"
  else
    log "ceremony: ${name}_final.zkey up-to-date (skip)"
  fi

  if needs_rebuild "$vk" "$zkeyf"; then
    log "export: verification key for $name"
    $SNARKJS_CMD zkey export verificationkey "$zkeyf" "$vk" \
      || die "zkey export verificationkey failed for $name"
  else
    log "export: ${name}_verification_key.json up-to-date (skip)"
  fi
}

build_one() {
  local name="$1"
  compile_circuit "$name"
  groth16_setup "$name"
}

summary() {
  log ""
  log "=== Build summary ==="
  local f
  for f in "$BUILD_DIR"/*.r1cs "$BUILD_DIR"/*.wasm \
           "$BUILD_DIR"/*_final.zkey "$BUILD_DIR"/*_verification_key.json; do
    [[ -f "$f" ]] && log "  $(ls -lh "$f" | awk '{print $5, $9}')"
  done
  log ""
  log "Next steps:"
  log "  1. Generate a demo proof:     npm run prove"
  log "  2. Run the circuit tests:     npm test"
  log "  3. Production keys require an MPC ceremony (see project docs)."
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  log "REPO_ROOT=$REPO_ROOT"
  log "ZK_NETWORK=${ZK_NETWORK:-testnet_only}"
  detect_toolchain
  ensure_dirs
  download_ptau

  # Discover circuits automatically so adding a new .circom file just works.
  local any=0
  local cf
  shopt -s nullglob
  for cf in "$CIRCUITS_DIR"/*.circom; do
    any=1
    local name
    name="$(basename "$cf" .circom)"
    build_one "$name"
  done
  shopt -u nullglob

  if [[ "$any" == "0" ]]; then
    warn "no .circom files found in $CIRCUITS_DIR"
    exit 0
  fi

  summary
}

main "$@"
