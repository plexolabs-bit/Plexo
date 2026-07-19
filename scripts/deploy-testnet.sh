#!/usr/bin/env bash
# StellarHub — Confidential Send on Stellar · https://stellarhub.io
#
# deploy-testnet.sh — friendbot-fund a FRESH identity and deploy the two
# Confidential Send contracts to Stellar testnet, then print their FRESH
# contract addresses and stellar.expert explorer links.
#
#   Contracts deployed (all Groth16 / BLS12-381 over Soroban host functions):
#     1. groth16-verifier    — generic on-chain Groth16 verifier (verify_proof)
#     2. zk-verified-payment — a payment that executes only on a valid proof
#                              with an unspent nullifier (pay_verified)
#
# Each run is reproducible and self-contained: it creates a brand-new funded
# testnet identity and brand-new contract instances. The README's pre-deployed
# reference addresses are SEPARATE (instant proof) and are never touched here.
#
# Requirements: the Stellar CLI and Rust/cargo (for the wasm build). The wasm32
# build target is added automatically if rustup is available.
#
# Usage:  bash scripts/deploy-testnet.sh        (normally invoked by ./run.sh --testnet)
#
# All command flags target stellar-cli 26.x.   # verify against stellar --version
set -euo pipefail

# Repo root = parent of this script's directory (no hardcoded absolute paths).
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
NETWORK="${STELLAR_NETWORK:-testnet}"
EXPLORER="https://stellar.expert/explorer/${NETWORK}"
OUT_DIR="build/contracts-wasm"                       # where built wasm is collected
IDENTITY="${DEMO_IDENTITY:-cs-demo-$(date +%Y%m%d-%H%M%S)-$$}"  # fresh, unique per run
LOG="$(mktemp -t cs-deploy.XXXXXX)"                  # verbose CLI output (shown on error)

# ---------------------------------------------------------------------------
# Output helpers (colour only on an interactive terminal)
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
  BOLD="$(printf '\033[1m')"; DIM="$(printf '\033[2m')"
  CYAN="$(printf '\033[36m')"; GREEN="$(printf '\033[32m')"
  YELLOW="$(printf '\033[33m')"; RESET="$(printf '\033[0m')"
else
  BOLD=""; DIM=""; CYAN=""; GREEN=""; YELLOW=""; RESET=""
fi
step() { printf '\n%s%s» %s%s\n' "$BOLD" "$CYAN" "$*" "$RESET"; }
ok()   { printf '%s  ✓ %s%s\n' "$GREEN" "$*" "$RESET"; }
note() { printf '%s  · %s%s\n' "$DIM" "$*" "$RESET"; }
warn() { printf '%s  ! %s%s\n' "$YELLOW" "$*" "$RESET"; }
die()  { printf '\n%s  ✗ %s%s\n' "$YELLOW" "$*" "$RESET" >&2; [[ -s "$LOG" ]] && { echo "  --- last CLI output ---" >&2; tail -n 20 "$LOG" >&2; }; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# A Soroban contract id is 56 chars of base32 (alphabet A-Z, 2-7) starting with 'C'.
is_contract_id() { [[ "$1" =~ ^C[A-Z2-7]{55}$ ]]; }

# Contracts: "<source dir>|<built wasm basename>" (basename = cargo package name
# with dashes turned into underscores).
CONTRACTS=(
  "contracts/groth16-verifier|stellar_confidential_send_verifier.wasm"
  "contracts/zk-verified-payment|stellar_zk_verified_payment.wasm"
)

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
step "Preflight"
have stellar || die "Stellar CLI not found. Install it: https://developers.stellar.org/docs/tools/cli"
have cargo   || die "Rust/cargo not found. Install it: https://rustup.rs"
ok "stellar $(stellar --version 2>/dev/null | head -n1 | awk '{print $2}')   cargo $(cargo --version 2>/dev/null | awk '{print $2}')"

# Make sure a wasm build target is installed (best-effort; non-fatal). stellar-cli
# 26.x builds for `wasm32v1-none`; older toolchains use `wasm32-unknown-unknown`.
# Adding an already-installed target is a harmless no-op.  # verify against stellar --version
if have rustup; then
  note "ensuring a wasm build target is installed…"
  rustup target add wasm32v1-none          >>"$LOG" 2>&1 || true
  rustup target add wasm32-unknown-unknown >>"$LOG" 2>&1 || true
fi
ok "network: $NETWORK"

# ---------------------------------------------------------------------------
# 1. Fresh, friendbot-funded testnet identity
# ---------------------------------------------------------------------------
step "Creating + funding a fresh testnet identity (Friendbot)"
note "identity alias: $IDENTITY"
# `--fund` funds the new key via Friendbot on a test network. If the combined
# generate+fund hiccups (Friendbot can be flaky), fall back to an explicit fund.
if ! stellar keys generate "$IDENTITY" --network "$NETWORK" --fund --overwrite >>"$LOG" 2>&1; then
  stellar keys generate "$IDENTITY" --overwrite >>"$LOG" 2>&1 || die "could not generate a testnet identity."
  stellar keys fund "$IDENTITY" --network "$NETWORK" >>"$LOG" 2>&1 || die "Friendbot funding failed — try again in a moment."
fi
ADDRESS="$(stellar keys public-key "$IDENTITY" 2>>"$LOG" | tr -d '[:space:]')"
[[ -n "$ADDRESS" ]] || die "could not read the funded account address."
ok "funded account: $ADDRESS"
note "$EXPLORER/account/$ADDRESS"

# ---------------------------------------------------------------------------
# 2. Build the contracts to wasm (cargo-backed; skipped if already built)
# ---------------------------------------------------------------------------
step "Building contracts to wasm"
mkdir -p "$OUT_DIR"
for entry in "${CONTRACTS[@]}"; do
  dir="${entry%%|*}"; wasm="${entry##*|}"
  if [[ -f "$OUT_DIR/$wasm" ]]; then
    note "$wasm already built — skipping"
    continue
  fi
  note "building $dir …"
  # `stellar contract build` wraps cargo and copies the wasm into --out-dir.
  stellar contract build --manifest-path "$dir/Cargo.toml" --out-dir "$OUT_DIR" >>"$LOG" 2>&1 \
    || die "build failed for $dir (see CLI output above)."
  [[ -f "$OUT_DIR/$wasm" ]] || die "expected wasm not produced: $OUT_DIR/$wasm (check the cargo package name)."
  ok "built $wasm"
done

# ---------------------------------------------------------------------------
# 3. Deploy each contract → fresh contract id
# ---------------------------------------------------------------------------
step "Deploying fresh contracts to $NETWORK"
deploy_one() {
  local wasm="$1" label="$2" id attempt
  # Retry transient testnet hiccups (e.g. "transaction submission timeout"). All
  # progress messages go to STDERR so the captured stdout is ONLY the contract id.
  for attempt in 1 2 3; do
    id="$(stellar contract deploy --wasm "$OUT_DIR/$wasm" --source-account "$IDENTITY" --network "$NETWORK" 2>>"$LOG" | tr -d '[:space:]')"
    if is_contract_id "$id"; then printf '%s' "$id"; return 0; fi
    if [[ "$attempt" -lt 3 ]]; then
      printf '%s  · %s deploy attempt %s did not confirm (testnet can be flaky) — retrying…%s\n' "$DIM" "$label" "$attempt" "$RESET" >&2
      sleep 4
    fi
  done
  printf '%s  ! could not deploy %s after 3 attempts (last id: %s)%s\n' "$YELLOW" "$label" "${id:-<empty>}" "$RESET" >&2
  return 1
}

VERIFIER_ID="$(deploy_one stellar_confidential_send_verifier.wasm groth16-verifier)" || die "deploy failed: groth16-verifier"
ok "groth16-verifier    → $VERIFIER_ID"
PAYMENT_ID="$(deploy_one stellar_zk_verified_payment.wasm zk-verified-payment)" || die "deploy failed: zk-verified-payment"
ok "zk-verified-payment → $PAYMENT_ID"

# ---------------------------------------------------------------------------
# 4. (best-effort) Initialize zk-verified-payment with the native XLM SAC + the
#    circuit's verifying key. Non-fatal: transcoding the snarkjs VK into the
#    contract's BLS12-381 byte form needs the @noble/curves helper (see
#    scripts/vk_to_soroban.mjs). If it is not installed we skip
#    init and point at the deterministic on-chain check instead — we never
#    fabricate a result.
# ---------------------------------------------------------------------------
step "Initializing zk-verified-payment (best-effort)"
NOBLE_OK=0
node -e "import('@noble/curves/bls12-381.js').then(()=>process.exit(0)).catch(()=>process.exit(1))" >/dev/null 2>&1 && NOBLE_OK=1

if [[ "$NOBLE_OK" -eq 1 ]]; then
  # Native XLM wrapped as a Stellar Asset Contract (deterministic id on testnet).
  SAC="$(stellar contract id asset --asset native --network "$NETWORK" 2>>"$LOG" | tr -d '[:space:]')" || SAC=""
  # Transcode build/.../verification_key.json -> the --vk JSON the contract expects.
  VK_JSON="$(node scripts/vk_to_soroban.mjs contracts/zk-verified-payment/data/verification_key.json 2>>"$LOG")" || VK_JSON=""
  if [[ -n "$SAC" && -n "$VK_JSON" ]]; then
    # initialize(token: Address, vk: VerificationKey)            # verify against stellar --version
    if stellar contract invoke --id "$PAYMENT_ID" --source-account "$IDENTITY" --network "$NETWORK" \
         -- initialize --token "$SAC" --vk "$VK_JSON" >>"$LOG" 2>&1; then
      ok "initialized with native XLM SAC + verifying key (token: $SAC)"
    else
      warn "initialize invoke did not complete (arg encoding can vary by CLI version) — # verify against stellar --version"
    fi
  else
    note "skipping init — could not resolve the native SAC id or transcode the VK."
  fi
else
  note "skipping init — the @noble/curves helper is not installed (npm i @noble/curves to enable VK transcoding)."
fi

# On-chain proof submission (verify_proof / pay_verified) takes the
# Groth16 Proof + Vec<Fr> public signals in the contract's BLS12-381 byte form.
# Producing those args from the CLI is encoding-sensitive across CLI versions, so
# the DETERMINISTIC verify-success + replay-rejection (NullifierUsed) check is the
# contract test suite, which runs the exact same on-chain BLS12-381 verify logic:
#     npm run test:contracts          # verify against stellar --version
# (The pre-deployed reference tx in the README also shows verify_proof -> true.)

# ---------------------------------------------------------------------------
# 5. Summary — fresh addresses + explorer links
# ---------------------------------------------------------------------------
step "Fresh deployment summary (Stellar $NETWORK)"
printf '%s  groth16-verifier   %s %s/contract/%s%s\n'  "$DIM" "$RESET" "$EXPLORER" "$VERIFIER_ID" ""
printf '%s  zk-verified-payment%s %s/contract/%s%s\n'  "$DIM" "$RESET" "$EXPLORER" "$PAYMENT_ID" ""
printf '%s  deployer account   %s %s/account/%s%s\n'   "$DIM" "$RESET" "$EXPLORER" "$ADDRESS" ""
echo
note "Deterministic on-chain verify + replay-rejection (NullifierUsed): npm run test:contracts"
note "Full recorded end-to-end run + tx hashes: docs/e2e-results.md"

rm -f "$LOG" 2>/dev/null || true
ok "done — fresh contracts are live on $NETWORK."
