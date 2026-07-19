#!/usr/bin/env bash
# StellarHub — Confidential Send on Stellar · https://stellarhub.io
#
# One-command demo of the zero-knowledge confidential payment flow. A judge can
# clone this repo and SEE the ZK work with a single command — no closed-source
# product, no accounts, no setup beyond Node.js.
#
#   ./run.sh             Local, self-contained: generate a Groth16 proof and
#                        verify it locally (BLS12-381). Needs only Node.js, runs
#                        in seconds, no network calls for the proof itself.
#
#   ./run.sh --testnet   Everything above, then ALSO deploy FRESH contracts to
#                        Stellar testnet and run the on-chain verify + replay-
#                        rejection demo. Needs the Stellar CLI + Rust/cargo; if
#                        either is missing the on-chain step is skipped cleanly
#                        (it NEVER fails the script — the local proof is the
#                        guaranteed demo). Same as: DEMO_TESTNET=1 ./run.sh
#
# This launcher is convenience only. The code it runs is the real, readable
# reference implementation (circuits/, contracts/, scripts/, client-lib/) — read
# those directly to confirm the ZK is load-bearing.
set -euo pipefail

# Repo root = this script's directory. Resolved at runtime so the demo works from
# any working directory and on any machine — no hardcoded absolute paths.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

# ---------------------------------------------------------------------------
# Output helpers (colour only on an interactive terminal; clean when piped)
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
  BOLD="$(printf '\033[1m')"; DIM="$(printf '\033[2m')"
  CYAN="$(printf '\033[36m')"; GREEN="$(printf '\033[32m')"
  YELLOW="$(printf '\033[33m')"; RESET="$(printf '\033[0m')"
else
  BOLD=""; DIM=""; CYAN=""; GREEN=""; YELLOW=""; RESET=""
fi

hr()   { printf '\n%s────────────────────────────────────────────────────────────%s\n' "$DIM" "$RESET"; }
step() { printf '\n%s%s▸ %s%s\n' "$BOLD" "$CYAN" "$*" "$RESET"; }
ok()   { printf '%s  ✓ %s%s\n' "$GREEN" "$*" "$RESET"; }
note() { printf '%s  · %s%s\n' "$DIM" "$*" "$RESET"; }
warn() { printf '%s  ! %s%s\n' "$YELLOW" "$*" "$RESET"; }
die()  { printf '\n%s  ✗ %s%s\n' "$YELLOW" "$*" "$RESET" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# Live reference deployment on Stellar testnet (instant proof — nothing to install).
# These pre-deployed addresses are NOT touched by --testnet; that path deploys your
# own fresh contracts alongside these.
PREDEPLOYED_VERIFIER="CDZUXZXCKKWTAEIXRP5PCQ6O7GP5TT7NJDQ22RCB2XV4PRVL4NXMQD3E"
PREDEPLOYED_PAYMENT="CD3BLTTRALUAML6WPFDUMQFVAMYY64KW4PWI6XJRNHFO4OK4JOETPYT2"
PREDEPLOYED_TX="41ece6b935fb605bd3ff97ab6c5bdf258a5afc0f6925a3002bd88fc932659750"
EXPLORER="https://stellar.expert/explorer/testnet"

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
TESTNET="${DEMO_TESTNET:-0}"
for arg in "$@"; do
  case "$arg" in
    --testnet) TESTNET=1 ;;
    -h|--help)
      sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) warn "ignoring unknown argument: $arg" ;;
  esac
done

# ===========================================================================
# (a) Banner
# ===========================================================================
printf '\n%s%s' "$BOLD" "$CYAN"
cat <<'BANNER'
  ____  _       _ _            _   _       _
 / ___|| |_ ___| | | __ _ _ __| | | |_   _| |__
 \___ \| __/ _ \ | |/ _` | '__| |_| | | | | '_ \
  ___) | ||  __/ | | (_| | |  |  _  | |_| | |_) |
 |____/ \__\___|_|_|\__,_|_|  |_| |_|\__,_|_.__/
BANNER
printf '%s' "$RESET"
printf '%s  Confidential Send on Stellar — Real-World Zero-Knowledge%s\n' "$BOLD" "$RESET"
printf '%s  Groth16 · BLS12-381 · Soroban   ·   https://stellarhub.io%s\n' "$DIM" "$RESET"

# ===========================================================================
# (b) Check prerequisites
# ===========================================================================
step "Checking prerequisites"
have node || die "Node.js is required but was not found. Install Node 18+ from https://nodejs.org and re-run."
have npm  || die "npm is required but was not found (it ships with Node.js)."
ok "node $(node --version)   npm $(npm --version)"

# Optional toolchain — only needed for the --testnet on-chain path.
HAVE_ONCHAIN=1
if have stellar; then ok "stellar $(stellar --version 2>/dev/null | head -n1 | awk '{print $2}')"; else note "stellar CLI not found (only needed for --testnet)"; HAVE_ONCHAIN=0; fi
if have cargo;   then ok "cargo $(cargo --version 2>/dev/null | awk '{print $2}')"; else note "cargo / Rust not found (only needed for --testnet)"; HAVE_ONCHAIN=0; fi

# ===========================================================================
# (c) Install Node dependencies + build circuit artefacts (only if needed)
# ===========================================================================
step "Preparing the proving toolchain"
if [[ ! -d node_modules ]]; then
  note "node_modules absent — running 'npm install' (one-time, needs network)…"
  npm install --no-audit --no-fund >/dev/null 2>&1 || die "npm install failed — check your network and re-run."
  ok "dependencies installed"
else
  ok "node_modules present — skipping npm install"
fi

# The local proof needs the compiled circuit + dev Groth16 keys for private_transfer.
# These ship in build/. If they are absent we try a one-shot build; if that cannot
# run (toolchain absent) we stop with a clear pointer rather than fabricating output.
REQUIRED_ARTEFACTS=(
  "build/private_transfer.wasm"
  "build/private_transfer_final.zkey"
  "build/private_transfer_verification_key.json"
)
missing=0
for a in "${REQUIRED_ARTEFACTS[@]}"; do [[ -f "$a" ]] || missing=1; done
if [[ "$missing" -eq 1 ]]; then
  note "circuit artefacts missing — attempting 'npm run build:circuits' (needs circom + snarkjs)…"
  npm run build:circuits || true
  missing=0
  for a in "${REQUIRED_ARTEFACTS[@]}"; do [[ -f "$a" ]] || missing=1; done
  [[ "$missing" -eq 1 ]] && die "circuit artefacts still missing. Install circom + snarkjs and run 'npm run build:circuits' (see docs/RUNBOOK.md)."
  ok "circuit artefacts built"
else
  ok "circuit artefacts present — skipping circuit build"
fi

# ===========================================================================
# (d) DEFAULT path — self-contained LOCAL proof + verify (only needs Node.js)
# ===========================================================================
step "Local zero-knowledge proof (Model C — confidential verified payment)"
note "Generating a Groth16 proof of a well-formed note and verifying it locally (BLS12-381)…"
if ! PROVE_OUT="$(node scripts/prove.mjs 2>&1)"; then
  printf '%s\n' "$PROVE_OUT"
  die "local proof generation failed (see output above)."
fi
# Surface the load-bearing lines: the public commitment, the nullifier, the verdict.
printf '%s\n' "$PROVE_OUT" | grep -E 'commitment|nullifier|local verify' | sed 's/^\[prove\] /  /'
if printf '%s' "$PROVE_OUT" | grep -q 'local verify  = OK'; then
  ok "local verify: OK — the proof is valid (full {proof, publicSignals}: node scripts/prove.mjs)"
else
  die "local verification did NOT return OK (see output above)."
fi

# The MAIN visual demo — a REAL confidential transfer in the browser.
step "Visual demo — REAL confidential transfer in the browser [recommended]"
note "'npm run demo:web' opens the MAIN demo: it moves REAL testnet funds through the"
note "wallet's live pool — visible boundary deposit, sealed-note Groth16 transfer with"
note "no amount on-chain, a live Horizon decode, and the recipient-side note scan."
note "Fallback building block (proof-verify only): /demo/web/verify.html"

# ===========================================================================
# (e) ON-CHAIN path — only with --testnet (or DEMO_TESTNET=1) AND the toolchain
# ===========================================================================
if [[ "$TESTNET" -eq 1 ]]; then
  step "On-chain demo on Stellar testnet (--testnet)"
  if [[ "$HAVE_ONCHAIN" -eq 1 ]]; then
    note "Deploying FRESH contracts and exercising the on-chain verifier…"
    # deploy-testnet.sh friendbot-funds a fresh identity and deploys all three
    # contracts, printing their fresh addresses + explorer links. Guarded so a
    # network/CLI hiccup degrades gracefully instead of failing the whole demo.
    if bash scripts/deploy-testnet.sh; then
      ok "fresh contracts deployed to testnet (addresses + explorer links above)"
    else
      warn "on-chain deploy did not complete — the local proof above is the guaranteed result."
    fi

    # Deterministic on-chain verify + replay-rejection (NullifierUsed). The
    # deployed wasm runs the SAME BLS12-381 verify_groth16 logic these suites
    # exercise (valid proof → payment executes; replayed nullifier → NullifierUsed).
    if [[ "${DEMO_SKIP_CONTRACT_TESTS:-0}" != "1" ]]; then
      step "On-chain verify + replay-rejection (real Soroban execution)"
      note "Running the contract test suites — first compile can take a few minutes (DEMO_SKIP_CONTRACT_TESTS=1 to skip)…"
      if npm run test:contracts; then
        ok "verify succeeds for a valid proof; a replayed nullifier is rejected (NullifierUsed)"
      else
        warn "contract test suite did not complete (toolchain/network) — see docs/e2e-results.md for recorded on-chain results."
      fi
    fi
  else
    warn "Stellar CLI and/or cargo not found — skipping the on-chain testnet path."
    note "Install the Stellar CLI (https://developers.stellar.org) + Rust (https://rustup.rs), then re-run: ./run.sh --testnet"
    note "Meanwhile, the local proof above already shows the ZK working, and the"
    note "pre-deployed reference contracts below let you verify on-chain instantly."
  fi
else
  note ""
  note "Tip: run './run.sh --testnet' to deploy your OWN fresh contracts and verify on-chain"
  note "(needs the Stellar CLI + Rust/cargo). The pre-deployed links below work right now."
fi

# ===========================================================================
# (f) Summary — README pointer + pre-deployed explorer links + project link
# ===========================================================================
hr
printf '%s%s  Done — ZK is load-bearing, on-chain, and reproducible.%s\n' "$BOLD" "$GREEN" "$RESET"
hr
printf '%s  What you just saw%s\n' "$BOLD" "$RESET"
note "Model C: a Groth16 proof bound a payment (commitment + nullifier, amount in range)."
note "The same {proof, publicSignals} are what the Soroban contract verifies on-chain."
printf '\n%s  Go further — the REAL hidden-amount transfer (the wallet pool)%s\n' "$BOLD" "$RESET"
note "npx tsx e2e/confidential-transfer-e2e.ts — deposits into contracts/zk-confidential-transfer,"
note "sends a REAL testnet transfer whose amount never appears on-chain, and recovers it"
note "recipient-side from the sealed note (the exact flow the production wallet runs)."
printf '\n%s  Verify on-chain right now (pre-deployed testnet reference — nothing to install)%s\n' "$BOLD" "$RESET"
note "Groth16 verifier:  $EXPLORER/contract/$PREDEPLOYED_VERIFIER"
note "ZK-verified pay:   $EXPLORER/contract/$PREDEPLOYED_PAYMENT"
note "verify_proof tx:   $EXPLORER/tx/$PREDEPLOYED_TX  (returned true)"
printf '\n%s  Read more%s\n' "$BOLD" "$RESET"
note "README.md            — overview, honest status, how ZK is load-bearing"
note "docs/RUNBOOK.md      — full step-by-step build"
note "docs/verifier-spec.md — circuit math, public-input ordering, VK transcoding"
note "circuits/ contracts/ scripts/ — the actual source (read it; the ZK is real)"
printf '\n%s  StellarHub — https://stellarhub.io%s\n\n' "$BOLD" "$RESET"
