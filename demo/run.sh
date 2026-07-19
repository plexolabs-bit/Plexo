#!/usr/bin/env bash
# StellarHub ZK reference · https://stellarhub.io
#
# One-command Confidential Send demo (hide the amount), from this repo only.
# Prereqs: `npm install` + `npm run build:circuits` (see demo/README.md).
#
# Usage:
#   ./run.sh             off-chain prove + verify, then point at the live reference
#                        contracts already deployed on Stellar testnet.
#   ./run.sh --testnet   build the circuits locally + print the stellar-cli steps to
#                        deploy your OWN fresh contracts on Stellar testnet.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

hr() { printf '\n────────────────────────────────────────\n%s\n────────────────────────────────────────\n' "$*"; }

# Live reference deployment on Stellar testnet (verify on-chain via the explorer links).
VERIFIER_CONTRACT="CDZUXZXCKKWTAEIXRP5PCQ6O7GP5TT7NJDQ22RCB2XV4PRVL4NXMQD3E"
PAYMENT_CONTRACT="CD3BLTTRALUAML6WPFDUMQFVAMYY64KW4PWI6XJRNHFO4OK4JOETPYT2"
EXPLORER="https://stellar.expert/explorer/testnet/contract"

# --testnet: build the circuits locally and print the steps to deploy your own contracts.
if [[ "${1:-}" == "--testnet" ]]; then
  hr "Deploy your OWN fresh contracts on Stellar testnet"
  echo "Step 1/2 — build the circuits + dev Groth16 keys locally"
  echo "(graceful-degrades with install hints if the toolchain is absent):"
  bash scripts/build.sh || {
    echo
    echo "Toolchain missing — see docs/RUNBOOK.md for circom + snarkjs + stellar-cli setup."
    exit 1
  }
  echo
  echo "Step 2/2 — deploy + initialize on testnet with the Stellar CLI"
  echo "(needs stellar-cli and a Friendbot-funded testnet key):"
  cat <<'DEPLOY'
  stellar keys generate zk-deployer --network testnet
  stellar keys fund     zk-deployer --network testnet
  stellar contract build  --manifest-path contracts/zk-verified-payment/Cargo.toml
  stellar contract deploy --wasm <built .wasm> --source zk-deployer --network testnet
  # then `initialize` with the native XLM SAC + your exported verifying key,
  # and `pay_verified` to move value gated on a valid proof.
DEPLOY
  echo
  echo "Full step-by-step: docs/RUNBOOK.md (off-chain) + docs/verifier-spec.md (on-chain)."
  hr "Done — your own testnet deployment is ready to run."
  exit 0
fi

hr "Confidential Send — hide the amount (private_transfer circuit)"
echo "Proving knowledge of a note (commitment + nullifier), amount range-bound,"
echo "then verifying the Groth16 proof locally (BLS12-381):"
node scripts/prove.mjs | grep -E "commitment|nullifier|local verify" || node scripts/prove.mjs

hr "On-chain (Stellar testnet)"
echo "These same proofs verify on the deployed Soroban contracts (docs/e2e-results.md):"
echo "  verifier  $VERIFIER_CONTRACT"
echo "            $EXPLORER/$VERIFIER_CONTRACT   (verify_proof -> true)"
echo "  payment   $PAYMENT_CONTRACT"
echo "            $EXPLORER/$PAYMENT_CONTRACT   (pay_verified, live tx)"
echo
echo "Verify on-chain instantly via the explorer links above (nothing to install),"
echo "or deploy your own fresh contracts with:  ./run.sh --testnet"
echo "Run the on-chain contract test suites standalone with:  npm run test:contracts"
echo
echo "Prefer a button to the terminal? Launch the in-browser Confidential Send demo"
echo "(enter an amount → a real Groth16 proof hides it → see what the chain sees):"
echo "  npm run demo:web        # then open the printed http://localhost:8788/"
hr "Done — ZK is load-bearing, on-chain, reproducible."
