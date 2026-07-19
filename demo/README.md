# Demo — Confidential Send on Stellar (Real-World ZK)

> Part of the [StellarHub](https://stellarhub.io) ecosystem.

A judge can reproduce the whole ZK flow **without any closed-source product** —
just this repo. The proof does real work (not a slide):

| | What the ZK proves | On-chain |
|---|---|---|
| **Confidential Send** | knowledge of a note that opens `commitment` + a unique `nullifier`, amount range-bound — the **amount is a private input** | `verify_proof` accepts the proof on-chain (BLS12-381); `pay_verified` executes a payment ONLY if the proof verifies + nullifier unused (one atomic tx) |

The amount is hidden inside the commitment; the public signals are only
`[commitment, nullifier]`. Sender & recipient stay visible — this is
**confidential: it hides the amount, not the identities.** See
[the repo README](../README.md#what-this-protects-and-what-it-does-not) for the full
honest scope (visible boundaries, small-pool inference).

## Prerequisites (one-time)

```bash
npm install                 # snarkjs + circomlib + circomlibjs + vitest
npm run build:circuits      # circom compile + dev Groth16 trusted setup (local, DEV keys)
# Rust toolchain + the host target are needed for the contract tests.
```

## Run it

```bash
bash demo/run.sh
```

…or step by step:

```bash
# Off-chain prove + verify (private_transfer circuit) — the amount stays private
node scripts/prove.mjs                 # -> "local verify = OK (curve: bls12381)"

# On-chain — the Soroban contracts (verify these run standalone):
npm run test:contracts                 # groth16-verifier + zk-verified-payment
```

## Click a button — in-browser Confidential Send

Prefer a UI to the terminal? A zero-dependency page runs a **confidential payment
in your browser**: you enter an amount + recipient, a **real** Groth16 proof
(snarkjs, BLS12-381) binds the amount inside a commitment, and the page shows a
split view — **what the chain sees (a commitment) vs what only you know (the amount)**:

```bash
npm run demo:web        # zero-dep Node static server; prints http://localhost:8788/
```

Open the printed URL and click **🔒 Send confidentially**. The amount, recipient,
and fresh per-payment secrets never leave the page — only the proof + its public
signals (`commitment`, `nullifier`, **no amount**) would go on-chain. Tamper the
commitment to watch a forged amount get rejected. This is the same `fullProve` path
as `scripts/prove.mjs`, wrapped in a real send flow. Source:
[`demo/web/index.html`](web/index.html) + [`demo/serve.mjs`](serve.mjs).

## Live reference deployment on Stellar testnet

Verify these on-chain instantly via the explorer links below (nothing to install), or
run `./run.sh --testnet` to deploy your own fresh contracts. These deployed contracts
verify the same proofs the demo generates (full log + tx hashes in
[`docs/e2e-results.md`](../docs/e2e-results.md)):

- **Groth16 verifier** [`CDZUXZXCKKWTAEIXRP5PCQ6O7GP5TT7NJDQ22RCB2XV4PRVL4NXMQD3E`](https://stellar.expert/explorer/testnet/contract/CDZUXZXCKKWTAEIXRP5PCQ6O7GP5TT7NJDQ22RCB2XV4PRVL4NXMQD3E) — `verify_proof → true` (tampered → `false`).
- **ZK-verified payment** [`CD3BLTTRALUAML6WPFDUMQFVAMYY64KW4PWI6XJRNHFO4OK4JOETPYT2`](https://stellar.expert/explorer/testnet/contract/CD3BLTTRALUAML6WPFDUMQFVAMYY64KW4PWI6XJRNHFO4OK4JOETPYT2) — live `pay_verified` tx moved 0.1 XLM; replay rejected (`NullifierUsed`).

## Honest scope

- testnet + **dev** trusted setup (single-participant; a production ceremony is out of scope and labelled everywhere).
- **Confidential — hides the amount, not the identities**: the amount is hidden and the payment is bound (replay-safe), but sender & recipient are visible on-chain. Auditable amount-privacy with a selective-disclosure path.
