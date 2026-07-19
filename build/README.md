# build/ — Compiled circuit artefacts

_Part of the [StellarHub](https://stellarhub.io) ecosystem._

This directory holds the **compiled outputs** of the circuits in [`circuits/`](../circuits/).
They are committed so the demo ([`./run.sh`](../run.sh)) can generate and verify a real
Groth16 proof with **only Node.js installed** — no `circom`/`snarkjs` toolchain is
required just to watch the zero-knowledge proof work.

It is generated, not hand-authored. Treat it like `dist/`: do not edit by hand.
Regenerate everything from source with [`scripts/build.sh`](../scripts/build.sh)
(needs `circom` + `snarkjs`).

## What's here

| Artefact | Produced by | Purpose |
|---|---|---|
| `<circuit>.wasm`, `<circuit>_js/` | `circom` compile | witness generator |
| `<circuit>.r1cs`, `<circuit>.sym` | `circom` compile | constraint system + symbol table |
| `<circuit>_final.zkey` | `snarkjs groth16 setup` + contribute | Groth16 proving key |
| `<circuit>_verification_key.json` | `snarkjs zkey export verificationkey` | verification key |
| `proof.json`, `public.json` | `snarkjs groth16 fullprove` | a sample proof + its public signals |

> Note: only the proving keys the demos need are committed (`private_transfer`,
> `credentials`, `confidential_transfer`, `confidential_withdraw`). The other
> `*_final.zkey` files (proof-of-reserves, range_proof, balance_commitment) are
> gitignored — the affected tests `skip` on a fresh clone until you run
> `npm run build:circuits`.

## Pipeline (all three stages live in `scripts/build.sh`)

1. **Compile** — `circom <source> --r1cs --wasm --sym`. No trusted setup,
   reproducible from source, safe to run anywhere.
2. **Dev trusted setup** — `snarkjs groth16 setup` + a single contribution →
   `<circuit>_final.zkey` + the verification key.
3. **Export** — write out the verification key consumed by the on-chain verifier.

## Honest caveat — development trusted setup

The proving/verifying keys here come from a **single-participant DEV ceremony**.
They are correct for local testing and the testnet demo, but are **NOT for
production / mainnet** — a real deployment needs a proper multi-party (MPC)
Powers-of-Tau + phase-2 ceremony, which is out of scope for this submission and
labelled as such throughout. This mirrors the "honest status" section of the
top-level [`README.md`](../README.md); the circuit math, public-input ordering,
and verification-key transcoding are documented in
[`docs/verifier-spec.md`](../docs/verifier-spec.md).
