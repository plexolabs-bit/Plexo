# StellarHub · Confidential Send on Stellar (ZK private payments)

> **Part of the [StellarHub](https://stellarhub.io) ecosystem.** StellarHub builds
> privacy-preserving payment infrastructure on Stellar; this repository is the open,
> reproducible reference implementation of its zero-knowledge payment layer.

A zero-knowledge private payment on Stellar testnet. A Groth16 circuit (written in
[circom](https://docs.circom.io/)) proves that a transfer is well-formed — the amount
is in range, the output commitment is correctly bound, and a nullifier prevents
double-spends — and a Soroban smart contract verifies that proof **on-chain** before
the payment is allowed to execute. The **amount** is hidden — bound inside the
commitment, never present in the proof's public signals — while the sender and recipient
stay visible on the ledger. Selective-disclosure viewing keys give a recipient or auditor
a compliance path to reveal a payment on request. This is **confidential — it hides the
amount, not the identities** (sender and recipient stay visible).

This repository is the **open, reproducible reference implementation** of that ZK layer.

---

## Quick start

Clone the repo and run **one command**. The launcher installs the Node
dependencies and uses the committed circuit artefacts, so the local proof needs
**only Node.js** — no accounts, no network calls for the proof itself:

```bash
./run.sh            # local: generate a Groth16 proof + verify it locally (BLS12-381). Fast.
./run.sh --testnet  # also deploy FRESH contracts to Stellar testnet + run the on-chain
                    # verify + replay-rejection demo. Needs the Stellar CLI + Rust/cargo;
                    # if either is missing the on-chain step is skipped cleanly.
npm run demo:web    # THE MAIN DEMO: a REAL confidential transfer in the browser, on the
                    # wallet's live pool — visible boundary deposit, sealed-note Groth16
                    # transfer (no amount on-chain), live Horizon decode, recipient-side
                    # note scan. Opens http://localhost:8788/ · fallback proof-verify
                    # building block: http://localhost:8788/demo/web/verify.html
```

`./run.sh` prints the public `commitment`, the `nullifier`, and `local verify: OK`.
`./run.sh --testnet` additionally friendbot-funds a fresh account, deploys the two
contracts (via [`scripts/deploy-testnet.sh`](scripts/deploy-testnet.sh)), and prints
stellar.expert links to the freshly-deployed instances.

Prefer to confirm it on-chain with nothing to install? The **pre-deployed** testnet
reference contracts are linked under [What works / honest status](#what-works--honest-status)
below (and are never touched by `--testnet`).

---

## How ZK is load-bearing

The zero-knowledge proof is not decoration on a slide — it is the gate the payment must
pass through:

- The prover produces a Groth16 proof attesting `commitment == Poseidon(amount, blinding, recipient)`,
  `nullifier == Poseidon(senderSecret, serial)`, and `0 <= amount < 2^64` (a range proof).
- The Soroban verifier contract checks that proof using Stellar's native BLS12-381
  elliptic-curve host functions (available since Protocol 22, CAP-0059). **If the proof
  is missing or invalid, the contract refuses the payment.**
- Remove the proof step and the privacy property disappears entirely: there is no
  unprotected fallback path that moves the funds. The proof *is* the authorization.

That is the property the hackathon asks for: the ZK "powers a real part of how the
project works." Concretely — delete the `proof` field from the submission payload, or
flip one bit in `publicSignals`, and the verifier rejects the transaction.

---

## What works / honest status

Proven end-to-end on Stellar **testnet** (2026-06-12): the circuit compiles, a Groth16
proof generates and verifies off-chain, the Soroban verifier contract is deployed, and an
on-chain `verify_proof` call returns `true` for a valid proof and `false` for a tampered
one. Build steps to reproduce are in the runbook. Honest caveats (testnet-only, dev
trusted setup, MVP circuit) are listed below.

- ✅ **Circuit** — `private_transfer.circom`: MVP confidential-payment circuit (~520
  constraints) using circomlib Poseidon + bitify. Public signals (outputs):
  `commitment`, `nullifier`. Private witness: `amount`, `blinding`, `recipient`,
  `senderSecret`, `serial` — the **amount stays private**. Three constraints: a
  `Num2Bits(64)` range proof on the amount, a Poseidon commitment binding, and a
  Poseidon nullifier.
- ✅ **Off-chain prove/verify harness** — `scripts/prove.mjs`: computes the
  commitment + nullifier via circomlibjs Poseidon, runs `snarkjs groth16 fullProve`,
  verifies the proof locally, and prints the `{ proof, publicSignals }` submission
  payload.
- ✅ **Backend prover reference** — `generator.py`: shells out to `snarkjs`
  (out-of-process, 30 s timeout) when the build artefacts exist, and otherwise raises
  a typed error that surfaces as **HTTP 501** — a clean graceful-degrade when the
  toolchain is absent.
- ✅ **Viewing keys / selective disclosure** — working signed-request backend for
  publishing, looking up, and unpublishing viewing keys (the compliance "audit door").
- ⚠️ **Testnet only.** Everything targets the Stellar **test** network. The mainnet
  approval flag is intentionally untouched. Do not point this at mainnet.
- ⚠️ **Development trusted setup.** The Groth16 proving/verifying keys come from a
  single-participant dev ceremony. Soundness of *this* circuit holds, but a production
  deployment needs a proper multi-party (MPC) Powers-of-Tau + phase-2 ceremony. That
  ceremony is **out of scope** for the hackathon and is labelled as such everywhere
  (including the dev-key manifest).
- ⚠️ **Two circuits ship — the pool is the main one.** The MAIN demo runs the
  confidential-pool circuit the production wallet uses: a **4-commitment state
  transition with in-circuit balance conservation + range proofs** (deposit →
  `confidential_transfer` → withdraw, C0 fold-in for unregistered recipients).
  The `private_transfer` building block (single commitment + nullifier + range
  proof, `verify.html` fallback) is kept as the minimal, fast-to-read intro;
  the full math is in the spec under `docs/`.
- ✅ **Soroban verifier deployed + verified on testnet.** The verifier contract verifies
  our proof on-chain (real BLS12-381 host functions) and rejects a tampered public signal.

> **Live reference deployment on Stellar testnet** — verify it on-chain via the
> explorer links below (instant proof, nothing to install), or run
> `./run.sh --testnet` to deploy your own fresh contracts. Artefacts (2026-06-12):
> - Verifier contract: [`CDZUXZXCKKWTAEIXRP5PCQ6O7GP5TT7NJDQ22RCB2XV4PRVL4NXMQD3E`](https://stellar.expert/explorer/testnet/contract/CDZUXZXCKKWTAEIXRP5PCQ6O7GP5TT7NJDQ22RCB2XV4PRVL4NXMQD3E)
> - `verify_proof` on-chain tx (returned `true`): [`41ece6b935fb605bd3ff97ab6c5bdf258a5afc0f6925a3002bd88fc932659750`](https://stellar.expert/explorer/testnet/tx/41ece6b935fb605bd3ff97ab6c5bdf258a5afc0f6925a3002bd88fc932659750)
> - Wasm hash: `f1468a9a91f15deba8ac574a0b2936dfd0faaa5f20efd063add982260632d95a`

---

## Confidential transfer pool — the wallet's "green eye" (hide the amount end-to-end)

The second, deeper confidential layer in this repo (beyond the Model C verified
payment above): a Soroban **pool contract** where each account's balance lives
on-chain only as a **Poseidon commitment**. An in-pool transfer is an atomic
**commitment swap** — it moves **no tokens**, takes **no amount argument**, and emits
**no amount in any event**. What makes the swap sound is a Groth16/BLS12-381 proof of
**value conservation**, checked on-chain before the swap:

- the prover opens all four balance commitments in-circuit and proves
  `sender_old = sender_new + t` and `recipient_new = recipient_old + t` for the SAME
  hidden `t` (Poseidon is not additively homomorphic, so the conservation MUST be
  proven in zero knowledge — the contract cannot subtract commitments);
- the recipient needs only their **plain Stellar `G…` address**: the sender derives
  the recipient's X25519 encryption key from the address itself (Ed25519→Curve25519)
  and seals the amount into an **ECDH-sealed note** echoed by the `conf_xfer` event —
  no receive code, and the blinding is re-derived by both sides, never transmitted
  ([`client-lib/confidential-note.ts`](client-lib/confidential-note.ts));
- an **unregistered** recipient is credited in ONE signed tx: an absent account
  defaults to the constant `C0 = Poseidon(0,0)` (the provably-empty balance), and the
  compare-and-swap creates the slot — the **C0 fold-in**;
- the exit is **trustless**: `withdraw()` pays out only after a second proof
  (`confidential_withdraw`) shows the burned commitment opens to EXACTLY the public
  boundary amount — no operator attestation.

**Live pool on Stellar testnet** (2026-07-02, v2 with note delivery + C0 fold-in):

- Pool contract: [`CC6LDUHVSSVNAEI5XQPQVDZPQCUJYONPPO7OL5AOWHIKHXLQTQ6FDO2K`](https://stellar.expert/explorer/testnet/contract/CC6LDUHVSSVNAEI5XQPQVDZPQCUJYONPPO7OL5AOWHIKHXLQTQ6FDO2K)
- Live confidential transfer to a bare G-address: [`bffd3e9acd6c45f44700a3520e305e0dcb6722344d7e4f97c09be3ad301036d4`](https://stellar.expert/explorer/testnet/tx/bffd3e9acd6c45f44700a3520e305e0dcb6722344d7e4f97c09be3ad301036d4)
- Live run of THIS repo's own e2e (2026-07-03): [`005dabe7f55bd6fbf3f86465053cf45f777776f02ee2cb2672b44a754da5800a`](https://stellar.expert/explorer/testnet/tx/005dabe7f55bd6fbf3f86465053cf45f777776f02ee2cb2672b44a754da5800a)

Open either tx in the explorer and inspect the operation: the arguments are two
addresses, a proof, four 32-byte commitments, an ephemeral key and an opaque note —
**zero cleartext amounts**.

### Reproduce it yourself (one command, Node.js only)

```bash
npm install
npm run e2e:confidential   # ~60s: friendbot-funds two FRESH accounts, deposits,
                           # proves conservation (real snarkjs, committed artefacts),
                           # submits the amount-hiding transfer to the UNREGISTERED
                           # second account, then recovers the hidden amount from the
                           # sealed note with only the recipient's key.
                           # Prints the fresh tx hash + stellar.expert link.
```

No secrets are baked in — every run generates new keypairs and lands a new, publicly
checkable transaction on the deployed pool.

### Where the pieces live

| Piece | Path |
|---|---|
| Conservation circuit (4 Poseidon openings + shared-`t` + ranges) | [`circuits/confidential_transfer.circom`](circuits/confidential_transfer.circom) |
| Open-to-amount withdraw circuit | [`circuits/confidential_withdraw.circom`](circuits/confidential_withdraw.circom) |
| Pool contract (deposit / confidential_transfer / withdraw + C0 fold-in) | [`contracts/zk-confidential-transfer/`](contracts/zk-confidential-transfer/) — 33 `cargo test`s incl. a REAL-pairing C0 fold-in happy path |
| Sealed-note crypto (G-address → X25519, ECDH, view tag) | [`client-lib/confidential-note.ts`](client-lib/confidential-note.ts) |
| Commitments + circuit witness builder (BLS12-381 Poseidon) | [`client-lib/confidential-commit.ts`](client-lib/confidential-commit.ts) |
| Client-side Soroban invoke (deposit / transfer / getters) | [`client-lib/confidential-pool.ts`](client-lib/confidential-pool.ts) |
| Recipient scanner (`conf_xfer` events → note open → verify opening) | [`client-lib/confidential-receive.ts`](client-lib/confidential-receive.ts) |
| Live testnet e2e | [`e2e/confidential-transfer-e2e.ts`](e2e/confidential-transfer-e2e.ts) |
| Committed prover artefacts (wasm / zkey / vk) | `build/confidential_*` |

The committed `build/confidential_transfer*` artefacts are the **exact set the
deployed pool was initialized with** — the test suite pins `build/…verification_key.json`
byte-equal to the contract's `data/verification_key.json`, and the e2e proves it
live. The `build/confidential_withdraw*` artefacts are a reproducible dev setup for
the same circuit source; the pre-deployed pool holds an earlier dev withdraw VK
(whose proving key was not preserved), so to exercise the full
deposit → transfer → **withdraw** loop, deploy a fresh pool and initialize it with the
committed VKs.

### Honest scope (same rules as everywhere in this repo)

- **Only the transfer AMOUNT is hidden.** Sender and recipient identities are visible
  (the op names both accounts) — this is confidential, **not** anonymous.
- The boundary `deposit()` / `withdraw()` move real tokens and expose their amounts in
  the clear, by construction. In a small pool a global observer can often infer
  amounts by differencing the boundaries.
- The recipient must run a wallet that holds the raw seed to open notes (the
  decryption key is derived from it) — hardware/third-party signers cannot.
- One outstanding commitment per account (first-deposit-only, no top-up) — a
  documented PoC limit, not a protocol property.
- Single-participant dev trusted setup, unaudited, **testnet only**. Do not point
  this at mainnet.

---

## Architecture

```
   Client (prover)                Backend prover ref            Soroban (Stellar testnet)
   ───────────────                ──────────────────            ─────────────────────────
   amount, blinding,
   recipient, secret    ──────►   POST /zk/generate
   serial                          └─ snarkjs subprocess:
                                      witness + Groth16
                                      prove (BLS12-381)
                                ◄──  { proof, publicSignals }

   sign transfer XDR
   locally (keys never
   leave the client)

   submit               ──────►   InvokeHostFunction  ─────────►   Groth16 verifier contract
                                  (verifier invoke)                 ├─ BLS12-381 pairing check
                                                                    ├─ nullifier not seen?
                                                                    └─ execute payment
                                ◄──  { tx_hash }       ◄─────────   tx success

   "Sent!" + explorer link
```

Three moving parts: a **prover** (off-chain, produces the proof), a **verifier**
(on-chain Soroban contract, the gate), and the **payment** (executed only after the
verifier accepts). Signing stays client-side — the prover reference never holds user
keys.

---

## Run it

The one-command [`./run.sh`](#quick-start) does the local path for you (install →
build → prove → verify). To reproduce the full flow by hand — step-by-step in
[`docs/RUNBOOK.md`](docs/RUNBOOK.md) — in short:

1. **Install the toolchain** — `circom` 2.x, `snarkjs` (via `npx`), and a Powers-of-Tau
   file (`*.ptau`); the Stellar CLI for the contract step.
2. **Compile the circuit** — `circom circuits/private_transfer.circom --r1cs --wasm --sym`.
3. **Dev trusted setup** — `snarkjs groth16 setup` + a single-participant contribution →
   `private_transfer_final.zkey` + `verification_key.json` (dev keys, **not** for mainnet).
4. **Prove & verify off-chain** — `node scripts/prove.mjs` (computes commitment + nullifier,
   runs `groth16 fullProve`, verifies locally, prints the submission payload).
5. **Deploy the verifier** — embed the verification key into the forked Soroban
   `groth16-verifier`, build, and deploy to testnet; record the contract ID.
6. **End-to-end** — submit the proof via `InvokeHostFunction`; a valid proof executes the
   payment, an invalid proof or a replayed nullifier is rejected; record the testnet tx
   hash.

The maintainer running these steps fills the resulting contract ID and tx hash back into
this README and the status list above.

---

## How it works

- **Circuit** — [`circuits/private_transfer.circom`](circuits/private_transfer.circom):
  the constraints in source form (the other circuits live under [`circuits/`](circuits/)).
- **Math / design** — the R1CS spec (commitment binding, nullifier, range proof), the
  public-input ordering, and the VK transcoding are documented in
  [`docs/verifier-spec.md`](docs/verifier-spec.md); how the MVP simplifies a fuller
  multi-commitment design is covered there and in the circuit sources.
- **Threat model** — what is and is not protected, the trust boundaries, and the
  testnet / dev-setup caveats are listed in the **honest status** section above and in
  the end-to-end results ([`docs/e2e-results.md`](docs/e2e-results.md)).

---

## Scope — what existed before vs what was built for this hackathon

**Judge this on its own merit: this standalone repo is the submission.** A reviewer
with no prior exposure to our other work can clone it, run the build, and verify the
full `prove → on-chain verify → payment` path **without** any access to the closed
product. The StellarHub wallet is prior context, shown only *in part* in the video.

| Component | Status |
|---|---|
| `private_transfer.circom` (circuit) | **Built for this hackathon** |
| Soroban Groth16 verifier (fork + our VK + nullifier registry) | **Built for this hackathon** |
| Backend prover wiring (snarkjs subprocess) | **Built for this hackathon** |
| Off-chain prove/verify harness + reference demo | **Built for this hackathon** |
| Confidential pool: `confidential_transfer` / `confidential_withdraw` circuits + `zk-confidential-transfer` contract (C0 fold-in) | **Built for this hackathon** |
| Sealed-note client crypto + recipient scanner + live e2e (`client-lib/confidential-*`, `e2e/`) | **Built for this hackathon** |
| Viewing-key primitives (selective disclosure) | Pre-existing — reused as components |
| StellarHub wallet (Shadow Pocket UI, product backend) | Pre-existing, closed-source — **context only**, not part of this submission |

This mirrors the mentor's guidance: use prior work and third-party components freely,
but the hackathon contribution (circuit + verifier + prover wiring + demo) must stand on
its own and be judged on its own merit.

## What this protects (and what it does not)

This repository is **Confidential Send — it hides the payment AMOUNT.** Sender and
recipient stay visible on-chain; a selective-disclosure viewing key gives a recipient or
auditor a lawful path to reveal a payment on request. There is a real, legitimate need to
not broadcast payment sizes — payroll, settlements, invoices — and that is exactly what
this layer provides: *auditable amount-privacy*, not identity-anonymity. The pool's
deposit/withdraw boundaries move real tokens and so are visible by construction (see the
honest-scope notes above); the transfer amount itself is never on the ledger.

## Demo video vs this repo

The **demo video focuses on this standalone submission** — running the circuit, the
on-chain Soroban verification on testnet, an invalid-proof / replayed-nullifier
rejection, and the compliance viewing-key reveal. It then shows, *in part*, the same ZK
layer working inside the closed-source **StellarHub wallet** (the per-transaction privacy
toggle in the Shadow Pocket UI) — real-product context, not the main subject.

**This repository is the open, reproducible reference**: full source of the ZK layer —
circuit, prover harness, backend prover reference, the forked verifier contract, and a
minimal demo. Its commit history stands on its own.

---

## Team

Built by the **StellarHub** team — [stellarhub.io](https://stellarhub.io).

| Member | Role | Focus |
|--------|------|-------|
| **Spacewalker** | Project Lead | Project direction, team coordination, and the submission (demo, video, repo) |
| **Ishikawa** | ZK Protocol Architect | The zero-knowledge core — circom circuits, the Soroban BLS12-381 verifier contracts, and the browser-side prover |
| **Argon** | Infrastructure Engineer | Build & deploy automation, testnet tooling, the one-command demo launcher |

Commit history reflects this split — see [`AUTHORS`](AUTHORS) and `git shortlog -sn`.

---

## Attribution

The on-chain verifier is a fork of
[`stellar/soroban-examples` → `groth16_verifier`](https://github.com/stellar/soroban-examples/tree/main/groth16_verifier)
(Apache-2.0), with our verification key embedded and a nullifier registry added. The
circuit uses [circomlib](https://github.com/iden3/circomlib) (GPL-3.0 — used as a circuit
dependency at build time, not redistributed in this repo's artefacts). This repository is
licensed **Apache-2.0** (see [`LICENSE`](LICENSE)).

## On-chain curve & Stellar protocol support

Verification uses Stellar's native **BLS12-381** elliptic-curve host functions (pairing,
MSM, scalar-field arithmetic), available on Soroban since **Protocol 22** (CAP-0059). The
on-chain `pairing_check` runs the Groth16 verification equation against the curve directly
— no in-contract pairing math. (Stellar **Protocol 25 "X-Ray"** additionally added
**BN254 + Poseidon** host functions per CAP-0074 / CAP-0075; BN254 is a viable second
curve path for a future build, but this submission's verifier is BLS12-381 — see
`docs/verifier-spec.md`.)

---

**Tags:** ZK, Zero-Knowledge, Stellar, Soroban, Circom, Groth16
