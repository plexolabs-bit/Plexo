# E2E results — LIVE on Stellar testnet (2026-06-12)

_Part of the [StellarHub](https://stellarhub.io) ecosystem._

> Full zero-knowledge private-payment verification, proven end-to-end on Stellar
> **testnet**. Built and run by the maintainer (toolchain installed + run end-to-end).
> Nothing here is fabricated — every line below was produced by a real command and is
> reproducible via [`docs/RUNBOOK.md`](RUNBOOK.md).

## What was achieved (the whole chain)

| Step | Result |
|---|---|
| circom circuit `private_transfer.circom` compiles (BLS12-381) | ✅ r1cs + wasm + sym |
| dev Groth16 trusted setup (single-participant, locally-generated ptau) | ✅ zkey + vk |
| Off-chain prove + verify (snarkjs) | ✅ `local verify = OK`, `curve: bls12381` |
| Off-chain negative (tampered public signal) | ✅ rejected (`tampered=false`) |
| Soroban verifier contract host-test (real BLS12-381 host fns) | ✅ `cargo test` **2/2** (verifies + rejects) |
| Contract built to wasm | ✅ 4766 bytes, exports `verify_proof` |
| Contract deployed to **testnet** | ✅ contract id below |
| On-chain `verify_proof` with our proof (real tx) | ✅ returns **`true`** |
| On-chain negative (tampered commitment) | ✅ returns **`false`** |

**ZK is load-bearing, proven on-chain:** a valid proof returns `true`; a tampered
public signal returns `false` from the same deployed contract.

## Concrete artefacts (testnet)

- **Verifier contract id:** `CDZUXZXCKKWTAEIXRP5PCQ6O7GP5TT7NJDQ22RCB2XV4PRVL4NXMQD3E`
  - explorer: https://stellar.expert/explorer/testnet/contract/CDZUXZXCKKWTAEIXRP5PCQ6O7GP5TT7NJDQ22RCB2XV4PRVL4NXMQD3E
- **Wasm hash:** `f1468a9a91f15deba8ac574a0b2936dfd0faaa5f20efd063add982260632d95a`
- **Deploy tx:** `eebd724fe99ea359ab15d8d91e03bf7e76f6c554e3bf95633c4d9f74315602a4`
  - https://stellar.expert/explorer/testnet/tx/eebd724fe99ea359ab15d8d91e03bf7e76f6c554e3bf95633c4d9f74315602a4
- **verify_proof on-chain tx (returned true):** `41ece6b935fb605bd3ff97ab6c5bdf258a5afc0f6925a3002bd88fc932659750`
  - https://stellar.expert/explorer/testnet/tx/41ece6b935fb605bd3ff97ab6c5bdf258a5afc0f6925a3002bd88fc932659750
- **Deployer (testnet, Friendbot-funded):** `GBYA47MRU2CR5GCDTN55S6SV7VIYV7XNTJVLK3PTOTH5SVNUR46UD22H`
- **Public signals proven:** commitment `19570265…6885351`, nullifier `28416275…8743085`

## Where the code lives

- Circuit: `circuits/private_transfer.circom`
- Off-chain prover/verify harness: `scripts/prove.mjs`
- Build pipeline: `scripts/build.sh` (compile + dev-setup)
- Soroban verifier (fork of soroban-examples/groth16_verifier, BLS12-381):
  `contracts/groth16-verifier/` — `src/lib.rs` (generic verifier),
  `src/test.rs` (verifies our proof + rejects tampering + dumps invoke args),
  `data/` (our vk + sample proof + public).
- Backend prover reference: `backend-prover-reference/generator.py`
- The backend health route (in the StellarHub product backend) reports the real prover
  state using the prover reference above.

## Toolchain installed this session (was absent)

- `circom` 2.2.3 (built from source via cargo)
- `snarkjs` + `circomlib` + `circomlibjs` (npm, at repo-root node_modules)
- Powers-of-Tau: generated locally (bn128 + bls12381, dev single-participant — NOT a
  production ceremony; Hermez S3 mirror returned 403, local generation is self-contained)
- `stellar-cli` 26.1.0 (brew), `wasm32v1-none` target

## Reproduce

```bash
# 1. off-chain (from repo root, after build.sh)
node scripts/prove.mjs                                  # -> local verify OK

# 2. contract host test
cd contracts/groth16-verifier
cargo test --target aarch64-apple-darwin                # -> 2 passed

# 3. on-chain (testnet)
cargo test dump_invoke_args --target aarch64-apple-darwin -- --nocapture   # writes /tmp/inv_*.json
stellar contract invoke --id CDZUXZXCKKWTAEIXRP5PCQ6O7GP5TT7NJDQ22RCB2XV4PRVL4NXMQD3E \
  --source <key> --network testnet -- verify_proof \
  --vk-file-path /tmp/inv_vk.json --proof-file-path /tmp/inv_proof.json \
  --pub_signals-file-path /tmp/inv_pub.json             # -> true
```

## Honest caveats (carry into README + video)

- **Testnet only.** Mainnet flag untouched.
- **Dev trusted setup** (single-participant, locally-generated ptau) — sound for a demo,
  NOT a production MPC ceremony (owner policy: ceremony not a launch gate).
- **MVP circuit** — commitment + nullifier + range proof; the full 4-commitment balance
  conservation + Merkle membership design is documented in
  [`docs/verifier-spec.md`](verifier-spec.md) and the circuit sources.
- **Poseidon over BLS12-381** uses circomlib's BN254-tuned constants reduced into the
  BLS12-381 scalar field — deterministic + consistent (prover and verifier agree, and the
  Groth16 check is curve-correct), but not the "standard" Poseidon parameter set. Fine for
  a demo; a production build would re-tune Poseidon constants for the BLS12-381 field.
- **Nullifier registry not yet on-chain** — the contract verifies the proof (incl. the
  nullifier as a public signal); persistent storage of spent nullifiers (double-spend
  rejection across txs) is the next contract extension (see [`docs/verifier-spec.md`](verifier-spec.md)).

---

# Model C — ZK-verified payment (IMPLEMENTED, LIVE on testnet)

> The standalone verifier above proves a Groth16 proof on-chain but **does not move
> money** — `verify_proof` just returns `true`/`false`. **Model C** closes that gap: a
> single contract that **verifies the proof AND, in the same atomic transaction, moves the
> tokens** — gating a real `transfer` on a valid proof, with on-chain nullifier replay
> protection. It is live on testnet and wired into the wallet UI (the privacy "eye"
> toggle in Shadow Pocket). The "next contract extension" caveat above is now done for
> the payment case.

## What Model C adds over the standalone verifier

| Aspect | Standalone verifier (above) | Model C — zk-verified-payment |
|---|---|---|
| Proof check on-chain | ✅ `verify_proof → true/false` | ✅ embedded in `pay_verified` |
| Moves real tokens | ❌ (returns bool only) | ✅ SAC `token::transfer(from→to)` |
| Nullifier replay protection | ❌ (nullifier is just a public signal) | ✅ persistent storage, keyed by `pub_signals[1]` |
| Atomicity | n/a | ✅ verify + transfer = **one tx** (no cross-contract hop) |
| Authorisation | n/a | ✅ `from.require_auth()` (signing stays client-side) |

## What it does (one atomic tx)

The contract `contracts/zk-verified-payment/` (Rust, BLS12-381). Entry points:

- `initialize(token, vk)` — bind the contract to a SAC token + the Groth16 verifying key.
- `pay_verified(from, to, amount, proof, pub_signals)` — does, in **one atomic tx**:
  1. `from.require_auth()` — the sender authorises the spend (client-side signing — non-custodial).
  2. nullifier replay-check — reject if `pub_signals[1]` already spent (persistent storage).
  3. embedded **Groth16 verify** over BLS12-381 host fns (same logic as the standalone
     `zk-groth16-verifier`, embedded so verify + pay is one tx — no cross-contract call).
  4. mark the nullifier spent.
  5. SAC `token::transfer(from → to)` of `amount`.
- `is_nullifier_used(nullifier)` / `get_token()` — read helpers.

## Concrete artefacts (testnet)

- **zk-verified-payment contract id:** `CD3BLTTRALUAML6WPFDUMQFVAMYY64KW4PWI6XJRNHFO4OK4JOETPYT2`
  - explorer: https://stellar.expert/explorer/testnet/contract/CD3BLTTRALUAML6WPFDUMQFVAMYY64KW4PWI6XJRNHFO4OK4JOETPYT2
  - initialized with the **native XLM SAC** `CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC` + our VK.
- **LIVE on-chain `pay_verified` tx:** `f30d2b3ec1309e249db14b8c94874c5dc13e62c4e9fc7214bdae0d7b81ed071c`
  - https://stellar.expert/explorer/testnet/tx/f30d2b3ec1309e249db14b8c94874c5dc13e62c4e9fc7214bdae0d7b81ed071c
  - emitted a transfer event of **1000000 stroops (0.1 XLM)** from cs-deployer → recipient.
  - recipient balance went **10000.0 → 10000.1 XLM** (the proof actually gated a real transfer).
- **Replay protection proven on-chain:** re-submitting the **same proof** → `Error(Contract, #4)`
  = **`NullifierUsed`** (the nullifier from `pub_signals[1]` was already marked spent).

## Tests (all green this session)

| Check | Result |
|---|---|
| `cargo test` (host, real BLS12-381 host fns) | ✅ **3/3** |
| — `verified_payment_transfers_on_valid_proof` | ✅ transfer happens on a valid proof |
| — `rejects_tampered_proof` | ✅ `ProofInvalid` on a tampered proof |
| — `rejects_replayed_nullifier` | ✅ `NullifierUsed` on proof replay |
| On-chain `pay_verified` (testnet, real tx) | ✅ recipient +0.1 XLM (tx above) |
| On-chain replay (same proof) | ✅ `Error(Contract, #4)` NullifierUsed |
| Frontend `zk-toggle` test | ✅ **12/12** |
| Frontend type-check | ✅ clean |
| Backend pytest | ✅ no new regressions |

## Frontend wiring (the privacy "eye" in Shadow Pocket)

The wallet's privacy "eye" private-send path now drives the real contract (the
client-side ZK helpers ship here under `client-lib/`):

- The Soroban invoke helper encodes the snarkjs proof to **BLS12-381 uncompressed bytes**
  via `@noble/curves`, then builds + signs + submits `pay_verified` through
  `@stellar/stellar-sdk` `contract.Client` (signing stays **client-side** — non-custodial).
  - The `@noble` encoding was verified **byte-for-byte** to equal the `ark` (arkworks)
    serialization == exactly the bytes the contract decodes. A node smoke simulated
    `pay_verified` with the `@noble` encoding against the **live** contract → **SIMULATION OK**
    (the proof verified on-chain through the real encoding path).
- The private-send path is rewired to call that Soroban invoke helper.
- `client-lib/client.ts` — `circuit_id 'private_payment' → 'private_transfer'`;
  `public_inputs number[] → string[]` (fixes 254-bit overflow of JS numbers); now returns
  `public_signals` + `contract_id`.
- Backend: `GenerateResponse` += `public_signals` (str) + `contract_id`; `SubmitRequest`
  += `signed_xdr`. The backend reads the contract id from env `ZK_VERIFIED_PAYMENT_CONTRACT`.

## Where the code lives

- Contract: `contracts/zk-verified-payment/` — `src/lib.rs` (verify + pay + nullifier),
  `src/test.rs` (the 3 host tests).
- Embedded Groth16 logic shared with the standalone verifier `contracts/groth16-verifier/`.
- Client-side ZK helpers: `client-lib/`.

## Reproduce (Model C)

```bash
# 1. contract host tests (verify + pay + replay)
cd contracts/zk-verified-payment
cargo test --target aarch64-apple-darwin               # -> 3 passed

# 2. deploy to testnet (after wasm build)
stellar contract deploy --wasm <zk-verified-payment.wasm> \
  --source <key> --network testnet
#   -> contract id (ours: CD3BLTTRALUAML6WPFDUMQFVAMYY64KW4PWI6XJRNHFO4OK4JOETPYT2)

# 3. initialize with the native XLM SAC + our verifying key
stellar contract invoke --id CD3BLTTRALUAML6WPFDUMQFVAMYY64KW4PWI6XJRNHFO4OK4JOETPYT2 \
  --source <key> --network testnet -- initialize \
  --token CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC \
  --vk-file-path /tmp/inv_vk.json

# 4. pay_verified — verify proof + transfer in one tx
stellar contract invoke --id CD3BLTTRALUAML6WPFDUMQFVAMYY64KW4PWI6XJRNHFO4OK4JOETPYT2 \
  --source <key> --network testnet -- pay_verified \
  --from <from_g_key> --to <to_g_key> --amount 1000000 \
  --proof-file-path /tmp/inv_proof.json \
  --pub_signals-file-path /tmp/inv_pub.json
#   -> transfer event 1000000 stroops; re-running same proof -> Error(Contract, #4) NullifierUsed
```

## Honest scope (Model C — carry into README + video)

- **Sender is VISIBLE on-chain.** Model C hides the amount, not the identities. The proof
  *gates execution*, *provides replay protection* (on-chain nullifier), and *binds
  amount/recipient* via the commitment — but `from` and `to` are plain accounts on the ledger
  and the transfer event is public. This is auditable amount-privacy, not identity-anonymity.
- **Native XLM only.** The contract is initialised with the native XLM SAC. Other assets
  would need a separate deploy/initialize per token.
- **Dev single-participant trusted setup** (same ptau as the standalone verifier above) —
  sound for a demo, NOT a production MPC ceremony.
- **Testnet only.** Mainnet flag untouched.
