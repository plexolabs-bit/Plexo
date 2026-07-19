# On-chain Soroban Groth16 verifier — integration spec

_Part of the [StellarHub](https://stellarhub.io) ecosystem._

> **This is the integration / design spec for the on-chain verifier** — the contract
> surface, VK transcoding, public-input ordering, and the deploy + test plan. The verifier
> has since been implemented and deployed on testnet: the as-built code is in
> [`contracts/groth16-verifier/`](../contracts/groth16-verifier) (and
> [`contracts/zk-verified-payment/`](../contracts/zk-verified-payment)), and the live
> testnet artefacts + tx hashes are recorded in [`docs/e2e-results.md`](e2e-results.md).
> Read this spec for the *why* and the wiring contract; read
> [`docs/RUNBOOK.md`](RUNBOOK.md) for the build steps.
>
> **Scope guard:** the verifier contract is the **load-bearing** ZK piece — remove it and
> the privacy property disappears (the contract is what refuses a payment whose proof
> doesn't verify or whose nullifier was already spent). The circuit / verifier / signing /
> crypto code is the sensitive core and is changed deliberately, with review.
>
> Curve: **BLS12-381** (Soroban `crypto().bls12_381()` host functions — pairing + MSM +
> scalar-field ops, available since Protocol 22 / CAP-0059). The shipped verifier
> (`contracts/groth16-verifier`) uses BLS12-381; BN254 (added later in Protocol 25
> X-Ray, CAP-0074) is a possible alternative curve but is NOT what this submission ships.

---

## 0. TL;DR

| | |
|---|---|
| **Approach** | **Fork** `stellar/soroban-examples/groth16_verifier` (Apache-2.0), inject our VK + add a nullifier registry. Do **not** hand-roll a BLS12-381 pairing verifier. |
| **VM choice** | Stellar smart contracts are **Rust → wasm on Soroban**, not EVM bytecode — so a Solidity verifier is the wrong VM. This repo ships the Soroban (Rust) path. |
| **Contract surface** | `init(vk)` · `verify_proof(proof, public_signals) -> bool` · nullifier registry (`is_spent` / `mark_spent`) · payment path (recommend thin **verify-then-emit** for the demo). |
| **Public inputs order** | `[commitment, nullifier]` — must match `private_transfer.circom` exactly. |
| **Submit path** | `@stellar/stellar-sdk` `InvokeHostFunction` from Node/browser — the JS SDK has full Soroban support today, sidestepping the Python `SorobanRpcClient` limitations. |
| **Network** | **testnet only.** Do not touch `NEXT_PUBLIC_ZK_MAINNET_APPROVED` / `ZK_MAINNET_APPROVED`. |

---

## 1. Approach — fork, don't write a pairing verifier

### 1.1 Why fork the example

The official `stellar/soroban-examples/groth16_verifier` already:

- implements the Groth16 verification equation `e(A,B) = e(α,β)·e(L,γ)·e(C,δ)` over
  **BLS12-381** using the Soroban **`bls12_381` host functions** (Protocol 22 / CAP-0059)
  (no in-contract pairing math to audit or pay gas for hand-written field ops);
- ships a VK loader + proof/public-signal deserialization in the exact byte format
  the host functions expect;
- is **Apache-2.0**, compatible with this repo's license (Apache-2.0; see [`LICENSE`](../LICENSE)).

Writing a BLS12-381 pairing verifier from scratch would be the single largest soundness
risk in the submission and is exactly what the example exists to prevent. The
hackathon's own Primer names this fork as the canonical circom path.

**Day-0 action (gates everything else):** clone the example, read its `VerifyingKey`
/ `Proof` structs + its `verify` entrypoint, and record:
1. the **field order of `public_signals`** the example expects (we must emit
   `[commitment, nullifier]` in that exact order — see §4);
2. the **VK serialization** (G1/G2 point encoding, `IC`/`gamma_abc` length, endianness)
   — our `setup` output must be transcoded to this (see §3);
3. the **Poseidon parameters** baked into any in-circuit hash the example assumes
   (BLS12-381 `F_r`; circomlib ships bn128-tuned constants which our build reduces into
   the BLS12-381 scalar field — see docs/e2e-results.md — we only need to confirm they match).

The build landed on **BLS12-381** — the circuit is compiled `circom -p bls12381`, the
verifier uses the Soroban `bls12_381` host functions, and our math-spec already covers
BLS12-381. A future **BN254** path (Protocol 25 X-Ray, CAP-0074) remains a viable
alternative — it would mean recompiling `circom -p bn128` + forking a BN254 verifier —
but it is NOT the default this submission ships.

### 1.2 Why not Solidity / EVM

Stellar smart contracts are **Rust compiled to wasm running on Soroban**, not EVM
bytecode, so a Solidity verifier would target the **wrong virtual machine**. (An early
Solidity `verifyProof` placeholder existed only so EVM-shaped type bindings could compile
against a stable interface before a real verifier existed — it is not part of this repo.)
The Soroban verifier crate described here is the real, on-chain verifier, written in Rust.

---

## 2. Contract surface

Target crate: `contracts/groth16-verifier/` (a Rust/Soroban crate forked from the
example), wasm output `private_transfer_verifier.wasm`. Storage uses Soroban
**persistent** storage for the VK and the nullifier set (they must survive across
invocations and not expire silently — bump TTL on access).

### 2.1 `init(vk)` — store the verification key

```rust
// pseudo-Soroban — exact types come from the forked example's VerifyingKey struct
pub fn init(env: Env, admin: Address, vk: VerifyingKey) {
    admin.require_auth();
    if env.storage().instance().has(&DataKey::Vk) {
        panic_with_error!(&env, Error::AlreadyInitialized); // idempotency guard
    }
    env.storage().instance().set(&DataKey::Admin, &admin);
    env.storage().instance().set(&DataKey::Vk, &vk);
}
```

- VK is set **once** at deploy time and is immutable for the demo (a `set_vk`
  admin path is out of scope — re-deploy instead if the circuit changes).
- `admin.require_auth()` keeps a stranger from front-running `init`. For a testnet
  demo the admin is the deployer keypair.

### 2.2 `verify_proof(proof, public_signals) -> bool`

```rust
pub fn verify_proof(env: Env, proof: Proof, public_signals: Vec<U256>) -> bool {
    let vk: VerifyingKey = env.storage().instance().get(&DataKey::Vk).unwrap();
    // Delegates to the forked example's pairing check, which calls the
    // BLS12-381 host functions (pairing, MSM, scalar arithmetic).
    groth16_verify(&env, &vk, &proof, &public_signals)
}
```

- `public_signals` MUST be `[commitment, nullifier]` in that order (§4).
- This is a **pure** verification predicate — no storage writes, no payment. It is
  safe to call as a read-only simulation (`stellar contract invoke --is-view`-style)
  for the "tampered proof → false" test before spending fees.

### 2.3 Nullifier registry — replay protection (persistent storage)

The nullifier is what makes double-spend impossible: each spend reveals a unique
`nullifier = Poseidon(senderSecret, serial)`; once the contract has seen it, the same
note can never be spent again.

```rust
// key: the nullifier field element (public_signals[1])
pub fn is_spent(env: Env, nullifier: U256) -> bool {
    env.storage().persistent().has(&DataKey::Nullifier(nullifier))
}

fn mark_spent(env: &Env, nullifier: U256) {
    let key = DataKey::Nullifier(nullifier);
    if env.storage().persistent().has(&key) {
        panic_with_error!(env, Error::NullifierAlreadySpent); // replay → reject
    }
    env.storage().persistent().set(&key, &true);
    // bump TTL so a long-lived nullifier entry is not archived out from under us
    env.storage().persistent().extend_ttl(&key, MIN_TTL, MAX_TTL);
}
```

**Critical ordering rule:** `mark_spent` must run inside the **same invocation** that
verified the proof and **after** verification succeeds, and the check-then-set must be
atomic (Soroban executes one contract call atomically, so the `has` → `set` pair above
is safe within `verify_and_execute`). Never split "verify" and "mark spent" across two
client-submitted transactions — a caller could replay the verified proof in the gap.

### 2.4 Payment path — two options

The proof + nullifier prove *validity*; something still has to **move value**. Two ways:

**Option A — "verify-then-emit" (RECOMMENDED for the demo).** The contract verifies +
marks the nullifier + emits an event; a **classic Stellar payment** is paired by the
backend in the same submitted transaction (or as the operation that the signed XDR
already carries). The contract does *not* custody or move funds.

```rust
pub fn verify_and_emit(env: Env, proof: Proof, public_signals: Vec<U256>) {
    let vk: VerifyingKey = env.storage().instance().get(&DataKey::Vk).unwrap();
    if !groth16_verify(&env, &vk, &proof, &public_signals) {
        panic_with_error!(&env, Error::InvalidProof); // bad proof → whole tx fails
    }
    let nullifier = public_signals.get(1).unwrap();   // [commitment, nullifier]
    mark_spent(&env, nullifier);                      // replay → whole tx fails
    env.events().publish(
        (symbol_short!("zk_spent"),),
        (public_signals.get(0).unwrap(), nullifier),  // (commitment, nullifier)
    );
}
```

Why recommended:
- **No SAC / token-custody / balance bookkeeping inside the circuit or contract** —
  the simplified MVP is "commitment + nullifier + range",
  not a full 4-commitment confidential-balance pool with on-chain balances. Option A keeps the
  contract tiny and auditable for the demo window.
- Matches the architecture diagram in the README
  (verifier verifies → payment executes). The on-chain observer sees the payment
  sourced from the verifier-contract context, not the sender's pubkey.
- The atomicity we need (verify **and** pay, or neither) comes from bundling the
  `InvokeHostFunction` (verify_and_emit) **and** the payment op in one transaction:
  if `verify_and_emit` panics, the classic payment in the same tx never applies.

**Option B — contract executes the payment itself** via a Stellar Asset Contract
(SAC) `transfer`, contract-as-custodian. This is the full custodial-pool end — the
contract holds/routes value, manages a deposit pool, and reasons about balances. The
repo's `zk-confidential-transfer` contract is exactly this pool-based amount-hiding model
(deposit / confidential_transfer / withdraw); Model C uses Option A. Documented here so
the design is honest about what each payment model requires.

**Recommendation for Model C: ship Option A.** Note it explicitly in the public README as a
simplification ("the contract proves validity + blocks replay; value moves via a
paired classic payment, not a custodial on-chain balance model").

### 2.5 Error surface (panics → failed tx)

| Error | When | Effect |
|---|---|---|
| `AlreadyInitialized` | `init` called twice | tx fails |
| `InvalidProof` | pairing check false | tx fails (**tampered proof → reject**) |
| `NullifierAlreadySpent` | nullifier in storage | tx fails (**replay → reject**) |
| (panic in `groth16_verify`) | malformed proof bytes / wrong public-input arity (**wrong public inputs**) | tx fails |

All four are *negative*-path test rows in §7.

---

## 3. Mapping our VK into the contract's VK format

Our setup (see [`docs/RUNBOOK.md`](RUNBOOK.md) and `scripts/build.sh`) produces
`build/private_transfer_verification_key.json` (snarkjs format: `vk_alpha_1`,
`vk_beta_2`, `vk_gamma_2`, `vk_delta_2`, `IC[]`, all as decimal-string coordinate
arrays).

The Soroban verifier does **not** read snarkjs JSON directly. Two transcoding routes:

1. **Use the forked example's own VK loader (CANONICAL).** The example defines the
   on-chain `VerifyingKey` struct and a constructor/loader that takes the curve points
   in the byte layout the BLS12-381 host functions expect (typically big-endian 32-byte
   field-element limbs, G1 = 2 coords, G2 = 4 coords). Write a tiny build-time
   transcoder (`scripts/vk_to_soroban.mjs`) that reads `*_verification_key.json` and
   emits the example's expected input (a constructor arg blob, a generated Rust
   `const`, or a JSON the deploy script feeds to `init`). **The example's loader
   format is the source of truth — match it, don't invent one.**

2. **snarkjs `zkey export solidityverifier` / `export verifier` exists but is a
   trap here.** snarkjs can emit a *Solidity* (and a generic) verifier from the zkey,
   but that targets EVM, not Soroban — same dead end as §1.2. We use snarkjs only to
   produce the **VK JSON + proofs**; the **on-chain verifier is the Soroban fork**, and
   its loader is canonical for VK ingestion.

**Day-0 sub-task:** after reading the example's `VerifyingKey` struct (§1.1), write
`scripts/vk_to_soroban.mjs` and assert round-trip: snarkjs JSON → Soroban VK input →
`init` → `verify_proof(valid_proof) == true`. The number of `IC` entries must equal
`(#public_inputs + 1)` = **3** (commitment, nullifier, +1 constant term). A mismatch
here is the most likely silent integration bug.

---

## 4. Public inputs ordering — `[commitment, nullifier]`

The circuit `private_transfer.circom` declares its public signals in this order
(public outputs of `main`):

```
public_signals[0] = commitment   // Poseidon(amount, blinding, recipient)
public_signals[1] = nullifier    // Poseidon(senderSecret, serial)
```

This ordering is **load-bearing across three layers** and must be identical in all of them:

| Layer | Where | Must emit / read |
|---|---|---|
| Circuit | `private_transfer.circom` `main {public [...]}` | `[commitment, nullifier]` |
| Prover output | snarkjs `publicSignals` array (`scripts/prove.mjs`) | `[commitment, nullifier]` |
| Backend → frontend | `Proof.public_inputs` (`lib/zk/client.ts`, decimal strings) | same order |
| Contract | `verify_proof(_, public_signals)` + `public_signals.get(1)` for nullifier | indexes `[0]=commitment`, `[1]=nullifier` |

⚠️ **Off-by-order = silent soundness break.** If the contract reads `nullifier` from
`public_signals[0]`, replay protection keys on the wrong value and the pairing check
may still pass for a *different* statement. The §7 "wrong public inputs" row exists to
catch exactly this. snarkjs orders `publicSignals` by the circuit's declared public
signal order, so the contract's index assumptions must be pinned to the `.circom`
declaration and asserted in a test, not assumed.

> Note on serialization width: `Proof.public_inputs` is typed `number[]` in
> `lib/zk/client.ts` with a `// beware >2^53` comment, and `zk-send.ts` maps them with
> `Number(...)`. BLS12-381 field elements are 255-bit and **overflow JS `number`**. For the
> on-chain call the public signals MUST be carried as **decimal strings → `U256`/byte
> arrays**, never as JS `number`. The contract-facing JS submit path (§6) must read the
> raw decimal-string `proof.public_inputs` (or a `public_inputs_raw` string field), not
> the lossy numeric projection used for UI display. Flag this when wiring §6.

---

## 5. Deploy steps (testnet)

Cross-ref [`docs/RUNBOOK.md`](RUNBOOK.md) for the circuit-compile + trusted-setup half;
this section is the **contract** half. All commands are `stellar-cli` (a.k.a. `soroban`)
and require the toolchain installed + a Friendbot-funded testnet key.

```bash
# 0. one-time: identity + testnet funding
stellar keys generate zk-deployer --network testnet
stellar keys fund zk-deployer --network testnet     # friendbot

# 1. build the verifier crate → wasm
cd contracts/groth16-verifier
stellar contract build                              # -> target/wasm32-unknown-unknown/release/private_transfer_verifier.wasm

# 2. optimize (shrinks wasm, lowers deploy + invoke cost)
stellar contract optimize \
  --wasm target/wasm32-unknown-unknown/release/private_transfer_verifier.wasm
# -> private_transfer_verifier.optimized.wasm

# 3. deploy to testnet, capture the contract ID
CONTRACT_ID=$(stellar contract deploy \
  --wasm private_transfer_verifier.optimized.wasm \
  --source zk-deployer --network testnet)
echo "$CONTRACT_ID"            # C... — record in README + backend config

# 4. init with the transcoded VK (from §3 / scripts/vk_to_soroban.mjs)
stellar contract invoke --id "$CONTRACT_ID" \
  --source zk-deployer --network testnet \
  -- init --admin "$(stellar keys address zk-deployer)" \
          --vk "$(node scripts/vk_to_soroban.mjs build/private_transfer_verification_key.json)"

# 5. smoke: verify a known-good proof (off-chain proof from scripts/prove.mjs)
stellar contract invoke --id "$CONTRACT_ID" \
  --source zk-deployer --network testnet --is-view \
  -- verify_proof --proof @proof.json --public_signals @public_signals.json
# expect: true
```

**Record after deploy:** `CONTRACT_ID` goes into (a) the README "what works" block,
(b) the backend so `/zk/generate` returns it as `contract_id`, and (c) the frontend's
ready-state. Carry the verifier contract ID in an env var (suggest
`ZK_VERIFIER_CONTRACT_ID`, env-configurable) rather than hardcoding it.

---

## 6. How the backend + frontend call the contract (JS `InvokeHostFunction` path)

**Key decision: the on-chain invocation is done from JavaScript via
`@stellar/stellar-sdk`, NOT from Python.** A Python `submit_proof_to_chain(...)` path was
a documented **stub** (returns a placeholder tx hash; the Python Soroban-RPC client lacked
`SorobanRpcClient` + `TxBuilder.add_soroban_invoke` support at the time). The JS SDK has
full Soroban support today, so the submit path uses JS and sidesteps those gaps entirely.

### 6.1 Wiring shape and the exact gap

The orchestration scaffold is correctly shaped — only the actual RPC invocation needs to
land. The roles:

| Layer | State |
|---|---|
| Frontend send path (`client-lib/`) | **Signs `unsignedXdr` locally** (`Keypair.fromSecret` or an external wallet — non-custodial), then submits. Already imports `@stellar/stellar-sdk` `TransactionBuilder`/`Keypair`. |
| Frontend client (`client-lib/client.ts`) | Already POSTs `{proof, contract_id, network, signed_xdr, stellar_network}` to the `/zk/submit` endpoint. |
| Backend `SubmitRequest` schema | The submit request must bind `signed_xdr` (the field the frontend already sends), not only `{proof, contract_id, network}`. |
| Backend `submit_proof_to_chain(...)` | The Python stub returns a placeholder tx hash; it is replaced by a real Soroban invocation (in JS, per the decision above). |

So the integration work is: **(1)** bind `signed_xdr` in the submit request; **(2)**
replace the stub with a real Soroban invocation; **(3)** decide where the JS SDK runs
(below).

### 6.2 Two placements for the JS `InvokeHostFunction` (pick one)

The proof is generated client-side, signing is client-side (non-custodial). The
`InvokeHostFunction` that calls `verify_and_emit` can be assembled in either place:

**Placement 1 — frontend assembles + signs the contract invocation directly
(simplest, most non-custodial, RECOMMENDED).** The frontend builds the
`InvokeHostFunction` op against `CONTRACT_ID`, signs it locally, and submits to Soroban
RPC itself; `/zk/submit` becomes an optional audit/echo endpoint. Pseudocode:

```ts
import {
  Contract, TransactionBuilder, Networks, BASE_FEE, nativeToScVal,
  rpc, // SorobanRpc server
} from '@stellar/stellar-sdk';

const server = new rpc.Server('https://soroban-testnet.stellar.org');
const contract = new Contract(contractId);   // CONTRACT_ID from §5
const account = await server.getAccount(senderPublicKey);

// public_signals MUST be the RAW decimal strings (§4 width note), not JS numbers
const op = contract.call(
  'verify_and_emit',
  proofToScVal(proof),                        // serialize Groth16 proof → ScVal
  nativeToScVal(publicSignalsRaw.map(toU256)),// [commitment, nullifier] as U256
);

let tx = new TransactionBuilder(account, { fee: BASE_FEE, networkPassphrase: Networks.TESTNET })
  .addOperation(op)
  .setTimeout(60)
  .build();

tx = await server.prepareTransaction(tx);     // simulate + assemble footprint + resource fees
tx.sign(Keypair.fromSecret(secretKey));       // local signing (non-custodial)
const sent = await server.sendTransaction(tx);
// poll server.getTransaction(sent.hash) until SUCCESS → return tx_hash
```

`server.prepareTransaction` is what handles Soroban's simulate→assemble→resource-fee
dance (the thing the Python `TxBuilder` couldn't do). This is why the JS path is
unblocked.

**Placement 2 — backend assembles the invocation, frontend signs it.** `/zk/generate`
returns an `unsignedXdr` that **already contains** the `InvokeHostFunction(verify_and_emit)`
op (built server-side with `@stellar/stellar-sdk` in a small Node helper the FastAPI
backend shells out to, OR in the Express tier). Frontend signs (existing `zk-send.ts`
flow, unchanged), POSTs `signed_xdr` to `/zk/submit`, backend `sendTransaction`s it.
This matches the *current* `zk-send.ts` shape (it already signs `unsignedXdr` and sends
`signed_xdr`) but requires the backend to host the JS SDK and the `SubmitRequest`
schema gap (§6.1) to be closed.

**Recommendation:** **Placement 1** for the demo — fewer moving parts, no backend Soroban
tier, strongest non-custodial story (the user's wallet talks to Soroban directly). Keep
`/zk/submit` as a thin audit log. If the demo needs the "payment appears sourced from the
verifier context" framing to be backend-mediated, fall back to Placement 2 and close the
`signed_xdr` gap.

Either way: **signing stays client-side (non-custodial)**, the proof is verified
**on-chain** before value moves, and the Python path is untouched (its Soroban-RPC gaps
remain deferred — not on the critical path).

---

## 7. Test matrix

Run off-chain first (snarkjs local verify in `scripts/prove.mjs`), then on-chain against
the deployed `CONTRACT_ID`. The as-run results (T1–T4 on testnet, with tx hashes) are
recorded in [`docs/e2e-results.md`](e2e-results.md); this matrix is the spec those runs
follow.

| # | Case | Setup | Expected | Layer |
|---|---|---|---|---|
| T1 | **Valid proof → success** | Honest witness, fresh nullifier | `verify_proof == true`; `verify_and_emit` succeeds, `zk_spent` event emitted, paired payment applies | off-chain + on-chain |
| T2 | **Tampered proof → fail** | Flip one byte of `proof.pi_a` / wrong `proof` for the public signals | `verify_proof == false`; `verify_and_emit` panics `InvalidProof`, whole tx fails, nullifier **not** marked | off-chain + on-chain |
| T3 | **Replayed nullifier → reject** | Submit T1's exact `{proof, public_signals}` a second time | First succeeds; second panics `NullifierAlreadySpent`, tx fails | on-chain (state-dependent) |
| T4 | **Wrong public inputs → fail** | Valid proof but `public_signals` reordered (`[nullifier, commitment]`) or a value mutated | Pairing check fails → `false`/`InvalidProof`; catches the §4 off-by-order class | off-chain + on-chain |
| T5 | *(bonus)* **Uninitialized contract** | Call `verify_proof` before `init` | Panics (no VK) — confirms `init` is required | on-chain |
| T6 | *(bonus)* **Double `init`** | Call `init` twice | Second panics `AlreadyInitialized` | on-chain |

T1–T4 are the required hackathon rows (the Definition of Done: "valid → success,
invalid → fail, replay → reject"). T5/T6 harden the admin surface and are cheap to add.

**Where these live:** Rust `#[test]` for the contract logic using the Soroban test
harness (mocked host fns) for T2/T5/T6; a live-testnet integration script
(`scripts/e2e_testnet.mjs`, JS SDK) for T1/T3/T4 against the deployed contract, recording
a real `tx_hash` for the README + video.

---

## 8. Open items / honest gaps (carry into implementation)

1. **Toolchain install is a prerequisite** — `stellar-cli`, `circom`, `circomlib`, a
   `.ptau` (`pot15_final.ptau` covers the ~520-constraint circuit), and the compiled
   circuit. See [`docs/RUNBOOK.md`](RUNBOOK.md) for setup.
2. **`SubmitRequest` schema gap** (§6.1): frontend sends `signed_xdr`, backend doesn't
   bind it yet. One-field fix when wiring Placement 2; moot for Placement 1.
3. **Public-signal width** (§4 note): `public_inputs` is lossy `number[]` for UI; the
   on-chain call must use raw decimal strings → `U256`. Add a `public_inputs_raw` field
   or read the unparsed backend value.
4. **Verifier contract ID env var** — carry `ZK_VERIFIER_CONTRACT_ID` (env-configurable)
   rather than hardcoding the deployed `C...`.
5. **VK transcoder** (`scripts/vk_to_soroban.mjs`) doesn't exist — write it Day-0 against
   the forked example's `VerifyingKey` struct; assert `IC.length == 3`.
6. **Dev trusted setup** (single-participant) — soundness comes from the scheme; a
   production MPC ceremony is explicitly **out of scope** (the hackathon allows honest
   WIP). Label it in the README.
7. **Model C's payment model is Option A (verify-then-emit)** — not a full custodial
   on-chain balance pool. State this plainly in the public README.

---

## 9. Related documents

- [`README.md`](../README.md) — project overview, architecture diagram, honest status.
- [`docs/RUNBOOK.md`](RUNBOOK.md) — circuit compile + dev trusted setup + `prove.mjs` (the half this spec cross-refs at §3/§5).
- [`docs/e2e-results.md`](e2e-results.md) — the as-built live testnet results + tx hashes.
- `contracts/groth16-verifier/` — the forked Soroban verifier crate (BLS12-381).
- `contracts/zk-verified-payment/` — verify + pay + nullifier in one atomic tx.
- Reference example: <https://github.com/stellar/soroban-examples/tree/main/groth16_verifier> (Apache-2.0).
