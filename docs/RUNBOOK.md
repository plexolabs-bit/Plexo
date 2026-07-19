# Build runbook: bare machine → live testnet e2e

_Part of the [StellarHub](https://stellarhub.io) ecosystem._

> One document that takes a clean machine and drives the ZK layer all the way to a live
> `proof → on-chain verify → payment` on Stellar **testnet**.
>
> These are the build + deploy steps. The **as-run results** (with real testnet contract
> IDs and tx hashes) are recorded in [`docs/e2e-results.md`](e2e-results.md); the on-chain
> verifier design + deploy detail is in [`docs/verifier-spec.md`](verifier-spec.md). Every
> step below is written so it can be run top-to-bottom on a fresh machine.

---

## 0. Prerequisites

What you need on the machine, and what each piece is for:

| Tool | Needed for |
|---|---|
| `cargo` (Rust) | building `circom` from source, building `stellar-cli` |
| `wasm32-unknown-unknown` target | Soroban / circom toolchain |
| `node` (≥ 20) + `npm` | `snarkjs`, `circomlibjs`, `scripts/prove.mjs` |
| `npx` | resolving `snarkjs` without a global install |
| `circom` 2.2.x | compiling the circuit (install in §1) |
| `circomlib` | `include "poseidon.circom"` etc. in the circuit (§2) |
| `circomlibjs` | Poseidon in `scripts/prove.mjs` (§2) |
| `snarkjs` | Groth16 setup / prove / verify (§2) |
| `stellar-cli` / `soroban` | deploying the verifier to testnet (§8) |
| Powers of Tau (`.ptau`) | Groth16 trusted setup, phase-1 (§3) |
| Build artefacts (`build/*.wasm`, `_final.zkey`, `_verification_key.json`) | proving + verify (produced by §4–§5) |

Until the circuit is compiled and the keys are generated, a backend `/zk/generate`
endpoint degrades gracefully (HTTP **501**) and a `/zk/health` probe reports the prover as
not-yet-wired — by design, until this runbook has been run.

**"Honest WIP" is welcome** (the hackathon explicitly allows it): until this runbook has
been executed on a machine, say so plainly in the README ("off-chain demo runs locally;
on-chain testnet deploy is a documented step in `docs/RUNBOOK.md`"). Never fabricate tx
hashes.

---

## 1. Install circom (the Rust compiler)

`circom` is written in Rust. If `cargo` is present, the canonical path is to build it from
the iden3 source. (`brew install circom` is unreliable — the formula comes and goes across
taps; don't depend on it.)

### Option A — clone + `cargo build --release` (recommended, deterministic)

```bash
# Clone into any working dir OUTSIDE this repo (it is an external tool).
git clone https://github.com/iden3/circom.git ~/src/circom
cd ~/src/circom
cargo build --release            # ~3-6 min on the first run
# The binary lands in target/release/circom
```

Put it on PATH — two ways:

```bash
# (1) cargo install from the local clone — installs into ~/.cargo/bin (already on PATH)
cargo install --path circom

# (2) OR symlink manually, if you'd rather not install
ln -sf ~/src/circom/target/release/circom ~/.cargo/bin/circom
```

### Option B — `cargo install` straight from git (shorter, compiles the same thing)

```bash
cargo install --git https://github.com/iden3/circom.git
```

### Verify

```bash
circom --version          # expect 2.2.x
command -v circom         # should point at ~/.cargo/bin/circom
```

> If `circom: command not found` after install, `~/.cargo/bin` isn't on PATH. Add it to
> your shell profile: `export PATH="$HOME/.cargo/bin:$PATH"`.

---

## 2. Install circomlib + circomlibjs + snarkjs

From the repo root, `npm install` pulls these in (they are devDependencies):

```bash
npm install
```

What each is for:

| Package | Role |
|---|---|
| `circomlib` | circom template sources (`poseidon.circom`, `bitify.circom`) — the circuit `include`s them at compile time |
| `circomlibjs` | JS Poseidon — `scripts/prove.mjs` uses it to compute `commitment` + `nullifier` (must match the circuit) |
| `snarkjs` | Groth16 setup / prove / verify (CLI + JS library) |

Verify:

```bash
npx snarkjs --version                                  # CLI resolves
node -e "import('circomlibjs').then(m=>m.buildPoseidon()).then(()=>console.log('circomlibjs OK'))"
ls node_modules/circomlib/circuits/poseidon.circom     # template present
```

> **circom include-path resolution.** The circuit `include`s circomlib templates. At
> compile time (§4) we tell circom where to look with `-l node_modules`. The one-shot
> `scripts/build.sh` passes the include path for you. If circom complains "include not
> found", check the path in the header of `circuits/private_transfer.circom` and pass a
> matching `-l`.

---

## 3. Get the Powers of Tau (phase-1 ceremony artefact)

A Groth16 trusted setup is two-phase: **phase-1** (universal, circuit-agnostic — the
reusable public "Powers of Tau" artefact) + **phase-2** (per-circuit — that's §5). We do
not generate phase-1 ourselves: we download a finished one from a public
Hermez / Perpetual-Powers-of-Tau ceremony. It is a **public artefact** with no secrets in
it (the toxic waste was destroyed by the ceremony participants), so it is safe to download
from a mirror.

`private_transfer.circom` is ~520 constraints, so even `2^14` is plenty. The one-shot
`scripts/build.sh` downloads **pot14** (`2^14 = 16 384` constraints) by default, which
fits the current circuit. A larger **pot15** (`2^15 = 32 768`) leaves headroom for a
growing circuit (Merkle membership, balance flow) without re-downloading.

```bash
mkdir -p ptau
curl -fL --retry 3 \
  -o ptau/powersOfTau28_hez_final_15.ptau \
  https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_15.ptau
```

Expected size: **~5 MB** for `2^15` (for reference: `2^14` ~2.4 MB, `2^16` ~9 MB).

```bash
ls -lh ptau/powersOfTau28_hez_final_15.ptau    # sanity: ~5M, not 0 / not an HTML error
```

> **Filenames the scripts expect.**
> - `scripts/build.sh` downloads **pot14** by default to
>   `ptau/powersOfTau28_hez_final_14.ptau` and uses it (a valid path for the current
>   circuit). To make it fetch pot15 instead, override the URL before running:
>   ```bash
>   export ZK_PTAU_URL=https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_15.ptau
>   ```
> - The manual path (§5) takes the ptau path as an argument, so the filename is free.
>
> **If the Hermez mirror is unavailable:** snarkjs maintains a list of Powers-of-Tau
> mirrors (see the snarkjs README, "Powers of Tau"). Any
> `powersOfTau28_hez_final_NN.ptau` from the same ceremony is interchangeable (use
> `NN >= 14`). snarkjs can also generate a small dev ptau locally if no mirror is reachable.

---

## 4. Compile the circuit

```bash
circom circuits/private_transfer.circom --r1cs --wasm --sym -o build/
```

This emits (by circom convention):
- `build/private_transfer.r1cs` — constraint system
- `build/private_transfer.sym` — symbol table
- `build/private_transfer_js/private_transfer.wasm` — witness generator (in a nested `_js/`)

⚠️ **Important: `prove.mjs` and the backend expect the wasm FLAT** —
`build/private_transfer.wasm`, not `build/private_transfer_js/private_transfer.wasm`. Copy it:

```bash
cp build/private_transfer_js/private_transfer.wasm build/private_transfer.wasm
```

(`scripts/build.sh` does this flat-copy automatically — see §6 for the one-shot path.)

With include-path resolution (since §2 installed circomlib locally):

```bash
circom circuits/private_transfer.circom --r1cs --wasm --sym \
  -l node_modules \
  -o build/
```

Verify:

```bash
ls -lh build/private_transfer.r1cs build/private_transfer.wasm
npx snarkjs r1cs info build/private_transfer.r1cs    # prints #constraints (~520 expected)
```

---

## 5. Dev Groth16 setup (phase-2) — DEV SINGLE-PARTICIPANT, NOT a production ceremony

⚠️ **Label this explicitly:** this is a **development, single-participant** setup. One
participant, a fixed/random seed on this machine. It is **NOT** a production MPC
trusted-setup ceremony (that needs ≥7 participants and is out of scope here). For the
hackathon this is sufficient (and the hackathon explicitly allows honest WIP), but the
README and video must say so: "dev single-participant setup, production ceremony out of
scope, testnet only". Soundness of the scheme is preserved; single-participant affects the
trust assumption on the keys, not the correctness of the proof.

```bash
PTAU=ptau/powersOfTau28_hez_final_15.ptau

# (1) groth16 setup: r1cs + ptau -> initial zkey
npx snarkjs groth16 setup \
  build/private_transfer.r1cs "$PTAU" \
  build/private_transfer_0000.zkey

# (2) one dev contribution (NOT production). -e = entropy; fix the string for
#     reproducibility, or use a random one for a one-off.
npx snarkjs zkey contribute \
  build/private_transfer_0000.zkey \
  build/private_transfer_final.zkey \
  --name="stellarhub-dev" -e="dev-contribution-$(date +%s)"

# (3) export the verification key (which we later embed into the Soroban verifier)
npx snarkjs zkey export verificationkey \
  build/private_transfer_final.zkey \
  build/private_transfer_verification_key.json
```

After this, `build/` holds the three files `prove.mjs` and the backend expect:

```bash
ls -lh build/private_transfer.wasm \
       build/private_transfer_final.zkey \
       build/private_transfer_verification_key.json
```

> **Note on `setup.sh`.** Some comments mention "run build.sh + setup.sh first" — there is
> **no separate `setup.sh`**. The trusted-setup steps (this §5) are built into
> `scripts/build.sh` (the `groth16_setup` function). Don't look for a file that doesn't
> exist; use either the manual commands above or the one-shot `build.sh` (§6).

---

## 6. One-shot alternative to steps 3–5: `scripts/build.sh`

`scripts/build.sh` does §3+§4+§5 in one pass and **auto-discovers all**
`circuits/*.circom` (it compiles `private_transfer`, `range_proof`, `balance_commitment`,
and the rest). It is idempotent (skips fresh artefacts; `ZK_FORCE_REBUILD=1` forces a
rebuild).

```bash
# Requires: circom on PATH (§1) + snarkjs available (§2, or via npx).
# It downloads the ptau (pot14 by default — override ZK_PTAU_URL for pot15),
# compiles, flat-copies the wasm, runs the dev setup, and exports the vk.
npm run build:circuits        # i.e. bash scripts/build.sh
```

`build.sh` prints an artefact summary + "next steps" at the end. Exit codes: `0` ok,
`1` toolchain missing (prints install hints), `2` compile/setup failed.

> Use the manual commands (§4–§5) instead of `build.sh` when you only want
> `private_transfer` (build.sh builds every circuit), or when you're debugging a single
> step and want to see it in isolation.

---

## 7. Off-chain demo: `scripts/prove.mjs` (expect local verify OK)

This is the heart of the open reference demo: it computes `commitment` + `nullifier` via
Poseidon (the same one as the circuit), generates a Groth16 proof via snarkjs,
**verifies it locally**, and prints the submission payload `{proof, publicSignals}`.

```bash
node scripts/prove.mjs
```

Expected tail of output:

```
[prove] public commitment = <big int>
[prove] public nullifier  = <big int>
[prove] generating Groth16 proof…
[prove] local verify  = OK ✅
[prove] submission payload:
{ "proof": {...}, "publicSignals": [...] }
```

`prove.mjs` exit codes: `0` proof verified, `1` verify failed, `2` artefacts missing (go
back to §4–§5). Custom inputs:

```bash
node scripts/prove.mjs --amount 4200000 --recipient 7 --serial 123
```

> If `[prove] missing wasm/zkey/vkey`, the artefacts aren't where the script expects.
> `prove.mjs` reads `build/private_transfer.{wasm,_final.zkey,_verification_key.json}`.
> Check that you flat-copied the wasm (§4) and that the zkey/vk landed in `build/` (§5).

**This step already demonstrates ZK** (off-chain proof + verify) even without the on-chain
part. It is a valid "honest WIP" minimum for a submission if §8 stalls.

---

## 8. On-chain verifier (Soroban) — install stellar-cli + deploy

### 8a. Install stellar-cli

With `cargo` present, the canonical path is:

```bash
cargo install --locked stellar-cli       # ~5-10 min to compile
# OR (faster, if brew works):
brew install stellar-cli
```

Verify:

```bash
stellar --version
command -v stellar
```

### 8b. Generate and fund a testnet deployer key

```bash
# Generate an identity (stored in the stellar-cli local keystore)
stellar keys generate zk-deployer --network testnet

# Show the public address
stellar keys address zk-deployer

# Fund it via Friendbot (testnet faucet)
stellar keys fund zk-deployer --network testnet
# (if your CLI version lacks this command, open
#  https://friendbot.stellar.org/?addr=<PUBLIC_KEY> in a browser)
```

> ⚠️ **testnet-only.** This is a testnet key for deploying the demo contract. Do not
> confuse it with a user's wallet key (signing the payment always stays client-side —
> non-custodial). Do not touch the mainnet approval flags
> (`NEXT_PUBLIC_ZK_MAINNET_APPROVED` / `ZK_MAINNET_APPROVED`) — the whole demo is testnet.

### 8c. Deploy the verifier

The exact compile + deploy commands for the verifier contract (the fork of
`stellar/soroban-examples/groth16_verifier`, with our
`private_transfer_verification_key.json` embedded and a nullifier registry added) are in
[`docs/verifier-spec.md`](verifier-spec.md). This runbook gets you to the point where you
have the `stellar` CLI + a funded key + the exported VK; from there, follow the verifier
spec.

> The official example is the circom-native path the organisers recommend; the curve is
> BLS12-381 (Soroban host functions, Protocol 22 / CAP-0059). Before integrating, open
> `groth16_verifier` and pin down its VK/proof format + Poseidon parameters.

---

## 9. Wire up the backend (`/zk/generate`, `/zk/health`)

### 9a. Point at the build dir (if artefacts aren't in the default place)

The prover reference (`backend-prover-reference/generator.py`) resolves the build dir
env-first:
1. `ZK_CIRCUITS_BUILD_DIR` if set;
2. otherwise the repo's `build/` directory.

If you built artefacts into the default `build/`, **nothing to set**. Override only for an
ephemeral/CI build dir:

```bash
export ZK_CIRCUITS_BUILD_DIR=/abs/path/to/build
```

It finds `<circuit>.wasm` + `<circuit>_final.zkey`, resolves snarkjs (PATH or `npx`), and
shells out to `groth16 fullprove` out-of-process. Once the artefacts exist and snarkjs is
available, `/zk/generate` stops returning 501 and starts returning a real proof.

Restart the backend through your normal process manager after the artefacts land.

### 9b. Note on `/zk/health` reporting

The goal is for `/zk/health` to stop reporting the prover as "stub" once the artefacts
exist. Depending on the backend revision, the health fields may be scaffold constants that
need a small wiring change to probe the build dir — for example:

- if `<build dir>/private_transfer.wasm` and `_final.zkey` exist and snarkjs is resolvable
  → report the prover as wired (else "stub");
- report the verifier as wired only after the deployed contract ID is recorded (§8c);
  until then, honestly "stub"/"placeholder".

Until that wiring lands, **don't trust a green health field** — verify for real: that
`node scripts/prove.mjs` prints `local verify OK` (§7), and that `/zk/generate` returns a
proof rather than 501.

```bash
# health (note 9b — fields may still show "stub" until the wiring change)
curl -s http://localhost:3001/api/v1/zk/health | python3 -m json.tool
```

---

## "What blocks what" (step dependencies)

| Step | Blocks | Blocked by |
|---|---|---|
| §1 circom | §4 compile, §6 build.sh | cargo |
| §2 npm (circomlib/circomlibjs/snarkjs) | §4 (include circomlib), §5 setup, §7 prove.mjs | node/npm |
| §3 ptau | §5 setup, §6 build.sh | network |
| §4 compile | §5 setup, §7 prove.mjs | §1 + §2 |
| §5 dev-setup | §7 prove.mjs, §9 `/zk/generate` | §3 + §4 |
| §6 build.sh (one-shot §3–§5) | §7, §9 | §1 + §2 |
| §7 prove.mjs (off-chain demo) | — (terminal off-chain check) | §4 + §5 |
| §8a stellar-cli | §8b, §8c | cargo or brew |
| §8b testnet key + funding | §8c deploy | §8a + network (Friendbot) |
| §8c deploy verifier (→ verifier-spec) | on-chain e2e | §8b + §5 (needs the VK) + verifier-spec |
| §9a backend build-dir | real `/zk/generate` | §4 + §5 (artefacts) |
| §9b health wiring | `prover` ≠ "stub" in `/zk/health` | §9a + the wiring change |

Critical path to the **off-chain demo**: §1 → §2 → (§3 → §4 → §5 | or §6) → §7.
Critical path to **on-chain e2e**: + §8a → §8b → §8c (per verifier-spec) → §9.

---

## Exit-criteria checklist

Off-chain (minimum for an honest-WIP submission):
- [ ] `circom --version` → 2.2.x on PATH (§1)
- [ ] `npx snarkjs --version` + circomlibjs imports + `circomlib/circuits/poseidon.circom` present (§2)
- [ ] `ptau/powersOfTau28_hez_final_15.ptau` downloaded, ~5 MB, not 0 / not HTML (§3)
- [ ] `build/private_transfer.r1cs` + flat `build/private_transfer.wasm` exist (§4)
- [ ] `build/private_transfer_final.zkey` + `_verification_key.json` exist, marked DEV single-participant (§5)
- [ ] `node scripts/prove.mjs` → `local verify = OK ✅`, exit 0 (§7)

On-chain (full e2e):
- [ ] `stellar --version` on PATH (§8a)
- [ ] testnet deployer key generated and **funded** (Friendbot), address recorded (§8b)
- [ ] verifier deployed to testnet, contract ID recorded, valid proof → success / invalid → fail / replay → reject (§8c + verifier-spec)
- [ ] backend: `/zk/generate` returns a real proof (NOT 501) after restart (§9a)
- [ ] (wiring change) `/zk/health` shows `prover` ≠ "stub" (§9b)
- [ ] e2e: privacy eye → `/zk/generate` → local XDR signing (non-custodial) → `/zk/submit` → on-chain verify → payment, with a testnet tx hash

Discipline:
- [ ] run it yourself, don't trust a self-report: `prove.mjs` + e2e on live testnet + footprint diff
- [ ] README/video honest: dev single-participant setup, testnet-only, what is simplified / mocked — no fabricated results
- [ ] before a public push — grep for absolute paths / secrets

---

## Related documents
- [`README.md`](../README.md) — project overview, architecture diagram, honest status
- [`docs/verifier-spec.md`](verifier-spec.md) — on-chain Soroban verifier deploy (continues §8c)
- [`docs/e2e-results.md`](e2e-results.md) — the as-run live testnet results + tx hashes
- `scripts/build.sh` — one-shot pipeline (§6)
- `scripts/prove.mjs` — off-chain reference demo (§7)
- `backend-prover-reference/generator.py` — backend snarkjs subprocess (§9)
