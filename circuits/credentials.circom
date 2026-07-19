// StellarHub ZK reference · https://stellarhub.io
pragma circom 2.2.0;

// Credentials — verifiable-credential predicate circuit for Stellar Hacks:
// Real-World ZK. Mirrors the Model C (private_transfer.circom) style: circom
// 2.2.0, BLS12-381, circomlib Poseidon + bitify range checks, commitment +
// nullifier as in-circuit OUTPUTS.
//
// STATUS 2026-06-13: AUTHORED — circuit written, NOT yet compiled / proven.
// Compile + dev-setup + verify are manual build steps (ptau + trusted-setup
// are slow). See the project build docs (build.sh
// auto-discovers every circuits/*.circom, so this file builds with the others).
//
// Curve: BLS12-381 — matches stellar/soroban-examples groth16_verifier
// (env.crypto().bls12_381()) and the project circuit math spec.
// Compile with: circom credentials.circom -p bls12381 --r1cs --wasm --sym
//
// What it proves (zero-knowledge), and why ZK is load-bearing here:
//   The prover holds a credential value `attribute` (e.g. an age, or a KYC=1
//   flag) bound under a secret to a public `issuerCommitment` the issuer
//   registered, and proves — WITHOUT revealing `attribute` — that it satisfies
//   a predicate the verifier picks:
//     issuerCommitment = Poseidon(attribute, secret)  — binds the credential
//     nullifier        = Poseidon(secret, credentialId)— single-use spend marker
//   AND one of two parameterized predicates holds (public `mode` selects):
//     mode == 0 (equality):  attribute == expectedValue   (e.g. KYC-passed == 1)
//     mode == 1 (threshold): attribute >= minValue         (e.g. age >= 18)
//   The presenter learns the holder satisfies the policy, never the value.
//   Remove the proof and the selective-disclosure property is gone.
//
// Design note (mirrors private_transfer.circom):
//   * issuerCommitment + nullifier are circuit OUTPUTS (computed in-circuit via
//     Poseidon), NOT checked public inputs. This keeps the public signals
//     field-correct on any curve and removes off-chain hash precomputation from
//     the prover path. The verifier-side registry compares the OUTPUT
//     issuerCommitment against the issuer's published commitment; the nullifier
//     output is recorded on-chain to prevent credential replay.
//   * The predicate is enforced as a hard CONSTRAINT (=== 1), not an output —
//     an unsatisfied predicate makes the witness unsatisfiable and proof
//     generation fails, exactly like the Num2Bits range guard in
//     private_transfer. So a verified proof is itself the attestation; there is
//     no extra boolean for the verifier to (mis)read.
//
// Public signals:
//   inputs  (checked, in declaration order): mode, expectedValue, minValue
//   outputs (become public signals too):     issuerCommitment, nullifier
//   => nPublic = 5  (3 public inputs + 2 outputs). NB: this differs from
//   private_transfer's nPublic=2, so credentials needs its OWN verification key
//   (per-circuit vk) — the Soroban groth16_verifier is generic over the vk it is
//   handed (verify_proof(vk, proof, pub_signals)), so the SAME deployed verifier
//   serves this circuit with the credentials vk. No new contract required; see
//   the design note in the project docs.
//
// Private inputs: attribute, secret, credentialId (never leave the prover).
//
// Range model: comparisons use circomlib GreaterEqThan(N_BITS), which internally
// builds Num2Bits(N_BITS+1) over a biased difference. For the comparison to be
// SOUND both operands must independently lie in [0, 2^N_BITS) — otherwise field
// wraparound could forge the inequality. We therefore Num2Bits-bound `attribute`
// AND `minValue` to N_BITS bits before comparing (the same guard private_transfer
// applies to `amount`). 64 bits covers ages, KYC flags, tiers, and timestamps
// with huge headroom while staying far below the scalar field order.

include "../../../node_modules/circomlib/circuits/poseidon.circom";
include "../../../node_modules/circomlib/circuits/bitify.circom";
include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../node_modules/circomlib/circuits/mux1.circom";

template Credentials(N_BITS) {
    // --- Private witness (MUST never leave the prover) ---
    signal input attribute;     // the credential value, e.g. age or KYC flag
    signal input secret;        // holder's binding secret (hiding + nullifier seed)
    signal input credentialId;  // per-credential id (issuer-assigned, unique)

    // --- Public inputs (the verifier's policy: which predicate + bound) ---
    signal input mode;          // predicate selector: 0 = equality, 1 = threshold
    signal input expectedValue; // equality target (used when mode == 0)
    signal input minValue;      // threshold floor (used when mode == 1)

    // --- Public outputs (become public signals) ---
    signal output issuerCommitment; // Poseidon(attribute, secret)
    signal output nullifier;        // Poseidon(secret, credentialId)

    // (1) Mode MUST be a single bit. Without this a prover could pass mode=2 and
    //     Mux1 would select out-of-range; pin it to {0,1}.
    mode * (mode - 1) === 0;

    // (2) Range-bound the comparison operands so GreaterEqThan is sound (no field
    //     wraparound). attribute is also implicitly bounded for the equality case
    //     (a 64-bit KYC flag / tier is the natural domain). minValue is bounded so
    //     a malicious verifier-supplied bound can't wrap either.
    component attrBits = Num2Bits(N_BITS);
    attrBits.in <== attribute;
    component minBits = Num2Bits(N_BITS);
    minBits.in <== minValue;

    // (3) Commitment binding: issuerCommitment = Poseidon(attribute, secret).
    //     The verifier checks this OUTPUT against the issuer's registered
    //     commitment for this credential (registry membership is enforced
    //     verifier-side, off-circuit, in the MVP — see design doc §4).
    component commHash = Poseidon(2);
    commHash.inputs[0] <== attribute;
    commHash.inputs[1] <== secret;
    issuerCommitment <== commHash.out;

    // (4) Nullifier derivation: nullifier = Poseidon(secret, credentialId). The
    //     verifier contract stores spent nullifiers; re-presenting the same
    //     credential reproduces this nullifier and is rejected on-chain.
    component nullHash = Poseidon(2);
    nullHash.inputs[0] <== secret;
    nullHash.inputs[1] <== credentialId;
    nullifier <== nullHash.out;

    // (5) Parameterized predicate.
    //     eqResult  = (attribute == expectedValue)      -> 1 / 0
    //     geResult  = (attribute >= minValue)           -> 1 / 0
    //     selected  = mode ? geResult : eqResult        (Mux1, s = mode)
    //     Constrain selected === 1, so exactly the chosen predicate must hold.
    component eq = IsEqual();
    eq.in[0] <== attribute;
    eq.in[1] <== expectedValue;

    component ge = GreaterEqThan(N_BITS);
    ge.in[0] <== attribute;
    ge.in[1] <== minValue;

    // Mux1: out = (s == 0) ? c[0] : c[1]. Select threshold when mode==1.
    component sel = Mux1();
    sel.c[0] <== eq.out;
    sel.c[1] <== ge.out;
    sel.s <== mode;

    // The selected predicate MUST be satisfied — unsatisfiable witness otherwise,
    // so proof generation fails (the guard we want; no extra public boolean).
    sel.out === 1;
}

// Public signals = the 3 declared public inputs (mode, expectedValue, minValue)
// + the 2 outputs (issuerCommitment, nullifier). The 3 witness inputs
// (attribute, secret, credentialId) stay private.
// Expected constraint count: ~560 (2× Poseidon(2) ~430 + 2× Num2Bits(64) ~128 +
// IsEqual ~2 + GreaterEqThan(64) ~67 + Mux1 ~1).
component main { public [mode, expectedValue, minValue] } = Credentials(64);
