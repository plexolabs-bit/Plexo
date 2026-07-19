// StellarHub ZK reference · https://stellarhub.io
pragma circom 2.2.0;

// ProofOfReserves — solvency / "I hold at least X" circuit for Stellar Hacks:
// Real-World ZK. Mirrors the proven Model C style of private_transfer.circom
// (circom 2.2.0, BLS12-381, circomlib Poseidon + Num2Bits range), so the same
// build.sh + dev-setup + prove pipeline compiles and proves it unchanged.
//
// Curve: BLS12-381 — matches stellar/soroban-examples groth16_verifier
// (env.crypto().bls12_381()) and our zk-groth16-verifier contract. Compile with:
//   circom proof_of_reserves.circom -p bls12381 --r1cs --wasm --sym
//
// What it proves (zero-knowledge), and why ZK is load-bearing here:
//   The prover knows (balance, blinding) such that
//     commitment = Poseidon(balance, blinding)   — a hiding commitment to the balance
//     AND 0 <= balance < 2^64                     — the balance is a real 64-bit reserve
//     AND balance >= threshold                    — solvency: holds at least the threshold
//   The public input `threshold` is the only bound the verifier learns; the actual
//   `balance` stays hidden. An exchange / treasury / individual can publish
//   "reserves >= threshold" without revealing the exact figure or doxxing the wallet.
//   Strip the proof and the solvency claim is unbacked — the proof IS the attestation.
//
// Design note (matches private_transfer.circom): `commitment` is a circuit OUTPUT
// (in-circuit Poseidon), not a checked public input. This keeps the public signals
// field-correct on any curve (the in-circuit Poseidon defines the commitment) and
// removes off-chain hash precomputation from the prover path. The commitment is the
// anchor a verifier records so a later reveal / audit can be bound to this proof.
//
// Public signals:
//   input  : threshold   (the solvency floor the claim is about — what the chain sees)
//   output : commitment  (Poseidon(balance, blinding) — recorded alongside the claim)
// Private inputs: balance, blinding (never leave the prover)
//
// Soundness note on the comparator domain: circomlib GreaterEqThan(n) is sound only
// when BOTH operands fit in n bits (it computes in[0] + (1<<n) - in[1] and constrains
// the result to n+1 bits). We therefore range-bind BOTH `balance` AND `threshold` to
// [0, 2^64) with Num2Bits(64) before the GreaterEqThan(64) check — otherwise a prover
// could feed an out-of-range threshold that wraps the comparator and forge solvency.
// 64 bits is plenty for stroop-denominated reserves (max ~1.8e19 stroops > total XLM
// supply in stroops) and stays far below the BLS12-381 scalar field order.

include "../../../node_modules/circomlib/circuits/poseidon.circom";
include "../../../node_modules/circomlib/circuits/bitify.circom";
include "../../../node_modules/circomlib/circuits/comparators.circom";

template ProofOfReserves() {
    // --- Private witness (MUST never leave the prover) ---
    signal input balance;      // actual reserves, range-bound to [0, 2^64)
    signal input blinding;     // commitment randomness (hiding)

    // --- Public input ---
    signal input threshold;    // solvency floor the claim attests to (range-bound below)

    // --- Public output (becomes a proof public signal) ---
    signal output commitment;  // Poseidon(balance, blinding)

    // (1) Range proof on the private balance: balance in [0, 2^64). Num2Bits is
    //     unsatisfiable outside the range, so a balance that doesn't fit makes
    //     proof generation fail — same guard as private_transfer.circom.
    component balanceRange = Num2Bits(64);
    balanceRange.in <== balance;

    // (2) Range proof on the public threshold: keeps both comparator operands in
    //     the 64-bit domain so GreaterEqThan(64) is sound (see header note). A
    //     threshold outside [0, 2^64) makes the proof unsatisfiable rather than
    //     letting it wrap the comparison.
    component thresholdRange = Num2Bits(64);
    thresholdRange.in <== threshold;

    // (3) Solvency constraint: balance >= threshold. GreaterEqThan(64).out is 1
    //     iff the inequality holds; constrain it to exactly 1 so any balance below
    //     the threshold is unprovable.
    component solvent = GreaterEqThan(64);
    solvent.in[0] <== balance;
    solvent.in[1] <== threshold;
    solvent.out === 1;

    // (4) Commitment binding: commitment = Poseidon(balance, blinding). Recorded
    //     by the verifier so a future reveal / audit can be tied back to this exact
    //     attested balance.
    component commHash = Poseidon(2);
    commHash.inputs[0] <== balance;
    commHash.inputs[1] <== blinding;
    commitment <== commHash.out;
}

// `threshold` is the only PUBLIC INPUT; `commitment` (a main-component output) is
// public by default; `balance` + `blinding` stay private.
// Expected constraint count: ~430 (Poseidon(2) ~215 + 2× Num2Bits(64) ~128 +
// GreaterEqThan(64) ~65). Comfortably within the pot14/pot15 ceiling.
component main { public [threshold] } = ProofOfReserves();
