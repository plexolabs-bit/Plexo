// StellarHub ZK reference · https://stellarhub.io
pragma circom 2.2.0;

// PrivateTransfer — MVP confidential-payment circuit for Stellar Hacks: Real-World ZK.
//
// STATUS 2026-06-12: COMPILED + PROVEN. Compiles with circom 2.2.x, generates a
// Groth16 proof that verifies off-chain (snarkjs) and on-chain (Soroban
// groth16_verifier, BLS12-381). See the project build docs.
//
// Curve: BLS12-381 — matches stellar/soroban-examples/groth16_verifier
// (env.crypto().bls12_381()) and the project circuit math spec.
// Compile with: circom private_transfer.circom -p bls12381 --r1cs --wasm --sym
//
// What it proves (zero-knowledge), and why ZK is load-bearing here:
//   The prover knows (amount, blinding, recipient, senderSecret, serial) such that
//   the public outputs are exactly:
//     commitment = Poseidon(amount, blinding, recipient)   — binds the transfer
//     nullifier  = Poseidon(senderSecret, serial)          — unique double-spend marker
//   AND 0 <= amount < 2^64 (range proof — the amount stays hidden but bounded).
//   The Soroban verifier accepts the payment ONLY if the Groth16 proof over these
//   constraints checks out; remove the proof and the privacy/safety property is gone.
//
// Design note: commitment + nullifier are circuit OUTPUTS (computed in-circuit),
// not checked public inputs. This keeps the public signals field-correct on any
// curve (the in-circuit Poseidon defines them) and removes any off-chain hash
// precomputation from the prover path.
//
// Public signals (outputs): commitment, nullifier  (what the chain sees + records)
// Private inputs: amount, blinding, recipient, senderSecret, serial (never leave prover)
//
// MVP slice of the full design (which adds the
// 4-commitment balance-conservation flow + Merkle membership). Kept small so a
// proof generates fast enough for a live demo.

include "../../../node_modules/circomlib/circuits/poseidon.circom";
include "../../../node_modules/circomlib/circuits/bitify.circom";

template PrivateTransfer() {
    // --- Private witness (MUST never leave the prover) ---
    signal input amount;       // transfer value, range-bound to [0, 2^64)
    signal input blinding;     // commitment randomness (hiding)
    signal input recipient;    // recipient identity as a field element
    signal input senderSecret; // sender spending secret
    signal input serial;       // unique note serial (per-note, prevents replay)

    // --- Public outputs (become the proof's public signals) ---
    signal output commitment;  // Poseidon(amount, blinding, recipient)
    signal output nullifier;   // Poseidon(senderSecret, serial)

    // (1) Range proof: amount in [0, 2^64). Num2Bits is unsatisfiable for any
    //     amount outside the range, so proof generation fails — exactly the guard
    //     we want. Caps the value well below the scalar field order.
    component rangeCheck = Num2Bits(64);
    rangeCheck.in <== amount;

    // (2) Commitment binding: commitment = Poseidon(amount, blinding, recipient).
    component commHash = Poseidon(3);
    commHash.inputs[0] <== amount;
    commHash.inputs[1] <== blinding;
    commHash.inputs[2] <== recipient;
    commitment <== commHash.out;

    // (3) Nullifier derivation: nullifier = Poseidon(senderSecret, serial). The
    //     verifier contract stores spent nullifiers; a second spend of the same
    //     note reproduces this nullifier and is rejected on-chain.
    component nullHash = Poseidon(2);
    nullHash.inputs[0] <== senderSecret;
    nullHash.inputs[1] <== serial;
    nullifier <== nullHash.out;
}

// Outputs of the main component are public by default; the 5 inputs stay private.
// Expected constraint count: ~520 (Poseidon(3) ~240 + Poseidon(2) ~215 + Num2Bits(64) ~64).
component main = PrivateTransfer();
