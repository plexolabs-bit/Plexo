pragma circom 2.2.0;

// ConfidentialWithdraw — EXPERIMENTAL testnet PoC circuit that makes the
// confidential-pool withdraw() TRUSTLESS. Sibling in style to
// confidential_transfer.circom (circom 2.2.x, BLS12-381, circomlib Poseidon +
// Num2Bits), so the same `-p bls12381` compile + dev trusted setup + snarkjs
// prove pipeline applies. Compile with:
//   circom confidential_withdraw.circom -p bls12381 --r1cs --wasm --sym
//
// ---------------------------------------------------------------------------
// WHY THIS EXISTS — closing the v1 withdraw trust note.
//
// In the v1 pool, withdraw() is OPERATOR-ATTESTED: the contract burns a stored
// balance commitment and pays out a public amount, but NOTHING proves that the
// burned commitment actually opened to that amount. A malicious prover (or a
// compromised attester) could burn a commitment to 1 token and withdraw 1000.
//
// This circuit removes that trust. It proves, in zero knowledge of the blinding:
//   "I know the opening (amount, blinding) of this PUBLIC stored commitment, and
//    the committed value EQUALS this PUBLIC withdrawn amount."
// Because `amount` is the SAME signal that (a) is exposed as a public input and
// (b) is hashed into the commitment, the revealed boundary amount is cryptographi-
// cally bound to the burned commitment — the operator no longer has to be trusted
// for value conservation at the withdraw boundary.
//
// ---------------------------------------------------------------------------
// WHY `amount` IS PUBLIC (and that is the whole point).
//
// Unlike the in-pool transfer (where the amount stays a hidden commitment), a
// withdraw MOVES REAL TOKENS OUT of the confidential pool, so the boundary amount
// is visible on-chain by construction. This circuit does not pretend otherwise —
// it makes the visible amount HONEST by proving it matches the commitment being
// destroyed, instead of asserting "amount is a Poseidon secret" (which would be a
// false privacy claim for a boundary op).
//
// ---------------------------------------------------------------------------
// FORGE RESISTANCE — why a wrong-amount withdraw is UNSATISFIABLE.
//
// To withdraw a WRONG public amount a' (!= the real committed amount a) against a
// real stored commitment C = Poseidon(a, blinding), the prover would need some
// blinding' with Poseidon(a', blinding') == C. Since a' != a, that is a Poseidon
// second-preimage — infeasible. The honest witness the prover actually holds is
// (a, blinding); feeding it with the public amount overwritten to a' makes the
// SAME `amount` signal a', so the opener computes Poseidon(a', blinding) != C and
// the `commitment === opener.out` constraint is violated ⇒ no satisfying witness
// ⇒ proof generation FAILS. There is no separate "claimed amount" knob to desync
// from the hashed amount: it is one signal.
//
// ---------------------------------------------------------------------------
// HONEST SCOPE — read before believing anything about this circuit.
//   * the withdrawn AMOUNT is public (revealed on-chain) — NOT hidden;
//   * sender/recipient identities at the boundary are visible (separate op);
//   * this proves an OPENING + range only — it does NOT prove the commitment is
//     a live unspent leaf; the contract's commitment binding + nullifier/burn
//     bookkeeping enforce that, exactly as in confidential_transfer.circom;
//   * the dev trusted setup is single-participant (NOT an MPC ceremony);
//   * UNAUDITED, testnet only, NOT production / NOT mainnet-ready.
//
// ---------------------------------------------------------------------------
// Public signals:  commitment (the stored balance commitment being burned),
//                   amount     (the public withdrawn value).
// Private witness:  blinding   (the commitment randomness; MUST stay secret).

include "../../../node_modules/circomlib/circuits/poseidon.circom"; // PROD-CHAIN Poseidon (circomlib poseidon_opt) — MUST match the wallet's poseidon-client.ts AND the openings already stored in the deployed pool. The joinsplit pool-tree hash (lib/poseidon_bls.circom) is a DIFFERENT permutation — swapping it in here silently orphans every live commitment (2026-07-03 incident: withdraw rebuilt on the pool-tree hash could never open a wallet commitment).
include "../../../node_modules/circomlib/circuits/bitify.circom";

template ConfidentialWithdraw() {
    // --- Public inputs ---
    signal input commitment;   // stored balance commitment = Poseidon(amount, blinding)
    signal input amount;        // PUBLIC withdrawn value, bound to the commitment below

    // --- Private witness (never leaves the prover) ---
    signal input blinding;      // commitment randomness (hiding factor)

    // (1) OPEN the commitment: commitment === Poseidon(amount, blinding).
    //     Binds the PUBLIC amount to the PUBLIC commitment through the secret
    //     blinding. A wrong amount has no blinding that re-hashes to commitment
    //     (Poseidon second-preimage) ⇒ the witness is UNSATISFIABLE.
    component opener = Poseidon(2);
    opener.inputs[0] <== amount;
    opener.inputs[1] <== blinding;
    commitment === opener.out;

    // (2) RANGE — Num2Bits(64) keeps the withdrawn amount in [0, 2^64): a
    //     field-negative or oversized amount (which could alias/inflate value
    //     via modular wrap) is rejected. Mirrors the transfer circuit's range
    //     discipline at the boundary.
    component range = Num2Bits(64);
    range.in <== amount;
}

// commitment + amount are the public signals; blinding stays private.
// Expected constraint count: ~580 (1x Poseidon(2) + 1x Num2Bits(64) + 1 opening
// equality). Well within the BLS pot (potbls12_final.ptau) ceiling.
component main {
    public [
        commitment,
        amount
    ]
} = ConfidentialWithdraw();
