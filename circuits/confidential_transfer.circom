pragma circom 2.2.0;

// ConfidentialTransfer — EXPERIMENTAL testnet PoC circuit for a confidential-AMOUNT
// transfer on Stellar/Soroban. Sibling in style to private_transfer.circom /
// proof_of_reserves.circom (circom 2.2.x, BLS12-381, circomlib Poseidon + Num2Bits),
// so the same `-p bls12381` compile + dev trusted setup + snarkjs prove pipeline
// applies. Compile with:
//   circom confidential_transfer.circom -p bls12381 --r1cs --wasm --sym
//
// ---------------------------------------------------------------------------
// HONEST SCOPE — read before believing anything about this circuit.
//
// The ONLY truthful privacy claim this PoC supports: the transfer AMOUNT lives
// on-chain only as a Poseidon balance commitment — it is never a transaction
// argument and never an event field. A Groth16/BLS12-381 proof enforces value
// conservation in zero-knowledge. NOTHING ELSE is hidden:
//   * sender and recipient identities ARE visible on-chain (the contract still
//     names which two balance commitments it updates);
//   * the boundary deposit()/withdraw() that move real tokens in/out of the
//     confidential pool expose their amounts in the clear (separate ops);
//   * in a small pool a global observer can often infer amounts by differencing;
//   * the dev trusted setup is single-participant (NOT an MPC ceremony);
//   * UNAUDITED, testnet only, NOT production / NOT mainnet-ready.
// This is NOT a "private payment", NOT "anonymous", NOT a confidential-balances
// product, and amounts are NOT "impossible to recover".
//
// ---------------------------------------------------------------------------
// DESIGN — why conservation MUST be proven INSIDE the circuit.
//
// Poseidon is NOT additively homomorphic, so the contract CANNOT subtract
// commitments on-chain to check value conservation. Instead the prover opens all
// four balance commitments inside the circuit and proves, over the scalar field:
//     amount_sender_old    = amount_sender_new    + t      (sender debited by t)
//     amount_recipient_new = amount_recipient_old + t      (recipient credited by t)
// for the SAME field element t. Adding the two relations cancels t and yields the
// exact identity  (sender_new + recipient_new) == (sender_old + recipient_old):
// the post-transfer total equals the pre-transfer total. The confidential-transfer
// contract op performs NO token::transfer — it only swaps commitment_*_old for
// commitment_*_new atomically — so the amount t never appears in any event.
//
// Soundness of the integer identity (no field wraparound): t and the two NEW
// balances are range-bound to [0, 2^64) (Num2Bits(64)). Since each summand is far
// below the BLS12-381 scalar prime (~2^255), the field equation sum_new == sum_old
// also holds over the integers — value cannot be created by modular wrap, and t
// cannot be a field-negative value (which would inflate one side). The two OLD
// balances are NOT re-range-checked here: they are openings of commitments that a
// prior valid transfer/deposit already range-checked as its NEW amounts, so their
// 0 <= x < 2^64 bound is an inductive invariant maintained by the contract binding
// commitment_*_old to the on-chain balance — it is not re-proven each hop. The
// on-chain binding of the old commitments is what stops a prover from opening a
// fabricated old balance; this circuit alone does not enforce that.
//
// ---------------------------------------------------------------------------
// Public signals (the 4 balance commitments the contract reads / writes):
//   commitment_sender_old, commitment_sender_new,
//   commitment_recipient_old, commitment_recipient_new
// Private witness (MUST never leave the prover): the 4 opened amounts, the
//   transfer amount t, and the 4 per-commitment blindings.

include "../../../node_modules/circomlib/circuits/poseidon.circom"; // PROD-CHAIN Poseidon (circomlib poseidon_opt) — MUST match the wallet's poseidon-client.ts AND the openings already stored in the deployed pool. The joinsplit pool-tree hash (lib/poseidon_bls.circom) is a DIFFERENT permutation — swapping it in here silently orphans every live commitment (2026-07-03 incident: withdraw rebuilt on the pool-tree hash could never open a wallet commitment).
include "../../../node_modules/circomlib/circuits/bitify.circom";

template ConfidentialTransfer() {
    // --- Public inputs: balance commitments = Poseidon(amount, blinding) ---
    signal input commitment_sender_old;
    signal input commitment_sender_new;
    signal input commitment_recipient_old;
    signal input commitment_recipient_new;

    // --- Private witness (never leaves the prover) ---
    signal input amount_sender_old;
    signal input amount_sender_new;
    signal input amount_recipient_old;
    signal input amount_recipient_new;
    signal input transfer_amount;            // t — the confidential amount
    signal input blinding_sender_old;
    signal input blinding_sender_new;
    signal input blinding_recipient_old;
    signal input blinding_recipient_new;

    // (1) Open all four commitments: commitment === Poseidon(amount, blinding).
    //     Binds each public commitment to its hidden (amount, blinding) preimage.
    component openSenderOld = Poseidon(2);
    openSenderOld.inputs[0] <== amount_sender_old;
    openSenderOld.inputs[1] <== blinding_sender_old;
    commitment_sender_old === openSenderOld.out;

    component openSenderNew = Poseidon(2);
    openSenderNew.inputs[0] <== amount_sender_new;
    openSenderNew.inputs[1] <== blinding_sender_new;
    commitment_sender_new === openSenderNew.out;

    component openRecipientOld = Poseidon(2);
    openRecipientOld.inputs[0] <== amount_recipient_old;
    openRecipientOld.inputs[1] <== blinding_recipient_old;
    commitment_recipient_old === openRecipientOld.out;

    component openRecipientNew = Poseidon(2);
    openRecipientNew.inputs[0] <== amount_recipient_new;
    openRecipientNew.inputs[1] <== blinding_recipient_new;
    commitment_recipient_new === openRecipientNew.out;

    // (2) CONSERVATION — the dangerous constraint. The SAME t debits the sender and
    //     credits the recipient; adding the two cancels t ⇒ total is preserved.
    //     A forge that debits t' but credits t (t' != t) has no single t solving
    //     both equations ⇒ the witness is UNSATISFIABLE.
    amount_sender_old === amount_sender_new + transfer_amount;
    amount_recipient_new === amount_recipient_old + transfer_amount;

    // (3) RANGE — Num2Bits(64) on the new balances and on t. Keeps every summand in
    //     [0, 2^64) so (a) the conservation identity holds over the integers (no
    //     modular wrap creates value), (b) t is non-negative (no inflation via a
    //     field-negative transfer), and (c) the sender's new balance cannot
    //     underflow (sender_new >= 0 with sender_old = sender_new + t forces
    //     sender_old >= t, i.e. the sender actually held at least t).
    component rangeSenderNew = Num2Bits(64);
    rangeSenderNew.in <== amount_sender_new;

    component rangeRecipientNew = Num2Bits(64);
    rangeRecipientNew.in <== amount_recipient_new;

    component rangeTransfer = Num2Bits(64);
    rangeTransfer.in <== transfer_amount;
}

// The 4 commitments are the public signals; all amounts + blindings stay private.
// Expected constraint count: ~1050 (4x Poseidon(2) ~215 each + 3x Num2Bits(64) ~64
// + 2 conservation). Well within the BLS pot (potbls12_final.ptau) ceiling.
component main {
    public [
        commitment_sender_old,
        commitment_sender_new,
        commitment_recipient_old,
        commitment_recipient_new
    ]
} = ConfidentialTransfer();
