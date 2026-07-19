// StellarHub ZK reference · https://stellarhub.io
pragma circom 2.2.0;

// Second canary circuit for the ZK toolchain (smoke-tests the build pipeline).
//
// Purpose: prove knowledge of a (balance, nonce) pair such that
//          Poseidon(balance, nonce) == commitment (public).
//
// Why it matters: exercises the Poseidon hash gadget from circomlib, which
// matches the CAP-0075 host function shipped in Protocol 25 (X-Ray, live on
// testnet 2026-01-07 and mainnet 2026-01-22). A mismatch between the
// Poseidon parameters used in the circuit and the ones the Soroban verifier
// contract pins would make every proof fail on-chain — so this canary is a
// toolchain-level parity check in addition to being a pipeline smoke test.
//
// Privacy: (balance, nonce) are private; only `commitment` is public.
// This is a minimal pedersen-like commitment, NOT a production privacy
// primitive. Range checks and nullifier bindings belong to the full
// balance_range / private_transfer circuits.
//
// Expected constraint count: ~240 (Poseidon(2) with t=3 over BN254).
// Well within the pot14 (2^14) powers-of-tau ceiling.
//
// Public inputs:
//   commitment : Poseidon(balance, nonce)
//
// Private inputs:
//   balance : field element (caller may bind to a specific range in an
//             outer circuit)
//   nonce   : field element (blinding factor; caller must sample ≥ 254-bit
//             entropy for hiding to hold against a distinguisher)

include "../../../node_modules/circomlib/circuits/poseidon.circom";

template BalanceCommitment() {
    signal input  balance;
    signal input  nonce;
    signal input  commitment;

    // Poseidon(2) hashes two BN254 field elements into one.
    component hasher = Poseidon(2);
    hasher.inputs[0] <== balance;
    hasher.inputs[1] <== nonce;

    // Constrain the computed hash to equal the public commitment.
    hasher.out === commitment;
}

component main { public [commitment] } = BalanceCommitment();
