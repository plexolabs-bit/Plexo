// StellarHub ZK reference · https://stellarhub.io
pragma circom 2.2.0;

// Canary circuit for the ZK toolchain (smoke-tests the build pipeline).
//
// Purpose: prove that `amount` is a non-negative 64-bit integer, i.e.
//          0 <= amount < 2^64.
//
// This is deliberately trivial. It exists to validate the end-to-end
// pipeline (circom compile -> snarkjs groth16 setup -> proof -> verify)
// before non-trivial privacy circuits (private_transfer, balance_range,
// compliance_membership) are authored.
//
// Privacy: NONE on its own. The caller commits a value; this circuit
// only certifies that the value fits in 64 bits. A real private-transfer
// circuit wraps this sub-circuit inside nullifier + Merkle membership
// gadgets.
//
// Expected constraint count: ~64 (Num2Bits(64)).
//
// Public inputs:
//   amount : field element expected to lie in [0, 2^64)
//
// Private inputs: none (this is a pure range proof).

include "../../../node_modules/circomlib/circuits/bitify.circom";

template RangeProof64() {
    signal input amount;

    // Num2Bits(64) constrains `amount` to the 64-bit range.
    // If `amount` is outside [0, 2^64), the circuit is unsatisfiable
    // and proof generation fails — which is exactly what we want.
    component n2b = Num2Bits(64);
    n2b.in <== amount;
}

component main { public [amount] } = RangeProof64();
