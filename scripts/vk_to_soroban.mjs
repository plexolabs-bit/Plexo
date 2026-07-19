// StellarHub ZK reference · https://stellarhub.io
// vk_to_soroban.mjs — transcode a snarkjs Groth16 verification_key.json into the
// JSON arg the zk-verified-payment `initialize(token, vk: VerificationKey)` expects.
//
// VerificationKey { alpha: G1Affine, beta/gamma/delta: G2Affine, ic: Vec<G1Affine> }
// G1Affine = BytesN<96> uncompressed, G2Affine = BytesN<192> uncompressed — the
// SAME encoding the StellarHub frontend client's g1Bytes/g2Bytes helpers produce
// (proven byte-for-byte == ark serialize; the verified-payment contract verifies
// on-chain with it). The Rust
// `test.rs` g1()/g2() helpers decode the identical snarkjs JSON, so the bytes here
// match what the contract stores + later feeds to `pairing_check`.
//
// Usage: node vk_to_soroban.mjs data/verification_key.json  -> prints the --vk JSON.

import { bls12_381 } from '@noble/curves/bls12-381.js';
import { readFileSync } from 'node:fs';

const path = process.argv[2];
if (!path) {
  console.error('usage: node vk_to_soroban.mjs <verification_key.json>');
  process.exit(1);
}
const vk = JSON.parse(readFileSync(path, 'utf8'));

// snarkjs G1 = [x, y, z] projective (z == "1"); take the affine (x, y).
const g1 = (p) =>
  Buffer.from(
    bls12_381.G1.Point.fromAffine({ x: BigInt(p[0]), y: BigInt(p[1]) }).toBytes(false),
  ).toString('hex');

// snarkjs G2 = [[x.c0, x.c1], [y.c0, y.c1], [z...]] projective; take affine.
const g2 = (p) =>
  Buffer.from(
    bls12_381.G2.Point.fromAffine({
      x: { c0: BigInt(p[0][0]), c1: BigInt(p[0][1]) },
      y: { c0: BigInt(p[1][0]), c1: BigInt(p[1][1]) },
    }).toBytes(false),
  ).toString('hex');

const out = {
  alpha: g1(vk.vk_alpha_1),
  beta: g2(vk.vk_beta_2),
  gamma: g2(vk.vk_gamma_2),
  delta: g2(vk.vk_delta_2),
  ic: vk.IC.map(g1),
};

console.log(JSON.stringify(out));
