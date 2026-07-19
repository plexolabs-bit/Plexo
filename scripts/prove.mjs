#!/usr/bin/env node
// StellarHub ZK reference · https://stellarhub.io
/**
 * prove.mjs — off-chain prove/verify harness for the PrivateTransfer circuit.
 *
 * The heart of the open reference-demo for Stellar Hacks: Real-World ZK. It runs
 * the witness generator + Groth16 prover (snarkjs) over the private witness and
 * verifies the proof locally. commitment + nullifier are circuit OUTPUTS, so they
 * come back in publicSignals — no off-chain hash precomputation needed. The same
 * {proof, publicSignals} are what the Soroban verifier checks on-chain.
 *
 * PREREQUISITES (see project docs):
 *   - npm i snarkjs  (resolvable from this repo)
 *   - circom + circomlib installed, and build.sh has produced (BLS12-381):
 *       build/private_transfer.wasm
 *       build/private_transfer_final.zkey
 *       build/private_transfer_verification_key.json
 *
 * USAGE:
 *   node scripts/prove.mjs
 *   node scripts/prove.mjs --amount 4200000 --recipient 7 --serial 123
 *
 * Exit codes: 0 = proof verified, 1 = verification failed, 2 = missing artefacts.
 */

import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const BUILD = resolve(__dirname, '..', 'build');
const WASM = resolve(BUILD, 'private_transfer.wasm');
const ZKEY = resolve(BUILD, 'private_transfer_final.zkey');
const VKEY = resolve(BUILD, 'private_transfer_verification_key.json');

function parseArgs(argv) {
  const out = {};
  for (let i = 2; i < argv.length; i += 2) {
    const k = argv[i]?.replace(/^--/, '');
    if (k) out[k] = argv[i + 1];
  }
  return out;
}

async function main() {
  for (const [label, p] of [['wasm', WASM], ['zkey', ZKEY], ['vkey', VKEY]]) {
    if (!existsSync(p)) {
      console.error(`[prove] missing ${label}: ${p}`);
      console.error('[prove] run "npm run build:circuits" first (compile + dev-setup in one pass).');
      process.exit(2);
    }
  }

  const snarkjs = await import('snarkjs');

  const args = parseArgs(process.argv);
  // Private witness only — the circuit computes commitment + nullifier as outputs.
  const input = {
    amount: String(args.amount ?? '4200000'),          // e.g. 0.42 XLM in stroops
    blinding: String(args.blinding ?? '88159137330'),   // demo randomness
    recipient: String(args.recipient ?? '7'),           // recipient as field element
    senderSecret: String(args.senderSecret ?? '1234567890'),
    serial: String(args.serial ?? '20260612'),          // unique per note
  };

  console.log('[prove] generating Groth16 proof…');
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);

  // publicSignals = [commitment, nullifier] (circuit outputs, in declaration order).
  console.log('[prove] public commitment =', publicSignals[0]);
  console.log('[prove] public nullifier  =', publicSignals[1]);

  const vKey = JSON.parse(readFileSync(VKEY, 'utf8'));
  const ok = await snarkjs.groth16.verify(vKey, publicSignals, proof);
  console.log(`[prove] local verify  = ${ok ? 'OK ✅' : 'FAILED ❌'} (curve: ${proof.curve})`);

  console.log('[prove] submission payload:');
  console.log(JSON.stringify({ proof, publicSignals }, null, 2));

  process.exit(ok ? 0 : 1);
}

main().catch((err) => {
  console.error('[prove] error:', err?.message ?? err);
  process.exit(1);
});
