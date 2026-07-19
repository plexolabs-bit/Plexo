#!/usr/bin/env node
// StellarHub ZK reference · https://stellarhub.io
/**
 * prove-credentials.mjs — off-chain prove/verify harness for credentials.circom.
 *
 * Sibling of prove.mjs (PrivateTransfer). Runs the witness generator + Groth16
 * prover (snarkjs) over a private credential witness and verifies the proof
 * locally. issuerCommitment + nullifier are circuit OUTPUTS, so they come back in
 * publicSignals — no off-chain hash precomputation. The same {proof,
 * publicSignals} are what the Soroban groth16_verifier checks on-chain (with the
 * credentials verification key — per-circuit vk; see project docs).
 *
 * PREREQUISITES (see project docs):
 *   - npm i snarkjs  (resolvable from this repo)
 *   - circom + circomlib installed, and build.sh has produced (BLS12-381):
 *       build/credentials.wasm
 *       build/credentials_final.zkey
 *       build/credentials_verification_key.json
 *
 * USAGE:
 *   # threshold predicate: prove age (private 21) >= 18
 *   node scripts/prove-credentials.mjs --mode 1 --attribute 21 --minValue 18
 *   # equality predicate: prove KYC-passed flag (private 1) == 1
 *   node scripts/prove-credentials.mjs --mode 0 --attribute 1 --expectedValue 1
 *
 * Exit codes: 0 = proof verified, 1 = verification failed, 2 = missing artefacts.
 */

import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const BUILD = resolve(__dirname, '..', 'build');
const WASM = resolve(BUILD, 'credentials.wasm');
const ZKEY = resolve(BUILD, 'credentials_final.zkey');
const VKEY = resolve(BUILD, 'credentials_verification_key.json');

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
      console.error(`[prove-credentials] missing ${label}: ${p}`);
      console.error('[prove-credentials] run "npm run build:circuits" first (compiles every circuits/*.circom).');
      process.exit(2);
    }
  }

  const snarkjs = await import('snarkjs');

  const args = parseArgs(process.argv);
  const mode = String(args.mode ?? '1'); // default: threshold (age >= 18)
  // Private witness only — the circuit computes issuerCommitment + nullifier.
  const input = {
    attribute: String(args.attribute ?? '21'),       // e.g. age 21 (private)
    secret: String(args.secret ?? '1234567890'),       // binding + nullifier seed
    credentialId: String(args.credentialId ?? '777'),  // issuer-assigned id
    mode,                                               // 0 = equality, 1 = threshold
    expectedValue: String(args.expectedValue ?? '1'),  // used when mode == 0
    minValue: String(args.minValue ?? '18'),           // used when mode == 1
  };

  const predicate = mode === '0'
    ? `attribute == ${input.expectedValue}`
    : `attribute >= ${input.minValue}`;
  console.log(`[prove-credentials] predicate (mode=${mode}): ${predicate}  (attribute is PRIVATE)`);
  console.log('[prove-credentials] generating Groth16 proof…');
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);

  // publicSignals order: [mode, expectedValue, minValue, issuerCommitment, nullifier].
  // (circom emits public inputs first, then outputs, each in declaration order.)
  console.log('[prove-credentials] public mode             =', publicSignals[0]);
  console.log('[prove-credentials] public expectedValue    =', publicSignals[1]);
  console.log('[prove-credentials] public minValue         =', publicSignals[2]);
  console.log('[prove-credentials] public issuerCommitment =', publicSignals[3]);
  console.log('[prove-credentials] public nullifier        =', publicSignals[4]);

  const vKey = JSON.parse(readFileSync(VKEY, 'utf8'));
  const ok = await snarkjs.groth16.verify(vKey, publicSignals, proof);
  console.log(`[prove-credentials] local verify  = ${ok ? 'OK ✅' : 'FAILED ❌'} (curve: ${proof.curve})`);

  console.log('[prove-credentials] submission payload:');
  console.log(JSON.stringify({ proof, publicSignals }, null, 2));

  process.exit(ok ? 0 : 1);
}

main().catch((err) => {
  console.error('[prove-credentials] error:', err?.message ?? err);
  process.exit(1);
});
