// StellarHub ZK reference · https://stellarhub.io
// poseidon_bls.mjs — circomlib-compatible Poseidon over the BLS12-381 scalar field.
//
// WHY THIS EXISTS
// circomlibjs's buildPoseidon (src/poseidon_opt.js) hardcodes the bn128 scalar
// field (getCurveFromName("bn128")). Our circuits are compiled with
// `circom -p bls12381`, so the IN-CIRCUIT Poseidon runs the SAME optimized
// algorithm with the SAME numeric constants, but reduced modulo the BLS12-381
// scalar prime. To recompute the circuit's public outputs OFF-chain whose values
// equal what the circuit emits (private_transfer.circom → commitment =
// Poseidon(amount, blinding, recipient) and nullifier = Poseidon(senderSecret,
// serial)), every Poseidon call must run in that exact field. Hashing with the
// bn128 default produces different outputs and the parity check fails.
//
// PARITY CLAIM
// identical opt-constants (poseidon_constants_opt.json) + identical algorithm
// (the poseidon_opt.js permutation, copied verbatim below) + identical field
// (bls12381 Fr) ⇒ identical output to circomlib's poseidon.circom compiled
// under -p bls12381. The opt-vs-reference equivalence that holds ONLY on bn128
// is irrelevant here: the circuit itself runs the OPT form with these exact
// numeric constants, so we match the circuit, not the textbook reference.
//
// This is a thin re-instantiation of poseidon_opt.js — kept byte-faithful to
// the upstream permutation so it tracks circomlib's behaviour; only the curve
// (bn128 → bls12381) and the constants-load path differ.

import { getCurveFromName } from "ffjavascript";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
// Load circomlibjs's shipped opt-constants from node_modules.
// (circomlibjs restricts package "exports" to ./main.js, so the opt constants
// are not importable by subpath — read the JSON the package ships instead.)
const CONSTANTS_PATH = resolve(
  __dirname, "..",
  "node_modules", "circomlibjs", "src", "poseidon_constants_opt.json",
);

function unstringifyConstants(Fr, o) {
  if (typeof o === "string" && /^[0-9]+$/.test(o)) return Fr.e(o);
  if (typeof o === "string" && /^0x[0-9a-fA-F]+$/.test(o)) return Fr.e(o);
  if (Array.isArray(o)) return o.map((x) => unstringifyConstants(Fr, x));
  if (typeof o === "object" && o !== null) {
    const res = {};
    for (const k of Object.keys(o)) res[k] = unstringifyConstants(Fr, o[k]);
    return res;
  }
  return o;
}

// N_ROUNDS_P[t-2] — partial rounds per width t (== inputs+1). Copied from
// circomlibjs/src/poseidon_opt.js so widths 2..17 (t=3..18) match the circuit.
const N_ROUNDS_F = 8;
const N_ROUNDS_P = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68];

export default async function buildPoseidonBls() {
  const bls = await getCurveFromName("bls12381", true);
  const F = bls.Fr;
  const opt = unstringifyConstants(F, JSON.parse(readFileSync(CONSTANTS_PATH, "utf8")));

  const pow5 = (a) => F.mul(a, F.square(F.square(a)));

  function poseidon(inputs, initState, nOut) {
    if (inputs.length <= 0 || inputs.length > N_ROUNDS_P.length) {
      throw new Error(`poseidon_bls: unsupported input arity ${inputs.length}`);
    }
    initState = initState ? F.e(initState) : F.zero;
    nOut = nOut || 1;

    const t = inputs.length + 1;
    const nRoundsF = N_ROUNDS_F;
    const nRoundsP = N_ROUNDS_P[t - 2];
    const C = opt.C[t - 2];
    const S = opt.S[t - 2];
    const M = opt.M[t - 2];
    const P = opt.P[t - 2];

    let state = [initState, ...inputs.map((a) => F.e(a))];
    state = state.map((a, i) => F.add(a, C[i]));

    for (let r = 0; r < nRoundsF / 2 - 1; r++) {
      state = state.map((a) => pow5(a));
      state = state.map((a, i) => F.add(a, C[(r + 1) * t + i]));
      state = state.map((_, i) =>
        state.reduce((acc, a, j) => F.add(acc, F.mul(M[j][i], a)), F.zero),
      );
    }
    state = state.map((a) => pow5(a));
    state = state.map((a, i) => F.add(a, C[(nRoundsF / 2 - 1 + 1) * t + i]));
    state = state.map((_, i) =>
      state.reduce((acc, a, j) => F.add(acc, F.mul(P[j][i], a)), F.zero),
    );
    for (let r = 0; r < nRoundsP; r++) {
      state[0] = pow5(state[0]);
      state[0] = F.add(state[0], C[(nRoundsF / 2 + 1) * t + r]);
      const s0 = state.reduce(
        (acc, a, j) => F.add(acc, F.mul(S[(t * 2 - 1) * r + j], a)),
        F.zero,
      );
      for (let k = 1; k < t; k++) {
        state[k] = F.add(state[k], F.mul(state[0], S[(t * 2 - 1) * r + t + k - 1]));
      }
      state[0] = s0;
    }
    for (let r = 0; r < nRoundsF / 2 - 1; r++) {
      state = state.map((a) => pow5(a));
      state = state.map((a, i) =>
        F.add(a, C[(nRoundsF / 2 + 1) * t + nRoundsP + r * t + i]),
      );
      state = state.map((_, i) =>
        state.reduce((acc, a, j) => F.add(acc, F.mul(M[j][i], a)), F.zero),
      );
    }
    state = state.map((a) => pow5(a));
    state = state.map((_, i) =>
      state.reduce((acc, a, j) => F.add(acc, F.mul(M[j][i], a)), F.zero),
    );

    return nOut === 1 ? state[0] : state.slice(0, nOut);
  }

  poseidon.F = F;
  return poseidon;
}
