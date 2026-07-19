// StellarHub ZK reference · https://stellarhub.io
// poseidon-browser.mjs — BROWSER twin of scripts/poseidon_bls.mjs (same Poseidon
// permutation over the BLS12-381 scalar field, verbatim). The ONLY difference is
// how the circomlib opt-constants are loaded: node reads the JSON from disk at
// runtime; here esbuild INLINES the same JSON at bundle time (circomlibjs's
// package "exports" hides the subpath, so we import the file by relative path).
// The demo bundle aliases `scripts/poseidon_bls.mjs` → this file (see
// build-lib.mjs), so client-lib code runs unmodified in the browser.

import { getCurveFromName } from "ffjavascript";
// Same file scripts/poseidon_bls.mjs reads at runtime — inlined by esbuild.
import constantsJson from "../../node_modules/circomlibjs/src/poseidon_constants_opt.json";

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

const N_ROUNDS_F = 8;
const N_ROUNDS_P = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68];

export default async function buildPoseidonBls() {
  const bls = await getCurveFromName("bls12381", true);
  const F = bls.Fr;
  const opt = unstringifyConstants(F, constantsJson);

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
