// StellarHub ZK reference · https://stellarhub.io
// build-lib.mjs — bundles the repo's REAL client-lib for the in-browser demo:
//
//   node demo/web/build-lib.mjs      (or: npm run build:demo-lib)
//
// One esbuild pass over demo/web/lib-entry.ts → demo/web/vendor/confidential-lib.mjs
// (ESM). The only substitution is node-only constant loading: scripts/
// poseidon_bls.mjs (readFileSync) → demo/web/poseidon-browser.mjs (same
// permutation verbatim, constants inlined at bundle time). Everything else —
// sealed-note crypto, Poseidon commitments, Soroban submit/simulate — is the
// exact client-lib source the wallet uses.

import { build } from "esbuild";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));

const poseidonBrowserAlias = {
  name: "poseidon-browser-alias",
  setup(b) {
    b.onResolve({ filter: /scripts\/poseidon_bls\.mjs$/ }, () => ({
      path: resolve(here, "poseidon-browser.mjs"),
    }));
  },
};

await build({
  entryPoints: [resolve(here, "lib-entry.ts")],
  outfile: resolve(here, "vendor", "confidential-lib.mjs"),
  bundle: true,
  format: "esm",
  platform: "browser",
  minify: true,
  sourcemap: false,
  logLevel: "info",
  plugins: [poseidonBrowserAlias],
  inject: [resolve(here, "buffer-shim.js")],
  define: {
    "process.env.NODE_ENV": '"production"',
    global: "globalThis",
  },
});
