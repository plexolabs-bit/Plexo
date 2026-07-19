// StellarHub ZK reference · https://stellarhub.io
import { defineConfig } from 'vitest/config';
// Standalone circuit-test runner. Layer-1 (source-structure) always runs;
// Layer-2 (witness satisfiability) runs only when `npm run build:circuits` has
// produced build/<name>.{wasm,_final.zkey,_verification_key.json} + snarkjs is
// installed. No StellarHub product dependency.
export default defineConfig({ test: { root: '.', include: ['scripts/__tests__/**/*.test.ts'] } });
