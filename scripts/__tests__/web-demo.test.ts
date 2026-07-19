// StellarHub ZK reference · https://stellarhub.io
/**
 * scripts/__tests__/web-demo.test.ts
 *
 * Structure tests for the TWO in-browser demos (layer-1 only — no headless
 * browser, no snarkjs run, no live RPC; the real flows are exercised by hand /
 * Playwright):
 *
 *   demo/web/index.html   — the MAIN demo: a REAL variant-A confidential
 *     transfer on the wallet's live pool (fund → visible boundary deposit →
 *     sealed note + Groth16 → confidential_transfer → Horizon decode →
 *     recipient-side note scan). Runs the repo's client-lib UNMODIFIED via the
 *     esbuild bundle (vendor/confidential-lib.mjs, built by build-lib.mjs).
 *
 *   demo/web/verify.html  — the FALLBACK building block: prove + on-chain
 *     verify_proof (no funds move), kept as the safety net.
 *
 * These guard the wiring that would silently break either page: committed
 * artefacts, vendored bundles, on-chain calls, honesty copy, no hardcoded
 * recipient, serve.mjs contract, and the only-confidential-surface rule.
 */

import { describe, expect, it } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = resolve(fileURLToPath(import.meta.url), "..");
const ZK_DIR = resolve(__dirname, "..", "..");

const MAIN_HTML = join(ZK_DIR, "demo", "web", "index.html");
const VERIFY_HTML = join(ZK_DIR, "demo", "web", "verify.html");
const SERVE = join(ZK_DIR, "demo", "serve.mjs");
const SNARKJS_VENDOR = join(ZK_DIR, "demo", "web", "vendor", "snarkjs.min.js");
const SDK_VENDOR = join(ZK_DIR, "demo", "web", "vendor", "stellar-sdk.min.js");
const LIB_VENDOR = join(ZK_DIR, "demo", "web", "vendor", "confidential-lib.mjs");
const LIB_BUILD = join(ZK_DIR, "demo", "web", "build-lib.mjs");
const PKG = join(ZK_DIR, "package.json");

// verify.html (Model C building block) artefacts
const PT_WASM = join(ZK_DIR, "build", "private_transfer.wasm");
const PT_ZKEY = join(ZK_DIR, "build", "private_transfer_final.zkey");
const PT_VKEY = join(ZK_DIR, "build", "private_transfer_verification_key.json");
// index.html (variant A) artefacts
const CT_WASM = join(ZK_DIR, "build", "confidential_transfer.wasm");
const CT_ZKEY = join(ZK_DIR, "build", "confidential_transfer_final.zkey");

// The deployed verifier the FALLBACK page calls on-chain — MUST match README + run.sh.
const VERIFIER_CONTRACT = "CDZUXZXCKKWTAEIXRP5PCQ6O7GP5TT7NJDQ22RCB2XV4PRVL4NXMQD3E";

describe("web-demo — committed artefacts + vendored bundles", () => {
  it("ships the private_transfer wasm + final zkey (verify.html)", () => {
    expect(existsSync(PT_WASM)).toBe(true);
    expect(existsSync(PT_ZKEY)).toBe(true);
  });

  it("ships the confidential_transfer wasm + final zkey (index.html)", () => {
    expect(existsSync(CT_WASM)).toBe(true);
    expect(existsSync(CT_ZKEY)).toBe(true);
  });

  it("vendors all three browser bundles (snarkjs + stellar-sdk + client-lib)", () => {
    expect(existsSync(SNARKJS_VENDOR)).toBe(true);
    expect(existsSync(SDK_VENDOR)).toBe(true);
    expect(existsSync(LIB_VENDOR)).toBe(true);
    expect(existsSync(LIB_BUILD)).toBe(true);
  });

  it("the client-lib bundle is rebuildable via npm run build:demo-lib", () => {
    const pkg = JSON.parse(readFileSync(PKG, "utf8"));
    expect(pkg.scripts["build:demo-lib"]).toContain("build-lib.mjs");
  });

  it("the verifying key is groth16 / bls12381 with exactly 2 public signals", () => {
    expect(existsSync(PT_VKEY)).toBe(true);
    const vk = JSON.parse(readFileSync(PT_VKEY, "utf8"));
    expect(vk.protocol).toBe("groth16");
    expect(vk.curve).toBe("bls12381");
    expect(vk.nPublic).toBe(2);
  });
});

describe("web-demo — MAIN page (index.html): a REAL variant-A transfer", () => {
  const html = readFileSync(MAIN_HTML, "utf8");

  it("runs the bundled client-lib + the confidential_transfer artefacts", () => {
    expect(html).toContain("/demo/web/vendor/confidential-lib.mjs");
    expect(html).toContain("/build/confidential_transfer.wasm");
    expect(html).toContain("/build/confidential_transfer_final.zkey");
    expect(html).toContain("/demo/web/vendor/snarkjs.min.js");
  });

  it("uses the wallet's pool via the lib (no hardcoded contract id drift)", () => {
    expect(html).toContain("DEFAULT_CONFIDENTIAL_CONTRACT_ID");
    expect(html).not.toMatch(/C[A-Z2-7]{55}/); // ids come from client-lib, not the page
  });

  it("executes the full flow: deposit → seal+prove → transfer → decode → scan", () => {
    expect(html).toContain("submitConfidentialDepositOnchain");
    expect(html).toContain("sealConfNote");
    expect(html).toContain("groth16.fullProve");
    expect(html).toContain("submitConfidentialTransferOnchain");
    expect(html).toContain("horizon-testnet.stellar.org");
    expect(html).toContain("scanConfidentialTransfersForMe");
    expect(html.toLowerCase()).toContain("friendbot");
  });

  it("shows BOTH transactions (visible boundary deposit + hidden transfer)", () => {
    expect(html).toMatch(/id="txDepositLink"/);
    expect(html).toMatch(/id="txTransferLink"/);
    expect(html).toContain("stellar.expert/explorer/testnet/tx/");
  });

  it("is HONEST the OTHER way — this one IS a money transfer, amount-privacy only", () => {
    const low = html.toLowerCase();
    expect(low).toContain("is a money transfer");
    expect(low).toContain("identities are visible");
    expect(low).toContain("visible by design"); // the boundary deposit
    expect(low).toContain("dev trusted setup");
    expect(low).toContain("testnet");
  });

  it("recipient is generated (receive side provable), never hardcoded", () => {
    expect(html).toMatch(/id="rand"/);
    expect(html).toContain("Keypair.random");
    expect(html).not.toMatch(/value="G[A-Z2-7]{55}"/);
  });

  it("links the fallback building-block demo", () => {
    expect(html).toContain("/demo/web/verify.html");
  });
});

describe("web-demo — FALLBACK page (verify.html): proof-verify building block", () => {
  const html = readFileSync(VERIFY_HTML, "utf8");

  it("fetches the same artefact + vendor paths the server serves", () => {
    expect(html).toContain("/build/private_transfer.wasm");
    expect(html).toContain("/build/private_transfer_final.zkey");
    expect(html).toContain("/build/private_transfer_verification_key.json");
    expect(html).toContain("/demo/web/vendor/snarkjs.min.js");
    expect(html).toContain("/demo/web/vendor/stellar-sdk.min.js");
  });

  it("generates a real proof (snarkjs fullProve + local sanity verify)", () => {
    expect(html).toContain("groth16.fullProve");
    expect(html).toContain("groth16.verify");
    expect(html).toContain("esm.sh/@noble/curves"); // BLS g1/g2 encoding
  });

  it("REALLY calls verify_proof on-chain — Friendbot + RPC + Soroban Client", () => {
    expect(html).toContain("verify_proof");
    expect(html).toContain("Client.from");
    expect(html.toLowerCase()).toContain("friendbot");
    expect(html).toContain("soroban-testnet.stellar.org");
    expect(html).toContain(VERIFIER_CONTRACT);
  });

  it("submits the read-call for real (force: true) and shows YOUR transaction", () => {
    expect(html).toContain("force: true");
    expect(html).toMatch(/id="txlink"/);
    expect(html).toContain("stellar.expert/explorer/testnet/tx/");
  });

  it("recipient is generated, not hardcoded (random testnet key)", () => {
    expect(html).toMatch(/id="rand"/);
    expect(html).toContain("Keypair.random");
    expect(html).not.toMatch(/value="G[A-Z2-7]{55}"/);
  });

  it("is HONEST — not a money transfer, verify_proof moves no funds", () => {
    const low = html.toLowerCase();
    expect(low).toContain("not a money transfer");
    expect(low).toContain("no funds move");
  });

  it("keeps the amount private + the split view (chain sees no amount)", () => {
    expect(html).toMatch(/id="amount"/);
    expect(html).toMatch(/id="commitment"/);
    expect(html).toMatch(/id="p-amount"/);
    expect(html.toLowerCase()).toContain("no amount");
  });

  it("points back at the MAIN real-transfer demo", () => {
    expect(html.toLowerCase()).toContain("fallback");
    expect(html).toContain('href="/"');
  });
});

describe("web-demo — serve.mjs", () => {
  const serve = readFileSync(SERVE, "utf8");

  it("declares application/wasm (octet-stream wasm is refused by browsers)", () => {
    expect(serve).toContain("application/wasm");
  });

  it("guards against path traversal outside the repo root", () => {
    expect(serve).toContain("startsWith(ROOT)");
  });

  it("is exposed via the npm run demo:web script", () => {
    const pkg = JSON.parse(readFileSync(PKG, "utf8"));
    expect(pkg.scripts["demo:web"]).toContain("demo/serve.mjs");
  });
});

describe("web-demo — only the confidential-amount surface ships", () => {
  it("does not ship any non-amount-privacy ZK circuit / pool contract / prover", () => {
    expect(existsSync(join(ZK_DIR, "circuits", "shielded_transfer.circom"))).toBe(false);
    expect(existsSync(join(ZK_DIR, "contracts", "zk-shielded-pool"))).toBe(false);
    expect(existsSync(join(ZK_DIR, "scripts", "prove_shielded.mjs"))).toBe(false);
  });

  it("neither demo page exposes a non-confidential surface", () => {
    for (const p of [MAIN_HTML, VERIFY_HTML]) {
      const low = readFileSync(p, "utf8").toLowerCase();
      expect(low).not.toContain("shielded pool");
    }
  });
});
