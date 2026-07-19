// StellarHub ZK reference · https://stellarhub.io
/**
 * scripts/__tests__/private-transfer.test.ts
 *
 * Tests for the Model C PrivateTransfer (Confidential Send) circuit — the circuit
 * the deployed Soroban verifiers check on-chain (zk-groth16-verifier `CDZUX…` and
 * the embedded verify in zk-verified-payment `CD3BLT…`). Two layers, mirroring the
 * sibling proof-of-reserves / credentials suites:
 *   1. Source-structure (always run): the 5 private signals, the two Poseidon
 *      output bindings, the 64-bit range guard, pinned circom 2.2.0 + circomlib
 *      include conventions.
 *   2. Witness-satisfiability (CONDITIONAL — runs only when
 *      build/private_transfer.{wasm,_final.zkey,_verification_key.json} + the
 *      snarkjs CLI bundle are present): proves a valid note, checks the in-circuit
 *      Poseidon outputs equal the off-chain BLS Poseidon (parity), that an
 *      out-of-range amount is unprovable, and the commitment/nullifier binding.
 *
 * PARITY + PROCESS-ISOLATION (identical to proof-of-reserves.test.ts): the witness
 * is hashed with ../poseidon_bls.mjs (circomlib opt-Poseidon over the bls12381
 * scalar field) — NOT circomlibjs's bn128 default — and proving runs the snarkjs
 * CLI as a CHILD process (its JS API spins up Worker threads vitest's pool can't
 * host: "Worker is not a constructor"). No proof run is fabricated: layer 2
 * executes real snarkjs only when the compiled circuit is physically present.
 */

import { beforeAll, describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = resolve(fileURLToPath(import.meta.url), "..");
const ZK_DIR = resolve(__dirname, "..", "..");
const CIRCUIT_SRC = join(ZK_DIR, "circuits", "private_transfer.circom");
const BUILD_DIR = join(ZK_DIR, "build");
const WASM = join(BUILD_DIR, "private_transfer.wasm");
const ZKEY = join(BUILD_DIR, "private_transfer_final.zkey");
const VKEY = join(BUILD_DIR, "private_transfer_verification_key.json");
const CLI = resolve(ZK_DIR, "node_modules", "snarkjs", "build", "cli.cjs");

// ---------------------------------------------------------------------------
// Layer 1 — source-structure (always run)
// ---------------------------------------------------------------------------

describe("private_transfer.circom — source structure", () => {
  const src = readFileSync(CIRCUIT_SRC, "utf8");

  it("pins circom 2.2.0", () => {
    expect(src).toMatch(/pragma circom 2\.2\.0;/);
  });

  it("includes circomlib poseidon + bitify with the ../../../node_modules prefix", () => {
    expect(src).toContain("../../../node_modules/circomlib/circuits/poseidon.circom");
    expect(src).toContain("../../../node_modules/circomlib/circuits/bitify.circom");
  });

  it("declares exactly the 5 private witness inputs", () => {
    expect(src).toMatch(/signal input amount;/);
    expect(src).toMatch(/signal input blinding;/);
    expect(src).toMatch(/signal input recipient;/);
    expect(src).toMatch(/signal input senderSecret;/);
    expect(src).toMatch(/signal input serial;/);
  });

  it("emits commitment + nullifier as the only outputs (the public signals)", () => {
    expect(src).toMatch(/signal output commitment;/);
    expect(src).toMatch(/signal output nullifier;/);
    const outputs = [...src.matchAll(/signal output (\w+);/g)].map((m) => m[1]).sort();
    expect(outputs).toEqual(["commitment", "nullifier"]);
  });

  it("binds commitment = Poseidon(3)(amount, blinding, recipient)", () => {
    expect(src).toMatch(/component commHash = Poseidon\(3\);/);
    expect(src).toMatch(/commHash\.inputs\[0\] <== amount;/);
    expect(src).toMatch(/commHash\.inputs\[1\] <== blinding;/);
    expect(src).toMatch(/commHash\.inputs\[2\] <== recipient;/);
    expect(src).toMatch(/commitment <== commHash\.out;/);
  });

  it("derives nullifier = Poseidon(2)(senderSecret, serial)", () => {
    expect(src).toMatch(/component nullHash = Poseidon\(2\);/);
    expect(src).toMatch(/nullHash\.inputs\[0\] <== senderSecret;/);
    expect(src).toMatch(/nullHash\.inputs\[1\] <== serial;/);
    expect(src).toMatch(/nullifier <== nullHash\.out;/);
  });

  it("range-binds amount to 64 bits via Num2Bits(64)", () => {
    expect(src).toMatch(/component rangeCheck = Num2Bits\(64\);/);
    expect(src).toMatch(/rangeCheck\.in <== amount;/);
  });

  it("instantiates main = PrivateTransfer()", () => {
    expect(src).toMatch(/component main = PrivateTransfer\(\);/);
  });
});

// ---------------------------------------------------------------------------
// Layer 2 — witness satisfiability (conditional; real snarkjs, child process)
// ---------------------------------------------------------------------------

const artefactsPresent =
  existsSync(WASM) && existsSync(ZKEY) && existsSync(VKEY) && existsSync(CLI);

interface ProveResult {
  status: number | null;
  stderr: string;
  publicSignals: string[] | null;
  proofPath: string;
  publicPath: string;
}

function fullprove(input: Record<string, string>): ProveResult {
  const tmp = mkdtempSync(join(tmpdir(), "zk-pt-"));
  const inPath = join(tmp, "in.json");
  const proofPath = join(tmp, "proof.json");
  const publicPath = join(tmp, "public.json");
  writeFileSync(inPath, JSON.stringify(input));
  const r = spawnSync(
    process.execPath,
    [CLI, "groth16", "fullprove", inPath, WASM, ZKEY, proofPath, publicPath],
    { encoding: "utf8" },
  );
  const publicSignals =
    r.status === 0 && existsSync(publicPath)
      ? (JSON.parse(readFileSync(publicPath, "utf8")) as string[])
      : null;
  return { status: r.status, stderr: r.stderr ?? "", publicSignals, proofPath, publicPath };
}

function verify(publicPath: string, proofPath: string): number | null {
  return spawnSync(
    process.execPath,
    [CLI, "groth16", "verify", VKEY, publicPath, proofPath],
    { encoding: "utf8" },
  ).status;
}

// BLS12-381 Poseidon to recompute the expected outputs (parity with the circuit).
let H: ((xs: Array<string | number>) => string) | null = null;
let setupError: string | null = null;

// Same witness prove.mjs uses by default.
const BASE: Record<string, string> = {
  amount: "4200000",
  blinding: "88159137330",
  recipient: "7",
  senderSecret: "1234567890",
  serial: "20260612",
};

async function buildHasher(): Promise<((xs: Array<string | number>) => string) | null> {
  try {
    const { default: buildPoseidonBls } = await import("../poseidon_bls.mjs");
    const poseidon: any = await buildPoseidonBls();
    const F = poseidon.F;
    return (xs: Array<string | number>): string => F.toString(poseidon(xs));
  } catch (e) {
    setupError = `poseidon_bls import failed: ${(e as Error).message}`;
    return null;
  }
}

describe("private_transfer.circom — witness satisfiability (BLS12-381, snarkjs CLI)", () => {
  beforeAll(async () => {
    if (artefactsPresent) H = await buildHasher();
  }, 90_000);

  it.runIf(artefactsPresent)(
    "proves a valid note, verifies, and exposes [commitment, nullifier] matching the BLS Poseidon",
    () => {
      expect(H, setupError ?? "hasher not built").not.toBeNull();
      const p = fullprove(BASE);
      expect(p.status).toBe(0);
      expect(p.publicSignals).not.toBeNull();
      expect(verify(p.publicPath, p.proofPath)).toBe(0);

      const ps = p.publicSignals!;
      expect(ps.length).toBe(2);
      // The in-circuit Poseidon outputs MUST equal the off-chain BLS Poseidon —
      // this is the on-chain/off-chain parity the Soroban verifier relies on.
      expect(ps[0]).toBe(H!([BASE.amount, BASE.blinding, BASE.recipient])); // commitment
      expect(ps[1]).toBe(H!([BASE.senderSecret, BASE.serial])); // nullifier
    },
    120_000,
  );

  it.runIf(artefactsPresent)(
    "rejects an out-of-range amount >= 2^64 (Num2Bits(64) range soundness)",
    () => {
      const bad = fullprove({ ...BASE, amount: (2n ** 64n).toString() });
      expect(bad.status).not.toBe(0);
      expect(bad.publicSignals).toBeNull();
    },
    120_000,
  );

  it.runIf(artefactsPresent)(
    "recipient binds the commitment but leaves the nullifier independent",
    () => {
      const a = fullprove({ ...BASE, recipient: "7" });
      const b = fullprove({ ...BASE, recipient: "9" });
      expect(a.status).toBe(0);
      expect(b.status).toBe(0);
      // commitment = Poseidon(amount, blinding, recipient) -> differs with recipient.
      expect(a.publicSignals![0]).not.toBe(b.publicSignals![0]);
      // nullifier = Poseidon(senderSecret, serial) -> unaffected by recipient.
      expect(a.publicSignals![1]).toBe(b.publicSignals![1]);
    },
    180_000,
  );

  it.runIf(artefactsPresent)(
    "serial changes the nullifier (the per-note double-spend marker)",
    () => {
      const a = fullprove({ ...BASE, serial: "20260612" });
      const b = fullprove({ ...BASE, serial: "20260613" });
      expect(a.status).toBe(0);
      expect(b.status).toBe(0);
      expect(a.publicSignals![1]).not.toBe(b.publicSignals![1]);
    },
    180_000,
  );

  it.skipIf(artefactsPresent)(
    "[skipped] build artefacts or snarkjs CLI missing — run 'npm run build:circuits'",
    () => {
      expect(true).toBe(true);
    },
  );
});
