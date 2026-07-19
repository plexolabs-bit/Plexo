// StellarHub ZK reference · https://stellarhub.io
/**
 * scripts/__tests__/credentials-circuit.test.ts
 *
 * Two layers for circuits/credentials.circom:
 *   1. Hermetic structural guard (always run): asserts the soundness-critical
 *      invariants of the circuit SOURCE so a careless edit can't silently drop a
 *      constraint that the (slow) compile + prove pipeline would otherwise be the
 *      only thing to catch. Each one maps to an attack it blocks:
 *        - mode boolean         → stops mode=2 Mux1 out-of-range selection
 *        - Num2Bits on operands → stops field-wraparound forgery of `>=`
 *        - Poseidon arity       → commitment / nullifier bind the right tuple
 *        - predicate === 1      → the proof itself attests; no readable boolean
 *        - public signal list   → nPublic shape the per-circuit vk must match
 *   2. Witness-satisfiability (CONDITIONAL — runs only when build/credentials.*
 *      artefacts + the snarkjs CLI bundle are present): proves a satisfying
 *      credential verifies and a violating one is unprovable, for BOTH predicate
 *      modes (threshold `>=` and equality `==`). Records a skip otherwise so the
 *      baseline stays green on an un-provisioned host. No proof run is fabricated.
 */

import { describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CIRCUIT_PATH = resolve(
  __dirname,
  "..",
  "..",
  "circuits",
  "credentials.circom",
);
const SRC = readFileSync(CIRCUIT_PATH, "utf8");

// Collapse whitespace so multi-line / re-indented matches still hit.
const FLAT = SRC.replace(/\s+/g, " ");

// Layer-2 artefacts (built by build.sh). snarkjs CLI bundle is run out-of-process
// via process.execPath — its JS API uses Worker threads vitest's pool can't host.
const ZK_DIR = resolve(__dirname, "..", "..");
const BUILD_DIR = join(ZK_DIR, "build");
const WASM = join(BUILD_DIR, "credentials.wasm");
const ZKEY = join(BUILD_DIR, "credentials_final.zkey");
const VKEY = join(BUILD_DIR, "credentials_verification_key.json");
const CLI = join(ZK_DIR, "node_modules", "snarkjs", "build", "cli.cjs");
const canProve =
  existsSync(WASM) && existsSync(ZKEY) && existsSync(VKEY) && existsSync(CLI);

describe("credentials.circom — toolchain + curve invariants", () => {
  it("targets circom 2.2.0 (matches Model C private_transfer)", () => {
    expect(SRC).toMatch(/pragma\s+circom\s+2\.2\.0\s*;/);
  });

  it("includes circomlib poseidon, bitify, comparators, mux1", () => {
    expect(SRC).toContain("circomlib/circuits/poseidon.circom");
    expect(SRC).toContain("circomlib/circuits/bitify.circom");
    expect(SRC).toContain("circomlib/circuits/comparators.circom");
    expect(SRC).toContain("circomlib/circuits/mux1.circom");
  });

  it("uses the ../../../node_modules include prefix like the sibling circuits", () => {
    expect(SRC).toContain("../../../node_modules/circomlib/circuits/poseidon.circom");
  });
});

describe("credentials.circom — private witness stays private", () => {
  it("declares attribute / secret / credentialId as inputs", () => {
    expect(SRC).toMatch(/signal\s+input\s+attribute\s*;/);
    expect(SRC).toMatch(/signal\s+input\s+secret\s*;/);
    expect(SRC).toMatch(/signal\s+input\s+credentialId\s*;/);
  });

  it("does NOT mark the witness inputs public (only policy inputs are public)", () => {
    // The `public [...]` list must contain exactly the verifier policy inputs.
    const m = FLAT.match(/public\s*\[([^\]]*)\]/);
    expect(m).not.toBeNull();
    const publicList = (m![1] || "").split(",").map((s) => s.trim());
    expect(publicList).toContain("mode");
    expect(publicList).toContain("expectedValue");
    expect(publicList).toContain("minValue");
    // Secrets must never appear in the public declaration.
    expect(publicList).not.toContain("attribute");
    expect(publicList).not.toContain("secret");
    expect(publicList).not.toContain("credentialId");
  });
});

describe("credentials.circom — commitment + nullifier are in-circuit outputs", () => {
  it("declares issuerCommitment + nullifier as outputs (public signals, Model C style)", () => {
    expect(SRC).toMatch(/signal\s+output\s+issuerCommitment\s*;/);
    expect(SRC).toMatch(/signal\s+output\s+nullifier\s*;/);
  });

  it("issuerCommitment = Poseidon(attribute, secret) — arity 2", () => {
    expect(FLAT).toMatch(/Poseidon\(2\)/);
    expect(FLAT).toMatch(/commHash\.inputs\[0\]\s*<==\s*attribute\s*;/);
    expect(FLAT).toMatch(/commHash\.inputs\[1\]\s*<==\s*secret\s*;/);
    expect(FLAT).toMatch(/issuerCommitment\s*<==\s*commHash\.out\s*;/);
  });

  it("nullifier = Poseidon(secret, credentialId) — single-use replay marker", () => {
    expect(FLAT).toMatch(/nullHash\.inputs\[0\]\s*<==\s*secret\s*;/);
    expect(FLAT).toMatch(/nullHash\.inputs\[1\]\s*<==\s*credentialId\s*;/);
    expect(FLAT).toMatch(/nullifier\s*<==\s*nullHash\.out\s*;/);
  });
});

describe("credentials.circom — parameterized predicate soundness", () => {
  it("constrains mode to a single bit (blocks Mux1 out-of-range selection)", () => {
    expect(FLAT).toMatch(/mode\s*\*\s*\(\s*mode\s*-\s*1\s*\)\s*===\s*0\s*;/);
  });

  it("range-bounds BOTH comparison operands via Num2Bits (no field wraparound)", () => {
    // attribute and minValue each get a Num2Bits guard before GreaterEqThan.
    expect(FLAT).toMatch(/attrBits\.in\s*<==\s*attribute\s*;/);
    expect(FLAT).toMatch(/minBits\.in\s*<==\s*minValue\s*;/);
    // Two distinct Num2Bits range components exist.
    expect((FLAT.match(/Num2Bits\(/g) || []).length).toBeGreaterThanOrEqual(2);
  });

  it("wires equality (IsEqual) and threshold (GreaterEqThan) into a Mux1 selector", () => {
    expect(FLAT).toContain("IsEqual()");
    expect(FLAT).toMatch(/GreaterEqThan\(/);
    expect(FLAT).toContain("Mux1()");
    // Mux1: c[0] = equality, c[1] = threshold, s = mode.
    expect(FLAT).toMatch(/sel\.c\[0\]\s*<==\s*eq\.out\s*;/);
    expect(FLAT).toMatch(/sel\.c\[1\]\s*<==\s*ge\.out\s*;/);
    expect(FLAT).toMatch(/sel\.s\s*<==\s*mode\s*;/);
  });

  it("enforces the selected predicate as a hard constraint (=== 1), not a readable output", () => {
    expect(FLAT).toMatch(/sel\.out\s*===\s*1\s*;/);
    // There must be no `signal output` carrying a predicate boolean — the only
    // outputs are the commitment + nullifier.
    const outputs = [...SRC.matchAll(/signal\s+output\s+(\w+)\s*;/g)].map(
      (mm) => mm[1],
    );
    expect(outputs.sort()).toEqual(["issuerCommitment", "nullifier"]);
  });
});

describe("credentials.circom — main component / public-signal shape", () => {
  it("instantiates main with the 3 public policy inputs", () => {
    expect(FLAT).toMatch(
      /component\s+main\s*\{\s*public\s*\[\s*mode\s*,\s*expectedValue\s*,\s*minValue\s*\]\s*\}\s*=\s*Credentials\(\s*64\s*\)\s*;/,
    );
  });
});

// ---------------------------------------------------------------------------
// Layer 2 — witness satisfiability (conditional; real snarkjs, child process)
// ---------------------------------------------------------------------------

function fullprove(input: Record<string, string>): {
  status: number | null;
  publicSignals: string[] | null;
  proofPath: string;
  publicPath: string;
} {
  const tmp = mkdtempSync(join(tmpdir(), "zk-cred-"));
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
  return { status: r.status, publicSignals, proofPath, publicPath };
}

function verifyOk(publicPath: string, proofPath: string): number | null {
  return spawnSync(
    process.execPath,
    [CLI, "groth16", "verify", VKEY, publicPath, proofPath],
    { encoding: "utf8" },
  ).status;
}

// Satisfying witnesses for each predicate mode (same shape prove-credentials.mjs
// uses). snarkjs publicSignals order is OUTPUTS first, then public inputs:
// [issuerCommitment, nullifier, mode, expectedValue, minValue].
// (NB: prove-credentials.mjs's console labels assume the reverse — they mislabel.)
const THRESHOLD_OK = {
  attribute: "21", secret: "1234567890", credentialId: "777",
  mode: "1", expectedValue: "1", minValue: "18", // 21 >= 18 ✓
};
const EQUALITY_OK = {
  attribute: "1", secret: "1234567890", credentialId: "777",
  mode: "0", expectedValue: "1", minValue: "18", // 1 == 1 ✓
};

describe("credentials.circom — witness satisfiability (BLS12-381, snarkjs CLI)", () => {
  it.runIf(canProve)(
    "proves a threshold credential (attribute >= minValue) and exposes [mode, expectedValue, minValue, commitment, nullifier]",
    () => {
      const p = fullprove(THRESHOLD_OK);
      expect(p.status).toBe(0);
      expect(p.publicSignals).not.toBeNull();
      expect(verifyOk(p.publicPath, p.proofPath)).toBe(0);
      const ps = p.publicSignals!;
      expect(ps.length).toBe(5);
      // [issuerCommitment, nullifier, mode, expectedValue, minValue].
      expect(ps[2]).toBe("1");  // mode
      expect(ps[4]).toBe("18"); // minValue echoed as a public input
      expect(ps[0]).not.toBe("0"); // issuerCommitment = Poseidon(attribute, secret)
    },
    120_000,
  );

  it.runIf(canProve)(
    "rejects a threshold credential where attribute < minValue (sel.out === 1 unsatisfiable)",
    () => {
      const bad = fullprove({ ...THRESHOLD_OK, attribute: "10" }); // 10 < 18
      expect(bad.status).not.toBe(0);
      expect(bad.publicSignals).toBeNull();
    },
    120_000,
  );

  it.runIf(canProve)(
    "proves an equality credential (attribute == expectedValue) under mode 0",
    () => {
      const p = fullprove(EQUALITY_OK);
      expect(p.status).toBe(0);
      expect(verifyOk(p.publicPath, p.proofPath)).toBe(0);
      expect(p.publicSignals![2]).toBe("0"); // mode (outputs precede public inputs)
    },
    120_000,
  );

  it.runIf(canProve)(
    "rejects an equality credential where attribute != expectedValue",
    () => {
      const bad = fullprove({ ...EQUALITY_OK, attribute: "2" }); // 2 != 1
      expect(bad.status).not.toBe(0);
    },
    120_000,
  );

  it.skipIf(canProve)(
    "[skipped] build artefacts or snarkjs CLI missing — run 'npm run build:circuits'",
    () => {
      expect(true).toBe(true);
    },
  );
});
