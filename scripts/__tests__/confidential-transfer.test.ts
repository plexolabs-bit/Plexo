// StellarHub ZK reference · https://stellarhub.io
/**
 * scripts/__tests__/confidential-transfer.test.ts
 *
 * Tests for the confidential-amount transfer surface (the "green eye"): the
 * confidential_transfer + confidential_withdraw circuits, their committed build
 * artefacts, the zk-confidential-transfer Soroban pool contract, and the
 * standalone client-lib (note crypto + pool invoke + scanner). Two layers,
 * mirroring the sibling private-transfer / proof-of-reserves suites:
 *   1. Source-structure (always run): circuit signals + conservation + range
 *      constraints, committed artefact shapes, the DEPLOYED-pool VK match, the
 *      contract's C0 fold-in + auth gates, client-lib/e2e wiring, no baked-in
 *      secrets.
 *   2. Witness-satisfiability (CONDITIONAL — runs only when the committed
 *      build/confidential_* artefacts + the snarkjs CLI bundle are present):
 *      proves a real conserving transfer (with the C0 empty-balance recipient),
 *      checks in-circuit Poseidon parity with ../poseidon_bls.mjs AND with the
 *      contract's C0 constant, and asserts non-conserving / forged witnesses are
 *      UNPROVABLE. Proving runs the snarkjs CLI as a child process (its JS API
 *      spawns Worker threads vitest's pool can't host).
 */

import { beforeAll, describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = resolve(fileURLToPath(import.meta.url), "..");
const ZK_DIR = resolve(__dirname, "..", "..");

const TRANSFER_SRC = join(ZK_DIR, "circuits", "confidential_transfer.circom");
const WITHDRAW_SRC = join(ZK_DIR, "circuits", "confidential_withdraw.circom");
const BUILD_DIR = join(ZK_DIR, "build");
const T_WASM = join(BUILD_DIR, "confidential_transfer.wasm");
const T_ZKEY = join(BUILD_DIR, "confidential_transfer_final.zkey");
const T_VKEY = join(BUILD_DIR, "confidential_transfer_verification_key.json");
const W_WASM = join(BUILD_DIR, "confidential_withdraw.wasm");
const W_ZKEY = join(BUILD_DIR, "confidential_withdraw_final.zkey");
const W_VKEY = join(BUILD_DIR, "confidential_withdraw_verification_key.json");
const CLI = resolve(ZK_DIR, "node_modules", "snarkjs", "build", "cli.cjs");

const CONTRACT_DIR = join(ZK_DIR, "contracts", "zk-confidential-transfer");
const CONTRACT_LIB = join(CONTRACT_DIR, "src", "lib.rs");
const CONTRACT_VK = join(CONTRACT_DIR, "data", "verification_key.json");
const E2E = join(ZK_DIR, "e2e", "confidential-transfer-e2e.ts");
const POOL_TS = join(ZK_DIR, "client-lib", "confidential-pool.ts");

// The deployed confidential pool the e2e talks to — MUST match README + client-lib.
const POOL_CONTRACT = "CC6LDUHVSSVNAEI5XQPQVDZPQCUJYONPPO7OL5AOWHIKHXLQTQ6FDO2K";

// ---------------------------------------------------------------------------
// Layer 1 — source-structure (always run)
// ---------------------------------------------------------------------------

describe("confidential_transfer.circom — source structure", () => {
  const src = readFileSync(TRANSFER_SRC, "utf8");

  it("pins circom 2.2.0 + circomlib includes", () => {
    expect(src).toMatch(/pragma circom 2\.2\.0;/);
    expect(src).toContain("../../../node_modules/circomlib/circuits/poseidon.circom");
    expect(src).toContain("../../../node_modules/circomlib/circuits/bitify.circom");
  });

  it("declares the 4 public commitments + the 9 private witness signals", () => {
    for (const s of [
      "commitment_sender_old", "commitment_sender_new",
      "commitment_recipient_old", "commitment_recipient_new",
      "amount_sender_old", "amount_sender_new",
      "amount_recipient_old", "amount_recipient_new",
      "transfer_amount",
      "blinding_sender_old", "blinding_sender_new",
      "blinding_recipient_old", "blinding_recipient_new",
    ]) {
      expect(src).toMatch(new RegExp(`signal input ${s};`));
    }
  });

  it("opens all four commitments with Poseidon(2)", () => {
    expect(src.match(/= Poseidon\(2\);/g)?.length).toBe(4);
    expect(src).toMatch(/commitment_sender_old === openSenderOld\.out;/);
    expect(src).toMatch(/commitment_recipient_new === openRecipientNew\.out;/);
  });

  it("proves conservation with a single shared t (the dangerous constraint)", () => {
    expect(src).toMatch(/amount_sender_old === amount_sender_new \+ transfer_amount;/);
    expect(src).toMatch(/amount_recipient_new === amount_recipient_old \+ transfer_amount;/);
  });

  it("range-binds the new balances AND t via Num2Bits(64)", () => {
    // 3 component INSTANTIATIONS (comments also mention Num2Bits — count `= …;`).
    expect(src.match(/= Num2Bits\(64\);/g)?.length).toBe(3);
    expect(src).toMatch(/rangeTransfer\.in <== transfer_amount;/);
  });

  it("declares exactly the 4 commitments public", () => {
    const main = src.slice(src.indexOf("component main"));
    for (const s of [
      "commitment_sender_old", "commitment_sender_new",
      "commitment_recipient_old", "commitment_recipient_new",
    ]) {
      expect(main).toContain(s);
    }
    expect(main).not.toContain("transfer_amount");
  });
});

describe("confidential_withdraw.circom — source structure", () => {
  const src = readFileSync(WITHDRAW_SRC, "utf8");

  it("opens the burned commitment: commitment === Poseidon(amount, blinding)", () => {
    expect(src).toMatch(/component opener = Poseidon\(2\);/);
    expect(src).toMatch(/opener\.inputs\[0\] <== amount;/);
    expect(src).toMatch(/opener\.inputs\[1\] <== blinding;/);
    expect(src).toMatch(/commitment === opener\.out;/);
  });

  it("amount is PUBLIC (the trustless open-to-amount bind) and range-bound", () => {
    const main = src.slice(src.indexOf("component main"));
    expect(main).toContain("commitment");
    expect(main).toContain("amount");
    expect(main).not.toContain("blinding");
    expect(src).toMatch(/component range = Num2Bits\(64\);/);
  });
});

describe("confidential — committed artefacts", () => {
  it("ships wasm + final zkey + verification key for BOTH circuits", () => {
    for (const f of [T_WASM, T_ZKEY, T_VKEY, W_WASM, W_ZKEY, W_VKEY]) {
      expect(existsSync(f), f).toBe(true);
    }
  });

  it("transfer VK is groth16 / bls12381 with exactly 4 public signals", () => {
    const vk = JSON.parse(readFileSync(T_VKEY, "utf8"));
    expect(vk.protocol).toBe("groth16");
    expect(vk.curve).toBe("bls12381");
    expect(vk.nPublic).toBe(4);
  });

  it("withdraw VK is groth16 / bls12381 with exactly 2 public signals", () => {
    const vk = JSON.parse(readFileSync(W_VKEY, "utf8"));
    expect(vk.protocol).toBe("groth16");
    expect(vk.curve).toBe("bls12381");
    expect(vk.nPublic).toBe(2);
  });

  it("the committed transfer VK IS the deployed pool's VK (contract data/ match)", () => {
    // The build/ transfer artefacts are the exact set the deployed testnet pool
    // (CC6LDUHV…) was initialized with — proofs from this zkey verify on-chain.
    const build = JSON.parse(readFileSync(T_VKEY, "utf8"));
    const contract = JSON.parse(readFileSync(CONTRACT_VK, "utf8"));
    expect(build).toEqual(contract);
  });
});

describe("zk-confidential-transfer contract — source wiring", () => {
  const lib = readFileSync(CONTRACT_LIB, "utf8");

  it("C0 fold-in: an ABSENT recipient defaults to the Poseidon(0,0) constant", () => {
    expect(lib).toMatch(/const C0: \[u8; 32\]/);
    expect(lib).toContain("unwrap_or_else(|| BytesN::from_array(&env, &C0))");
  });

  it("conf_xfer event carries the sealed note (ephemeral_pubkey + note), NO amount", () => {
    expect(lib).toMatch(/ephemeral_pubkey: BytesN<32>/);
    expect(lib).toMatch(/note: Bytes/);
    expect(lib).toContain('symbol_short!("conf_xfer")');
    expect(lib).toContain("(c_sender_new, c_recipient_new, ephemeral_pubkey, note)");
  });

  it("auth gates: sender authorises the swap, recipient authorises the exit", () => {
    expect(lib).toContain("sender.require_auth();");
    expect(lib).toContain("to.require_auth();");
  });

  it("confidential_transfer moves NO tokens (token::transfer only at the boundaries)", () => {
    const start = lib.indexOf("pub fn confidential_transfer");
    const end = lib.indexOf("pub fn withdraw");
    const body = lib.slice(start, end);
    expect(body).not.toContain("token::Client");
    // Boundary ops DO move real tokens (that is the honest visible edge).
    expect(lib.slice(lib.indexOf("pub fn deposit"), start)).toContain("token::Client");
  });

  it("withdraw pins the open-to-amount bind (AmountMismatch) + replay burn", () => {
    expect(lib).toContain("AmountMismatch");
    expect(lib).toMatch(/if proven_amount != amount_fr/);
    expect(lib).toContain("env.storage().persistent().remove(&key);");
  });
});

describe("confidential client-lib + e2e — wiring, no baked-in secrets", () => {
  it("ships the standalone client modules", () => {
    for (const f of [
      "confidential-note.ts", "confidential-commit.ts",
      "confidential-pool.ts", "confidential-receive.ts", "sodium.ts",
    ]) {
      expect(existsSync(join(ZK_DIR, "client-lib", f)), f).toBe(true);
    }
  });

  it("client-lib pins the deployed pool contract id (matches README/e2e)", () => {
    expect(readFileSync(POOL_TS, "utf8")).toContain(POOL_CONTRACT);
  });

  it("e2e generates FRESH keypairs + Friendbot funding — no hardcoded accounts", () => {
    const e2e = readFileSync(E2E, "utf8");
    expect(e2e).toContain("Keypair.random");
    expect(e2e.toLowerCase()).toContain("friendbot");
    // no baked-in Stellar secret or account literals
    expect(e2e).not.toMatch(/"S[A-Z2-7]{55}"/);
    expect(e2e).not.toMatch(/"G[A-Z2-7]{55}"/);
  });

  it("e2e is exposed via npm run e2e:confidential", () => {
    const pkg = JSON.parse(readFileSync(join(ZK_DIR, "package.json"), "utf8"));
    expect(pkg.scripts["e2e:confidential"]).toContain("e2e/confidential-transfer-e2e.ts");
  });

  it("note crypto derives the recipient key from the PLAIN G-address (no receive code)", () => {
    const note = readFileSync(join(ZK_DIR, "client-lib", "confidential-note.ts"), "utf8");
    expect(note).toContain("crypto_sign_ed25519_pk_to_curve25519");
    expect(note).toContain("crypto_sign_ed25519_sk_to_curve25519");
    // domain separation pinned — changing these breaks note compatibility
    expect(note).toContain("StellarHub:ConfNote:v1");
    expect(note).toContain("StellarHub:ConfNote:blind:v1");
  });
});

// ---------------------------------------------------------------------------
// Layer 2 — witness satisfiability (conditional; real snarkjs, child process)
// ---------------------------------------------------------------------------

const artefactsPresent =
  existsSync(T_WASM) && existsSync(T_ZKEY) && existsSync(T_VKEY) &&
  existsSync(W_WASM) && existsSync(W_ZKEY) && existsSync(W_VKEY) && existsSync(CLI);

interface ProveResult {
  status: number | null;
  publicSignals: string[] | null;
  proofPath: string;
  publicPath: string;
}

function fullprove(input: Record<string, string>, wasm: string, zkey: string): ProveResult {
  const tmp = mkdtempSync(join(tmpdir(), "zk-ct-"));
  const inPath = join(tmp, "in.json");
  const proofPath = join(tmp, "proof.json");
  const publicPath = join(tmp, "public.json");
  writeFileSync(inPath, JSON.stringify(input));
  const r = spawnSync(
    process.execPath,
    [CLI, "groth16", "fullprove", inPath, wasm, zkey, proofPath, publicPath],
    { encoding: "utf8" },
  );
  const publicSignals =
    r.status === 0 && existsSync(publicPath)
      ? (JSON.parse(readFileSync(publicPath, "utf8")) as string[])
      : null;
  return { status: r.status, publicSignals, proofPath, publicPath };
}

function verify(vkey: string, publicPath: string, proofPath: string): number | null {
  return spawnSync(
    process.execPath,
    [CLI, "groth16", "verify", vkey, publicPath, proofPath],
    { encoding: "utf8" },
  ).status;
}

let H: ((xs: Array<string | number>) => string) | null = null;
let setupError: string | null = null;

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

// A conserving transfer witness: sender 150 -> 100, recipient 0 -> 50, t = 50.
// recipientOld opens the EMPTY balance (0, 0) — the C0 fold-in case the deployed
// contract accepts for a not-yet-registered recipient.
function transferInput(h: (xs: Array<string | number>) => string): Record<string, string> {
  const w = {
    amount_sender_old: "150", amount_sender_new: "100",
    amount_recipient_old: "0", amount_recipient_new: "50",
    transfer_amount: "50",
    blinding_sender_old: "111", blinding_sender_new: "222",
    blinding_recipient_old: "0", blinding_recipient_new: "333",
  };
  return {
    commitment_sender_old: h([w.amount_sender_old, w.blinding_sender_old]),
    commitment_sender_new: h([w.amount_sender_new, w.blinding_sender_new]),
    commitment_recipient_old: h(["0", "0"]),
    commitment_recipient_new: h([w.amount_recipient_new, w.blinding_recipient_new]),
    ...w,
  };
}

describe("confidential circuits — witness satisfiability (BLS12-381, snarkjs CLI)", () => {
  beforeAll(async () => {
    if (artefactsPresent) H = await buildHasher();
  }, 90_000);

  it.runIf(artefactsPresent)(
    "proves a conserving transfer (C0 empty recipient), verifies, Poseidon parity holds",
    () => {
      expect(H, setupError ?? "hasher not built").not.toBeNull();
      const input = transferInput(H!);
      const p = fullprove(input, T_WASM, T_ZKEY);
      expect(p.status).toBe(0);
      expect(verify(T_VKEY, p.publicPath, p.proofPath)).toBe(0);

      const ps = p.publicSignals!;
      expect(ps.length).toBe(4);
      expect(ps[0]).toBe(input.commitment_sender_old);
      expect(ps[3]).toBe(input.commitment_recipient_new);
      // pub[2] is the EMPTY balance commitment — must equal the CONTRACT's C0
      // constant (the byte array in src/lib.rs), pinning client/circuit/contract
      // hash parity in one assert.
      const c0Bytes = readFileSync(CONTRACT_LIB, "utf8")
        .match(/const C0: \[u8; 32\] = \[([\s\S]*?)\];/)![1]
        .match(/0x[0-9a-f]{2}/g)!;
      const c0Decimal = BigInt(
        "0x" + c0Bytes.map((b) => b.slice(2)).join(""),
      ).toString();
      expect(ps[2]).toBe(c0Decimal);
      expect(ps[2]).toBe(H!(["0", "0"]));
    },
    180_000,
  );

  it.runIf(artefactsPresent)(
    "a NON-CONSERVING transfer witness is UNPROVABLE (debit != credit)",
    () => {
      // credit the recipient 60 while debiting the sender 50 — no single t
      // satisfies both conservation constraints.
      const input = transferInput(H!);
      const forged = {
        ...input,
        amount_recipient_new: "60",
        commitment_recipient_new: H!(["60", "333"]),
      };
      const bad = fullprove(forged, T_WASM, T_ZKEY);
      expect(bad.status).not.toBe(0);
      expect(bad.publicSignals).toBeNull();
    },
    180_000,
  );

  it.runIf(artefactsPresent)(
    "withdraw: proves the open-to-amount bind and verifies",
    () => {
      const amount = "100000000";
      const blinding = "424242424242";
      const input = { commitment: H!([amount, blinding]), amount, blinding };
      const p = fullprove(input, W_WASM, W_ZKEY);
      expect(p.status).toBe(0);
      expect(verify(W_VKEY, p.publicPath, p.proofPath)).toBe(0);
      expect(p.publicSignals).toEqual([input.commitment, amount]);
    },
    180_000,
  );

  it.runIf(artefactsPresent)(
    "withdraw: a FORGED amount against a real commitment is UNPROVABLE",
    () => {
      const blinding = "424242424242";
      const input = {
        commitment: H!(["100000000", blinding]), // commitment to 100000000…
        amount: "999000000", // …but claim 999000000 (Poseidon second-preimage)
        blinding,
      };
      const bad = fullprove(input, W_WASM, W_ZKEY);
      expect(bad.status).not.toBe(0);
      expect(bad.publicSignals).toBeNull();
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
