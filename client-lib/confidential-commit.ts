// StellarHub ZK reference · https://stellarhub.io
/**
 * confidential-commit.ts — the client side of the confidential-amount commitments.
 *
 * commitment = Poseidon(amount, blinding) over the BLS12-381 scalar field — the SAME
 * hash the `confidential_transfer` / `confidential_withdraw` circuits run in-circuit
 * (circomlib Poseidon compiled with `-p bls12381`) and the SAME hash whose (0,0)
 * image is the contract's C0 "empty balance" constant. The hash itself is
 * `scripts/poseidon_bls.mjs` (circomlib opt-Poseidon re-instantiated over the
 * bls12381 Fr — see the parity claim there); this module wraps it with the witness
 * builder for the confidential_transfer circuit.
 *
 * All amounts are stroops as decimal strings; all blindings are decimal BLS12-381
 * field elements. Amounts + blindings are PRIVATE — they never leave the prover.
 */

// Plain-JS hasher shared with the circuit test-suites (no type declarations shipped).
// @ts-ignore — .mjs module without types
import buildPoseidonBls from '../scripts/poseidon_bls.mjs';

type PoseidonFn = ((inputs: Array<string | bigint>) => unknown) & {
  F: { toString(x: unknown): string };
};

let _poseidonPromise: Promise<PoseidonFn> | null = null;

async function poseidon(): Promise<PoseidonFn> {
  if (!_poseidonPromise) _poseidonPromise = buildPoseidonBls() as Promise<PoseidonFn>;
  return _poseidonPromise;
}

/** BLS12-381 Poseidon over decimal-string inputs → decimal field-element digest. */
export async function poseidonBls(inputs: Array<string | bigint>): Promise<string> {
  const p = await poseidon();
  return p.F.toString(p(inputs));
}

/** One opened balance: a confidential amount + its commitment blinding (both PRIVATE). */
export interface ConfidentialBalance {
  /** Opened amount in stroops, decimal string. Range-bound [0, 2^64) by the circuit. PRIVATE. */
  amount: string;
  /** Commitment blinding (decimal field element). PRIVATE — never leaves the device. */
  blinding: string;
}

/** commitment = Poseidon(amount, blinding) over BLS12-381 — same field + arity as the circuit. */
export async function commit(b: ConfidentialBalance): Promise<string> {
  return poseidonBls([b.amount, b.blinding]);
}

/**
 * A fresh random BLS12-381 field element (decimal). 31 random bytes (248 bits) are
 * unconditionally < r, so there is no modulo bias.
 */
export function randomFieldDecimal(): string {
  const b = new Uint8Array(31);
  crypto.getRandomValues(b);
  let n = 0n;
  for (const x of b) n = (n << 8n) | BigInt(x);
  return n.toString();
}

/**
 * The full witness of one confidential transfer: the sender's and recipient's
 * confidential balances BEFORE and AFTER, plus the transfer amount t. Conservation
 * must hold — the circuit proves it, an unsatisfiable witness fails inside snarkjs:
 *   senderOld.amount === senderNew.amount + transferAmount
 *   recipientNew.amount === recipientOld.amount + transferAmount
 */
export interface ConfidentialTransferWitness {
  senderOld: ConfidentialBalance;
  senderNew: ConfidentialBalance;
  recipientOld: ConfidentialBalance;
  recipientNew: ConfidentialBalance;
  /** t — the confidential transfer amount in stroops (decimal). PRIVATE. */
  transferAmount: string;
}

/**
 * The circuit input vector for `circuits/confidential_transfer.circom`: four PUBLIC
 * commitments + the nine PRIVATE witness signals. Field names match the circom
 * `signal input` declarations exactly (snake_case).
 */
export interface ConfidentialTransferCircuitInput {
  commitment_sender_old: string;
  commitment_sender_new: string;
  commitment_recipient_old: string;
  commitment_recipient_new: string;
  amount_sender_old: string;
  amount_sender_new: string;
  amount_recipient_old: string;
  amount_recipient_new: string;
  transfer_amount: string;
  blinding_sender_old: string;
  blinding_sender_new: string;
  blinding_recipient_old: string;
  blinding_recipient_new: string;
}

/**
 * Build the circuit input vector from the witness. Computes the four Poseidon
 * commitments locally; the amounts + blindings flow straight through as the
 * private witness. Exported separately from proving so the commitment +
 * conservation wiring is testable WITHOUT the heavy prover.
 */
export async function buildConfidentialTransferInput(
  w: ConfidentialTransferWitness,
): Promise<ConfidentialTransferCircuitInput> {
  const [cSenderOld, cSenderNew, cRecipientOld, cRecipientNew] = await Promise.all([
    commit(w.senderOld),
    commit(w.senderNew),
    commit(w.recipientOld),
    commit(w.recipientNew),
  ]);

  return {
    commitment_sender_old: cSenderOld,
    commitment_sender_new: cSenderNew,
    commitment_recipient_old: cRecipientOld,
    commitment_recipient_new: cRecipientNew,
    amount_sender_old: w.senderOld.amount,
    amount_sender_new: w.senderNew.amount,
    amount_recipient_old: w.recipientOld.amount,
    amount_recipient_new: w.recipientNew.amount,
    transfer_amount: w.transferAmount,
    blinding_sender_old: w.senderOld.blinding,
    blinding_sender_new: w.senderNew.blinding,
    blinding_recipient_old: w.recipientOld.blinding,
    blinding_recipient_new: w.recipientNew.blinding,
  };
}
