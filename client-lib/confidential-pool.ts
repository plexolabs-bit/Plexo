// StellarHub ZK reference · https://stellarhub.io
/**
 * confidential-pool.ts — client-side Soroban invoke of the deployed confidential-amount
 * pool (contracts/zk-confidential-transfer). The whole submission is client-side: the
 * account secret never leaves the caller (the `signTransaction` callback signs locally).
 *
 * ---------------------------------------------------------------------------
 * HONEST SCOPE — the ONLY truthful privacy claim:
 *   confidential_transfer hides the AMOUNT — on-chain it lives solely as a
 *   Poseidon commitment; it is NEVER a transaction argument and NEVER an event
 *   field (the `conf_xfer` event carries only the two new commitments + the sealed
 *   note, and there is no token::transfer). A Groth16/BLS12-381 proof enforces
 *   value conservation in-circuit.
 * NOTHING ELSE is hidden: sender + recipient IDENTITIES are visible (the op names
 *   both accounts). The boundary deposit()/withdraw() expose their amounts in
 *   cleartext (real token move + amount in the event). Single-participant dev VK
 *   (not an MPC ceremony). Unaudited. TESTNET-ONLY PoC.
 *
 * ---------------------------------------------------------------------------
 * ENCODING — confirmed against the deployed contract:
 *   proof       = { a: g1(96B), b: g2(192B), c: g1(96B) }  uncompressed BLS12-381
 *   pub_signals = bigint[]  (Vec<Fr>, U256-backed)
 */

import { bls12_381 } from '@noble/curves/bls12-381.js';
import {
  contract as sorobanContract,
  rpc as sorobanRpc,
  Account,
  Address,
  Contract,
  TransactionBuilder,
  nativeToScVal,
  scValToNative,
} from '@stellar/stellar-sdk';

/**
 * The deployed confidential-amount PoC pool contract (Stellar TESTNET).
 * v2: the conf_xfer event carries the ephemeral pubkey + sealed note for cross-person
 * recovery, and an ABSENT recipient defaults to C0 = Poseidon(0,0) so a sender can
 * credit a not-yet-registered recipient in one signed tx.
 */
export const DEFAULT_CONFIDENTIAL_CONTRACT_ID =
  'CC6LDUHVSSVNAEI5XQPQVDZPQCUJYONPPO7OL5AOWHIKHXLQTQ6FDO2K';

export const TESTNET_SOROBAN_RPC_URL = 'https://soroban-testnet.stellar.org';

/** A snarkjs Groth16 proof over BLS12-381 (decimal affine coords). */
export interface SnarkProofCoords {
  pi_a: [string, string, string];
  pi_b: [[string, string], [string, string], [string, string]];
  pi_c: [string, string, string];
}

/** G1 uncompressed serialization (96 bytes) — matches the contract's G1Affine::from_array. */
export function g1Bytes(x: string, y: string): Buffer {
  const point = bls12_381.G1.Point.fromAffine({ x: BigInt(x), y: BigInt(y) });
  return Buffer.from(point.toBytes(false));
}

/** G2 uncompressed serialization (192 bytes) — matches the contract's G2Affine::from_array. */
export function g2Bytes(b: SnarkProofCoords['pi_b']): Buffer {
  const point = bls12_381.G2.Point.fromAffine({
    x: { c0: BigInt(b[0][0]), c1: BigInt(b[0][1]) },
    y: { c0: BigInt(b[1][0]), c1: BigInt(b[1][1]) },
  });
  return Buffer.from(point.toBytes(false));
}

/** Decimal field element → 32-byte big-endian BytesN<32> (the deposit commitment). */
export function commitmentToBytes32(commitmentDecimal: string): Buffer {
  const n = BigInt(commitmentDecimal);
  if (n < 0n) throw new Error('commitmentToBytes32: negative field element');
  const hex = n.toString(16);
  if (hex.length > 64) throw new Error('commitmentToBytes32: field element exceeds 32 bytes');
  return Buffer.from(hex.padStart(64, '0'), 'hex');
}

/** 32-byte big-endian BytesN<32> → decimal field element (mirror of the above). */
export function bytes32ToDecimal(buf: Uint8Array): string {
  let n = 0n;
  for (const byte of buf) n = (n << 8n) | BigInt(byte);
  return n.toString();
}

/** Local signer callback — returns the signed tx XDR. Keys never leave the caller. */
export type SignTx = (
  xdr: string,
  opts: { networkPassphrase: string },
) => Promise<{ signedTxXdr: string } | string>;

/** Wall-clock ceiling for one on-chain submit — a hung RPC must reject, never hang. */
export const CONFIDENTIAL_SUBMIT_TIMEOUT_MS = 90_000;

function raceWithTimeout<T>(p: Promise<T>, ms: number, message: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(message)), ms);
    p.then(
      (v) => { clearTimeout(timer); resolve(v); },
      (e) => { clearTimeout(timer); reject(e); },
    );
  });
}

// The dynamically-generated contract client surface (Client.from adds the methods
// from the deployed spec at runtime; TS only sees the base Client, so we describe
// the shapes we use and cast). Spec maps: string→Address, bigint→i128, Buffer→BytesN,
// {a,b,c}→Proof struct, bigint[]→Vec<Fr>.
interface AssembledInvokeTx {
  signAndSend(opts: {
    signTransaction: (xdr: string) => Promise<{ signedTxXdr: string } | string>;
  }): Promise<{
    sendTransactionResponse?: { hash?: string } | null;
    getTransactionResponse?: { txHash?: string } | null;
  }>;
}
interface ConfidentialClient {
  deposit(args: { from: string; amount: bigint; commitment: Buffer }): Promise<AssembledInvokeTx>;
  confidential_transfer(args: {
    sender: string;
    recipient: string;
    proof: { a: Buffer; b: Buffer; c: Buffer };
    pub_signals: bigint[];
    ephemeral_pubkey: Buffer;
    note: Buffer;
  }): Promise<AssembledInvokeTx>;
}

function extractHash(sent: Awaited<ReturnType<AssembledInvokeTx['signAndSend']>>): string {
  const hash = sent.sendTransactionResponse?.hash ?? sent.getTransactionResponse?.txHash;
  if (!hash) throw new Error('confidential invoke submitted but no transaction hash was returned');
  return hash;
}

export interface ConfidentialDepositOnchainParams {
  contractId?: string;
  rpcUrl: string;
  networkPassphrase: string;
  /** Depositor G-address (must equal the signer — deposit does from.require_auth). */
  from: string;
  /** Boundary deposit amount in stroops (i128). PUBLIC — visible on-chain. */
  amountStroops: bigint;
  /** 32-byte BytesN<32> commitment = Poseidon(amount, blinding). PUBLIC. */
  commitment: Buffer;
  signTransaction: SignTx;
}

/**
 * BOUNDARY deposit — register the account's INITIAL confidential commitment and
 * move `amountStroops` of the pool token in. The amount IS visible on-chain here
 * (real token move + deposit event); only the in-pool bookkeeping is hidden.
 * Fails with the contract's BalanceExists(7) trap on a second deposit — check
 * {@link simulateHasBalance} first.
 */
export async function submitConfidentialDepositOnchain(
  p: ConfidentialDepositOnchainParams,
): Promise<string> {
  if (p.commitment.length !== 32) {
    throw new Error(`commitment must be 32 bytes (BytesN<32>), got ${p.commitment.length}`);
  }
  const submit = async (): Promise<string> => {
    const base = await sorobanContract.Client.from({
      contractId: p.contractId ?? DEFAULT_CONFIDENTIAL_CONTRACT_ID,
      rpcUrl: p.rpcUrl,
      networkPassphrase: p.networkPassphrase,
      publicKey: p.from,
    });
    const client = base as unknown as ConfidentialClient;
    const tx = await client.deposit({
      from: p.from,
      amount: p.amountStroops,
      commitment: p.commitment,
    });
    const sent = await tx.signAndSend({
      signTransaction: (xdr: string) => p.signTransaction(xdr, { networkPassphrase: p.networkPassphrase }),
    });
    return extractHash(sent);
  };
  return raceWithTimeout(
    submit(),
    CONFIDENTIAL_SUBMIT_TIMEOUT_MS,
    'confidential deposit submit timed out — no network response; the transaction may still have landed',
  );
}

export interface ConfidentialTransferOnchainParams {
  contractId?: string;
  rpcUrl: string;
  networkPassphrase: string;
  /** Debited account (must equal the signer — confidential_transfer does sender.require_auth). */
  sender: string;
  /** Credited account (visible on-chain; may be UNREGISTERED — C0 fold-in creates the slot). */
  recipient: string;
  /** snarkjs Groth16 proof (decimal affine coords). */
  proof: SnarkProofCoords;
  /** The 4 public commitments (decimal), circuit order: [sender_old, sender_new, recipient_old, recipient_new]. */
  publicSignals: string[];
  /** Sender's X25519 ephemeral pubkey (32B) — echoed in the conf_xfer event for note delivery. */
  ephemeralPublic: Uint8Array;
  /** Sealed note (viewTag ‖ secretbox(amount)) — echoed in the event so the recipient recovers the opening. */
  note: Uint8Array;
  signTransaction: SignTx;
}

/**
 * The amount-hiding op. Encodes the Groth16 proof + the four public commitments,
 * builds `confidential_transfer(sender, recipient, proof, pub_signals, ephemeral,
 * note)`, signs the envelope locally with the sender's key, submits to Soroban, and
 * returns the REAL tx hash. NO token::transfer, NO amount arg, NO amount in the
 * event — the value stays pooled and hidden behind the commitments.
 */
export async function submitConfidentialTransferOnchain(
  p: ConfidentialTransferOnchainParams,
): Promise<string> {
  if (p.publicSignals.length !== 4) {
    throw new Error(`confidential_transfer needs 4 public signals, got ${p.publicSignals.length}`);
  }
  if (p.ephemeralPublic.length !== 32) {
    throw new Error(`ephemeral pubkey must be 32 bytes, got ${p.ephemeralPublic.length}`);
  }
  const proofArg = {
    a: g1Bytes(p.proof.pi_a[0], p.proof.pi_a[1]),
    b: g2Bytes(p.proof.pi_b),
    c: g1Bytes(p.proof.pi_c[0], p.proof.pi_c[1]),
  };
  const pubSignals = p.publicSignals.map((s) => BigInt(s));

  const submit = async (): Promise<string> => {
    const base = await sorobanContract.Client.from({
      contractId: p.contractId ?? DEFAULT_CONFIDENTIAL_CONTRACT_ID,
      rpcUrl: p.rpcUrl,
      networkPassphrase: p.networkPassphrase,
      publicKey: p.sender,
    });
    const client = base as unknown as ConfidentialClient;
    const tx = await client.confidential_transfer({
      sender: p.sender,
      recipient: p.recipient,
      proof: proofArg,
      pub_signals: pubSignals,
      ephemeral_pubkey: Buffer.from(p.ephemeralPublic),
      note: Buffer.from(p.note),
    });
    const sent = await tx.signAndSend({
      signTransaction: (xdr: string) => p.signTransaction(xdr, { networkPassphrase: p.networkPassphrase }),
    });
    return extractHash(sent);
  };
  return raceWithTimeout(
    submit(),
    CONFIDENTIAL_SUBMIT_TIMEOUT_MS,
    'confidential transfer submit timed out — no network response; the transaction may still have landed',
  );
}

// ---------------------------------------------------------------------------
// Read-only getters (simulate; no submission, no funded source required). Used to
// check the compare-and-swap preconditions BEFORE spending fees — the confidential
// transfer reverts NoBalance(8)/CommitmentMismatch(6) if the local view has drifted
// from the on-chain commitment.
// ---------------------------------------------------------------------------

async function simulateGetter(
  rpcUrl: string,
  networkPassphrase: string,
  contractId: string,
  account: string,
  func: string,
  args: ReturnType<typeof nativeToScVal>[],
): Promise<unknown> {
  const server = new sorobanRpc.Server(rpcUrl);
  const source = new Account(account, '0');
  const tx = new TransactionBuilder(source, { fee: '100', networkPassphrase })
    .addOperation(new Contract(contractId).call(func, ...args))
    .setTimeout(30)
    .build();
  const sim = await server.simulateTransaction(tx);
  if (!sorobanRpc.Api.isSimulationSuccess(sim) || !sim.result?.retval) return null;
  return scValToNative(sim.result.retval);
}

/** True when `account` already registered a confidential balance (deposited). */
export async function simulateHasBalance(
  rpcUrl: string,
  networkPassphrase: string,
  contractId: string,
  account: string,
): Promise<boolean | null> {
  try {
    const native = await simulateGetter(rpcUrl, networkPassphrase, contractId, account, 'has_balance', [
      new Address(account).toScVal(),
    ]);
    return typeof native === 'boolean' ? native : null;
  } catch {
    return null;
  }
}

/** The account's CURRENT on-chain commitment as a decimal field element, or null. */
export async function simulateGetCommitment(
  rpcUrl: string,
  networkPassphrase: string,
  contractId: string,
  account: string,
): Promise<string | null> {
  try {
    const native = await simulateGetter(rpcUrl, networkPassphrase, contractId, account, 'get_commitment', [
      new Address(account).toScVal(),
    ]);
    if (native == null) return null;
    if (native instanceof Uint8Array) return bytes32ToDecimal(native);
    if (typeof native === 'string') return native;
    return null;
  } catch {
    return null;
  }
}
