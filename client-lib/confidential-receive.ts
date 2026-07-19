// StellarHub ZK reference · https://stellarhub.io
/**
 * confidential-receive.ts — recipient-side scan for incoming confidential-amount
 * transfers.
 *
 * The confidential pool's `conf_xfer` event carries the sender's X25519 ephemeral pubkey
 * + a sealed note (viewTag ‖ secretbox(amount)); the recipient's REAL G-address is the
 * event's recipient topic, so this scanner filters straight to events addressed to us,
 * ECDH-opens the note, VERIFIES the recovered opening against the on-chain commitment,
 * and hands the caller a spendable opening. There is NO sweep step: the recipient IS
 * their own account, so adopting the opening makes the confidential balance spendable
 * directly (spending is auth-gated by the account's own Stellar key).
 *
 * The decryption key is derived locally from the wallet seed and never leaves the device.
 */

import { rpc, Address, nativeToScVal, scValToNative, Keypair } from '@stellar/stellar-sdk';
import { openConfNote } from './confidential-note';
import { commit } from './confidential-commit';
import { bytes32ToDecimal } from './confidential-pool';

export interface ConfidentialHit {
  /** The received amount in stroops (decimal) — recovered from the sealed note. */
  amount: string;
  /** The recipient's new-commitment blinding (decimal), re-derived via ECDH. */
  blinding: string;
  /** The recipient's new on-chain commitment (c_recipient_new) this opening reopens. */
  commitment: string;
  /** Ledger the conf_xfer event was emitted in — lets the caller re-scan from here. */
  ledger?: number;
}

export interface ScanConfidentialParams {
  walletSecret: string;    // S… secret — Ed25519 seed → X25519 decryption key, locally
  address: string;         // the recipient G-address (event recipient topic filter)
  poolContractId: string;  // confidential pool contract
  rpcUrl: string;
  fromLedger: number;      // cursor; scan forward
}

const EVENT_PAGE_LIMIT = 200;
const MAX_EVENT_PAGES = 100;

/**
 * Open + verify a single conf_xfer event for this wallet. Pure (no I/O) so it is
 * unit-testable against a synthetic event.
 * `data` = [c_sender_new(32B), c_recipient_new(32B), ephemeral(32B), note(Bytes)].
 * Returns the hit only when the note decrypts AND the recovered opening reopens the
 * on-chain recipient commitment.
 */
export async function openConfidentialHit(
  data: unknown,
  ledger: number | undefined,
  recipientSeed: Uint8Array,
): Promise<ConfidentialHit | null> {
  if (!Array.isArray(data) || data.length < 4) return null;
  const toBytes = (v: unknown): Uint8Array | null =>
    v instanceof Uint8Array ? new Uint8Array(v) : (Buffer.isBuffer(v) ? new Uint8Array(v) : null);

  const cRecipientNew = toBytes(data[1]);
  const ephemeralPublic = toBytes(data[2]);
  const note = toBytes(data[3]);
  if (!cRecipientNew || cRecipientNew.length !== 32) return null;
  if (!ephemeralPublic || ephemeralPublic.length !== 32) return null;
  if (!note || note.length === 0) return null;

  const opened = await openConfNote({ recipientSeed, ephemeralPublic, note });
  if (!opened) return null;

  // Ownership: the recovered (amount, blinding) MUST reopen the on-chain c_recipient_new.
  const commitment = bytes32ToDecimal(cRecipientNew);
  const recomputed = await commit({ amount: opened.amount, blinding: opened.blinding });
  if (recomputed !== commitment) return null;

  return { amount: opened.amount, blinding: opened.blinding, commitment, ledger };
}

/** Scan the confidential pool's `conf_xfer` events addressed to `address` for openings this wallet can adopt. */
export async function scanConfidentialTransfersForMe(p: ScanConfidentialParams): Promise<ConfidentialHit[]> {
  const recipientSeed = Keypair.fromSecret(p.walletSecret).rawSecretKey(); // Ed25519 seed → X25519 decrypt key (local)
  const server = new rpc.Server(p.rpcUrl);

  const confXferTopic = nativeToScVal('conf_xfer', { type: 'symbol' }).toXDR('base64');
  const myAddrTopic = Address.fromString(p.address).toScVal().toXDR('base64');
  // topics = [conf_xfer, sender, recipient] → filter recipient==me (strict).
  const filters: rpc.Api.EventFilter[] = [
    { type: 'contract', contractIds: [p.poolContractId], topics: [[confXferTopic, '*', myAddrTopic]] },
  ];

  const hits: ConfidentialHit[] = [];
  let page = await getFirstEventsPageClamped(server, filters, p.fromLedger);

  for (let pageNum = 0; pageNum < MAX_EVENT_PAGES; pageNum++) {
    for (const ev of page.events) {
      let data: unknown;
      try { data = scValToNative(ev.value); } catch { continue; }
      const hit = await openConfidentialHit(data, ev.ledger, recipientSeed);
      if (hit) hits.push(hit);
    }
    if (page.events.length === 0 || !page.cursor || pageNum + 1 >= MAX_EVENT_PAGES) break;
    page = await server.getEvents({ filters, cursor: page.cursor, limit: EVENT_PAGE_LIMIT });
  }
  return hits;
}

/** First events page in ledger-range mode, clamped to the RPC retention floor. */
async function getFirstEventsPageClamped(
  server: rpc.Server,
  filters: rpc.Api.EventFilter[],
  fromLedger: number,
): Promise<rpc.Api.GetEventsResponse> {
  try {
    return await server.getEvents({ startLedger: fromLedger, filters, limit: EVENT_PAGE_LIMIT });
  } catch (err) {
    const oldest = await oldestRetainedLedger(server, filters);
    if (oldest != null && fromLedger < oldest) {
      return await server.getEvents({ startLedger: oldest, filters, limit: EVENT_PAGE_LIMIT });
    }
    throw err;
  }
}

async function oldestRetainedLedger(
  server: rpc.Server,
  filters: rpc.Api.EventFilter[],
): Promise<number | null> {
  try {
    const latest = (await server.getLatestLedger()).sequence;
    const tip = await server.getEvents({ startLedger: latest, filters, limit: 1 });
    return tip.oldestLedger;
  } catch { return null; }
}
