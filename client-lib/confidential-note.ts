// StellarHub ZK reference · https://stellarhub.io
/**
 * confidential-note.ts — sealed note delivery for the confidential-amount transfer.
 *
 * The confidential pool hides the AMOUNT (a Poseidon commitment, never a tx arg / event
 * field). For a CROSS-PERSON send the recipient must be able to reopen their new
 * commitment, so the sender delivers an encrypted note carrying the amount; the blinding
 * is re-derived by BOTH sides via ECDH (never transmitted). Mirrors the stealth delivery
 * pattern (X25519 keys, ephemeral pubkey echoed on-chain — see `stealth.ts`) but is a
 * PLAIN sealed note — NOT DKSAP.
 *
 * WHY no DKSAP here (unlike stealth): the delivered opening is witness-privacy bookkeeping,
 * NOT spend authority. Spending is gated by the account's ordinary Stellar signature
 * (`confidential_transfer` → `sender.require_auth`, `withdraw` → `to.require_auth`), which
 * is orthogonal to opening-knowledge. A sender who knows the recipient's opening can only
 * ever GIFT the recipient more (the recipient leg is additive, t ≥ 0) — never debit or
 * withdraw the recipient's balance. So it is harmless that the sender can derive the
 * recipient's blinding; the note only hides the amount from THIRD parties.
 */

import nacl from 'tweetnacl';
import { StrKey } from '@stellar/stellar-sdk';
import { getSodium } from './sodium';

/** Domain separation for the confidential-note ECDH (distinct from the stealth domain). */
const CONF_NOTE_DOMAIN = 'StellarHub:ConfNote:v1';
const CONF_BLIND_DOMAIN = 'StellarHub:ConfNote:blind:v1';
const CONF_ENC_DOMAIN = 'StellarHub:ConfNote:enc:v1';
const CONF_NONCE_DOMAIN = 'StellarHub:ConfNote:nonce:v1';

/**
 * BLS12-381 scalar field order r. Confidential blindings are BLS12-381 field elements —
 * do NOT reuse an ed25519-L reduction here (proof-breaking field-order bug).
 */
const BLS12_381_R =
  52435875175126190479447740508185965837690552500527637822603658699938581184513n;

/** Amount is carried as an 8-byte big-endian u64 (Stellar stroops fit i64). */
const AMOUNT_BYTES = 8;

export interface SealedConfNote {
  /** Sender's fresh X25519 ephemeral public key (goes into the conf_xfer event). */
  ephemeralPublic: Uint8Array;
  /** The recipient's new-commitment blinding (decimal) — both sides derive it via ECDH. */
  blinding: string;
  /** viewTag(1B) ‖ secretbox(amount_u64_BE) — the opaque note echoed by the contract. */
  note: Uint8Array;
}

export interface OpenedConfNote {
  /** The transferred amount in stroops (decimal). */
  amount: string;
  /** The recipient's new-commitment blinding (decimal), re-derived via ECDH. */
  blinding: string;
}

function domainBytes(domain: string, data: Uint8Array): Uint8Array {
  const d = new TextEncoder().encode(domain);
  const out = new Uint8Array(d.length + data.length);
  out.set(d);
  out.set(data, d.length);
  return out;
}

function beToDecimal(bytes: Uint8Array): string {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return n.toString();
}

function amountToU64Be(amount: string): Uint8Array {
  let n = BigInt(amount);
  if (n < 0n) throw new Error('confidential-note: amount must be non-negative');
  if (n >> 64n) throw new Error('confidential-note: amount exceeds u64');
  const out = new Uint8Array(AMOUNT_BYTES);
  for (let i = AMOUNT_BYTES - 1; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

/**
 * ECDH shared secret over X25519, domain-separated for confidential notes.
 * Symmetric: `derive(eph_priv, recipient_pub) === derive(recipient_secret, eph_pub)`.
 */
export async function deriveConfNoteSecret(
  privateKey: Uint8Array,
  publicKey: Uint8Array,
): Promise<Uint8Array> {
  const sodium = await getSodium();
  const sharedPoint = nacl.scalarMult(privateKey, publicKey);
  return sodium.crypto_generichash(32, domainBytes(CONF_NOTE_DOMAIN, sharedPoint), null);
}

/**
 * Derive the recipient's new-commitment blinding from the ECDH secret. 31-byte truncation
 * (248 bits) is unconditionally < r, so it is a valid BLS12-381 field element with no
 * modulo bias — same convention as `randomFieldDecimal` in confidential-commit.ts.
 */
export async function deriveBlindingBls(shared: Uint8Array): Promise<string> {
  const sodium = await getSodium();
  const h = sodium.crypto_generichash(31, domainBytes(CONF_BLIND_DOMAIN, shared), null);
  const blinding = beToDecimal(h);
  // Belt-and-suspenders: a 31-byte value is always < r, but assert the invariant.
  if (BigInt(blinding) >= BLS12_381_R) throw new Error('confidential-note: blinding out of field');
  return blinding;
}

async function noteKey(shared: Uint8Array): Promise<Uint8Array> {
  const sodium = await getSodium();
  return sodium.crypto_generichash(nacl.secretbox.keyLength, domainBytes(CONF_ENC_DOMAIN, shared), null);
}

async function noteNonce(ephemeralPublic: Uint8Array): Promise<Uint8Array> {
  const sodium = await getSodium();
  // Deterministic from the (unique per tx) ephemeral pubkey → both sides recompute it,
  // so it never rides the note. Fresh ephemeral per send ⇒ fresh nonce.
  return sodium.crypto_generichash(nacl.secretbox.nonceLength, domainBytes(CONF_NONCE_DOMAIN, ephemeralPublic), null);
}

/**
 * Derive the recipient's X25519 ENCRYPTION public key from their Stellar G-address ALONE
 * (Ed25519 → Curve25519 birational map, libsodium `pk_to_curve25519`). This is why a
 * confidential send needs ONLY the recipient's normal address — no separate receive code:
 * the sender encrypts the amount to the key derived from the address, and the recipient
 * decrypts with the matching key derived from their own seed.
 */
async function recipientEncryptionPub(gAddress: string): Promise<Uint8Array> {
  const sodium = await getSodium();
  const edPub = new Uint8Array(StrKey.decodeEd25519PublicKey(gAddress)); // normalize Buffer → Uint8Array
  return sodium.crypto_sign_ed25519_pk_to_curve25519(edPub);
}

/** The wallet's own X25519 decryption secret, from its 32-byte Ed25519 seed (the S… key). */
async function ownEncryptionSecret(ed25519Seed: Uint8Array): Promise<Uint8Array> {
  const sodium = await getSodium();
  const kp = sodium.crypto_sign_seed_keypair(new Uint8Array(ed25519Seed));
  return sodium.crypto_sign_ed25519_sk_to_curve25519(new Uint8Array(kp.privateKey));
}

/** Sender: seal an amount note addressed to a recipient's plain Stellar G-address. */
export async function sealConfNote(params: {
  recipientGAddress: string;
  amount: string;
}): Promise<SealedConfNote> {
  const eph = nacl.box.keyPair();
  const shared = await deriveConfNoteSecret(eph.secretKey, await recipientEncryptionPub(params.recipientGAddress));
  const blinding = await deriveBlindingBls(shared);
  const ciphertext = nacl.secretbox(
    amountToU64Be(params.amount),
    await noteNonce(eph.publicKey),
    await noteKey(shared),
  );
  const note = new Uint8Array(1 + ciphertext.length);
  note[0] = shared[0]; // view tag — cheap reject before secretbox.open
  note.set(ciphertext, 1);
  return { ephemeralPublic: eph.publicKey, blinding, note };
}

/**
 * Recipient: open a note from a conf_xfer event using the wallet's own Ed25519 seed
 * (converted to its X25519 decryption secret). Returns null for a note not addressed to
 * this wallet or a tampered ciphertext.
 */
export async function openConfNote(params: {
  recipientSeed: Uint8Array;
  ephemeralPublic: Uint8Array;
  note: Uint8Array;
}): Promise<OpenedConfNote | null> {
  if (params.note.length < 1 + nacl.secretbox.overheadLength + AMOUNT_BYTES) return null;
  const shared = await deriveConfNoteSecret(await ownEncryptionSecret(params.recipientSeed), params.ephemeralPublic);
  if (params.note[0] !== shared[0]) return null; // view-tag fast reject
  const plaintext = nacl.secretbox.open(
    params.note.slice(1),
    await noteNonce(params.ephemeralPublic),
    await noteKey(shared),
  );
  if (!plaintext || plaintext.length !== AMOUNT_BYTES) return null;
  const amount = beToDecimal(plaintext);
  const blinding = await deriveBlindingBls(shared);
  return { amount, blinding };
}
