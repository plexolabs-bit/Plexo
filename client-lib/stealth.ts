// StellarHub ZK reference · https://stellarhub.io
import nacl from 'tweetnacl';
import { Keypair, StrKey } from '@stellar/stellar-sdk';
import { getSodium } from './sodium';

export interface StealthKeyPair {
  scanKey: Uint8Array;
  spendKey: Uint8Array;
  scanPublic: Uint8Array;
  spendPublic: Uint8Array;
}

export interface StealthMeta {
  stealthAddress: string;
  ephemeralPublic: Uint8Array;
  viewTag: number;
}

export interface StealthPayment {
  stealthAddress: string;
  ephemeralPublic: string;
  viewTag: number;
}

const STEALTH_DOMAIN = 'StellarHub:Stealth:v1';

export function generateStealthKeys(): StealthKeyPair {
  const scan = nacl.box.keyPair();
  const spend = nacl.sign.keyPair();

  return {
    scanKey: scan.secretKey,
    spendKey: spend.secretKey,
    scanPublic: scan.publicKey,
    spendPublic: spend.publicKey,
  };
}

export function generateEphemeralKeyPair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  return nacl.box.keyPair();
}

export async function deriveSharedSecret(
  privateKey: Uint8Array,
  publicKey: Uint8Array
): Promise<Uint8Array> {
  const sodium = await getSodium();

  const sharedPoint = nacl.scalarMult(privateKey, publicKey);
  const domainBytes = new TextEncoder().encode(STEALTH_DOMAIN);
  const combined = new Uint8Array(domainBytes.length + sharedPoint.length);
  combined.set(domainBytes);
  combined.set(sharedPoint, domainBytes.length);

  return sodium.crypto_generichash(32, combined, null);
}

function viewTagFromSecret(sharedSecret: Uint8Array): number {
  return sharedSecret[0];
}

export async function deriveStealthAddress(
  scanPublic: Uint8Array,
  spendPublic: Uint8Array,
  ephemeralPrivate: Uint8Array
): Promise<StealthMeta> {
  const sharedSecret = await deriveSharedSecret(ephemeralPrivate, scanPublic);
  const viewTag = viewTagFromSecret(sharedSecret);
  const stealthPrivateSeed = nacl.hash(
    Uint8Array.from([...sharedSecret, ...spendPublic])
  ).slice(0, 32);

  const stealthKeypair = Keypair.fromRawEd25519Seed(Buffer.from(stealthPrivateSeed));

  const ephemeralKeyPair = nacl.box.keyPair.fromSecretKey(
    ephemeralPrivate.slice(0, 32)
  );

  return {
    stealthAddress: stealthKeypair.publicKey(),
    ephemeralPublic: ephemeralKeyPair.publicKey,
    viewTag,
  };
}

export async function recoverStealthPrivateKey(
  scanKey: Uint8Array,
  spendKey: Uint8Array,
  ephemeralPublic: Uint8Array
): Promise<Keypair> {
  const sharedSecret = await deriveSharedSecret(scanKey, ephemeralPublic);

  const spendPublic = nacl.sign.keyPair.fromSecretKey(spendKey).publicKey;
  const stealthPrivateSeed = nacl.hash(
    Uint8Array.from([...sharedSecret, ...spendPublic])
  ).slice(0, 32);

  return Keypair.fromRawEd25519Seed(Buffer.from(stealthPrivateSeed));
}

export async function canSpend(
  stealthAddress: string,
  scanKey: Uint8Array,
  spendKey: Uint8Array,
  ephemeralPublic: Uint8Array
): Promise<boolean> {
  try {
    const recoveredKeypair = await recoverStealthPrivateKey(
      scanKey,
      spendKey,
      ephemeralPublic
    );

    return recoveredKeypair.publicKey() === stealthAddress;
  } catch {
    return false;
  }
}

export async function checkViewTag(
  scanKey: Uint8Array,
  ephemeralPublic: Uint8Array,
  expectedViewTag: number
): Promise<boolean> {
  const sharedSecret = await deriveSharedSecret(scanKey, ephemeralPublic);
  const viewTag = viewTagFromSecret(sharedSecret);
  return viewTag === expectedViewTag;
}

export async function scanPayments(
  payments: StealthPayment[],
  scanKey: Uint8Array,
  spendKey: Uint8Array
): Promise<Array<{ payment: StealthPayment; keypair: Keypair }>> {
  const results: Array<{ payment: StealthPayment; keypair: Keypair }> = [];

  for (const payment of payments) {
    const ephemeralPublic = decodeEphemeralPublic(payment.ephemeralPublic);
    const viewTagMatch = await checkViewTag(scanKey, ephemeralPublic, payment.viewTag);

    if (!viewTagMatch) {
      continue;
    }

    const isOurs = await canSpend(
      payment.stealthAddress,
      scanKey,
      spendKey,
      ephemeralPublic
    );

    if (isOurs) {
      const keypair = await recoverStealthPrivateKey(scanKey, spendKey, ephemeralPublic);
      results.push({ payment, keypair });
    }
  }

  return results;
}

export function encodeStealthMeta(meta: StealthMeta): {
  stealthAddress: string;
  ephemeralPublic: string;
  viewTag: number;
} {
  return {
    stealthAddress: meta.stealthAddress,
    ephemeralPublic: Buffer.from(meta.ephemeralPublic).toString('base64'),
    viewTag: meta.viewTag,
  };
}

export function decodeEphemeralPublic(encoded: string): Uint8Array {
  return new Uint8Array(Buffer.from(encoded, 'base64'));
}

export function serializeStealthKeys(keys: StealthKeyPair): {
  scanKey: string;
  spendKey: string;
  scanPublic: string;
  spendPublic: string;
} {
  return {
    scanKey: Buffer.from(keys.scanKey).toString('base64'),
    spendKey: Buffer.from(keys.spendKey).toString('base64'),
    scanPublic: Buffer.from(keys.scanPublic).toString('base64'),
    spendPublic: Buffer.from(keys.spendPublic).toString('base64'),
  };
}

export function deserializeStealthKeys(serialized: {
  scanKey: string;
  spendKey: string;
  scanPublic: string;
  spendPublic: string;
}): StealthKeyPair {
  return {
    scanKey: new Uint8Array(Buffer.from(serialized.scanKey, 'base64')),
    spendKey: new Uint8Array(Buffer.from(serialized.spendKey, 'base64')),
    scanPublic: new Uint8Array(Buffer.from(serialized.scanPublic, 'base64')),
    spendPublic: new Uint8Array(Buffer.from(serialized.spendPublic, 'base64')),
  };
}

export function getStealthMetaAddress(scanPublic: Uint8Array, spendPublic: Uint8Array): string {
  const combined = new Uint8Array(scanPublic.length + spendPublic.length);
  combined.set(scanPublic);
  combined.set(spendPublic, scanPublic.length);

  const hash = nacl.hash(combined).slice(0, 32);
  return StrKey.encodeEd25519PublicKey(Buffer.from(hash));
}
