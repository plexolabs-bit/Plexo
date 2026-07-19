// StellarHub ZK reference · https://stellarhub.io
/**
 * ZK-Proofs HTTP client (reference implementation).
 *
 * Mirrors the Pydantic models exposed by the backend ZK service (see project docs).
 * No UI is wired here — this module is the client-side ZK helper layer only.
 */

export type ProofType = 'groth16' | 'plonk' | 'stark';

export interface Proof {
  proof_type: ProofType;
  proof_bytes: string;            // base64-encoded snarkjs proof JSON {pi_a, pi_b, pi_c}
  public_inputs: string[];        // decimal field elements as STRINGS (254-bit overflows JS number)
  verification_key_id: string;
  circuit_id?: string | null;
}

/** snarkjs Groth16 proof shape (decoded from `Proof.proof_bytes`). */
export interface SnarkProofJson {
  pi_a: [string, string, string];
  pi_b: [[string, string], [string, string], [string, string]];
  pi_c: [string, string, string];
  protocol?: string;
  curve?: string;
}

export interface GenerateProofRequest {
  circuit_id: string;
  proof_type?: ProofType;
  inputs: Record<string, unknown>;
  verification_key_id?: string | null;
}

export interface GenerateProofResponse {
  proof: Proof;
  /** Decimal public signals [commitment, nullifier] as strings (Model C). */
  public_signals?: string[];
  /** Deployed zk-verified-payment contract id the client invokes. */
  contract_id?: string | null;
}

export interface VerifyProofResponse {
  valid: boolean;
  verification_key_id: string;
}

export interface SubmitProofResponse {
  tx_hash: string;
  contract_id: string;
  network: string;
}

export interface ZkClientOptions {
  /** Base URL for the FastAPI service (defaults to same-origin `/api/v1/v1`). */
  baseUrl?: string;
  /** Optional `X-API-Key` header. */
  apiKey?: string;
  /** Pluggable fetch (for SSR/tests). */
  fetchImpl?: typeof fetch;
}

function resolveBaseUrl(opts?: ZkClientOptions): string {
  if (opts?.baseUrl) return opts.baseUrl.replace(/\/+$/, '');
  // ZK endpoints are proxied by Express at `/api/v1/zk/*` → FastAPI :3002.
  // (Was `/api/v1/v1` — a double-v1 typo that 404'd through the proxy chain so
  // the privacy-eye toggle never reached the prover.)
  return '/api/v1';
}

async function postJson<T>(
  path: string,
  body: unknown,
  opts?: ZkClientOptions,
): Promise<T> {
  const fetchImpl = opts?.fetchImpl ?? fetch;
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (opts?.apiKey) headers['X-API-Key'] = opts.apiKey;

  const res = await fetchImpl(`${resolveBaseUrl(opts)}${path}`, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`ZK ${path} failed: ${res.status} ${text}`);
  }
  return (await res.json()) as T;
}

export async function generateProof(
  circuitId: string,
  inputs: Record<string, unknown>,
  opts?: ZkClientOptions & { proofType?: ProofType; verificationKeyId?: string },
): Promise<Proof> {
  const body: GenerateProofRequest = {
    circuit_id: circuitId,
    inputs,
    proof_type: opts?.proofType ?? 'groth16',
    verification_key_id: opts?.verificationKeyId ?? null,
  };
  const out = await postJson<GenerateProofResponse>('/zk/generate', body, opts);
  return out.proof;
}

export async function verifyProof(
  proof: Proof,
  verificationKeyId: string,
  opts?: ZkClientOptions,
): Promise<boolean> {
  const out = await postJson<VerifyProofResponse>(
    '/zk/verify',
    { proof, verification_key_id: verificationKeyId },
    opts,
  );
  return out.valid;
}

export async function submitProof(
  proof: Proof,
  contractId: string,
  network: 'testnet' | 'public' | 'futurenet' | 'standalone' = 'testnet',
  opts?: ZkClientOptions,
): Promise<SubmitProofResponse> {
  return postJson<SubmitProofResponse>(
    '/zk/submit',
    { proof, contract_id: contractId, network },
    opts,
  );
}

// ---------------------------------------------------------------------------
// Model C — confidential send helpers (hide the amount)
//
// These wrap the generic `generate` / `submit` calls with the confidential-payment
// semantics the send controller needs: the amount is a PRIVATE witness bound into
// the commitment; sender + recipient stay visible on the ledger. The user signs the
// envelope locally (non-custodial — signing keys never leave the client).
// ---------------------------------------------------------------------------

export interface PreparePrivatePaymentInput {
  /** Transfer amount in stroops (decimal string). */
  amountStroops: string;
  /** Stellar public key of the recipient (56-char G...). */
  recipient: string;
}

export interface PrivatePaymentReady {
  /** Decoded snarkjs proof, ready for BLS encoding by soroban-invoke. */
  snarkProof: SnarkProofJson;
  /** Public signals [commitment, nullifier] as decimal strings. */
  publicSignals: string[];
  /** Deployed zk-verified-payment contract id to invoke. */
  contractId: string;
}

function randomFieldDecimal(): string {
  // 31 bytes (248 bits) stays below the BLS12-381 scalar field order.
  const buf = new Uint8Array(31);
  if (typeof crypto !== 'undefined' && 'getRandomValues' in crypto) {
    crypto.getRandomValues(buf);
  }
  const hex = Array.from(buf).map((b) => b.toString(16).padStart(2, '0')).join('');
  return BigInt('0x' + (hex || '01')).toString();
}

async function recipientToField(recipient: string): Promise<string> {
  // Bind the recipient into the commitment as a field element derived from the
  // ed25519 public key bytes (31 bytes → below field order).
  const { StrKey } = await import('@stellar/stellar-sdk');
  const raw = StrKey.decodeEd25519PublicKey(recipient);
  const hex = Buffer.from(raw.subarray(0, 31)).toString('hex');
  return BigInt('0x' + hex).toString();
}

/**
 * Build the private witness, ask the backend to prove it (snarkjs Groth16), and
 * return the decoded proof + public signals + the contract to invoke. The proof's
 * public outputs are [commitment, nullifier]; a fresh per-send serial makes the
 * nullifier unique (one proof → at most one payment).
 *
 * Returns 501-typed errors if the prover is not provisioned (E3 graceful fallback).
 */
export async function generatePrivatePaymentProof(
  input: PreparePrivatePaymentInput,
  opts?: ZkClientOptions,
): Promise<PrivatePaymentReady> {
  const body: GenerateProofRequest = {
    circuit_id: 'private_transfer',
    proof_type: 'groth16',
    inputs: {
      amount: input.amountStroops,
      blinding: randomFieldDecimal(),
      recipient: await recipientToField(input.recipient),
      senderSecret: randomFieldDecimal(),
      serial: randomFieldDecimal(),
    },
  };
  const out = await postJson<GenerateProofResponse>('/zk/generate', body, opts);

  const snarkProof = JSON.parse(
    typeof atob === 'function'
      ? atob(out.proof.proof_bytes)
      : Buffer.from(out.proof.proof_bytes, 'base64').toString('utf8'),
  ) as SnarkProofJson;

  return {
    snarkProof,
    publicSignals: out.public_signals ?? out.proof.public_inputs,
    contractId: out.contract_id ?? '',
  };
}

/**
 * Submit a signed ZK payment to the verifier. Mirrors `/zk/submit` but pairs
 * the signed XDR with the originating proof so the backend can stitch them
 * before Soroban invocation.
 */
export async function submitPrivatePayment(
  proof: Proof,
  contractId: string,
  signedXdr: string,
  network: 'testnet' | 'public' | 'futurenet' | 'standalone' = 'testnet',
  opts?: ZkClientOptions,
): Promise<SubmitProofResponse & { signed_xdr_accepted?: boolean }> {
  return postJson<SubmitProofResponse & { signed_xdr_accepted?: boolean }>(
    '/zk/submit',
    {
      proof,
      contract_id: contractId,
      network,
      signed_xdr: signedXdr,
      stellar_network: network,
    },
    opts,
  );
}

// ---------------------------------------------------------------------------
// Verifiable Credentials (credentials.circom) helpers — Stellar Hacks: Real-World
// ZK. Prove a private attribute satisfies a verifier-chosen predicate WITHOUT
// revealing it. The circuit's public outputs are [issuerCommitment, nullifier];
// the public input `mode` picks the predicate (0 = equality, 1 = threshold). The
// presenter learns the holder satisfies the policy, never the underlying value.
//
// Honest-stub status: routes through the `/zk/credentials` proxy (→ FastAPI
// `/zk/generate` with circuit_id="credentials"). Until the credentials circuit is
// compiled + a dev zkey produced (see project docs), the backend returns 501
// (E3 graceful fallback) and this helper surfaces that to the UI.
// ---------------------------------------------------------------------------

export type CredentialPredicateMode = 'equality' | 'threshold';

export interface ProveCredentialInput {
  /** The private credential value (e.g. age, or a KYC=1 flag). Never sent raw to
   *  the chain — only the proof + commitment + nullifier are public. */
  attribute: string;
  /** Holder binding secret (hiding + nullifier seed). Decimal field element. */
  secret: string;
  /** Issuer-assigned credential id (unique → nullifier is single-use). */
  credentialId: string;
  /** Which predicate to prove. */
  mode: CredentialPredicateMode;
  /** Equality target (used when mode === 'equality'), decimal string. */
  expectedValue?: string;
  /** Threshold floor (used when mode === 'threshold'), decimal string. */
  minValue?: string;
}

export interface CredentialProofReady {
  /** Decoded snarkjs proof, ready for BLS encoding by the Soroban verifier. */
  snarkProof: SnarkProofJson;
  /** Public signals [mode, expectedValue, minValue, issuerCommitment, nullifier]. */
  publicSignals: string[];
  /** Convenience: the issuerCommitment public output (Poseidon(attribute, secret)). */
  issuerCommitment: string;
  /** Convenience: the nullifier public output (Poseidon(secret, credentialId)). */
  nullifier: string;
  /** Deployed verifier contract id (generic Groth16 verifier + credentials vk). */
  contractId: string;
}

/**
 * Build the credential witness, ask the backend to prove it (snarkjs Groth16 over
 * circuit_id="credentials"), and return the decoded proof + public signals.
 *
 * The witness `attribute` stays private; a verified proof is itself the
 * attestation that the predicate held. Returns 501-typed errors when the
 * credentials circuit is not yet provisioned (E3 graceful fallback — same
 * contract as `generatePrivatePaymentProof` / `generateReservesProof`).
 */
export async function proveCredential(
  input: ProveCredentialInput,
  opts?: ZkClientOptions,
): Promise<CredentialProofReady> {
  const body: GenerateProofRequest = {
    circuit_id: 'credentials',
    proof_type: 'groth16',
    inputs: {
      attribute: input.attribute,
      secret: input.secret,
      credentialId: input.credentialId,
      // mode is a PUBLIC input: 0 = equality, 1 = threshold.
      mode: input.mode === 'threshold' ? '1' : '0',
      // The inactive branch's bound is still a public input, so default it to 0
      // to complete the witness; the predicate constraint ignores the unused arm.
      expectedValue: input.expectedValue ?? '0',
      minValue: input.minValue ?? '0',
    },
  };
  // Dedicated `/zk/credentials` convenience proxy → FastAPI `/zk/generate`. (The
  // generic `/zk/generate` works too; the named route is self-documenting.)
  const out = await postJson<GenerateProofResponse>('/zk/credentials', body, opts);

  const snarkProof = JSON.parse(
    typeof atob === 'function'
      ? atob(out.proof.proof_bytes)
      : Buffer.from(out.proof.proof_bytes, 'base64').toString('utf8'),
  ) as SnarkProofJson;

  const publicSignals = out.public_signals ?? out.proof.public_inputs;
  return {
    snarkProof,
    publicSignals,
    // Circuit declares public inputs (mode, expectedValue, minValue) before the
    // outputs (issuerCommitment, nullifier); snarkjs orders inputs then outputs.
    issuerCommitment: publicSignals[3] ?? '',
    nullifier: publicSignals[4] ?? '',
    contractId: out.contract_id ?? '',
  };
}

// ---------------------------------------------------------------------------
// Proof of Reserves helpers (Stellar Hacks: Real-World ZK)
//
// Wrap the generic `/zk/proof-of-reserves` route with the solvency semantics the
// privacy-eye "Prove I hold >= X" control needs. The circuit
// (`proof_of_reserves.circom`) proves `balance >= threshold` and emits
// `commitment = Poseidon(balance, blinding)` as a public output; `threshold` is
// the only public input the verifier learns. The balance stays private.
// ---------------------------------------------------------------------------

export interface PrepareReservesInput {
  /** The wallet's balance in stroops (decimal string). Stays PRIVATE. */
  balanceStroops: string;
  /** The solvency floor to attest, in stroops (decimal string). PUBLIC. */
  thresholdStroops: string;
}

export interface ReservesProofReady {
  /** Decoded snarkjs proof for the proof-of-reserves circuit. */
  snarkProof: SnarkProofJson;
  /** Public signals from the circuit: [commitment, threshold] (declaration order). */
  publicSignals: string[];
  /** Convenience: the commitment public signal (Poseidon(balance, blinding)). */
  commitment: string;
  /** Convenience: the threshold public input echoed back. */
  threshold: string;
}

function randomBlindingDecimal(): string {
  // 31 bytes (248 bits) stays below the BLS12-381 scalar field order — same
  // hiding-randomness convention as `randomFieldDecimal` above.
  const buf = new Uint8Array(31);
  if (typeof crypto !== 'undefined' && 'getRandomValues' in crypto) {
    crypto.getRandomValues(buf);
  }
  const hex = Array.from(buf).map((b) => b.toString(16).padStart(2, '0')).join('');
  return BigInt('0x' + (hex || '01')).toString();
}

/**
 * Build the proof-of-reserves witness, ask the backend to prove it (snarkjs
 * Groth16), and return the decoded proof + public signals. The circuit's public
 * outputs are [commitment, threshold]; `balance` + `blinding` are the private
 * witness and never appear in the returned signals.
 *
 * Returns 501-typed errors if the prover is not provisioned (E3 graceful
 * fallback) — the caller (`proof-of-reserves.ts`) maps those to a typed domain
 * error so the UI degrades honestly rather than faking a proof.
 */
export async function generateReservesProof(
  input: PrepareReservesInput,
  opts?: ZkClientOptions,
): Promise<ReservesProofReady> {
  const body: GenerateProofRequest = {
    circuit_id: 'proof_of_reserves',
    proof_type: 'groth16',
    inputs: {
      balance: input.balanceStroops,
      blinding: randomBlindingDecimal(),
      threshold: input.thresholdStroops,
    },
  };
  const out = await postJson<GenerateProofResponse>('/zk/proof-of-reserves', body, opts);

  const snarkProof = JSON.parse(
    typeof atob === 'function'
      ? atob(out.proof.proof_bytes)
      : Buffer.from(out.proof.proof_bytes, 'base64').toString('utf8'),
  ) as SnarkProofJson;

  const publicSignals = out.public_signals ?? out.proof.public_inputs;
  return {
    snarkProof,
    publicSignals,
    // Circuit declares `commitment` (output) before `threshold` (input); snarkjs
    // orders outputs ahead of public inputs in publicSignals.
    commitment: publicSignals[0] ?? '',
    threshold: publicSignals[1] ?? input.thresholdStroops,
  };
}
