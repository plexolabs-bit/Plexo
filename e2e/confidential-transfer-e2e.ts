// StellarHub ZK reference · https://stellarhub.io
/**
 * LIVE testnet e2e for the confidential-amount transfer (self-contained, repeatable).
 *
 *   npx tsx e2e/confidential-transfer-e2e.ts
 *
 * Proves, against the DEPLOYED pool contract (CC6LDUHV… — see
 * client-lib/confidential-pool.ts), that:
 *   1. a fresh Friendbot-funded sender A joins the pool (boundary deposit, amount
 *      VISIBLE — that is the honest boundary);
 *   2. A confidentially credits an UNREGISTERED recipient B, knowing ONLY B's plain
 *      Stellar G-address (the C0 fold-in creates B's slot in the same signed tx);
 *   3. the transfer amount is NEVER a cleartext argument — it rides only as Poseidon
 *      commitments + a sealed (encrypted) note;
 *   4. B's scanner recovers the exact hidden amount from the sealed note with nothing
 *      but B's own secret key, and the recovered opening reopens the on-chain
 *      commitment.
 *
 * Everything is generated fresh at run time: real Friendbot funding, a real snarkjs
 * Groth16/BLS12-381 proof (committed artefacts in build/), a real Soroban submit.
 * NO baked-in accounts or secrets. Prints the tx hash + a stellar.expert link so the
 * run is independently checkable.
 */

import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { Keypair, Networks, rpc as sorobanRpc, TransactionBuilder } from '@stellar/stellar-sdk';
import * as snarkjs from 'snarkjs';

import { sealConfNote } from '../client-lib/confidential-note';
import {
  buildConfidentialTransferInput,
  commit,
  randomFieldDecimal,
} from '../client-lib/confidential-commit';
import {
  DEFAULT_CONFIDENTIAL_CONTRACT_ID,
  TESTNET_SOROBAN_RPC_URL,
  commitmentToBytes32,
  simulateGetCommitment,
  submitConfidentialDepositOnchain,
  submitConfidentialTransferOnchain,
  type SnarkProofCoords,
} from '../client-lib/confidential-pool';
import { scanConfidentialTransfersForMe } from '../client-lib/confidential-receive';

const __dirname = resolve(fileURLToPath(import.meta.url), '..');
const WASM = resolve(__dirname, '..', 'build', 'confidential_transfer.wasm');
const ZKEY = resolve(__dirname, '..', 'build', 'confidential_transfer_final.zkey');

const friendbot = async (addr: string) => {
  const r = await fetch(`https://friendbot.stellar.org?addr=${addr}`);
  if (!r.ok && r.status !== 400) throw new Error(`friendbot ${r.status}`);
};
const assert = (c: unknown, m: string) => {
  if (!c) { console.error('FAIL:', m); process.exit(1); }
  console.log('ok  ', m);
};

async function main() {
  const PASS = Networks.TESTNET;
  const rpcUrl = TESTNET_SOROBAN_RPC_URL;
  const contractId = DEFAULT_CONFIDENTIAL_CONTRACT_ID;
  console.log('contract:', contractId);

  // Fresh throwaway testnet accounts — nothing baked in.
  const A = Keypair.random();
  const B = Keypair.random();
  console.log('A', A.publicKey(), '\nB', B.publicKey());
  await Promise.all([friendbot(A.publicKey()), friendbot(B.publicKey())]);
  await new Promise((f) => setTimeout(f, 5000));

  const signA = async (xdr: string) => {
    const tx = TransactionBuilder.fromXDR(xdr, PASS);
    tx.sign(A);
    return { signedTxXdr: tx.toXDR() };
  };

  // 1) A joins the pool (boundary deposit, amount VISIBLE) with a known opening.
  const depositAmt = '50000000'; // 5 XLM in stroops
  const openingA = { amount: depositAmt, blinding: randomFieldDecimal() };
  const commitmentA = await commit(openingA);
  await submitConfidentialDepositOnchain({
    contractId, rpcUrl, networkPassphrase: PASS,
    from: A.publicKey(), amountStroops: BigInt(depositAmt),
    commitment: commitmentToBytes32(commitmentA), signTransaction: signA,
  });
  assert(
    (await simulateGetCommitment(rpcUrl, PASS, contractId, A.publicKey())) === commitmentA,
    'A registered in the pool',
  );
  assert(
    (await simulateGetCommitment(rpcUrl, PASS, contractId, B.publicKey())) === null,
    'B is UNREGISTERED (C0-fold-in target)',
  );

  // 2) CROSS-WALLET: A has ONLY B's plain Stellar G-address (a STRANGER's address). The
  //    sender derives B's X25519 encryption key FROM that address (Ed25519→Curve25519)
  //    and seals the amount note to it — NO receive code, NO B secret.
  const t = '12000000'; // 1.2 XLM — the HIDDEN amount
  const sealed = await sealConfNote({ recipientGAddress: B.publicKey(), amount: t });

  // 3) Prove conservation: recipient_old = the empty balance (0, 0) → C0 fold-in;
  //    recipient_new is note-bound to (t, sealed.blinding).
  const witness = {
    senderOld: openingA,
    senderNew: { amount: String(BigInt(depositAmt) - BigInt(t)), blinding: randomFieldDecimal() },
    recipientOld: { amount: '0', blinding: '0' },
    recipientNew: { amount: t, blinding: sealed.blinding },
    transferAmount: t,
  };
  const input = await buildConfidentialTransferInput(witness);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input as unknown as Record<string, unknown>,
    WASM,
    ZKEY,
  );
  console.log('proof built; c_recipient_new (pub[3]) =', publicSignals[3]);

  // 4) Submit the amount-hiding transfer to the UNREGISTERED recipient. The tx
  //    carries: 2 addresses + proof + 4 commitments + ephemeral + note. NO amount.
  const hash = await submitConfidentialTransferOnchain({
    contractId, rpcUrl, networkPassphrase: PASS,
    sender: A.publicKey(), recipient: B.publicKey(),
    proof: proof as unknown as SnarkProofCoords,
    publicSignals, ephemeralPublic: sealed.ephemeralPublic, note: sealed.note,
    signTransaction: signA,
  });
  assert(/^[0-9a-f]{64}$/i.test(hash), `confidential_transfer landed: ${hash}`);

  // 5) B is now registered on-chain at exactly recipient_new (C0 fold-in worked).
  const bOnchain = await simulateGetCommitment(rpcUrl, PASS, contractId, B.publicKey());
  assert(
    bOnchain === publicSignals[3],
    'B on-chain commitment == recipient_new (C0 fold-in created the slot)',
  );

  // 6) B's SCANNER recovers the exact amount from the sealed note — using nothing
  //    but B's own secret key.
  const server = new sorobanRpc.Server(rpcUrl);
  const latest = (await server.getLatestLedger()).sequence;
  const hits = await scanConfidentialTransfersForMe({
    walletSecret: B.secret(), address: B.publicKey(),
    poolContractId: contractId, rpcUrl, fromLedger: Math.max(latest - 300, 1),
  });
  const mine = hits.find((h) => h.commitment === bOnchain);
  assert(mine, 'B scanner found the credit');
  assert(mine!.amount === t, `B recovered the hidden amount (${t} stroops) from the note`);
  assert(
    (await commit({ amount: mine!.amount, blinding: mine!.blinding })) === bOnchain,
    'recovered opening reopens the on-chain commitment',
  );

  console.log(`\nE2E PASSED — tx ${hash}`);
  console.log(`https://stellar.expert/explorer/testnet/tx/${hash}`);
  process.exit(0); // snarkjs/ffjavascript keep worker threads alive — exit explicitly
}
main().catch((e) => { console.error('E2E ERROR:', e?.message || e); process.exit(1); });
