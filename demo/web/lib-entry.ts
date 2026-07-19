/**
 * lib-entry.ts — the SINGLE bundling entry for the in-browser variant-A demo.
 *
 * The demo page does not re-implement any cryptography: this file re-exports the
 * repo's REAL client-lib (the same code the production wallet runs) and esbuild
 * bundles it — libsodium, tweetnacl, Poseidon and the Stellar SDK included — into
 * `vendor/confidential-lib.mjs`. Rebuild after editing client-lib:
 *
 *   npm run build:demo-lib
 */

export {
  DEFAULT_CONFIDENTIAL_CONTRACT_ID,
  TESTNET_SOROBAN_RPC_URL,
  submitConfidentialDepositOnchain,
  submitConfidentialTransferOnchain,
  simulateGetCommitment,
  commitmentToBytes32,
} from '../../client-lib/confidential-pool';

export { sealConfNote } from '../../client-lib/confidential-note';
export { scanConfidentialTransfersForMe } from '../../client-lib/confidential-receive';
export {
  commit,
  randomFieldDecimal,
  buildConfidentialTransferInput,
} from '../../client-lib/confidential-commit';

// Re-export the SDK pieces the page itself needs, so it shares the bundled copy
// instead of loading a second Stellar SDK.
export { Keypair, TransactionBuilder, Networks } from '@stellar/stellar-sdk';
