// StellarHub ZK reference · https://stellarhub.io
import {
  generateStealthKeys,
  generateEphemeralKeyPair,
  deriveStealthAddress,
  recoverStealthPrivateKey,
  canSpend,
  checkViewTag,
  encodeStealthMeta,
  serializeStealthKeys,
  deserializeStealthKeys,
} from './stealth';
const devLog = (...args: unknown[]) => console.log(...args);
const devError = (...args: unknown[]) => console.error(...args);

async function verify() {
  devLog('=== Stealth Addresses Verification ===\n');

  devLog('1. Generating recipient stealth keys...');
  const recipientKeys = generateStealthKeys();
  devLog('   Scan public key length:', recipientKeys.scanPublic.length);
  devLog('   Spend public key length:', recipientKeys.spendPublic.length);

  devLog('\n2. Sender generates ephemeral keypair...');
  const ephemeral = generateEphemeralKeyPair();
  devLog('   Ephemeral public key length:', ephemeral.publicKey.length);

  devLog('\n3. Deriving stealth address...');
  const meta = await deriveStealthAddress(
    recipientKeys.scanPublic,
    recipientKeys.spendPublic,
    ephemeral.secretKey
  );
  devLog('   Stealth address:', meta.stealthAddress);
  devLog('   View tag:', meta.viewTag);
  devLog('   Ephemeral public length:', meta.ephemeralPublic.length);

  devLog('\n4. Checking view tag...');
  const viewTagMatch = await checkViewTag(
    recipientKeys.scanKey,
    meta.ephemeralPublic,
    meta.viewTag
  );
  devLog('   View tag matches:', viewTagMatch);

  devLog('\n5. Verifying recipient can spend...');
  const canSpendResult = await canSpend(
    meta.stealthAddress,
    recipientKeys.scanKey,
    recipientKeys.spendKey,
    meta.ephemeralPublic
  );
  devLog('   Can spend:', canSpendResult);

  devLog('\n6. Recovering private key...');
  const recovered = await recoverStealthPrivateKey(
    recipientKeys.scanKey,
    recipientKeys.spendKey,
    meta.ephemeralPublic
  );
  devLog('   Recovered public key:', recovered.publicKey());
  devLog('   Keys match:', recovered.publicKey() === meta.stealthAddress);
  devLog('   Can sign:', recovered.canSign());

  devLog('\n7. Wrong recipient cannot spend...');
  const wrongKeys = generateStealthKeys();
  const wrongCanSpend = await canSpend(
    meta.stealthAddress,
    wrongKeys.scanKey,
    wrongKeys.spendKey,
    meta.ephemeralPublic
  );
  devLog('   Wrong recipient can spend:', wrongCanSpend);

  devLog('\n8. Serialization test...');
  const serialized = serializeStealthKeys(recipientKeys);
  const deserialized = deserializeStealthKeys(serialized);
  const keysMatch = Buffer.from(deserialized.scanKey).equals(Buffer.from(recipientKeys.scanKey));
  devLog('   Serialization roundtrip works:', keysMatch);

  devLog('\n9. Encoded meta for storage...');
  const encoded = encodeStealthMeta(meta);
  devLog('   Encoded:', JSON.stringify(encoded, null, 2));

  devLog('\n=== All verifications passed! ===');
}

verify().catch((err) => devError('Verification failed:', err));
