// StellarHub ZK reference · https://stellarhub.io
/**
 * Lazy libsodium loader shared by the confidential-note crypto. `libsodium-wrappers`
 * must be awaited (`sodium.ready`) before any call — this caches a single ready
 * instance for the whole process.
 */

import type { default as SodiumType } from 'libsodium-wrappers';

let sodiumInstance: typeof SodiumType | null = null;
let sodiumPromise: Promise<typeof SodiumType> | null = null;

export async function getSodium(): Promise<typeof SodiumType> {
  if (sodiumInstance) return sodiumInstance;
  if (sodiumPromise) return sodiumPromise;
  sodiumPromise = (async () => {
    const sodium = await import('libsodium-wrappers');
    await sodium.default.ready;
    sodiumInstance = sodium.default;
    return sodiumInstance;
  })();
  return sodiumPromise;
}
