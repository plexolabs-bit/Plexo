// Injected by build-lib.mjs: client-lib + the Stellar SDK use node's Buffer;
// the `buffer` npm ponyfill provides it in the browser bundle.
import { Buffer } from "buffer";
export { Buffer };
globalThis.Buffer = globalThis.Buffer || Buffer;
