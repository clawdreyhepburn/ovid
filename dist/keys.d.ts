import type { KeyPair } from './types.js';
export declare function generateKeypair(): Promise<KeyPair>;
export declare function exportPublicKeyBase64(publicKey: KeyPair['publicKey']): Promise<string>;
