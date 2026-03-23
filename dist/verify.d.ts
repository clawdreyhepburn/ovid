import type { OvidResult, VerifyOvidOptions } from './types.js';
export declare function verifyOvid(jwt: string, issuerPublicKey: CryptoKey, options?: VerifyOvidOptions): Promise<OvidResult>;
