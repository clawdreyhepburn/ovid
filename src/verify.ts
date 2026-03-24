import { jwtVerify } from 'jose';
import type { OvidResult, VerifyOvidOptions, OvidClaims } from './types.js';

const EMPTY_MANDATE = { type: '', rarFormat: 'cedar' as const, policySet: '' };

export async function verifyOvid(
  jwt: string,
  issuerPublicKey: CryptoKey,
  options?: VerifyOvidOptions,
): Promise<OvidResult> {
  try {
    const { payload } = await jwtVerify(jwt, issuerPublicKey, {
      algorithms: ['EdDSA'],
    });

    const claims = payload as unknown as OvidClaims;

    // Accept both old (numeric 1) and new (string "0.2.0") version formats
    const version = claims.ovid_version;
    if (version !== '0.2.0' && (version as unknown) !== 1) {
      return invalid();
    }

    const now = Math.floor(Date.now() / 1000);
    const expiresIn = claims.exp - now;

    if (expiresIn <= 0) {
      return invalid();
    }

    // Mandate is required for v0.2.0+ tokens
    if (typeof version === 'string' && !claims.mandate?.policySet) {
      return invalid();
    }

    // Backfill type if missing (tokens minted before type was required)
    const mandate = claims.mandate
      ? { ...claims.mandate, type: claims.mandate.type || 'agent_mandate' }
      : EMPTY_MANDATE;

    return {
      valid: true,
      principal: claims.sub,
      mandate,
      chain: claims.parent_chain,
      expiresIn,
    };
  } catch {
    return invalid();
  }
}

function invalid(): OvidResult {
  return {
    valid: false,
    principal: '',
    mandate: EMPTY_MANDATE,
    chain: [],
    expiresIn: 0,
  };
}
