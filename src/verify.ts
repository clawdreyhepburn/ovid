import { jwtVerify } from 'jose';
import { defaultAuditLogger } from './audit.js';
import type { OvidResult, VerifyOvidOptions, OvidClaims } from './types.js';

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

    const result: OvidResult = {
      valid: true,
      principal: claims.sub,
      mandate: claims.mandate ?? { rarFormat: 'cedar', policySet: '' },
      chain: claims.parent_chain,
      expiresIn,
    };

    const logger = options?.auditLogger ?? defaultAuditLogger;
    logger.logVerification(claims.jti, result);

    return result;
  } catch {
    return invalid();
  }
}

function invalid(): OvidResult {
  return {
    valid: false,
    principal: '',
    mandate: { rarFormat: 'cedar', policySet: '' },
    chain: [],
    expiresIn: 0,
  };
}
