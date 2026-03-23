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

    if (claims.ovid_version !== 1) {
      return invalid();
    }

    const now = Math.floor(Date.now() / 1000);
    const expiresIn = claims.exp - now;

    if (expiresIn <= 0) {
      return invalid();
    }

    const result: OvidResult = {
      valid: true,
      principal: claims.sub,
      role: claims.role,
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
    role: '',
    chain: [],
    expiresIn: 0,
  };
}
