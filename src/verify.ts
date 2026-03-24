import { jwtVerify } from 'jose';
import type { OvidResult, VerifyOvidOptions, OvidClaims, AuthorizationDetail } from './types.js';
import { EMPTY_AUTHORIZATION_DETAIL } from './types.js';

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

    // Backward compat: convert old v0.2.x tokens with top-level mandate claim
    const legacy = payload as any;
    if (legacy.mandate && !claims.authorization_details) {
      claims.authorization_details = [{
        type: legacy.mandate.type || 'agent_mandate',
        rarFormat: legacy.mandate.rarFormat,
        policySet: legacy.mandate.policySet,
        parent_chain: legacy.parent_chain,
        agent_pub: legacy.agent_pub,
        ovid_version: legacy.ovid_version,
      }];
    }

    // Validate authorization_details
    if (!Array.isArray(claims.authorization_details) || claims.authorization_details.length === 0) {
      return invalid();
    }

    // Find the agent_mandate entry
    const mandateDetail = claims.authorization_details.find(d => d.type === 'agent_mandate')
      ?? claims.authorization_details[0];

    // Version check: accept 0.2.0 (legacy converted), 0.3.0, or old numeric 1
    const version = mandateDetail.ovid_version;
    if (version && version !== '0.3.0' && version !== '0.2.0' && (version as unknown) !== 1) {
      return invalid();
    }

    const now = Math.floor(Date.now() / 1000);
    const expiresIn = claims.exp - now;
    if (expiresIn <= 0) {
      return invalid();
    }

    // Mandate policySet is required for versioned tokens
    if (version && !mandateDetail.policySet) {
      return invalid();
    }

    // Backfill type if missing
    const mandate: AuthorizationDetail = {
      ...mandateDetail,
      type: mandateDetail.type || 'agent_mandate',
    };

    return {
      valid: true,
      principal: claims.sub,
      mandate,
      chain: mandateDetail.parent_chain ?? [],
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
    mandate: EMPTY_AUTHORIZATION_DETAIL,
    chain: [],
    expiresIn: 0,
  };
}
