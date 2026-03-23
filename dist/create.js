import { SignJWT } from 'jose';
import { generateKeypair, exportPublicKeyBase64 } from './keys.js';
import { isSubsetScope } from './scope.js';
const DEFAULT_TTL = 1800;
const DEFAULT_MAX_CHAIN_DEPTH = 5;
export async function createOvid(options) {
    const { issuerKeys, issuerOvid, role, scope, ttlSeconds = DEFAULT_TTL, maxChainDepth = DEFAULT_MAX_CHAIN_DEPTH, kid, issuer, } = options;
    // Derive parent info
    const parentClaims = issuerOvid?.claims;
    // Check scope attenuation against parent
    if (parentClaims) {
        if (!isSubsetScope(scope, parentClaims.scope)) {
            throw new Error('Scope attenuation violation: child scope exceeds parent scope');
        }
    }
    // Check lifetime attenuation
    if (parentClaims) {
        const now = Math.floor(Date.now() / 1000);
        const childExp = now + ttlSeconds;
        if (childExp > parentClaims.exp) {
            throw new Error('Lifetime attenuation violation: child expiry exceeds parent expiry');
        }
    }
    // Check chain depth
    const parentChain = parentClaims
        ? [...parentClaims.parent_chain, parentClaims.iss]
        : [];
    if (parentChain.length >= maxChainDepth) {
        throw new Error(`Chain depth ${parentChain.length + 1} exceeds max ${maxChainDepth}`);
    }
    // Generate keypair for the new agent
    const agentKeys = await generateKeypair();
    const agentPub = await exportPublicKeyBase64(agentKeys.publicKey);
    const issuerName = issuer ?? parentClaims?.sub ?? 'root';
    const agentId = options.agentId ?? `${issuerName}/${role}-${randomHex(4)}`;
    const now = Math.floor(Date.now() / 1000);
    const claims = {
        jti: agentId,
        iss: issuerName,
        sub: agentId,
        iat: now,
        exp: now + ttlSeconds,
        ovid_version: 1,
        role,
        scope,
        parent_chain: parentChain,
        ...(parentClaims ? { parent_ovid: parentClaims.jti } : {}),
        agent_pub: agentPub,
    };
    const header = { alg: 'EdDSA', typ: 'ovid+jwt' };
    const finalHeader = kid ? { ...header, kid } : header;
    const jwt = await new SignJWT({ ...claims })
        .setProtectedHeader(finalHeader)
        .setIssuedAt(claims.iat)
        .setExpirationTime(claims.exp)
        .setJti(claims.jti)
        .setIssuer(claims.iss)
        .setSubject(claims.sub)
        .sign(issuerKeys.privateKey);
    return { jwt, claims, keys: agentKeys };
}
function randomHex(bytes) {
    const arr = new Uint8Array(bytes);
    globalThis.crypto.getRandomValues(arr);
    return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
}
