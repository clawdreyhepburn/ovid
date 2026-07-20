import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createOvid,
  verifyOvid,
  generateKeypair,
  OVID_PROTOCOL_VERSION,
  CHAIN_PROTOCOL_VERSIONS,
  isChainProtocolVersion,
} from '../src/index.js';
import type { AuthorizationDetail } from '../src/types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(
  readFileSync(resolve(__dirname, '../package.json'), 'utf-8'),
) as { version: string };

const testDetail: AuthorizationDetail = {
  type: 'agent_mandate',
  rarFormat: 'cedar',
  policySet: 'permit(principal, action == Ovid::Action::"read_file", resource);',
};

describe('protocol vs package version (C4)', () => {
  it('exports a fixed protocol version distinct from npm package version', () => {
    expect(OVID_PROTOCOL_VERSION).toBe('0.4.0');
    // Package may (and will) drift ahead of protocol as we ship non-wire fixes.
    expect(pkg.version).not.toBe(OVID_PROTOCOL_VERSION);
    expect(CHAIN_PROTOCOL_VERSIONS.has(OVID_PROTOCOL_VERSION)).toBe(true);
  });

  it('isChainProtocolVersion is an allowlist, not "any 0.4.x"', () => {
    expect(isChainProtocolVersion('0.4.0')).toBe(true);
    // These would silently demote to legacy verify if create stamped package version.
    expect(isChainProtocolVersion('0.4.2')).toBe(false);
    expect(isChainProtocolVersion('0.4.3')).toBe(false);
    expect(isChainProtocolVersion(pkg.version)).toBe(false);
    expect(isChainProtocolVersion('0.3.0')).toBe(false);
    expect(isChainProtocolVersion(undefined)).toBe(false);
    expect(isChainProtocolVersion(1)).toBe(false);
  });

  it('createOvid stamps protocol version, not package version', async () => {
    const keys = await generateKeypair();
    const ovid = await createOvid({
      issuerKeys: keys,
      authorizationDetails: testDetail,
      issuer: 'root',
    });
    const stamped = ovid.claims.authorization_details[0].ovid_version;
    expect(stamped).toBe(OVID_PROTOCOL_VERSION);
    expect(stamped).not.toBe(pkg.version);
  });

  it('verify takes crypto chain path for protocol tokens', async () => {
    const keys = await generateKeypair();
    const root = await createOvid({
      issuerKeys: keys,
      authorizationDetails: testDetail,
      issuer: 'root',
    });
    const child = await createOvid({
      issuerKeys: root.keys,
      issuerOvid: root,
      authorizationDetails: testDetail,
    });

    const result = await verifyOvid(child.jwt, { trustedRoots: [keys.publicKey] });
    expect(result.valid).toBe(true);
    expect(result.chain.length).toBe(2);
  });

  it('unknown ovid_version with ChainLink[] does NOT get chain-path verify', async () => {
    // Simulate the C4 footgun: stamp package version on a chain-shaped token.
    // verify must NOT treat it as chain-protocol; without a matching legacy
    // allowlist entry it should fail closed (invalid), not walk the chain
    // under a half-applied path.
    const keys = await generateKeypair({ extractable: true });
    const ovid = await createOvid({
      issuerKeys: keys,
      authorizationDetails: testDetail,
      issuer: 'root',
    });

    // Mutate claims + re-sign with leaf key so signature still verifies on
    // legacy path IF version were legacy-allowed — but package version isn't.
    const { SignJWT, decodeJwt } = await import('jose');
    const payload = decodeJwt(ovid.jwt) as any;
    payload.authorization_details[0].ovid_version = pkg.version; // e.g. 0.4.3

    const badJwt = await new SignJWT(payload)
      .setProtectedHeader({ alg: 'EdDSA', typ: 'ovid+jwt' })
      .sign(ovid.keys.privateKey);

    const result = await verifyOvid(badJwt, { trustedRoots: [keys.publicKey] });
    // Fail closed: not on chain allowlist, not on legacy allowlist.
    expect(result.valid).toBe(false);
  });
});
