import { describe, it, expect } from 'vitest';
import {
  buildMandate,
  buildMandateTag,
  validateCedarSyntax,
  type MandateIntent,
} from '../src/index.js';

describe('mandate builder', () => {
  it('emits the safe default when intent is empty', () => {
    const r = buildMandate();
    expect(r.policySet).toContain('Ovid::Action::"read"');
    expect(r.policySet).toContain('Ovid::Action::"search"');
    expect(r.policySet).toContain('Ovid::Action::"summarize"');
    expect(validateCedarSyntax(r.policySet).valid).toBe(true);
    expect(r.summary).toBe('default: read, search, summarize');
  });

  it('single action wildcard resource', () => {
    const r = buildMandate({ allow: [{ action: 'read' }] });
    expect(r.policySet).toBe('permit(principal, action == Ovid::Action::"read", resource);');
    expect(validateCedarSyntax(r.policySet).valid).toBe(true);
  });

  it('multi action uses action in [...]', () => {
    const r = buildMandate({ allow: [{ action: ['read', 'write'] }] });
    expect(r.policySet).toContain('action in [Ovid::Action::"read", Ovid::Action::"write"]');
    expect(validateCedarSyntax(r.policySet).valid).toBe(true);
  });

  it('shell binary allowlist → one statement per binary', () => {
    const r = buildMandate({
      allow: [{ action: 'exec', resource: { type: 'Shell', in: ['git', 'npm'] } }],
    });
    expect(r.policySet).toContain('resource == Ovid::Shell::"git"');
    expect(r.policySet).toContain('resource == Ovid::Shell::"npm"');
    expect(r.policySet.split('\n')).toHaveLength(2);
    expect(validateCedarSyntax(r.policySet).valid).toBe(true);
  });

  it('path glob → when clause', () => {
    const r = buildMandate({
      allow: [{ action: 'read', resource: { type: 'File', pathLike: ['/src/*'] } }],
    });
    expect(r.policySet).toContain('when { resource.path like "/src/*" }');
    expect(validateCedarSyntax(r.policySet).valid).toBe(true);
  });

  it('WebEndpoint normalizes from API kind', () => {
    const r = buildMandate({
      allow: [{ action: 'fetch', resource: { type: 'API', in: ['api.github.com'] } }],
    });
    expect(r.policySet).toContain('resource == Ovid::WebEndpoint::"api.github.com"');
  });

  it('forbid grants always emitted as forbid', () => {
    const r = buildMandate({
      allow: [{ action: 'exec', resource: { type: 'Shell', in: ['git'] } }],
      forbid: [{ action: 'exec', resource: { type: 'Shell', in: ['rm'] } }],
    });
    expect(r.policySet).toContain('permit(principal, action == Ovid::Action::"exec", resource == Ovid::Shell::"git")');
    expect(r.policySet).toContain('forbid(principal, action == Ovid::Action::"exec", resource == Ovid::Shell::"rm")');
    expect(validateCedarSyntax(r.policySet).valid).toBe(true);
  });

  it('drops unknown actions with a warning', () => {
    const r = buildMandate({ allow: [{ action: ['read', 'launch_missiles' as any] }] });
    expect(r.policySet).toContain('Ovid::Action::"read"');
    expect(r.policySet).not.toContain('launch_missiles');
    expect(r.warnings.some((w) => w.includes('launch_missiles'))).toBe(true);
  });

  it('rejects unsafe resource ids', () => {
    expect(() =>
      buildMandate({ allow: [{ action: 'exec', resource: { type: 'Shell', in: ['git"; DROP'] } }] }),
    ).toThrow(/unsafe resource id/);
  });

  it('rejects unsafe path globs', () => {
    expect(() =>
      buildMandate({ allow: [{ action: 'read', resource: { type: 'File', pathLike: ['a"b'] } }] }),
    ).toThrow(/unsafe path glob/);
  });

  it('custom namespace', () => {
    const r = buildMandate({ namespace: 'Jans', allow: [{ action: 'read' }] });
    expect(r.policySet).toContain('Jans::Action::"read"');
  });

  it('rejects invalid namespace', () => {
    expect(() => buildMandate({ namespace: 'bad ns' })).toThrow(/invalid Cedar namespace/);
  });

  it('type-only grant falls back to wildcard with a warning', () => {
    const r = buildMandate({ allow: [{ action: 'read', resource: { type: 'File' } }] });
    expect(r.policySet).toContain('permit(principal, action == Ovid::Action::"read", resource);');
    expect(r.warnings.some((w) => w.includes('wildcard'))).toBe(true);
  });

  it('all-empty grants produce a deny-all mandate', () => {
    const r = buildMandate({ allow: [{ action: [] as any }] });
    expect(r.policySet.startsWith('forbid(')).toBe(true);
    expect(validateCedarSyntax(r.policySet).valid).toBe(true);
  });

  it('buildMandateTag wraps policy with OVID markers + TTL', () => {
    const intent: MandateIntent = {
      ttlSeconds: 1800,
      allow: [{ action: 'exec', resource: { type: 'Shell', in: ['git'] } }],
    };
    const { tag, result } = buildMandateTag(intent);
    expect(tag).toContain('[OVID_TTL:1800]');
    expect(tag).toContain('[OVID_MANDATE]');
    expect(tag).toContain('[/OVID_MANDATE]');
    expect(tag).toContain(result.policySet);
  });

  it('tag omits TTL line when not set', () => {
    const { tag } = buildMandateTag({ allow: [{ action: 'read' }] });
    expect(tag).not.toContain('[OVID_TTL');
    expect(tag.startsWith('[OVID_MANDATE]')).toBe(true);
  });
});
