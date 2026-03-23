import { describe, it, expect } from 'vitest';
import { isSubsetScope } from '../src/index.js';

describe('isSubsetScope', () => {
  it('empty child is subset of any parent', () => {
    expect(isSubsetScope({}, { tools: { allow: ['exec'] } })).toBe(true);
  });

  it('child with subset tools.allow passes', () => {
    expect(isSubsetScope(
      { tools: { allow: ['read_file'] } },
      { tools: { allow: ['read_file', 'write', 'exec'] } },
    )).toBe(true);
  });

  it('child with extra tools.allow fails', () => {
    expect(isSubsetScope(
      { tools: { allow: ['read_file', 'browser'] } },
      { tools: { allow: ['read_file', 'exec'] } },
    )).toBe(false);
  });

  it('child must preserve parent deny list', () => {
    expect(isSubsetScope(
      { shell: { deny: ['rm'] } },
      { shell: { deny: ['rm', 'curl'] } },
    )).toBe(false);
  });

  it('child can add extra denies', () => {
    expect(isSubsetScope(
      { shell: { deny: ['rm', 'curl', 'wget'] } },
      { shell: { deny: ['rm', 'curl'] } },
    )).toBe(true);
  });

  it('paths subset check works', () => {
    expect(isSubsetScope(
      { paths: { allow: ['/a'] } },
      { paths: { allow: ['/a', '/b'] } },
    )).toBe(true);
    expect(isSubsetScope(
      { paths: { allow: ['/c'] } },
      { paths: { allow: ['/a', '/b'] } },
    )).toBe(false);
  });

  it('api subset check works', () => {
    expect(isSubsetScope(
      { api: { allow: ['github.com'] } },
      { api: { allow: ['github.com', 'google.com'] } },
    )).toBe(true);
  });

  it('mixed categories all checked', () => {
    expect(isSubsetScope(
      { tools: { allow: ['read'] }, shell: { allow: ['git'] } },
      { tools: { allow: ['read', 'write'] }, shell: { allow: ['git', 'npm'] } },
    )).toBe(true);
  });

  it('child with no parent restrictions is allowed', () => {
    expect(isSubsetScope(
      { tools: { allow: ['anything'] } },
      {},
    )).toBe(true);
  });
});
