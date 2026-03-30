/**
 * OVID + OVID-ME Benchmark Harness
 * Measures p50/p95/p99 latencies for all critical operations.
 * Run: npx tsx bench/benchmark.ts
 */

import { generateKeypair, createOvid, verifyOvid } from '../src/index.js';
import { performance } from 'node:perf_hooks';

const ITERATIONS = 1000;
const WARMUP = 50;

interface Stats {
  p50: number;
  p95: number;
  p99: number;
  min: number;
  max: number;
  mean: number;
}

function computeStats(samples: number[]): Stats {
  const sorted = [...samples].sort((a, b) => a - b);
  const n = sorted.length;
  return {
    p50: sorted[Math.floor(n * 0.5)],
    p95: sorted[Math.floor(n * 0.95)],
    p99: sorted[Math.floor(n * 0.99)],
    min: sorted[0],
    max: sorted[n - 1],
    mean: samples.reduce((a, b) => a + b, 0) / n,
  };
}

function printStats(name: string, stats: Stats) {
  console.log(`  ${name}:`);
  console.log(`    p50=${stats.p50.toFixed(3)}ms  p95=${stats.p95.toFixed(3)}ms  p99=${stats.p99.toFixed(3)}ms`);
  console.log(`    min=${stats.min.toFixed(3)}ms  max=${stats.max.toFixed(3)}ms  mean=${stats.mean.toFixed(3)}ms`);
  console.log();
}

async function bench(name: string, fn: () => void | Promise<void>): Promise<Stats> {
  // Warmup
  for (let i = 0; i < WARMUP; i++) await fn();

  const samples: number[] = [];
  for (let i = 0; i < ITERATIONS; i++) {
    const start = performance.now();
    await fn();
    samples.push(performance.now() - start);
  }

  const stats = computeStats(samples);
  printStats(name, stats);
  return stats;
}

async function main() {
  console.log(`OVID Benchmark — ${ITERATIONS} iterations, ${WARMUP} warmup\n`);
  console.log(`Platform: ${process.platform} ${process.arch}`);
  console.log(`Node: ${process.version}`);
  console.log();

  const results: Record<string, Stats> = {};

  // 1. Key generation
  results['keygen'] = await bench('Ed25519 key generation', () => {
    generateKeypair();
  });

  // 2. Token mint (no subset proof)
  const parentKeys = generateKeypair();
  const childKeys = generateKeypair();
  const mandate = {
    type: 'agent_mandate',
    rarFormat: 'cedar' as const,
    policySet: 'permit(principal, action == Ovid::Action::"tool_call", resource) when { resource.name == "web_search" };',
  };

  results['mint'] = await bench('Token mint (sign + encode)', () => {
    createOvid({
      issuer: 'urn:ovid:bench-parent',
      subject: 'urn:ovid:bench-child',
      signingKey: parentKeys.privateKey,
      mandate,
      ttlSeconds: 1800,
    });
  });

  // 3. Token verify
  const token = createOvid({
    issuer: 'urn:ovid:bench-parent',
    subject: 'urn:ovid:bench-child',
    signingKey: parentKeys.privateKey,
    mandate,
    ttlSeconds: 1800,
  });

  results['verify'] = await bench('Token verify (decode + validate)', () => {
    verifyOvid(token, parentKeys.publicKey);
  });

  // 4. Full round trip: keygen + mint + verify
  results['roundtrip'] = await bench('Full round trip (keygen + mint + verify)', () => {
    const kp = generateKeypair();
    const t = createOvid({
      issuer: 'urn:ovid:bench-parent',
      subject: 'urn:ovid:bench-child',
      signingKey: parentKeys.privateKey,
      mandate,
      ttlSeconds: 1800,
    });
    verifyOvid(t, parentKeys.publicKey);
  });

  // Summary table
  console.log('=== Summary (ms) ===');
  console.log('Operation          | p50    | p95    | p99    | mean');
  console.log('-------------------|--------|--------|--------|-------');
  for (const [name, s] of Object.entries(results)) {
    console.log(
      `${name.padEnd(19)}| ${s.p50.toFixed(3).padStart(6)} | ${s.p95.toFixed(3).padStart(6)} | ${s.p99.toFixed(3).padStart(6)} | ${s.mean.toFixed(3).padStart(6)}`
    );
  }

  // Output JSON for paper
  const jsonPath = new URL('./results.json', import.meta.url).pathname;
  const { writeFileSync } = await import('node:fs');
  writeFileSync(jsonPath, JSON.stringify({
    timestamp: new Date().toISOString(),
    platform: `${process.platform} ${process.arch}`,
    node: process.version,
    iterations: ITERATIONS,
    warmup: WARMUP,
    results,
  }, null, 2));
  console.log(`\nResults written to ${jsonPath}`);
}

main().catch(console.error);
