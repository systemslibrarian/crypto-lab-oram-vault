import { describe, expect, it } from 'vitest';
import { runCollusion, runTraceShape } from '../src/multiclient/scenario.js';
import { STORE_N, STORE_STASH_SLOTS, STORE_Z } from '../src/multiclient/store.js';

/**
 * The server-visible transcript, and the point at which it stops being enough.
 *
 * Two claims are tested here and they pull in opposite directions, which is
 * the lesson:
 *
 *   1. AGAINST THE SERVER ALONE the access shape carries no logical
 *      information. Read and write produce the identical event sequence and
 *      the identical slot counts, for every entry and every client. Only the
 *      leaf differs.
 *
 *   2. THE LEAF IS ENOUGH for anyone who can also read the shared leaf map -
 *      and every registered client can, because the map has to be shared
 *      (GORAM, IACR ePrint 2015/224, section 3.1) and is encrypted under a key
 *      every client holds. So one corrupted client plus the server reduces
 *      sixteen possible entries to a handful that always contains the right
 *      one. Stated as a reduction, not as an identification: several entries
 *      can share a leaf in a 16-leaf tree.
 *
 * Claim 2 is evidence consistent with ePrint 2017/329 section 2.2 Theorem 1,
 * which rules out obliviousness against malicious clients for any scheme
 * touching `o(n)` addresses per access. The test asserts the observed break,
 * not the theorem.
 */

describe('the access shape the server sees', () => {
  it('is identical for a read and a write, every entry, every client', async () => {
    const report = await runTraceShape();
    expect(report.perAccess.length).toBeGreaterThanOrEqual(8);
    expect(report.uniformShape, `signatures diverged: ${report.shapeSignature}`).toBe(true);

    // And the shape is the one the construction claims: log, state, path and
    // stash, read then written, with fixed slot counts.
    const kinds = report.perAccess[0]?.events.map((event) => `${event.kind}:${event.operation}`);
    expect(kinds).toEqual([
      'log:read',
      'state:read',
      'path:read',
      'stash:read',
      'path:write',
      'stash:write',
      'state:write',
      'log:write',
    ]);
  }, 60_000);

  it('transfers the same number of slots whatever the operation', async () => {
    const report = await runTraceShape();
    const reads = new Set(report.perAccess.map((row) => row.readSlots));
    const writes = new Set(report.perAccess.map((row) => row.writeSlots));
    expect(reads.size, 'read slot counts must not vary').toBe(1);
    expect(writes.size, 'write slot counts must not vary').toBe(1);
    // Five buckets of Z plus the whole stash, in each direction, plus the
    // single-slot state and log events.
    const expected = 5 * STORE_Z + STORE_STASH_SLOTS + 2;
    expect([...reads][0]).toBe(expected);
    expect([...writes][0]).toBe(expected);
  }, 60_000);

  it('never puts a logical entry index or a client identity in a data event', async () => {
    const report = await runTraceShape();
    for (const row of report.perAccess) {
      for (const event of row.events) {
        expect(Object.keys(event).sort()).toEqual(
          event.leaf === undefined
            ? ['kind', 'operation', 'slots']
            : ['kind', 'leaf', 'operation', 'slots'],
        );
        // A leaf appears only on a path access, which is the one thing the
        // server really does observe.
        if (event.leaf !== undefined) expect(event.kind).toBe('path');
      }
    }
  }, 60_000);

  it('re-randomises the path, so the leaf is not a stable entry label', async () => {
    const report = await runTraceShape();
    expect(report.distinctLeaves).toBeGreaterThan(1);
  }, 60_000);
});

describe('obliviousness once a client colludes with the server', () => {
  it('narrows sixteen entries to a handful that always contains the right one', async () => {
    const report = await runCollusion(8);
    expect(report.trials).toBe(8);
    // The map is exact, so the accessed entry is in the candidate set every
    // single time. This is the load-bearing assertion.
    expect(report.actualInCandidates).toBe(report.trials);
    // And the set is a handful out of sixteen, not sixteen. Several entries
    // can share a leaf in a 16-leaf tree, which is why this is stated as a
    // reduction rather than as an identification.
    expect(report.meanCandidates).toBeGreaterThan(0);
    expect(report.meanCandidates).toBeLessThanOrEqual(4);
    expect(report.baselineRate).toBeCloseTo(1 / STORE_N, 10);
    expect(report.collusionRate).toBeGreaterThan(report.baselineRate * 3);
  }, 60_000);

  it('uses only the two things the pair legitimately has', async () => {
    const report = await runCollusion(4);
    expect(report.method).toMatch(/decrypts the shared leaf map/);
    expect(report.method).toMatch(/leaf of the path access/);
    expect(report.method).toMatch(/No statistics/);
    for (const observation of report.observations) {
      expect(observation.leafObserved).toBeGreaterThanOrEqual(0);
      expect(observation.candidates).toContain(observation.actualIndex);
    }
  }, 60_000);

  it('beats a uniform guess by a margin no bias could explain', async () => {
    const report = await runCollusion(12);
    // Guessing from the candidate set, versus guessing from all sixteen.
    expect(report.collusionRate).toBeGreaterThan(report.baselineRate * 3);
    // And at least sometimes the set collapses to one entry outright.
    expect(report.uniquelyIdentified).toBeGreaterThan(0);
  }, 60_000);

  it('reports the reduction honestly rather than as an identification', async () => {
    const report = await runCollusion(6);
    expect(report.method).toMatch(/not always a single entry/);
    expect(report.method).toMatch(/always CONTAINS the/);
    expect(report.uniquelyIdentified).toBeLessThanOrEqual(report.trials);
  }, 60_000);
});
