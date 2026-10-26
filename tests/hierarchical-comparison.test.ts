import { describe, expect, it } from 'vitest';
import {
  COMPARISON_WORKLOAD,
  runORAMComparison,
  runSkippedProbeControl,
} from '../src/hierarchical/comparison.js';

describe('Path ORAM / bounded hierarchy comparison', () => {
  it('derives both cost traces from real executions and verifies the full logical state', async () => {
    const result = await runORAMComparison();
    expect(result.rows).toHaveLength(COMPARISON_WORKLOAD.length);
    expect(result.outputsMatch).toBe(true);
    expect(result.verificationBlocks).toBe(16);
    expect(result.path).toEqual({
      logicalBlocks: 16,
      levels: 5,
      bucketSize: 4,
      serverSlots: 124,
      clientPositionEntries: 16,
      fixedRoundTripSlots: 40,
    });
    expect(result.hierarchy.serverSlots).toBe(341);
    expect(result.hierarchy.fixedLookupRoundTripSlots).toBe(62);

    expect(result.rows.map((row) => row.pathTotalSlots)).toEqual(new Array(8).fill(40));
    expect(result.rows.map((row) => row.hierarchyTotalSlots))
      .toEqual([63, 68, 63, 88, 63, 68, 63, 168]);
    expect(result.rows.map((row) => row.hierarchyRebuildLevels))
      .toEqual([[0], [0, 1], [0], [0, 1, 2], [0], [0, 1], [0], [0, 1, 2, 3]]);
    expect(result.rows.map((row) => row.result))
      .toEqual(['(empty)', 'ALPHA', 'ALPHA', '(empty)', 'BETA', 'BETA', '(empty)', 'ALPHA']);
  });

  it('shows that skipping post-hit probes leaks depth despite returning the same data', async () => {
    const result = await runSkippedProbeControl();
    expect(result.fixedResult).toBe('DEPTH-CONTROL');
    expect(result.skippedResult).toBe(result.fixedResult);
    expect(result.fixedFoundLevel).toBe(0);
    expect(result.skippedFoundLevel).toBe(0);
    expect(result.fixedProbeCount).toBe(5);
    expect(result.skippedProbeCount).toBe(1);
    expect(result.fixedLookupReadSlots).toBe(31);
    expect(result.skippedLookupReadSlots).toBe(1);
  });
});
