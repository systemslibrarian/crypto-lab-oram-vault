import {
  initializeORAM,
  read as pathRead,
  write as pathWrite,
} from '../client/oram-client.js';
import { getServerStats } from '../server/oram-server.js';
import {
  getHierarchicalClientSummary,
  hierarchicalRead,
  hierarchicalWrite,
  initializeHierarchicalORAM,
  type HierarchicalAccessTrace,
  type HierarchicalClientSummary,
} from './client.js';

const N = 16;
const Z = 4;
const PATH_LEVELS = 5;

export interface ComparisonOperation {
  operation: 'read' | 'write';
  blockId: number;
  value?: string;
}

export interface ComparisonRow {
  index: number;
  operation: 'read' | 'write';
  blockId: number;
  result: string;
  pathReadSlots: number;
  pathWriteSlots: number;
  pathTotalSlots: number;
  hierarchyFoundLevel: number;
  hierarchyLookupSlots: number;
  hierarchyRebuildSlots: number;
  hierarchyTotalSlots: number;
  hierarchyRebuildLevels: number[];
}

export interface PathComparisonSummary {
  logicalBlocks: number;
  levels: number;
  bucketSize: number;
  serverSlots: number;
  clientPositionEntries: number;
  fixedRoundTripSlots: number;
}

export interface ORAMComparisonResult {
  rows: ComparisonRow[];
  path: PathComparisonSummary;
  hierarchy: HierarchicalClientSummary;
  verificationBlocks: number;
  outputsMatch: true;
}

export interface SkippedProbeControlResult {
  blockId: number;
  fixedResult: string;
  skippedResult: string;
  fixedFoundLevel: number;
  skippedFoundLevel: number;
  fixedProbeCount: number;
  skippedProbeCount: number;
  fixedLookupReadSlots: number;
  skippedLookupReadSlots: number;
}

export const COMPARISON_WORKLOAD: readonly ComparisonOperation[] = Object.freeze([
  { operation: 'read', blockId: 3 },
  { operation: 'write', blockId: 3, value: 'ALPHA' },
  { operation: 'read', blockId: 3 },
  { operation: 'read', blockId: 11 },
  { operation: 'write', blockId: 11, value: 'BETA' },
  { operation: 'read', blockId: 11 },
  { operation: 'read', blockId: 0 },
  { operation: 'read', blockId: 3 },
]);

function textToBlock(value: string): Uint8Array {
  const encoded = new TextEncoder().encode(value);
  if (encoded.length > 32) throw new RangeError('Comparison value exceeds one block.');
  const block = new Uint8Array(32);
  block.set(encoded);
  return block;
}

function blockToText(block: Uint8Array): string {
  return new TextDecoder().decode(block).replace(/\0+$/, '') || '(empty)';
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function pathTraffic(
  before: ReturnType<typeof getServerStats>,
  after: ReturnType<typeof getServerStats>,
): { readSlots: number; writeSlots: number; totalSlots: number } {
  const readSlots = (after.totalReads - before.totalReads) * Z;
  const writeSlots = (after.totalWrites - before.totalWrites) * Z;
  return { readSlots, writeSlots, totalSlots: readSlots + writeSlots };
}

function hierarchyTraffic(trace: HierarchicalAccessTrace): {
  lookupSlots: number;
  rebuildSlots: number;
} {
  return {
    lookupSlots: trace.traffic.lookupReadSlots + trace.traffic.lookupWriteSlots,
    rebuildSlots: trace.traffic.rebuildReadSlots + trace.traffic.rebuildWriteSlots,
  };
}

/** Run one declared workload through both real implementations, then verify all blocks. */
export async function runORAMComparison(): Promise<ORAMComparisonResult> {
  const path = await initializeORAM(N, Z);
  const hierarchy = await initializeHierarchicalORAM();
  const expected = new Map<number, Uint8Array>(
    Array.from({ length: N }, (_, blockId) => [blockId, new Uint8Array(32)]),
  );
  const rows: ComparisonRow[] = [];

  for (let index = 0; index < COMPARISON_WORKLOAD.length; index++) {
    const item = COMPARISON_WORKLOAD[index] as ComparisonOperation;
    const before = getServerStats();
    let pathOutput: Uint8Array;
    let hierarchyOutput: Uint8Array;
    let hierarchyTrace: HierarchicalAccessTrace;

    if (item.operation === 'write') {
      const payload = textToBlock(item.value ?? '');
      await pathWrite(path, item.blockId, payload);
      const hierarchyWriteResult = await hierarchicalWrite(hierarchy, item.blockId, payload);
      expected.set(item.blockId, payload);
      pathOutput = payload;
      hierarchyOutput = payload;
      hierarchyTrace = hierarchyWriteResult.trace;
    } else {
      pathOutput = await pathRead(path, item.blockId);
      const hierarchyReadResult = await hierarchicalRead(hierarchy, item.blockId);
      hierarchyOutput = hierarchyReadResult.data;
      hierarchyTrace = hierarchyReadResult.trace;
      const reference = expected.get(item.blockId);
      if (!reference || !sameBytes(pathOutput, reference) || !sameBytes(hierarchyOutput, reference)) {
        throw new Error(`Comparison read ${index + 1} disagreed with the independent reference map.`);
      }
    }

    if (!sameBytes(pathOutput, hierarchyOutput)) {
      throw new Error(`The ORAM implementations disagreed at workload operation ${index + 1}.`);
    }
    const pathCost = pathTraffic(before, getServerStats());
    const hierarchyCost = hierarchyTraffic(hierarchyTrace);
    rows.push({
      index: index + 1,
      operation: item.operation,
      blockId: item.blockId,
      result: blockToText(hierarchyOutput),
      pathReadSlots: pathCost.readSlots,
      pathWriteSlots: pathCost.writeSlots,
      pathTotalSlots: pathCost.totalSlots,
      hierarchyFoundLevel: hierarchyTrace.foundLevel,
      hierarchyLookupSlots: hierarchyCost.lookupSlots,
      hierarchyRebuildSlots: hierarchyCost.rebuildSlots,
      hierarchyTotalSlots: hierarchyTrace.traffic.totalSlots,
      hierarchyRebuildLevels: hierarchyTrace.rebuilds.map((entry) => entry.level),
    });
  }

  // This sweep is deliberately outside the displayed workload accounting. It
  // independently checks the complete logical state retained by both systems.
  for (let blockId = 0; blockId < N; blockId++) {
    const reference = expected.get(blockId) as Uint8Array;
    const pathOutput = await pathRead(path, blockId);
    const hierarchyOutput = (await hierarchicalRead(hierarchy, blockId)).data;
    if (!sameBytes(pathOutput, reference) || !sameBytes(hierarchyOutput, reference)) {
      throw new Error(`Post-workload verification failed for block ${blockId}.`);
    }
  }

  return {
    rows,
    path: {
      logicalBlocks: N,
      levels: PATH_LEVELS,
      bucketSize: Z,
      serverSlots: ((1 << PATH_LEVELS) - 1) * Z,
      clientPositionEntries: path.positionMap.size,
      fixedRoundTripSlots: 2 * PATH_LEVELS * Z,
    },
    hierarchy: getHierarchicalClientSummary(hierarchy),
    verificationBlocks: N,
    outputsMatch: true,
  };
}

/** Execute the intentionally insecure optimization beside the fixed schedule. */
export async function runSkippedProbeControl(): Promise<SkippedProbeControlResult> {
  const fixed = await initializeHierarchicalORAM();
  const skipped = await initializeHierarchicalORAM();
  const blockId = 5;
  const payload = textToBlock('DEPTH-CONTROL');

  await hierarchicalWrite(fixed, blockId, payload);
  await hierarchicalWrite(skipped, blockId, payload, 'skip-after-hit');
  const fixedRepeat = await hierarchicalRead(fixed, blockId);
  const skippedRepeat = await hierarchicalRead(skipped, blockId, 'skip-after-hit');
  if (!sameBytes(fixedRepeat.data, payload) || !sameBytes(skippedRepeat.data, payload)) {
    throw new Error('Skipped-probe control did not preserve the declared logical result.');
  }

  return {
    blockId,
    fixedResult: blockToText(fixedRepeat.data),
    skippedResult: blockToText(skippedRepeat.data),
    fixedFoundLevel: fixedRepeat.trace.foundLevel,
    skippedFoundLevel: skippedRepeat.trace.foundLevel,
    fixedProbeCount: fixedRepeat.trace.probes.length,
    skippedProbeCount: skippedRepeat.trace.probes.length,
    fixedLookupReadSlots: fixedRepeat.trace.traffic.lookupReadSlots,
    skippedLookupReadSlots: skippedRepeat.trace.traffic.lookupReadSlots,
  };
}
