import { describe, expect, it } from 'vitest';
import {
  getHierarchicalClientSummary,
  HierarchicalBlockUnavailableError,
  hierarchyShapes,
  hierarchicalRead,
  hierarchicalWrite,
  initializeHierarchicalORAM,
  placementBucket,
  type HierarchicalAccessTrace,
} from '../src/hierarchical/client.js';
import {
  BlockAuthenticationError,
  createDummyBlock,
} from '../src/client/encryption.js';

const N = 16;

function blockData(seed: number): Uint8Array {
  return Uint8Array.from({ length: 32 }, (_, index) => (seed * 29 + index * 7) & 0xff);
}

function deterministicRandomBytes(): (length: number) => Uint8Array {
  let call = 0;
  return (length) => {
    call += 1;
    return Uint8Array.from({ length }, (_, index) => (call * 53 + index * 17) & 0xff);
  };
}

function eventTraffic(trace: HierarchicalAccessTrace): {
  lookupReadSlots: number;
  lookupWriteSlots: number;
  rebuildReadSlots: number;
  rebuildWriteSlots: number;
  totalSlots: number;
} {
  const sum = (phase: 'lookup' | 'rebuild', operation: 'read' | 'write'): number =>
    trace.serverView.events
      .filter((event) => event.phase === phase && event.operation === operation)
      .reduce((total, event) => total + event.slotCount, 0);
  const lookupReadSlots = sum('lookup', 'read');
  const lookupWriteSlots = sum('lookup', 'write');
  const rebuildReadSlots = sum('rebuild', 'read');
  const rebuildWriteSlots = sum('rebuild', 'write');
  return {
    lookupReadSlots,
    lookupWriteSlots,
    rebuildReadSlots,
    rebuildWriteSlots,
    totalSlots: lookupReadSlots + lookupWriteSlots + rebuildReadSlots + rebuildWriteSlots,
  };
}

describe('bounded hierarchical ORAM — declared finite model', () => {
  it('fixes N=16 and exposes the deliberately overprovisioned level geometry', () => {
    const shapes = hierarchyShapes();
    expect(shapes).toEqual([
      { level: 0, logicalCapacity: 1, bucketCount: 1, bucketSize: 1 },
      { level: 1, logicalCapacity: 2, bucketCount: 2, bucketSize: 2 },
      { level: 2, logicalCapacity: 4, bucketCount: 4, bucketSize: 4 },
      { level: 3, logicalCapacity: 8, bucketCount: 8, bucketSize: 8 },
      { level: 4, logicalCapacity: 16, bucketCount: 16, bucketSize: 16 },
    ]);
    expect(shapes.reduce((sum, shape) => sum + shape.bucketCount * shape.bucketSize, 0))
      .toBe(341);
    expect(() => hierarchyShapes(32)).toThrow(/fixes N=16/);
  });

  it('maps an RFC 4231 HMAC-SHA-256 vector without modulo bias', async () => {
    // RFC 4231 test case 1 begins b0344c61...; masking its low four bits
    // therefore selects bucket 1 of a power-of-two table with 16 buckets.
    const key = await crypto.subtle.importKey(
      'raw',
      new Uint8Array(20).fill(0x0b),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    );
    const label = new TextEncoder().encode('Hi There');
    expect(await placementBucket(key, label, 16)).toBe(1);
    await expect(placementBucket(key, label, 3)).rejects.toThrow(/power of two/);
  });

  it('starts with all blocks in the bottom level and reports exact finite costs', async () => {
    const client = await initializeHierarchicalORAM({ randomBytes: deterministicRandomBytes() });
    expect(getHierarchicalClientSummary(client)).toEqual({
      logicalBlocks: 16,
      hashKeys: 4,
      occupancyBits: 5,
      accessCounterWords: 1,
      transientRebuildBlocks: 16,
      serverSlots: 341,
      fixedLookupReadSlots: 31,
      fixedLookupRoundTripSlots: 62,
      levelEpochs: [1, 1, 1, 1, 1],
      occupiedLevels: [false, false, false, false, true],
    });
    expect(client.server.getView()).toEqual({
      totalReadSlots: 0,
      totalWriteSlots: 0,
      events: [],
    });
  });
});

describe('bounded hierarchical ORAM — actual storage computation', () => {
  it('recovers every initialized block and independently checks the final state', async () => {
    const client = await initializeHierarchicalORAM({ randomBytes: deterministicRandomBytes() });
    for (let blockId = 0; blockId < N; blockId++) {
      const result = await hierarchicalRead(client, blockId);
      expect(result.data).toEqual(new Uint8Array(32));
    }
    expect(getHierarchicalClientSummary(client).occupiedLevels)
      .toEqual([false, false, false, false, true]);
  });

  it('matches an independent reference map across reads, writes, and repeated accesses', async () => {
    const client = await initializeHierarchicalORAM({ randomBytes: deterministicRandomBytes() });
    const reference = new Map<number, Uint8Array>(
      Array.from({ length: N }, (_, blockId) => [blockId, new Uint8Array(32)]),
    );
    const operations = [3, 3, 11, 0, 3, 15, 11, 11, 2, 9, 3, 4, 5, 3, 8, 3];
    for (let step = 0; step < operations.length; step++) {
      const blockId = operations[step] as number;
      if (step % 3 === 0) {
        const payload = blockData(step + 1);
        await hierarchicalWrite(client, blockId, payload);
        reference.set(blockId, payload);
      } else {
        const result = await hierarchicalRead(client, blockId);
        expect(result.data).toEqual(reference.get(blockId));
      }
    }
    for (let blockId = 0; blockId < N; blockId++) {
      const result = await hierarchicalRead(client, blockId);
      expect(result.data).toEqual(reference.get(blockId));
    }
  });

  it('returns copies and serializes concurrent calls in invocation order', async () => {
    const client = await initializeHierarchicalORAM({ randomBytes: deterministicRandomBytes() });
    const first = blockData(1);
    const second = blockData(2);
    await Promise.all([
      hierarchicalWrite(client, 6, first),
      hierarchicalWrite(client, 6, second),
    ]);
    const result = await hierarchicalRead(client, 6);
    expect(result.data).toEqual(second);
    result.data[0] ^= 0xff;
    expect((await hierarchicalRead(client, 6)).data).toEqual(second);
  });

  it('rejects invalid ids and payloads before changing the access schedule', async () => {
    const client = await initializeHierarchicalORAM({ randomBytes: deterministicRandomBytes() });
    await expect(hierarchicalRead(client, 16)).rejects.toThrow(/blockId/);
    await expect(hierarchicalWrite(client, 0, undefined as unknown as Uint8Array))
      .rejects.toThrow(/newData is required/);
    await expect(hierarchicalWrite(client, 0, new Uint8Array(33)))
      .rejects.toThrow(/at most 32 bytes/);
    expect(client.accessCount).toBe(0);
  });

  it('refuses before the 32-bit dummy-label counter can wrap or issue traffic', async () => {
    const client = await initializeHierarchicalORAM({ randomBytes: deterministicRandomBytes() });
    client.accessCount = 0xffffffff;
    const before = client.server.getView();
    await expect(hierarchicalRead(client, 0)).rejects.toThrow(/counter exhausted/);
    expect(client.accessCount).toBe(0xffffffff);
    expect(client.server.getView()).toEqual(before);
  });

  it('rejects a modified authenticated slot instead of treating it as padding', async () => {
    const client = await initializeHierarchicalORAM({ randomBytes: deterministicRandomBytes() });
    await hierarchicalRead(client, 0); // moves block 0 into the one-slot top level
    const bucket = client.server.readBucket(0, 0, 'lookup');
    const first = bucket[0];
    expect(first).toBeDefined();
    first!.ciphertext[0] ^= 0x80;
    client.server.writeBucket(0, 0, bucket, 'lookup');
    await expect(hierarchicalRead(client, 0)).rejects.toBeInstanceOf(BlockAuthenticationError);
  });

  it('fails closed when a valid encrypted dummy replaces the only target copy', async () => {
    const client = await initializeHierarchicalORAM({ randomBytes: deterministicRandomBytes() });
    await hierarchicalRead(client, 0); // removes the bottom copy and reinserts at level 0
    client.server.writeBucket(0, 0, [await createDummyBlock(client.key)], 'lookup');
    await expect(hierarchicalRead(client, 0))
      .rejects.toBeInstanceOf(HierarchicalBlockUnavailableError);
  });
});

describe('bounded hierarchical ORAM — lookup and rebuild evidence', () => {
  it('probes every level, then uses a unique dummy probe after a cache hit', async () => {
    const client = await initializeHierarchicalORAM({ randomBytes: deterministicRandomBytes() });
    const first = await hierarchicalRead(client, 7);
    expect(first.trace.foundLevel).toBe(4);
    expect(first.trace.probes.map((probe) => probe.kind))
      .toEqual(['cache', 'real', 'real', 'real', 'real']);

    const second = await hierarchicalRead(client, 7);
    expect(second.trace.foundLevel).toBe(0);
    expect(second.trace.probes.map((probe) => probe.kind))
      .toEqual(['cache', 'dummy', 'dummy', 'dummy', 'dummy']);
    expect(second.trace.probes.map((probe) => probe.slotCount)).toEqual([1, 2, 4, 8, 16]);
    expect(second.trace.traffic.lookupReadSlots).toBe(31);
    expect(second.trace.traffic.lookupWriteSlots).toBe(31);
  });

  it('changes a later-level dummy lookup on each access within one key epoch', async () => {
    const client = await initializeHierarchicalORAM({ randomBytes: deterministicRandomBytes() });
    const buckets: number[] = [];
    for (let index = 0; index < 8; index++) {
      const result = await hierarchicalRead(client, 7);
      const bottomProbe = result.trace.probes.find((probe) => probe.level === 4);
      expect(bottomProbe).toBeDefined();
      if (index > 0) {
        expect(bottomProbe?.kind).toBe('dummy');
        buckets.push(bottomProbe?.bucket as number);
      }
    }
    // Level 4 is not rebuilt before access 16. These accesses therefore use
    // one key epoch, while the access-number component changes every label.
    expect(new Set(buckets).size).toBeGreaterThan(1);
  });

  it('executes the binary-carry rebuild cadence and records real traffic spikes', async () => {
    const client = await initializeHierarchicalORAM({ randomBytes: deterministicRandomBytes() });
    const targetLevels: number[][] = [];
    const totals: number[] = [];
    for (let accessNumber = 1; accessNumber <= 16; accessNumber++) {
      const result = await hierarchicalRead(client, (accessNumber * 5) % N);
      targetLevels.push(result.trace.rebuilds.map((rebuild) => rebuild.level));
      totals.push(result.trace.traffic.totalSlots);
      expect(result.trace.traffic).toEqual(eventTraffic(result.trace));
    }
    expect(targetLevels[0]).toEqual([0]);
    expect(targetLevels[1]).toEqual([0, 1]);
    expect(targetLevels[3]).toEqual([0, 1, 2]);
    expect(targetLevels[7]).toEqual([0, 1, 2, 3]);
    expect(targetLevels[15]).toEqual([0, 1, 2, 3, 4]);
    expect(totals[0]).toBe(63);
    expect(totals[1]).toBe(68);
    expect(totals[3]).toBe(88);
    expect(totals[7]).toBe(168);
    expect(totals[15]).toBe(744);
    expect(getHierarchicalClientSummary(client).occupiedLevels)
      .toEqual([false, false, false, false, true]);
    expect(getHierarchicalClientSummary(client).transientRebuildBlocks).toBe(16);
  });

  it('rotates a hashed level key whenever that level is rebuilt', async () => {
    const client = await initializeHierarchicalORAM({ randomBytes: deterministicRandomBytes() });
    const initialKey = client.levels[1]?.hashKey;
    expect(initialKey).toBeInstanceOf(CryptoKey);
    await hierarchicalRead(client, 0);
    await hierarchicalRead(client, 1);
    expect(client.levels[1]?.epoch).toBe(2);
    expect(client.levels[1]?.hashKey).toBeInstanceOf(CryptoKey);
    expect(client.levels[1]?.hashKey).not.toBe(initialKey);
  });

  it('gives the storage observer only physical coordinates, phases, and sizes', async () => {
    const client = await initializeHierarchicalORAM({ randomBytes: deterministicRandomBytes() });
    const result = await hierarchicalWrite(client, 9, blockData(77));
    expect(result.trace.serverView.events.length).toBeGreaterThan(0);
    for (const event of result.trace.serverView.events) {
      expect(Object.keys(event).sort()).toEqual(['bucket', 'level', 'operation', 'phase', 'slotCount']);
    }
    const serialized = JSON.stringify(result.trace.serverView);
    expect(serialized).not.toContain('blockId');
    expect(serialized).not.toContain('dummy');
    expect(serialized).not.toContain('found');
    expect(serialized).not.toContain('hashKey');
    expect(serialized).not.toContain('77');
  });

  it('gives a logical read and write the same physical-operation footprint', async () => {
    const readClient = await initializeHierarchicalORAM({ randomBytes: deterministicRandomBytes() });
    const writeClient = await initializeHierarchicalORAM({ randomBytes: deterministicRandomBytes() });
    const readTrace = (await hierarchicalRead(readClient, 9)).trace.serverView;
    const writeTrace = (await hierarchicalWrite(writeClient, 9, blockData(4))).trace.serverView;
    expect(writeTrace).toEqual(readTrace);
  });

  it('makes skipped post-hit probes visibly leak depth while preserving the logical answer', async () => {
    const fixed = await initializeHierarchicalORAM({ randomBytes: deterministicRandomBytes() });
    const leaky = await initializeHierarchicalORAM({ randomBytes: deterministicRandomBytes() });
    await hierarchicalWrite(fixed, 5, blockData(42));
    await hierarchicalWrite(leaky, 5, blockData(42), 'skip-after-hit');

    const fixedRepeat = await hierarchicalRead(fixed, 5);
    const leakyRepeat = await hierarchicalRead(leaky, 5, 'skip-after-hit');
    expect(fixedRepeat.data).toEqual(blockData(42));
    expect(leakyRepeat.data).toEqual(blockData(42));
    expect(fixedRepeat.trace.foundLevel).toBe(0);
    expect(leakyRepeat.trace.foundLevel).toBe(0);
    expect(fixedRepeat.trace.probes).toHaveLength(5);
    expect(leakyRepeat.trace.probes).toHaveLength(1);
    expect(fixedRepeat.trace.traffic.lookupReadSlots).toBe(31);
    expect(leakyRepeat.trace.traffic.lookupReadSlots).toBe(1);
  });
});
