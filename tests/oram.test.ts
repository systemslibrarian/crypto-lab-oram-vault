import { describe, it, expect, beforeEach } from 'vitest';
import {
  initializeORAM,
  read,
  write,
  getStashSize,
  getStashHighWater,
  type ORAMClient,
} from '../src/client/oram-client.js';
import {
  getServerStats,
  getPathBucketIds,
} from '../src/server/oram-server.js';

const N = 16;
const Z = 4;
const L = Math.ceil(Math.log2(N)); // 4
const PATH_LEN = L + 1; // buckets touched per path access

function blockData(seed: number): Uint8Array {
  const d = new Uint8Array(32);
  for (let i = 0; i < d.length; i++) d[i] = (seed * 31 + i) & 0xff;
  return d;
}

describe('Path ORAM — correctness', () => {
  let client: ORAMClient;

  beforeEach(async () => {
    client = await initializeORAM(N, Z);
  });

  it('initializes every block to all-zero data and they are all recoverable', async () => {
    for (let id = 0; id < N; id++) {
      const data = await read(client, id);
      expect(data.length).toBe(32);
      expect(data.every((b) => b === 0)).toBe(true);
    }
  });

  it('reads back exactly what was written (read-after-write)', async () => {
    const payload = blockData(123);
    await write(client, 9, payload);
    const got = await read(client, 9);
    expect(Array.from(got)).toEqual(Array.from(payload));
  });

  it('keeps blocks independent — writing one never corrupts another', async () => {
    for (let id = 0; id < N; id++) {
      await write(client, id, blockData(id + 1));
    }
    for (let id = 0; id < N; id++) {
      const got = await read(client, id);
      expect(Array.from(got)).toEqual(Array.from(blockData(id + 1)));
    }
  });

  it('honors the most recent overwrite', async () => {
    await write(client, 3, blockData(1));
    await write(client, 3, blockData(2));
    await write(client, 3, blockData(3));
    const got = await read(client, 3);
    expect(Array.from(got)).toEqual(Array.from(blockData(3)));
  });

  it('survives a long randomized read/write workload (reference-model check)', async () => {
    const reference = new Map<number, Uint8Array>();
    for (let id = 0; id < N; id++) reference.set(id, new Uint8Array(32));

    for (let step = 0; step < 200; step++) {
      const id = Math.floor((step * 7 + 3) % N);
      if (step % 2 === 0) {
        const payload = blockData(step + 17);
        await write(client, id, payload);
        reference.set(id, payload);
      } else {
        const got = await read(client, id);
        expect(Array.from(got)).toEqual(Array.from(reference.get(id)!));
      }
    }
    // Final full sweep.
    for (let id = 0; id < N; id++) {
      const got = await read(client, id);
      expect(Array.from(got)).toEqual(Array.from(reference.get(id)!));
    }
  });

  it('throws on access to a block outside the position map', async () => {
    await expect(read(client, 999)).rejects.toThrow();
  });
});

describe('Path ORAM — obliviousness (what the server can observe)', () => {
  let client: ORAMClient;

  beforeEach(async () => {
    client = await initializeORAM(N, Z);
  });

  it('every access reads and writes a full root-to-leaf path', async () => {
    const before = getServerStats();
    await read(client, 0);
    const after = getServerStats();
    expect(after.totalReads - before.totalReads).toBe(PATH_LEN);
    expect(after.totalWrites - before.totalWrites).toBe(PATH_LEN);
  });

  it('the server log records only bucket ids — never block ids or operations on logical blocks', async () => {
    await read(client, 5);
    await write(client, 11, blockData(1));
    const { accessLog } = getServerStats();
    expect(accessLog.length).toBeGreaterThan(0);
    for (const entry of accessLog) {
      // The only fields the server holds about an access.
      expect(Object.keys(entry).sort()).toEqual(['bucketId', 'operation', 'timestamp']);
      expect(entry.operation === 'read' || entry.operation === 'write').toBe(true);
    }
  });

  it('a read and a write are indistinguishable to the server (both = one path read + one path write)', async () => {
    // Measure the server-visible footprint of a single access, isolated from
    // the init traffic, for each operation.
    function footprint(before: ReturnType<typeof getServerStats>, after: ReturnType<typeof getServerStats>) {
      return {
        reads: after.totalReads - before.totalReads,
        writes: after.totalWrites - before.totalWrites,
      };
    }

    const cRead = await initializeORAM(N, Z);
    const r0 = getServerStats();
    await read(cRead, 2);
    const readFp = footprint(r0, getServerStats());

    const cWrite = await initializeORAM(N, Z);
    const w0 = getServerStats();
    await write(cWrite, 2, blockData(99));
    const writeFp = footprint(w0, getServerStats());

    // A READ and a WRITE produce the byte-identical server footprint: one full
    // path read followed by one full path write. The server cannot tell them apart.
    expect(readFp).toEqual(writeFp);
    expect(readFp).toEqual({ reads: PATH_LEN, writes: PATH_LEN });
  });

  it('remaps the accessed block to a fresh random leaf on every access', async () => {
    const seen = new Set<number>();
    for (let i = 0; i < 60; i++) {
      await read(client, 4);
      seen.add(client.positionMap.get(4)!);
    }
    // With 16 leaves and 60 re-randomizations, the odds of landing on a single
    // leaf every time are ~(1/16)^59 — so we must observe several distinct leaves.
    expect(seen.size).toBeGreaterThan(3);
  });

  it('repeatedly accessing ONE block yields a near-uniform path distribution (chi-square)', async () => {
    const numLeaves = 1 << L;
    const samples = 1600;
    const counts = new Array<number>(numLeaves).fill(0);

    for (let i = 0; i < samples; i++) {
      const leaf = client.positionMap.get(7)!; // path that WILL be read
      counts[leaf]++;
      await read(client, 7);
    }

    const expected = samples / numLeaves;
    let chiSq = 0;
    for (const c of counts) chiSq += (c - expected) ** 2 / expected;

    // df = 15. Critical value at p = 0.001 is ~37.7; we use a loose 50 so this
    // is effectively never flaky while still catching a non-uniform sampler.
    expect(chiSq).toBeLessThan(50);
    // Every leaf must be reachable.
    expect(counts.every((c) => c > 0)).toBe(true);
  });
});

describe('Path ORAM — stash stays bounded', () => {
  it('keeps the stash within an O(log N) bound across a heavy workload', async () => {
    const client = await initializeORAM(N, Z);
    let highWater = getStashSize(client);

    for (let i = 0; i < 1000; i++) {
      const id = Math.floor((i * 13 + 5) % N);
      if (i % 3 === 0) await write(client, id, blockData(i));
      else await read(client, id);
      expect(getStashSize(client)).toBeLessThanOrEqual(getStashHighWater(client));
      highWater = Math.max(highWater, getStashSize(client));
    }

    // The client's own high-water mark must track the peak we observed externally.
    expect(getStashHighWater(client)).toBeGreaterThanOrEqual(highWater);

    // Path ORAM guarantees O(log N) stash whp. For N=16, Z=4 a generous,
    // comfortably-safe ceiling is N: the stash must never blow up to a
    // tree-sized structure. In practice it stays in the low single digits.
    expect(highWater).toBeLessThanOrEqual(N);
  });
});

describe('Path ORAM — path geometry', () => {
  beforeEach(async () => {
    await initializeORAM(N, Z); // ensures the server singleton is initialized
  });

  it('every leaf path runs root (bucket 0) to a distinct leaf with L+1 buckets', () => {
    const numLeaves = 1 << L;
    const leafBuckets = new Set<number>();
    for (let leaf = 0; leaf < numLeaves; leaf++) {
      const path = getPathBucketIds(leaf);
      expect(path.length).toBe(PATH_LEN);
      expect(path[0]).toBe(0); // root
      leafBuckets.add(path[path.length - 1]!);
    }
    expect(leafBuckets.size).toBe(numLeaves); // each leaf is unique
  });
});
