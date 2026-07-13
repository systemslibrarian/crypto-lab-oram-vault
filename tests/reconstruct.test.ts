import { describe, it, expect, beforeEach } from 'vitest';
import {
  initializeORAM,
  read,
  write,
  reconstructPathPlacement,
  type ORAMClient,
} from '../src/client/oram-client.js';
import { getServerBuckets, getPathBucketIds } from '../src/server/oram-server.js';
import { decryptBlock } from '../src/client/encryption.js';

const N = 16;
const Z = 4;

/**
 * The client-view tree renders block IDs by RECONSTRUCTING which real block sits
 * in each on-path bucket from the position map alone. That visualization is only
 * honest if the reconstruction matches what is PHYSICALLY (and encrypted) in the
 * server's buckets. This suite decrypts the real on-path buckets and asserts the
 * two agree exactly — so the demo never shows a fabricated placement.
 */
async function actualPlacement(client: ORAMClient, leaf: number): Promise<number[][]> {
  const buckets = getServerBuckets();
  const pathIds = getPathBucketIds(leaf); // index 0 = root ... index L = leaf
  const perLevel: number[][] = [];
  for (const bid of pathIds) {
    const bucket = buckets[bid];
    const ids: number[] = [];
    for (const enc of bucket?.blocks ?? []) {
      if (enc.ciphertext.length === 0) continue;
      const dec = await decryptBlock(enc, client.key);
      if (dec !== null) ids.push(dec.blockId);
    }
    perLevel.push(ids.sort((a, b) => a - b));
  }
  return perLevel;
}

function norm(perLevel: number[][]): number[][] {
  return perLevel.map((l) => [...l].sort((a, b) => a - b));
}

describe('client-view reconstruction matches the real encrypted server buckets', () => {
  let client: ORAMClient;
  beforeEach(async () => {
    client = await initializeORAM(N, Z);
  });

  it('agrees on the just-accessed path after each of many random accesses', async () => {
    for (let i = 0; i < 60; i++) {
      const blockId = i % N;
      const oldLeaf = client.positionMap.get(blockId)!;
      if (i % 2 === 0) await read(client, blockId);
      else await write(client, blockId, new Uint8Array(32).fill(i & 0xff));

      // The path that was just written back is P(oldLeaf) (remap happens before
      // write-back). The client reconstructs its contents; compare to reality.
      const recon = norm(reconstructPathPlacement(client, oldLeaf).perLevel);
      const actual = norm(await actualPlacement(client, oldLeaf));
      expect(recon).toEqual(actual);
    }
  });

  it('every block the reconstruction places is legally eligible for its bucket', async () => {
    await read(client, 5);
    const leaf = client.positionMap.get(5)!; // some path
    const { perLevel, eligibleLevel } = reconstructPathPlacement(client, leaf);
    for (let level = 0; level < perLevel.length; level++) {
      for (const bid of perLevel[level] ?? []) {
        // A block may only rest at or above (shallower than) its deepest eligible
        // level — never deeper than the lowest common node with the path.
        expect(level).toBeLessThanOrEqual(eligibleLevel.get(bid)!);
      }
    }
  });
});
