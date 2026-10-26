import { afterEach, describe, expect, it, vi } from 'vitest';
import { createDummyBlock, generateClientKey } from '../src/client/encryption.js';
import {
  createServer,
  getPathBucketIds,
  getServerBuckets,
  getServerView,
  serverReadPath,
  serverWritePath,
  type Bucket,
} from '../src/server/oram-server.js';

async function dummyPath(L: number, Z: number): Promise<Bucket[]> {
  const key = await generateClientKey();
  const buckets: Bucket[] = [];
  for (let level = 0; level <= L; level++) {
    buckets.push({
      blocks: await Promise.all(Array.from({ length: Z }, () => createDummyBlock(key))),
    });
  }
  return buckets;
}

afterEach(() => vi.restoreAllMocks());

describe('server boundary validation', () => {
  it('rejects unsafe tree geometry and out-of-range leaves', () => {
    expect(() => createServer(-1, 4)).toThrow(/tree height/i);
    expect(() => createServer(17, 4)).toThrow(/tree height/i);
    expect(() => createServer(4, 0)).toThrow(/bucket size/i);
    createServer(4, 4);
    expect(() => serverReadPath(-1)).toThrow(/leafId/i);
    expect(() => serverReadPath(16)).toThrow(/leafId/i);
    expect(() => getPathBucketIds(1.5)).toThrow(/leafId/i);
  });

  it('returns snapshots that cannot mutate server-owned bytes', async () => {
    createServer(2, 2);
    serverWritePath(0, await dummyPath(2, 2));
    const snapshot = getServerBuckets();
    const firstByte = snapshot[0]!.blocks[0]!.ciphertext[0]!;
    snapshot[0]!.blocks[0]!.ciphertext[0] ^= 0xff;
    expect(getServerBuckets()[0]!.blocks[0]!.ciphertext[0]).toBe(firstByte);
  });

  it('validates an entire write before changing any bucket', async () => {
    createServer(2, 2);
    const original = await dummyPath(2, 2);
    serverWritePath(0, original);
    const before = serverReadPath(0);
    const malformed = await dummyPath(2, 2);
    malformed[0]!.blocks[0]!.ciphertext[0] ^= 0xff;
    malformed[1]!.blocks.pop();

    expect(() => serverWritePath(0, malformed)).toThrow(/expected 2/i);
    const after = serverReadPath(0);
    expect(Array.from(after[0]!.blocks[0]!.ciphertext)).toEqual(
      Array.from(before[0]!.blocks[0]!.ciphertext),
    );
  });

  it('rejects malformed opaque block shapes', async () => {
    createServer(1, 1);
    const path = await dummyPath(1, 1);
    path[0]!.blocks[0]!.nonce = new Uint8Array(11);
    expect(() => serverWritePath(0, path)).toThrow(/nonce.*12 bytes/i);
  });

  it('groups path requests by request id even when timestamps collide', async () => {
    createServer(2, 1);
    serverWritePath(0, await dummyPath(2, 1));
    vi.spyOn(Date, 'now').mockReturnValue(1234);
    serverReadPath(0);
    serverReadPath(1);
    const reads = getServerView().filter((entry) => entry.operation === 'read');
    expect(reads).toHaveLength(2);
    expect(reads.every((entry) => entry.bucketIds.length === 3)).toBe(true);
  });
});
