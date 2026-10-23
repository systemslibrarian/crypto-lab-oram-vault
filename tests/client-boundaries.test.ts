import { describe, expect, it } from 'vitest';
import {
  BlockAuthenticationError,
  createDummyBlock,
  decryptBlock,
} from '../src/client/encryption.js';
import {
  BlockUnavailableError,
  initializeORAM,
  read,
  write,
} from '../src/client/oram-client.js';
import {
  getServerBuckets,
  getServerStats,
  serverReadPath,
  serverWritePath,
  type Bucket,
} from '../src/server/oram-server.js';

const N = 16;
const Z = 4;

function payload(seed: number): Uint8Array {
  return new Uint8Array(32).fill(seed & 0xff);
}

async function physicalRealIds(
  key: Awaited<ReturnType<typeof initializeORAM>>['key'],
): Promise<number[]> {
  const ids: number[] = [];
  for (const bucket of getServerBuckets()) {
    for (const encrypted of bucket.blocks) {
      const block = await decryptBlock(encrypted, key);
      if (block) ids.push(block.blockId);
    }
  }
  return ids;
}

async function removeOneRealBlock(
  client: Awaited<ReturnType<typeof initializeORAM>>,
): Promise<number> {
  for (let leaf = 0; leaf < (1 << client.L); leaf++) {
    const path: Bucket[] = serverReadPath(leaf);
    for (const bucket of path) {
      for (let index = 0; index < bucket.blocks.length; index++) {
        const block = await decryptBlock(bucket.blocks[index]!, client.key);
        if (!block) continue;
        bucket.blocks[index] = await createDummyBlock(client.key);
        serverWritePath(leaf, path);
        return block.blockId;
      }
    }
  }
  throw new Error('No real block found in the provisioned tree.');
}

describe('client fail-closed boundaries', () => {
  it('initialization preserves every logical block physically exactly once', async () => {
    const client = await initializeORAM(N, Z);
    const ids = [...await physicalRealIds(client.key), ...client.stash.keys()].sort((a, b) => a - b);
    expect(ids).toEqual(Array.from({ length: N }, (_, id) => id));
  });

  it('serializes concurrent accesses instead of racing shared client state', async () => {
    const client = await initializeORAM(N, Z);
    await Promise.all(Array.from({ length: N }, (_, id) => write(client, id, payload(id + 1))));
    const values = await Promise.all(Array.from({ length: N }, (_, id) => read(client, id)));
    values.forEach((value, id) => expect(Array.from(value)).toEqual(Array.from(payload(id + 1))));
  });

  it('throws when an authenticated target block is omitted', async () => {
    const client = await initializeORAM(N, Z);
    const removedId = await removeOneRealBlock(client);
    await expect(read(client, removedId)).rejects.toBeInstanceOf(BlockUnavailableError);
    expect(client.positionMap.has(removedId)).toBe(true);
  });

  it('throws on modified ciphertext instead of treating it as a dummy', async () => {
    const client = await initializeORAM(N, Z);
    const leaf = client.positionMap.get(0)!;
    const path = serverReadPath(leaf);
    // Any modified fixed-size blob on the authenticated path must abort before
    // client state is committed, whether it held the target, another block, or a dummy.
    path[0]!.blocks[0]!.ciphertext[0] ^= 0xff;
    serverWritePath(leaf, path);
    await expect(read(client, 0)).rejects.toBeInstanceOf(BlockAuthenticationError);
    expect(client.positionMap.get(0)).toBe(leaf);
  });

  it('returns copied plaintext and rejects oversized writes before server I/O', async () => {
    const client = await initializeORAM(N, Z);
    await write(client, 3, payload(7));
    const first = await read(client, 3);
    first.fill(0xff);
    expect(Array.from(await read(client, 3))).toEqual(Array.from(payload(7)));

    const before = getServerStats();
    await expect(write(client, 3, new Uint8Array(33))).rejects.toThrow(/at most 32 bytes/i);
    const after = getServerStats();
    expect(after.totalReads).toBe(before.totalReads);
    expect(after.totalWrites).toBe(before.totalWrites);
  });

  it('rejects invalid client geometry', async () => {
    await expect(initializeORAM(0, Z)).rejects.toThrow(/block count/i);
    await expect(initializeORAM(N, 0)).rejects.toThrow(/bucket size/i);
    await expect(initializeORAM((1 << 16) + 1, Z)).rejects.toThrow(/block count/i);
  });
});
