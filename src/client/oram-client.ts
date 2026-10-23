/**
 * Trusted Path ORAM client for the fixed-size browser demonstration.
 *
 * Implements the access algorithm from Stefanov et al., with explicit runtime
 * boundaries around the educational module API. This is not a hardened ORAM
 * service: the position map and stash remain ordinary browser memory.
 */

import type { ClientKey } from './encryption.js';
import {
  BLOCK_DATA_SIZE,
  createDummyBlock,
  decryptBlock,
  encryptBlock,
  generateClientKey,
  normalizeBlockData,
} from './encryption.js';
import type { Bucket } from '../server/oram-server.js';
import {
  createServer,
  getServerGeneration,
  serverReadPath,
  serverWritePath,
} from '../server/oram-server.js';

export class StaleVaultError extends Error {
  constructor() {
    super(
      'This ORAM client was provisioned against a server tree that has since been replaced. ' +
        'Re-initialize before accessing it.',
    );
    this.name = 'StaleVaultError';
  }
}

export class BlockUnavailableError extends Error {
  constructor(blockId: number) {
    super(
      `Block ${blockId} was not present in the authenticated path or client stash. ` +
        'The server response is incomplete, stale, or corrupt.',
    );
    this.name = 'BlockUnavailableError';
  }
}

export class DuplicateBlockError extends Error {
  constructor(blockId: number) {
    super(`Block ${blockId} appeared more than once across the path and stash.`);
    this.name = 'DuplicateBlockError';
  }
}

export interface ORAMClient {
  L: number;
  Z: number;
  N: number;
  key: ClientKey;
  positionMap: Map<number, number>;
  stash: Map<number, Uint8Array>;
  maxStashSize: number;
  lastWriteBack: { leaf: number; realIdsPerLevel: number[][] } | null;
  serverGeneration: number;
}

const MAX_BLOCKS = 1 << 16;
const MAX_BUCKET_SIZE = 64;
const accessTails = new WeakMap<ORAMClient, Promise<void>>();

function assertCurrentServer(client: ORAMClient): void {
  if (client.serverGeneration !== getServerGeneration()) throw new StaleVaultError();
}

function assertIntegerInRange(name: string, value: number, min: number, max: number): void {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new RangeError(`${name} must be an integer in [${min}, ${max}].`);
  }
}

/** Pick a uniformly random leaf. The leaf count is a power of two. */
function randomLeaf(L: number): number {
  const numLeaves = 1 << L;
  const sample = new Uint32Array(1);
  crypto.getRandomValues(sample);
  return (sample[0] as number) & (numLeaves - 1);
}

function intersects(blockLeaf: number, pathLeaf: number, level: number, L: number): boolean {
  const shift = L - level;
  return (blockLeaf >> shift) === (pathLeaf >> shift);
}

function copyLastWriteBack(
  value: ORAMClient['lastWriteBack'],
): ORAMClient['lastWriteBack'] {
  return value
    ? { leaf: value.leaf, realIdsPerLevel: value.realIdsPerLevel.map((ids) => [...ids]) }
    : null;
}

function copyStash(stash: Map<number, Uint8Array>): Map<number, Uint8Array> {
  return new Map([...stash].map(([id, data]) => [id, new Uint8Array(data)]));
}

async function serializeAccess<T>(client: ORAMClient, task: () => Promise<T>): Promise<T> {
  const previous = (accessTails.get(client) ?? Promise.resolve()).catch(() => undefined);
  let release = (): void => {};
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const tail = previous.then(() => gate);
  accessTails.set(client, tail);
  await previous;
  try {
    return await task();
  } finally {
    release();
    if (accessTails.get(client) === tail) accessTails.delete(client);
  }
}

async function decryptPath(client: ORAMClient, pathBuckets: Bucket[]): Promise<Map<number, Uint8Array>> {
  const recovered = new Map<number, Uint8Array>();
  for (const bucket of pathBuckets) {
    for (const encrypted of bucket.blocks) {
      // Empty slots occur only while the initial tree is being provisioned.
      if (encrypted.ciphertext.length === 0) continue;
      const block = await decryptBlock(encrypted, client.key);
      if (block === null) continue;
      if (!client.positionMap.has(block.blockId)) {
        throw new BlockUnavailableError(block.blockId);
      }
      if (recovered.has(block.blockId)) throw new DuplicateBlockError(block.blockId);
      recovered.set(block.blockId, new Uint8Array(block.data));
    }
  }
  return recovered;
}

function mergeRecovered(client: ORAMClient, recovered: Map<number, Uint8Array>): void {
  for (const [blockId, data] of recovered) {
    if (client.stash.has(blockId)) throw new DuplicateBlockError(blockId);
    client.stash.set(blockId, new Uint8Array(data));
  }
}

/** Initialize N zero-filled logical blocks and provision every server path. */
export async function initializeORAM(N: number, Z: number): Promise<ORAMClient> {
  assertIntegerInRange('block count N', N, 1, MAX_BLOCKS);
  assertIntegerInRange('bucket size Z', Z, 1, MAX_BUCKET_SIZE);
  const L = Math.ceil(Math.log2(N));

  // Generate before replacing the singleton tree. A concurrent initialization
  // that starts later will either become the new generation or be detected by
  // the generation checks around every asynchronous write-back.
  const key = await generateClientKey();
  createServer(L, Z);
  const positionMap = new Map<number, number>();
  const stash = new Map<number, Uint8Array>();
  for (let blockId = 0; blockId < N; blockId++) {
    positionMap.set(blockId, randomLeaf(L));
    stash.set(blockId, new Uint8Array(BLOCK_DATA_SIZE));
  }

  const client: ORAMClient = {
    L,
    Z,
    N,
    key,
    positionMap,
    stash,
    maxStashSize: stash.size,
    lastWriteBack: null,
    serverGeneration: getServerGeneration(),
  };

  // Each later path overlaps buckets written earlier. Reabsorb the path before
  // overwriting it so initialization never discards a real block from a shared
  // ancestor bucket.
  const numLeaves = 1 << L;
  for (let leaf = 0; leaf < numLeaves; leaf++) {
    assertCurrentServer(client);
    const recovered = await decryptPath(client, serverReadPath(leaf));
    assertCurrentServer(client);
    mergeRecovered(client, recovered);
    await writeBackPath(client, leaf);
  }

  // Setup stages all blocks temporarily. The displayed high-water mark starts
  // from the initialized steady state rather than counting that setup detail.
  client.maxStashSize = client.stash.size;
  return client;
}

/** Serialized Path ORAM access; concurrent callers execute in call order. */
export async function access(
  client: ORAMClient,
  op: 'read' | 'write',
  blockId: number,
  newData?: Uint8Array,
): Promise<Uint8Array> {
  return serializeAccess(client, async () => {
    if (op !== 'read' && op !== 'write') throw new TypeError('op must be read or write.');
    assertIntegerInRange('blockId', blockId, 0, client.N - 1);
    let writeData: Uint8Array | null = null;
    if (op === 'write') {
      if (newData === undefined) throw new TypeError('newData is required for write.');
      writeData = normalizeBlockData(newData);
    }
    assertCurrentServer(client);

    const oldLeaf = client.positionMap.get(blockId);
    if (oldLeaf === undefined) throw new Error(`Block ${blockId} is absent from the position map.`);
    const oldStash = copyStash(client.stash);
    const oldMaxStashSize = client.maxStashSize;
    const oldWriteBack = copyLastWriteBack(client.lastWriteBack);

    try {
      client.positionMap.set(blockId, randomLeaf(client.L));
      const recovered = await decryptPath(client, serverReadPath(oldLeaf));
      assertCurrentServer(client);
      mergeRecovered(client, recovered);
      client.maxStashSize = Math.max(client.maxStashSize, client.stash.size);

      if (!client.stash.has(blockId)) throw new BlockUnavailableError(blockId);
      let result: Uint8Array;
      if (op === 'write') {
        client.stash.set(blockId, new Uint8Array(writeData!));
        result = new Uint8Array(writeData!);
      } else {
        result = new Uint8Array(client.stash.get(blockId)!);
      }

      await writeBackPath(client, oldLeaf);
      return result;
    } catch (error) {
      // No server write occurred unless writeBackPath completed, in which case
      // it cannot throw afterwards. Restore client state for all failed reads,
      // authentication failures, stale-generation checks, and invalid payloads.
      client.positionMap.set(blockId, oldLeaf);
      client.stash.clear();
      for (const [id, data] of oldStash) client.stash.set(id, new Uint8Array(data));
      client.maxStashSize = oldMaxStashSize;
      client.lastWriteBack = oldWriteBack;
      throw error;
    }
  });
}

/** Build and atomically write one greedily evicted root-to-leaf path. */
export async function writeBackPath(client: ORAMClient, leafId: number): Promise<void> {
  assertCurrentServer(client);
  assertIntegerInRange('leafId', leafId, 0, (1 << client.L) - 1);
  const { L, Z, key, positionMap, stash } = client;
  const bucketsLeafToRoot: Bucket[] = [];
  const idsLeafToRoot: number[][] = [];
  const reserved = new Set<number>();

  for (let level = L; level >= 0; level--) {
    const candidates: number[] = [];
    for (const [blockId] of stash) {
      if (reserved.has(blockId)) continue;
      const blockLeaf = positionMap.get(blockId);
      if (blockLeaf !== undefined && intersects(blockLeaf, leafId, level, L)) {
        candidates.push(blockId);
      }
    }
    candidates.sort((a, b) => (positionMap.get(a) ?? 0) - (positionMap.get(b) ?? 0));
    const picked = candidates.slice(0, Z);
    picked.forEach((blockId) => reserved.add(blockId));
    idsLeafToRoot.push([...picked]);

    const blocks = await Promise.all(
      picked.map((blockId) => encryptBlock(blockId, stash.get(blockId)!, key)),
    );
    const dummyCount = Z - blocks.length;
    blocks.push(...await Promise.all(
      Array.from({ length: dummyCount }, () => createDummyBlock(key)),
    ));
    bucketsLeafToRoot.push({ blocks });
  }

  assertCurrentServer(client);
  serverWritePath(leafId, [...bucketsLeafToRoot].reverse());
  for (const blockId of reserved) stash.delete(blockId);
  client.lastWriteBack = {
    leaf: leafId,
    realIdsPerLevel: [...idsLeafToRoot].reverse().map((ids) => [...ids]),
  };
}

export async function read(client: ORAMClient, blockId: number): Promise<Uint8Array> {
  return access(client, 'read', blockId);
}

export async function write(
  client: ORAMClient,
  blockId: number,
  data: Uint8Array,
): Promise<void> {
  await access(client, 'write', blockId, data);
}

/** Report the recorded real placement for the most recently written path. */
export function reconstructPathPlacement(
  client: ORAMClient,
  leafId: number,
): { perLevel: number[][]; eligibleLevel: Map<number, number> } {
  assertIntegerInRange('leafId', leafId, 0, (1 << client.L) - 1);
  const { L, positionMap, lastWriteBack } = client;
  const eligibleLevel = new Map<number, number>();
  for (const [blockId, blockLeaf] of positionMap) {
    let deepest = -1;
    for (let level = 0; level <= L; level++) {
      if (intersects(blockLeaf, leafId, level, L)) deepest = level;
    }
    if (deepest >= 0) eligibleLevel.set(blockId, deepest);
  }
  const perLevel = lastWriteBack?.leaf === leafId
    ? lastWriteBack.realIdsPerLevel.map((ids) => [...ids])
    : Array.from({ length: L + 1 }, () => [] as number[]);
  return { perLevel, eligibleLevel };
}

export function getStashSize(client: ORAMClient): number {
  return client.stash.size;
}

export function getStashHighWater(client: ORAMClient): number {
  return client.maxStashSize;
}
