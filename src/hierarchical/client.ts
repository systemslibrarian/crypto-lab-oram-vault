/**
 * Bounded hierarchical-ORAM teaching adaptation.
 *
 * This follows the generic access/rebuild schedule in Alibi §2.5/Fig. 2:
 * scan the cache, probe every level with either the real label or a fresh
 * dummy label, remove the found item, reinsert it at the top, and rebuild
 * geometrically larger levels with fresh hash keys. The hash table used here
 * is intentionally overprovisioned for N=16 so a build cannot overflow. It is
 * not the papers' asymptotically efficient oblivious hash table or proof.
 */

import {
  BLOCK_DATA_SIZE,
  createDummyBlock,
  decryptBlock,
  encryptBlock,
  generateClientKey,
  normalizeBlockData,
  type ClientKey,
} from '../client/encryption.js';
import {
  HierarchicalServer,
  type HierarchicalLevelShape,
  type HierarchicalServerEvent,
  type HierarchicalServerView,
} from './server.js';

export type ProbePolicy = 'all-levels' | 'skip-after-hit';
export type ProbeKind = 'cache' | 'real' | 'dummy';

interface PlainBlock {
  blockId: number;
  data: Uint8Array;
}

interface LevelState {
  occupied: boolean;
  epoch: number;
  hashKey: CryptoKey | null;
}

export interface HierarchicalProbeTrace {
  level: number;
  bucket: number;
  kind: ProbeKind;
  foundHere: boolean;
  slotCount: number;
}

export interface HierarchicalRebuildTrace {
  level: number;
  action: 'clear-for-carry' | 'build';
  priorEpoch: number;
  newEpoch: number;
  realBlocks: number;
  readSlots: number;
  writeSlots: number;
}

export interface HierarchicalTraffic {
  lookupReadSlots: number;
  lookupWriteSlots: number;
  rebuildReadSlots: number;
  rebuildWriteSlots: number;
  totalSlots: number;
}

export interface HierarchicalAccessTrace {
  accessNumber: number;
  operation: 'read' | 'write';
  blockId: number;
  policy: ProbePolicy;
  foundLevel: number;
  probes: HierarchicalProbeTrace[];
  rebuilds: HierarchicalRebuildTrace[];
  traffic: HierarchicalTraffic;
  /** The storage observer's complete view: physical coordinates and sizes only. */
  serverView: HierarchicalServerView;
}

export interface HierarchicalReadResult {
  data: Uint8Array;
  trace: HierarchicalAccessTrace;
}

export interface HierarchicalWriteResult {
  trace: HierarchicalAccessTrace;
}

export interface HierarchicalClientSummary {
  logicalBlocks: number;
  hashKeys: number;
  occupancyBits: number;
  accessCounterWords: number;
  transientRebuildBlocks: number;
  serverSlots: number;
  fixedLookupReadSlots: number;
  fixedLookupRoundTripSlots: number;
  levelEpochs: number[];
  occupiedLevels: boolean[];
}

export interface HierarchicalORAMClient {
  readonly N: number;
  readonly key: ClientKey;
  readonly server: HierarchicalServer;
  readonly levels: LevelState[];
  accessCount: number;
  maxTransientRebuildBlocks: number;
  readonly randomBytes: (length: number) => Uint8Array;
}

export class HierarchicalBlockUnavailableError extends Error {
  constructor(blockId: number) {
    super(`Hierarchical ORAM could not find authenticated block ${blockId} in any level.`);
    this.name = 'HierarchicalBlockUnavailableError';
  }
}

export class HierarchicalDuplicateBlockError extends Error {
  constructor(blockId: number) {
    super(`Hierarchical ORAM found more than one authenticated copy of block ${blockId}.`);
    this.name = 'HierarchicalDuplicateBlockError';
  }
}

const DEMO_BLOCKS = 16;
const HASH_KEY_BYTES = 32;
const MAX_ACCESS_NUMBER = 0xffffffff;
const accessTails = new WeakMap<HierarchicalORAMClient, Promise<void>>();

function assertInteger(name: string, value: number, min: number, max: number): void {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new RangeError(`${name} must be an integer in [${min}, ${max}].`);
  }
}

function defaultRandomBytes(length: number): Uint8Array {
  assertInteger('random byte length', length, 1, 1 << 20);
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function checkedRandomBytes(
  source: (length: number) => Uint8Array,
  length: number,
): Uint8Array {
  const bytes = source(length);
  if (!(bytes instanceof Uint8Array) || bytes.length !== length) {
    throw new TypeError(`randomBytes(${length}) must return exactly ${length} bytes.`);
  }
  return new Uint8Array(bytes);
}

export function hierarchyShapes(N = DEMO_BLOCKS): HierarchicalLevelShape[] {
  if (N !== DEMO_BLOCKS) {
    throw new RangeError(`This bounded lesson fixes N=${DEMO_BLOCKS}.`);
  }
  const levels = Math.log2(N);
  const shapes: HierarchicalLevelShape[] = [
    { level: 0, logicalCapacity: 1, bucketCount: 1, bucketSize: 1 },
  ];
  for (let level = 1; level <= levels; level++) {
    const capacity = 1 << level;
    // Every bucket can hold the entire logical level, so no seed retry or
    // data-dependent build failure is possible in this finite lesson.
    shapes.push({
      level,
      logicalCapacity: capacity,
      bucketCount: capacity,
      bucketSize: capacity,
    });
  }
  return shapes;
}

export async function importPlacementKey(raw: Uint8Array): Promise<CryptoKey> {
  if (!(raw instanceof Uint8Array) || raw.length !== HASH_KEY_BYTES) {
    throw new RangeError(`Placement key material must be ${HASH_KEY_BYTES} bytes.`);
  }
  return crypto.subtle.importKey(
    'raw',
    new Uint8Array(raw),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
}

/** HMAC-SHA-256 placement into a power-of-two bucket count (no modulo bias). */
export async function placementBucket(
  key: CryptoKey,
  label: Uint8Array,
  bucketCount: number,
): Promise<number> {
  if (!(label instanceof Uint8Array) || label.length === 0) {
    throw new TypeError('Placement label must be a non-empty Uint8Array.');
  }
  if (!Number.isSafeInteger(bucketCount) || bucketCount < 1 || (bucketCount & (bucketCount - 1)) !== 0) {
    throw new RangeError('bucketCount must be a positive power of two.');
  }
  const tag = new Uint8Array(await crypto.subtle.sign('HMAC', key, new Uint8Array(label)));
  const word = new DataView(tag.buffer, tag.byteOffset, tag.byteLength).getUint32(0, false);
  return word & (bucketCount - 1);
}

function realLabel(blockId: number): Uint8Array {
  const label = new Uint8Array(5);
  label[0] = 0;
  new DataView(label.buffer).setUint32(1, blockId, false);
  return label;
}

function dummyLabel(accessNumber: number, level: number): Uint8Array {
  const label = new Uint8Array(9);
  label[0] = 1;
  new DataView(label.buffer).setUint32(1, accessNumber, false);
  new DataView(label.buffer).setUint32(5, level, false);
  return label;
}

async function freshHashKey(client: HierarchicalORAMClient): Promise<CryptoKey> {
  return importPlacementKey(checkedRandomBytes(client.randomBytes, HASH_KEY_BYTES));
}

function clonePlain(block: PlainBlock): PlainBlock {
  return { blockId: block.blockId, data: new Uint8Array(block.data) };
}

function mergeDistinct(into: Map<number, PlainBlock>, blocks: PlainBlock[]): void {
  for (const block of blocks) {
    if (into.has(block.blockId)) throw new HierarchicalDuplicateBlockError(block.blockId);
    into.set(block.blockId, clonePlain(block));
  }
}

async function decodeSlots(
  client: HierarchicalORAMClient,
  buckets: ReturnType<HierarchicalServer['readLevel']>,
): Promise<Array<PlainBlock | null>> {
  const decoded: Array<PlainBlock | null> = [];
  for (const bucket of buckets) {
    for (const encrypted of bucket) {
      const block = await decryptBlock(encrypted, client.key);
      if (block === null) {
        decoded.push(null);
        continue;
      }
      assertInteger('authenticated block id', block.blockId, 0, client.N - 1);
      decoded.push({ blockId: block.blockId, data: new Uint8Array(block.data) });
    }
  }
  return decoded;
}

async function encodeBucket(
  client: HierarchicalORAMClient,
  blocks: Array<PlainBlock | null>,
): Promise<Awaited<ReturnType<typeof createDummyBlock>>[]> {
  return Promise.all(
    blocks.map((block) =>
      block === null
        ? createDummyBlock(client.key)
        : encryptBlock(block.blockId, block.data, client.key),
    ),
  );
}

async function buildLevel(
  client: HierarchicalORAMClient,
  level: number,
  blocks: PlainBlock[],
  phase: 'setup' | 'rebuild',
): Promise<{ priorEpoch: number; newEpoch: number; writeSlots: number }> {
  const shape = client.server.getShapes()[level];
  const state = client.levels[level];
  if (!shape || !state) throw new Error(`Missing hierarchy level ${level}.`);
  if (blocks.length > shape.logicalCapacity) {
    throw new RangeError(
      `Level ${level} received ${blocks.length} real blocks, capacity ${shape.logicalCapacity}.`,
    );
  }
  const ids = new Set<number>();
  for (const block of blocks) {
    assertInteger('blockId', block.blockId, 0, client.N - 1);
    if (ids.has(block.blockId)) throw new HierarchicalDuplicateBlockError(block.blockId);
    ids.add(block.blockId);
  }

  const priorEpoch = state.epoch;
  state.epoch += 1;
  if (level > 0) state.hashKey = await freshHashKey(client);

  const plainBuckets: Array<Array<PlainBlock | null>> = Array.from(
    { length: shape.bucketCount },
    () => Array<PlainBlock | null>(shape.bucketSize).fill(null),
  );
  for (const block of blocks) {
    const bucket = level === 0
      ? 0
      : await placementBucket(state.hashKey as CryptoKey, realLabel(block.blockId), shape.bucketCount);
    const target = plainBuckets[bucket];
    if (!target) throw new Error(`Missing plaintext bucket ${bucket}.`);
    const slot = target.findIndex((item) => item === null);
    // With at most capacity real blocks and capacity slots in every bucket,
    // this cannot occur. It is an executable guard on that teaching bound.
    if (slot < 0) throw new Error(`Bounded level ${level} overflowed bucket ${bucket}.`);
    target[slot] = clonePlain(block);
  }

  const encrypted = await Promise.all(
    plainBuckets.map((bucket) => encodeBucket(client, bucket)),
  );
  client.server.replaceLevel(level, encrypted, phase);
  state.occupied = blocks.length > 0;
  return {
    priorEpoch,
    newEpoch: state.epoch,
    writeSlots: shape.bucketCount * shape.bucketSize,
  };
}

async function extractLevel(
  client: HierarchicalORAMClient,
  level: number,
): Promise<PlainBlock[]> {
  const decoded = await decodeSlots(client, client.server.readLevel(level, 'rebuild'));
  const blocks = new Map<number, PlainBlock>();
  for (const block of decoded) {
    if (block === null) continue;
    if (blocks.has(block.blockId)) throw new HierarchicalDuplicateBlockError(block.blockId);
    blocks.set(block.blockId, clonePlain(block));
  }
  return [...blocks.values()];
}

async function reinsert(
  client: HierarchicalORAMClient,
  block: PlainBlock,
): Promise<HierarchicalRebuildTrace[]> {
  const traces: HierarchicalRebuildTrace[] = [];
  const shapes = client.server.getShapes();
  let carry = new Map<number, PlainBlock>([[block.blockId, clonePlain(block)]]);

  for (let level = 0; level < shapes.length; level++) {
    const shape = shapes[level];
    const state = client.levels[level];
    if (!shape || !state) throw new Error(`Missing hierarchy level ${level}.`);
    const wasOccupied = state.occupied;
    let readSlots = 0;
    if (wasOccupied) {
      const extracted = await extractLevel(client, level);
      readSlots = shape.bucketCount * shape.bucketSize;
      mergeDistinct(carry, extracted);
    }
    client.maxTransientRebuildBlocks = Math.max(
      client.maxTransientRebuildBlocks,
      carry.size,
    );

    const isLast = level === shapes.length - 1;
    if (!wasOccupied || isLast) {
      const built = await buildLevel(client, level, [...carry.values()], 'rebuild');
      traces.push({
        level,
        action: 'build',
        priorEpoch: built.priorEpoch,
        newEpoch: built.newEpoch,
        realBlocks: carry.size,
        readSlots,
        writeSlots: built.writeSlots,
      });
      return traces;
    }

    const cleared = await buildLevel(client, level, [], 'rebuild');
    traces.push({
      level,
      action: 'clear-for-carry',
      priorEpoch: cleared.priorEpoch,
      newEpoch: cleared.newEpoch,
      realBlocks: carry.size,
      readSlots,
      writeSlots: cleared.writeSlots,
    });
  }
  throw new Error('Hierarchy reinsertion exhausted every level.');
}

function trafficFrom(events: HierarchicalServerEvent[]): HierarchicalTraffic {
  const sum = (phase: 'lookup' | 'rebuild', operation: 'read' | 'write'): number =>
    events
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

async function serialize<T>(
  client: HierarchicalORAMClient,
  task: () => Promise<T>,
): Promise<T> {
  const prior = (accessTails.get(client) ?? Promise.resolve()).catch(() => undefined);
  let release = (): void => {};
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const tail = prior.then(() => gate);
  accessTails.set(client, tail);
  await prior;
  try {
    return await task();
  } finally {
    release();
    if (accessTails.get(client) === tail) accessTails.delete(client);
  }
}

export async function initializeHierarchicalORAM(
  options: {
    randomBytes?: (length: number) => Uint8Array;
  } = {},
): Promise<HierarchicalORAMClient> {
  const shapes = hierarchyShapes();
  const server = new HierarchicalServer(shapes);
  const client: HierarchicalORAMClient = {
    N: DEMO_BLOCKS,
    key: await generateClientKey(),
    server,
    levels: shapes.map(() => ({ occupied: false, epoch: 0, hashKey: null })),
    accessCount: 0,
    maxTransientRebuildBlocks: 0,
    randomBytes: options.randomBytes ?? defaultRandomBytes,
  };

  // Every level exists from setup onward. Only the bottom starts occupied.
  for (let level = 0; level < shapes.length - 1; level++) {
    await buildLevel(client, level, [], 'setup');
  }
  const initial = Array.from({ length: client.N }, (_, blockId) => ({
    blockId,
    data: new Uint8Array(BLOCK_DATA_SIZE),
  }));
  await buildLevel(client, shapes.length - 1, initial, 'setup');
  client.maxTransientRebuildBlocks = client.N;
  server.clearTrace();
  return client;
}

async function access(
  client: HierarchicalORAMClient,
  operation: 'read' | 'write',
  blockId: number,
  newData: Uint8Array | undefined,
  policy: ProbePolicy,
): Promise<{ data: Uint8Array; trace: HierarchicalAccessTrace }> {
  return serialize(client, async () => {
    if (operation !== 'read' && operation !== 'write') throw new TypeError('Invalid operation.');
    assertInteger('blockId', blockId, 0, client.N - 1);
    if (policy !== 'all-levels' && policy !== 'skip-after-hit') {
      throw new TypeError('Invalid probe policy.');
    }
    if (operation === 'write' && newData === undefined) {
      throw new TypeError('newData is required for write.');
    }
    const writeData = operation === 'write'
      ? normalizeBlockData(newData as Uint8Array)
      : null;

    if (client.accessCount >= MAX_ACCESS_NUMBER) {
      throw new Error('Hierarchical ORAM access counter exhausted before dummy-label reuse.');
    }
    client.accessCount += 1;
    const accessNumber = client.accessCount;
    const eventStart = client.server.traceLength();
    const probes: HierarchicalProbeTrace[] = [];
    let found: PlainBlock | null = null;
    let foundLevel = -1;

    const shapes = client.server.getShapes();
    for (let level = 0; level < shapes.length; level++) {
      const shape = shapes[level];
      const state = client.levels[level];
      if (!shape || !state) throw new Error(`Missing hierarchy level ${level}.`);
      if (policy === 'skip-after-hit' && found !== null && level > 0) break;

      const kind: ProbeKind = level === 0 ? 'cache' : found === null ? 'real' : 'dummy';
      const bucket = level === 0
        ? 0
        : await placementBucket(
            state.hashKey as CryptoKey,
            kind === 'real' ? realLabel(blockId) : dummyLabel(accessNumber, level),
            shape.bucketCount,
          );
      const encrypted = client.server.readBucket(level, bucket, 'lookup');
      const decoded = await decodeSlots(client, [encrypted]);
      let foundHere = false;
      const seen = new Set<number>();
      for (let slot = 0; slot < decoded.length; slot++) {
        const item = decoded[slot];
        if (item === null) continue;
        if (seen.has(item.blockId)) throw new HierarchicalDuplicateBlockError(item.blockId);
        seen.add(item.blockId);
        if (item.blockId === blockId) {
          if (found !== null) throw new HierarchicalDuplicateBlockError(blockId);
          if (kind !== 'real' && kind !== 'cache') throw new HierarchicalDuplicateBlockError(blockId);
          found = clonePlain(item);
          foundLevel = level;
          foundHere = true;
          decoded[slot] = null;
        }
      }
      client.server.writeBucket(level, bucket, await encodeBucket(client, decoded), 'lookup');
      probes.push({ level, bucket, kind, foundHere, slotCount: shape.bucketSize });
    }

    if (found === null) throw new HierarchicalBlockUnavailableError(blockId);
    const returned = operation === 'write'
      ? new Uint8Array(writeData as Uint8Array)
      : new Uint8Array(found.data);
    const replacement: PlainBlock = {
      blockId,
      data: operation === 'write'
        ? new Uint8Array(writeData as Uint8Array)
        : new Uint8Array(found.data),
    };
    const rebuilds = await reinsert(client, replacement);
    const serverView = client.server.getView(eventStart);
    return {
      data: returned,
      trace: {
        accessNumber,
        operation,
        blockId,
        policy,
        foundLevel,
        probes,
        rebuilds,
        traffic: trafficFrom(serverView.events),
        serverView,
      },
    };
  });
}

export async function hierarchicalRead(
  client: HierarchicalORAMClient,
  blockId: number,
  policy: ProbePolicy = 'all-levels',
): Promise<HierarchicalReadResult> {
  const result = await access(client, 'read', blockId, undefined, policy);
  return { data: new Uint8Array(result.data), trace: result.trace };
}

export async function hierarchicalWrite(
  client: HierarchicalORAMClient,
  blockId: number,
  data: Uint8Array,
  policy: ProbePolicy = 'all-levels',
): Promise<HierarchicalWriteResult> {
  const result = await access(client, 'write', blockId, data, policy);
  return { trace: result.trace };
}

export function getHierarchicalServerView(
  client: HierarchicalORAMClient,
  fromEvent = 0,
): HierarchicalServerView {
  return client.server.getView(fromEvent);
}

export function getHierarchicalClientSummary(
  client: HierarchicalORAMClient,
): HierarchicalClientSummary {
  const shapes = client.server.getShapes();
  const fixedLookupReadSlots = shapes.reduce((total, shape) => total + shape.bucketSize, 0);
  return {
    logicalBlocks: client.N,
    hashKeys: client.levels.slice(1).length,
    occupancyBits: client.levels.length,
    accessCounterWords: 1,
    transientRebuildBlocks: client.maxTransientRebuildBlocks,
    serverSlots: client.server.physicalSlotCount(),
    fixedLookupReadSlots,
    fixedLookupRoundTripSlots: 2 * fixedLookupReadSlots,
    levelEpochs: client.levels.map((level) => level.epoch),
    occupiedLevels: client.levels.map((level) => level.occupied),
  };
}
