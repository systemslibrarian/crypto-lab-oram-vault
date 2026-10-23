/**
 * The untrusted storage service. It stores fixed-size encrypted buckets and
 * responds only to whole-path reads and writes. Logical block ids, plaintext,
 * the position map, and the stash are never passed across this API.
 */

export interface EncryptedBlock {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
}

export interface Bucket {
  blocks: EncryptedBlock[];
}

export interface ServerStats {
  totalReads: number;
  totalWrites: number;
  accessLog: Array<{
    bucketId: number;
    operation: 'read' | 'write';
    timestamp: number;
  }>;
}

interface InternalLogEntry {
  bucketId: number;
  operation: 'read' | 'write';
  timestamp: number;
  requestId: number;
}

interface ServerState {
  buckets: Bucket[];
  L: number;
  Z: number;
  totalReads: number;
  totalWrites: number;
  accessLog: InternalLogEntry[];
  nextRequestId: number;
}

const NONCE_BYTES = 12;
const CIPHERTEXT_BYTES = 4 + 32 + 16;
const MAX_TREE_HEIGHT = 16;
const MAX_BUCKET_SIZE = 64;
const MAX_LOG_ENTRIES = 10_000;

let state: ServerState | null = null;
let generation = 0;

function getState(): ServerState {
  if (!state) throw new Error('Server not initialized. Call createServer() first.');
  return state;
}

function assertIntegerInRange(name: string, value: number, min: number, max: number): void {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new RangeError(`${name} must be an integer in [${min}, ${max}].`);
  }
}

function assertLeaf(leafId: number, L: number): void {
  assertIntegerInRange('leafId', leafId, 0, (1 << L) - 1);
}

function copyEncryptedBlock(block: EncryptedBlock, context: string): EncryptedBlock {
  if (!block || !(block.ciphertext instanceof Uint8Array)) {
    throw new TypeError(`${context} ciphertext must be a Uint8Array.`);
  }
  if (!(block.nonce instanceof Uint8Array)) {
    throw new TypeError(`${context} nonce must be a Uint8Array.`);
  }
  if (block.ciphertext.length !== CIPHERTEXT_BYTES) {
    throw new RangeError(`${context} ciphertext must be exactly ${CIPHERTEXT_BYTES} bytes.`);
  }
  if (block.nonce.length !== NONCE_BYTES) {
    throw new RangeError(`${context} nonce must be exactly ${NONCE_BYTES} bytes.`);
  }
  return {
    ciphertext: new Uint8Array(block.ciphertext),
    nonce: new Uint8Array(block.nonce),
  };
}

function appendPathLog(
  current: ServerState,
  ids: number[],
  operation: 'read' | 'write',
): void {
  const timestamp = Date.now();
  const requestId = current.nextRequestId++;
  for (const bucketId of ids) {
    current.accessLog.push({ bucketId, operation, timestamp, requestId });
  }
  if (current.accessLog.length > MAX_LOG_ENTRIES) {
    current.accessLog.splice(0, current.accessLog.length - MAX_LOG_ENTRIES);
  }
}

/** Which provisioning of the singleton server tree is currently live. */
export function getServerGeneration(): number {
  return generation;
}

/** Map a validated leaf id to root-to-leaf bucket indices. */
function pathBucketIds(leafId: number, L: number): number[] {
  assertIntegerInRange('tree height L', L, 0, MAX_TREE_HEIGHT);
  assertLeaf(leafId, L);
  const ids: number[] = [];
  for (let level = 0; level <= L; level++) {
    const levelStart = (1 << level) - 1;
    const leavesPerNode = 1 << (L - level);
    ids.push(levelStart + Math.floor(leafId / leavesPerNode));
  }
  return ids;
}

/** Provision an empty fixed-geometry tree, replacing any previous tree. */
export function createServer(
  L: number,
  Z: number,
): { numBuckets: number; numLeaves: number; treeHeight: number } {
  assertIntegerInRange('tree height L', L, 0, MAX_TREE_HEIGHT);
  assertIntegerInRange('bucket size Z', Z, 1, MAX_BUCKET_SIZE);
  const numBuckets = (1 << (L + 1)) - 1;
  const numLeaves = 1 << L;

  generation += 1;
  state = {
    buckets: Array.from({ length: numBuckets }, () => ({ blocks: [] })),
    L,
    Z,
    totalReads: 0,
    totalWrites: 0,
    accessLog: [],
    nextRequestId: 1,
  };
  return { numBuckets, numLeaves, treeHeight: L };
}

/** Read one complete path. Returned bytes never alias server-owned storage. */
export function serverReadPath(leafId: number): Bucket[] {
  const current = getState();
  const ids = pathBucketIds(leafId, current.L);
  const result = ids.map((id) => {
    const bucket = current.buckets[id];
    if (!bucket) throw new Error(`Bucket ${id} does not exist.`);
    return {
      blocks: bucket.blocks.map((block, index) =>
        copyEncryptedBlock(block, `Bucket ${id} block ${index}`),
      ),
    };
  });
  appendPathLog(current, ids, 'read');
  current.totalReads += ids.length;
  return result;
}

/**
 * Atomically replace one complete path. The whole payload is validated and
 * copied before any server bucket changes, so a malformed later bucket cannot
 * leave a partially written tree.
 */
export function serverWritePath(leafId: number, buckets: Bucket[]): void {
  const current = getState();
  const ids = pathBucketIds(leafId, current.L);
  if (!Array.isArray(buckets) || buckets.length !== ids.length) {
    throw new RangeError(`Expected ${ids.length} buckets for path, got ${buckets?.length ?? 0}.`);
  }

  const prepared = buckets.map((bucket, level) => {
    if (!bucket || !Array.isArray(bucket.blocks)) {
      throw new TypeError(`Bucket at level ${level} must contain a blocks array.`);
    }
    if (bucket.blocks.length !== current.Z) {
      throw new RangeError(
        `Bucket at level ${level} has ${bucket.blocks.length} blocks, expected ${current.Z}.`,
      );
    }
    return {
      blocks: bucket.blocks.map((block, index) =>
        copyEncryptedBlock(block, `Bucket at level ${level} block ${index}`),
      ),
    };
  });

  for (let index = 0; index < ids.length; index++) {
    const bucketId = ids[index];
    const replacement = prepared[index];
    if (replacement === undefined) throw new Error(`Missing validated bucket ${index}.`);
    current.buckets[bucketId] = replacement;
  }
  appendPathLog(current, ids, 'write');
  current.totalWrites += ids.length;
}

/** Return bounded, copied server-visible statistics for the teaching UI. */
export function getServerStats(): ServerStats {
  const current = getState();
  return {
    totalReads: current.totalReads,
    totalWrites: current.totalWrites,
    accessLog: current.accessLog.slice(-200).map(({ bucketId, operation, timestamp }) => ({
      bucketId,
      operation,
      timestamp,
    })),
  };
}

/** Group bucket-level log entries by the exact path request that produced them. */
export function getServerView(): Array<{
  bucketIds: number[];
  operation: 'read' | 'write';
}> {
  const log = getState().accessLog;
  const grouped: Array<{ bucketIds: number[]; operation: 'read' | 'write' }> = [];
  let index = 0;
  while (index < log.length) {
    const first = log[index];
    if (!first) {
      index += 1;
      continue;
    }
    const bucketIds: number[] = [];
    while (
      index < log.length &&
      log[index]?.requestId === first.requestId &&
      log[index]?.operation === first.operation
    ) {
      const entry = log[index];
      if (entry) bucketIds.push(entry.bucketId);
      index += 1;
    }
    grouped.push({ bucketIds, operation: first.operation });
  }
  return grouped;
}

/**
 * Return a deep snapshot of the encrypted tree for visualization/testing.
 * Mutating the snapshot cannot alter server-owned state.
 */
export function getServerBuckets(): ReadonlyArray<Readonly<Bucket>> {
  return getState().buckets.map((bucket, bucketIndex) => ({
    blocks: bucket.blocks.map((block, blockIndex) =>
      copyEncryptedBlock(block, `Bucket ${bucketIndex} block ${blockIndex}`),
    ),
  }));
}

/** Return the bucket ids on one validated root-to-leaf path. */
export function getPathBucketIds(leafId: number): number[] {
  const current = getState();
  return pathBucketIds(leafId, current.L);
}
