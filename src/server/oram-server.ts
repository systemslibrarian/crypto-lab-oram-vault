/**
 * The untrusted server. Only stores encrypted buckets, only responds
 * to path requests. CANNOT see block IDs, cannot see access patterns
 * beyond "which bucket was read/written."
 *
 * In production, this is a Web Worker or separate module with a
 * message-passing interface. The client literally cannot peek at
 * position map or stash — they're not in this module.
 */

export interface EncryptedBlock {
  ciphertext: Uint8Array; // AES-GCM encryption of (id || data)
  nonce: Uint8Array; // 12 bytes
}

export interface Bucket {
  blocks: EncryptedBlock[]; // exactly Z blocks, real or dummy
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

// Internal server state — completely opaque to client code
interface ServerState {
  buckets: Bucket[];
  L: number;
  Z: number;
  stats: ServerStats;
}

let _state: ServerState | null = null;

function getState(): ServerState {
  if (!_state) throw new Error('Server not initialized. Call createServer() first.');
  return _state;
}

/**
 * Map a leafId to the sequence of bucket indices from root to leaf.
 * The tree is stored as a complete binary tree in array form.
 * Level 0 = root (bucket 0).
 * Level ℓ has 2^ℓ buckets starting at index 2^ℓ - 1.
 */
function pathBucketIds(leafId: number, L: number): number[] {
  // leafId ∈ [0, 2^L)
  // The leaf nodes start at index 2^L - 1 in the array.
  // To navigate from root to leaf: at each level ℓ the node index for
  // the path to leafId is: (2^ℓ - 1) + floor(leafId / 2^(L - ℓ))
  const ids: number[] = [];
  for (let level = 0; level <= L; level++) {
    const levelStart = (1 << level) - 1; // 2^level - 1
    const nodesPerLeaf = 1 << (L - level); // 2^(L-level)
    const nodeIndex = levelStart + Math.floor(leafId / nodesPerLeaf);
    ids.push(nodeIndex);
  }
  return ids;
}

/**
 * Initialize empty tree with dummy blocks in every bucket.
 * Returns metadata about the tree. Does NOT return the contents.
 */
export function createServer(
  L: number,
  Z: number,
): { numBuckets: number; numLeaves: number; treeHeight: number } {
  const numBuckets = (1 << (L + 1)) - 1; // 2^(L+1) - 1
  const numLeaves = 1 << L; // 2^L

  // Initialize with empty buckets — client will fill with dummy blocks
  const buckets: Bucket[] = Array.from({ length: numBuckets }, () => ({
    blocks: [],
  }));

  _state = {
    buckets,
    L,
    Z,
    stats: {
      totalReads: 0,
      totalWrites: 0,
      accessLog: [],
    },
  };

  return { numBuckets, numLeaves, treeHeight: L };
}

/**
 * READ a path from root to leaf `leafId`.
 * Server sees: leafId (just a number in [0, 2^L))
 * Server does NOT see: which block is being accessed
 */
export function serverReadPath(leafId: number): Bucket[] {
  const state = getState();
  const ids = pathBucketIds(leafId, state.L);
  const now = Date.now();
  const result: Bucket[] = [];

  for (const id of ids) {
    const bucket = state.buckets[id];
    if (!bucket) throw new Error(`Bucket ${id} does not exist`);
    // Deep copy so client cannot mutate internal state
    result.push({
      blocks: bucket.blocks.map((b) => ({
        ciphertext: new Uint8Array(b.ciphertext),
        nonce: new Uint8Array(b.nonce),
      })),
    });
    state.stats.accessLog.push({ bucketId: id, operation: 'read', timestamp: now });
    state.stats.totalReads++;
  }

  return result;
}

/**
 * WRITE back a path root-to-leaf.
 * Server sees: leafId and Z×(L+1) encrypted blocks
 * Server CANNOT tell real from dummy blocks (all encrypted the same)
 */
export function serverWritePath(leafId: number, buckets: Bucket[]): void {
  const state = getState();
  const ids = pathBucketIds(leafId, state.L);

  if (buckets.length !== ids.length) {
    throw new Error(
      `Expected ${ids.length} buckets for path, got ${buckets.length}`,
    );
  }

  const now = Date.now();
  for (let i = 0; i < ids.length; i++) {
    const id = ids[i];
    const incoming = buckets[i];
    if (!incoming) throw new Error(`Missing bucket at index ${i}`);
    if (incoming.blocks.length !== state.Z) {
      throw new Error(
        `Bucket at level ${i} has ${incoming.blocks.length} blocks, expected ${state.Z}`,
      );
    }
    // Deep copy incoming data
    state.buckets[id] = {
      blocks: incoming.blocks.map((b) => ({
        ciphertext: new Uint8Array(b.ciphertext),
        nonce: new Uint8Array(b.nonce),
      })),
    };
    state.stats.accessLog.push({ bucketId: id, operation: 'write', timestamp: now });
    state.stats.totalWrites++;
  }
}

/**
 * Get server statistics (for UI transparency).
 * What the server learns: total accesses, which paths were touched, timing.
 * What the server does NOT learn: block IDs, block contents, logical access pattern.
 */
export function getServerStats(): ServerStats {
  const state = getState();
  return {
    totalReads: state.stats.totalReads,
    totalWrites: state.stats.totalWrites,
    // Return a copy of the last N entries for display
    accessLog: state.stats.accessLog.slice(-200).map((e) => ({ ...e })),
  };
}

/**
 * Returns the "server view" — what an attacker watching the server
 * would see: just a stream of bucket accesses.
 */
export function getServerView(): Array<{ bucketIds: number[]; operation: 'read' | 'write' }> {
  const state = getState();
  // Group consecutive same-timestamp entries into path accesses
  const log = state.stats.accessLog;
  const grouped: Array<{ bucketIds: number[]; operation: 'read' | 'write' }> = [];
  let i = 0;
  while (i < log.length) {
    const entry = log[i];
    if (!entry) { i++; continue; }
    const ts = entry.timestamp;
    const op = entry.operation;
    const ids: number[] = [];
    while (i < log.length && log[i]?.timestamp === ts && log[i]?.operation === op) {
      const e = log[i];
      if (e) ids.push(e.bucketId);
      i++;
    }
    grouped.push({ bucketIds: ids, operation: op });
  }
  return grouped;
}

/**
 * Get all bucket contents (opaque encrypted blobs) for visualization.
 * Returns only the encrypted data — no block IDs visible.
 */
export function getServerBuckets(): ReadonlyArray<Readonly<Bucket>> {
  return getState().buckets;
}

/**
 * Get path bucket IDs for a given leaf (for UI visualization of which
 * buckets are on a path).
 */
export function getPathBucketIds(leafId: number): number[] {
  return pathBucketIds(leafId, getState().L);
}
