/**
 * The trusted client. Holds position map, stash, key.
 * Exposes only READ(id) and WRITE(id, data) to user.
 *
 * Implements Algorithm 1 from:
 * Stefanov, van Dijk, Shi, Fletcher, Ren, Yu, Devadas
 * "Path ORAM: An Extremely Simple Oblivious RAM Protocol"
 * JACM 2018 (originally CCS 2013)
 */

import type { ClientKey } from './encryption.js';
import {
  generateClientKey,
  encryptBlock,
  decryptBlock,
  createDummyBlock,
} from './encryption.js';
import type { Bucket } from '../server/oram-server.js';
import {
  createServer,
  serverReadPath,
  serverWritePath,
} from '../server/oram-server.js';

export interface ORAMClient {
  L: number; // tree height
  Z: number; // bucket size
  N: number; // max number of blocks
  key: ClientKey; // encryption key
  positionMap: Map<number, number>; // block_id → leaf_id
  stash: Map<number, Uint8Array>; // block_id → plaintext data
  maxStashSize: number; // high-water mark of stash occupancy (security metric)
  // The real placement the client wrote on its most recent write-back, recorded
  // as the eviction happened. Index 0 = root … index L = leaf; each entry lists
  // the REAL block IDs the client packed into that on-path bucket (dummies not
  // listed). Purely a client-side record for honest visualization — it is never
  // sent to the server and does not affect the protocol.
  lastWriteBack: { leaf: number; realIdsPerLevel: number[][] } | null;
}

/** Pick a cryptographically uniformly random leaf in [0, 2^L). */
function randomLeaf(L: number): number {
  // Use rejection sampling to avoid modulo bias.
  // 2^L is always a power of two, so modulo is actually unbiased here,
  // but we still use getRandomValues as required.
  const numLeaves = 1 << L; // always power of 2
  const arr = new Uint32Array(1);
  crypto.getRandomValues(arr);
  // For power-of-two numLeaves, modulo is perfectly uniform.
  return (arr[0] as number) % numLeaves;
}

/**
 * Check whether a block currently assigned to `blockLeaf` would pass
 * through the bucket at `level` on the path to `pathLeaf`.
 *
 * The path P(pathLeaf) at level ℓ covers all leaves that share the
 * same top-ℓ bits as pathLeaf.
 */
function intersects(blockLeaf: number, pathLeaf: number, level: number, L: number): boolean {
  // Shift right by (L - level) bits to get the node index at that level.
  const shift = L - level;
  return (blockLeaf >> shift) === (pathLeaf >> shift);
}

/**
 * Initialize ORAM with N blocks, all set to zero.
 * Assigns each block a random leaf. Writes initial encrypted state to server.
 */
export async function initializeORAM(N: number, Z: number): Promise<ORAMClient> {
  const L = Math.ceil(Math.log2(N));
  createServer(L, Z);

  const key = await generateClientKey();
  const positionMap = new Map<number, number>();
  const stash = new Map<number, Uint8Array>();

  for (let blockId = 0; blockId < N; blockId++) {
    positionMap.set(blockId, randomLeaf(L));
    stash.set(blockId, new Uint8Array(32)); // all-zero initial data
  }

  const client: ORAMClient = {
    L, Z, N, key, positionMap, stash, maxStashSize: stash.size, lastWriteBack: null,
  };

  // Write back all blocks so the server is fully initialized.
  // We do this by running a write for every block.
  // More efficiently: we can just evict the stash across all paths.
  // For initialization we batch-evict by writing each leaf path once
  // and greedily placing blocks.
  const numLeaves = 1 << L;
  for (let leaf = 0; leaf < numLeaves; leaf++) {
    // Server has empty buckets; read returns empty buckets.
    // We write back the path, evicting stash blocks whose position
    // maps to a leaf under this path.
    await writeBackPath(client, leaf);
  }

  return client;
}

/**
 * The Path ORAM ACCESS operation (Algorithm 1).
 * This is the only protocol step — both reads and writes go through it.
 *
 *   1. Look up current leaf x for block_id
 *   2. Remap: position[block_id] ← fresh random leaf
 *   3. Read path P(x) from server
 *   4. Decrypt all blocks, add real ones to stash
 *   5. For op=READ: get data from stash
 *      For op=WRITE: update data in stash
 *   6. Write back path P(x) with greedy eviction
 *   7. Return data
 */
export async function access(
  client: ORAMClient,
  op: 'read' | 'write',
  blockId: number,
  newData?: Uint8Array,
): Promise<Uint8Array> {
  // Step 1: Look up old leaf
  const x = client.positionMap.get(blockId);
  if (x === undefined) throw new Error(`Block ${blockId} not in position map`);

  // Step 2: Remap to fresh random leaf (BEFORE writing back)
  client.positionMap.set(blockId, randomLeaf(client.L));

  // Step 3: Read path P(x) from server
  const pathBuckets: Bucket[] = serverReadPath(x);

  // Step 4: Decrypt all blocks on path, add real ones to stash
  for (const bucket of pathBuckets) {
    for (const encBlock of bucket.blocks) {
      // Skip empty slots (uninitialized buckets with empty blocks array)
      if (encBlock.ciphertext.length === 0) continue;
      const decrypted = await decryptBlock(encBlock, client.key);
      if (decrypted !== null) {
        // Real block — add to stash (or update existing entry)
        if (!client.stash.has(decrypted.blockId)) {
          client.stash.set(decrypted.blockId, decrypted.data);
        }
      }
    }
  }

  // Record the stash high-water mark. The peak occurs here — right after a full
  // path has been pulled in but before eviction writes blocks back out. Path
  // ORAM guarantees this stays O(log N) with overwhelming probability.
  if (client.stash.size > client.maxStashSize) client.maxStashSize = client.stash.size;

  // Step 5: Apply operation
  let resultData: Uint8Array;
  if (op === 'read') {
    resultData = client.stash.get(blockId) ?? new Uint8Array(32);
  } else {
    // WRITE
    if (!newData) throw new Error('newData required for write operation');
    client.stash.set(blockId, new Uint8Array(newData));
    resultData = new Uint8Array(newData);
  }

  // Step 6: Write back path P(x) with greedy eviction
  await writeBackPath(client, x);

  // Step 7: Return data
  return resultData;
}

/**
 * Greedy eviction: write back the path P(x) by packing stash blocks
 * into buckets from leaf to root.
 *
 * At each level ℓ from L down to 0:
 *   - Find blocks in stash whose position maps to a leaf that
 *     passes through the bucket at level ℓ on path x
 *   - Select up to Z of them
 *   - Remove from stash, add to bucket at level ℓ
 *   - Pad with dummy blocks to exactly Z
 */
export async function writeBackPath(client: ORAMClient, leafId: number): Promise<void> {
  const { L, Z, key, positionMap, stash } = client;
  const newBuckets: Bucket[] = [];
  // Record, level by level (leaf→root), the real block IDs we actually pack, so
  // the UI can honestly show which block landed in which on-path bucket.
  const realIdsLeafToRoot: number[][] = [];

  for (let level = L; level >= 0; level--) {
    // Find stash blocks that intersect path at this level
    const candidates: number[] = [];
    for (const [bid] of stash) {
      const blockLeaf = positionMap.get(bid);
      if (blockLeaf === undefined) continue;
      if (intersects(blockLeaf, leafId, level, L)) {
        candidates.push(bid);
      }
    }

    // Greedy eviction (Stefanov et al., §3.3): place each block as DEEP as it
    // can legally go. Because we walk levels from leaf (L) up to root (0), any
    // block that fits at a deeper level was already given that slot on a prior
    // iteration — so the candidates remaining here are exactly those that could
    // not go deeper. Among equally-placeable candidates the choice is arbitrary;
    // we sort by assigned leaf only for deterministic, reproducible behavior.
    candidates.sort((a, b) => (positionMap.get(a) ?? 0) - (positionMap.get(b) ?? 0));

    const picked = candidates.slice(0, Z);
    realIdsLeafToRoot.push([...picked]);
    const blocks = await Promise.all(
      picked.map((bid) => {
        const data = stash.get(bid)!;
        stash.delete(bid);
        return encryptBlock(bid, data, key);
      }),
    );

    // Pad with dummy blocks
    while (blocks.length < Z) {
      blocks.push(await createDummyBlock(key));
    }

    newBuckets.push({ blocks });
  }

  // newBuckets was built leaf-to-root; serverWritePath expects root-to-leaf
  newBuckets.reverse();
  serverWritePath(leafId, newBuckets);

  // Store the placement root-to-leaf (index 0 = root … index L = leaf).
  client.lastWriteBack = { leaf: leafId, realIdsPerLevel: realIdsLeafToRoot.reverse() };
}

/**
 * READ convenience wrapper.
 */
export async function read(client: ORAMClient, blockId: number): Promise<Uint8Array> {
  return access(client, 'read', blockId);
}

/**
 * WRITE convenience wrapper.
 */
export async function write(
  client: ORAMClient,
  blockId: number,
  data: Uint8Array,
): Promise<void> {
  await access(client, 'write', blockId, data);
}

/**
 * Report which REAL block sits in each bucket along path P(leafId), for honest
 * client-view visualization.
 *
 * The `perLevel` placement is taken from `client.lastWriteBack` — the exact set
 * of blocks the client packed into each on-path bucket during its most recent
 * eviction (recorded as it happened, so it always matches the encrypted bytes on
 * the server). It is defined only for the path that was just written back; for
 * any other leaf we return empty buckets rather than guess, because the physical
 * contents of an unread path genuinely depend on stash history the client no
 * longer holds — the client would have to read that path to know, which is the
 * honest answer.
 *
 * `eligibleLevel[b]` is purely structural: the deepest on-path level block b may
 * legally occupy (the lowest node shared by b's assigned leaf and `leafId`). This
 * is the eviction-legality invariant the UI explains, and it is always well
 * defined from the position map alone.
 */
export function reconstructPathPlacement(
  client: ORAMClient,
  leafId: number,
): { perLevel: number[][]; eligibleLevel: Map<number, number> } {
  const { L, positionMap, lastWriteBack } = client;

  const eligibleLevel = new Map<number, number>();
  for (const [bid, blockLeaf] of positionMap) {
    let deepest = -1;
    for (let level = 0; level <= L; level++) {
      if (intersects(blockLeaf, leafId, level, L)) deepest = level;
    }
    if (deepest >= 0) eligibleLevel.set(bid, deepest);
  }

  const perLevel: number[][] =
    lastWriteBack && lastWriteBack.leaf === leafId
      ? lastWriteBack.realIdsPerLevel.map((l) => [...l])
      : Array.from({ length: L + 1 }, () => []);

  return { perLevel, eligibleLevel };
}

/**
 * Check stash size. For security analysis — should be O(log N) whp.
 */
export function getStashSize(client: ORAMClient): number {
  return client.stash.size;
}

/**
 * Peak stash occupancy observed so far. Path ORAM's central security/efficiency
 * guarantee is that this stays O(log N) with overwhelming probability — exposing
 * it lets the UI show the bound holding live.
 */
export function getStashHighWater(client: ORAMClient): number {
  return client.maxStashSize;
}
