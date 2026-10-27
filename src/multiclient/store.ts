/**
 * The untrusted shared store.
 *
 * It holds a Path ORAM tree of outer-encrypted entry envelopes, the shared
 * mutable client state every client needs in order to use that tree, and an
 * append-only upload log. It understands none of it.
 *
 * WHY THE CLIENT STATE IS HERE AND NOT IN A CLIENT. A single-client Path ORAM
 * keeps its position map and stash in trusted client memory. The moment two
 * mutually distrustful clients share one tree, that state has to be shared
 * too, or their views diverge. GORAM (IACR ePrint 2015/224) section 3.1 puts
 * it exactly there: the layout "follows the one proposed by Stefanov et al.",
 * with an index structure LM mapping entry indices to leaves, and "We assume
 * the stash to be stored and shared on the server like every other node".
 * ConcurORAM (arXiv:1811.04366v4) section I describes the same move and its
 * price: deploying existing schemes for multiple clients "by sharing ORAM
 * credentials and storing [state] that would normally be maintained
 * client-side ... on the server to ensure state consistency" means "only one
 * client can be allowed to access the [server-hosted data] structures at any
 * one time."
 *
 * So this store is where the multi-client problem actually lives, and it is
 * why `scenario.ts` can show a lost update as a consequence of real state
 * rather than as a label.
 *
 * WHAT THE SERVER LEARNS, exhaustively. Every call appends to a transcript
 * carrying only the kind of structure touched, read or write, the leaf of a
 * path access, and a slot count. No logical entry index, no client identity
 * for a data access, no version, no plaintext, no key. Envelope ciphertexts
 * are a constant length that does not depend on the entry, its version, its
 * writer, or how many clients may read it. The upload log is the one place a
 * client identity is visible, because its records are client-signed - the
 * anonymity A-GORAM section 4.2 explicitly sacrifices for accountability.
 *
 * THE MODULE BOUNDARY IS INFORMATIONAL. Owner, clients and this store are
 * modules in one browser page. Nothing here is process isolation, and
 * same-origin code can reach every key in the lesson.
 */

import {
  GCM_NONCE,
  sealedSize,
  type Bytes,
  type SealedEnvelope,
} from './envelope.js';

/** Tree height, matching this lab's existing Path ORAM geometry. */
export const STORE_L = 4;
/** Slots per bucket, matching this lab's existing Path ORAM geometry. */
export const STORE_Z = 4;
/** Logical entries. */
export const STORE_N = 16;
/** Buckets in the tree: 2^(L+1) - 1 = 31. */
export const STORE_BUCKETS = (1 << (STORE_L + 1)) - 1;
/** Leaves: 2^L = 16. */
export const STORE_LEAVES = 1 << STORE_L;
/**
 * Shared stash slots. Fixed, and always transmitted in full, so the number of
 * entries resting in the stash is not visible in the transfer size. A write
 * that would exceed it fails closed rather than silently dropping an entry.
 */
export const STORE_STASH_SLOTS = 8;

export type StructureKind = 'path' | 'stash' | 'state' | 'log';

/** One server-visible event. This is the complete adversary view. */
export interface StoreEvent {
  kind: StructureKind;
  operation: 'read' | 'write';
  /** Present only for a path access, because the server really does see it. */
  leaf?: number;
  /** Encrypted slots transferred. */
  slots: number;
}

/** A client-signed record of one upload, chained to its predecessor. */
export interface UploadLogRecord {
  seq: number;
  /** Visible: log records are client-signed, so the signer is not anonymous. */
  writerId: number;
  leaf: number;
  /** SHA-256 over the sealed path that was uploaded. */
  pathDigest: Bytes;
  /** SHA-256 over the previous record, or 32 zero bytes for the first. */
  prevDigest: Bytes;
  signature: Bytes;
  /**
   * The sealed path this record commits to, retained so `blame` can actually
   * walk the history rather than narrate it. A-GORAM section 4.1 defines the
   * log as "the list of paths uploaded to the server, each of them signed by
   * the respective client", and its section 4.2 Discussion states the cost:
   * the server stores "a log that is linear in the number of modifications to
   * the database". For a 16-entry lesson that is affordable; at scale it is
   * the reason the paper suggests periodic synchronisation and log reset.
   */
  path: SealedEnvelope[][];
}

/** An opaque fixed-length blob. The store never looks inside one. */
export interface SealedBlob {
  nonce: Bytes;
  ciphertext: Bytes;
}

export class StoreProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'StoreProtocolError';
  }
}

function copySealed(sealed: SealedEnvelope, context: string, clients: number): SealedEnvelope {
  if (!sealed || !(sealed.nonce instanceof Uint8Array) || !(sealed.ciphertext instanceof Uint8Array)) {
    throw new StoreProtocolError(`${context} must be a sealed envelope.`);
  }
  if (sealed.nonce.length !== GCM_NONCE) {
    throw new StoreProtocolError(`${context} nonce must be exactly ${GCM_NONCE} bytes.`);
  }
  if (sealed.ciphertext.length !== sealedSize(clients)) {
    throw new StoreProtocolError(
      `${context} ciphertext must be exactly ${sealedSize(clients)} bytes; a short or long ` +
        'envelope would make the transfer size depend on its contents.',
    );
  }
  return { nonce: new Uint8Array(sealed.nonce), ciphertext: new Uint8Array(sealed.ciphertext) };
}

function copyBlob(blob: SealedBlob, context: string, length: number): SealedBlob {
  if (!blob || !(blob.nonce instanceof Uint8Array) || !(blob.ciphertext instanceof Uint8Array)) {
    throw new StoreProtocolError(`${context} must be a sealed blob.`);
  }
  if (blob.nonce.length !== GCM_NONCE) {
    throw new StoreProtocolError(`${context} nonce must be exactly ${GCM_NONCE} bytes.`);
  }
  if (blob.ciphertext.length !== length) {
    throw new StoreProtocolError(`${context} ciphertext must be exactly ${length} bytes.`);
  }
  return { nonce: new Uint8Array(blob.nonce), ciphertext: new Uint8Array(blob.ciphertext) };
}

/** Root-to-leaf bucket indices for one leaf. */
export function pathBuckets(leaf: number): number[] {
  if (!Number.isSafeInteger(leaf) || leaf < 0 || leaf >= STORE_LEAVES) {
    throw new StoreProtocolError(`leaf must be an integer in [0, ${STORE_LEAVES - 1}].`);
  }
  const ids: number[] = [];
  for (let level = 0; level <= STORE_L; level++) {
    const levelStart = (1 << level) - 1;
    const leavesPerNode = 1 << (STORE_L - level);
    ids.push(levelStart + Math.floor(leaf / leavesPerNode));
  }
  return ids;
}

/** Does `entryLeaf` share the level-`level` ancestor of `pathLeaf`? */
export function intersects(entryLeaf: number, pathLeaf: number, level: number): boolean {
  const shift = STORE_L - level;
  return entryLeaf >> shift === pathLeaf >> shift;
}

export class MultiClientStore {
  private readonly buckets: SealedEnvelope[][];
  private readonly stash: SealedEnvelope[];
  private state: SealedBlob | null = null;
  private readonly log: UploadLogRecord[] = [];
  private readonly events: StoreEvent[] = [];
  /** How many registered clients each envelope carries a wrap slot for. */
  readonly clients: number;
  /** Fixed length of the shared-state blob ciphertext. */
  readonly stateCiphertextSize: number;

  constructor(clients: number, stateCiphertextSize: number) {
    if (!Number.isSafeInteger(clients) || clients < 1 || clients > 32) {
      throw new StoreProtocolError('A store supports 1 to 32 registered clients.');
    }
    this.clients = clients;
    this.stateCiphertextSize = stateCiphertextSize;
    this.buckets = Array.from({ length: STORE_BUCKETS }, () => []);
    this.stash = [];
  }

  // ── Provisioning, performed by the data owner ────────────────────────────

  /** Install the initial tree, stash and shared state. Not a client operation. */
  provision(
    buckets: SealedEnvelope[][],
    stash: SealedEnvelope[],
    state: SealedBlob,
  ): void {
    if (buckets.length !== STORE_BUCKETS) {
      throw new StoreProtocolError(`Provisioning needs exactly ${STORE_BUCKETS} buckets.`);
    }
    if (stash.length !== STORE_STASH_SLOTS) {
      throw new StoreProtocolError(`Provisioning needs exactly ${STORE_STASH_SLOTS} stash slots.`);
    }
    buckets.forEach((bucket, index) => {
      if (bucket.length !== STORE_Z) {
        throw new StoreProtocolError(`Bucket ${index} must hold exactly ${STORE_Z} slots.`);
      }
    });
    const preparedBuckets = buckets.map((bucket, index) =>
      bucket.map((slot, slotIndex) => copySealed(slot, `bucket ${index} slot ${slotIndex}`, this.clients)),
    );
    const preparedStash = stash.map((slot, index) =>
      copySealed(slot, `stash slot ${index}`, this.clients),
    );
    const preparedState = copyBlob(state, 'shared state', this.stateCiphertextSize);
    preparedBuckets.forEach((bucket, index) => {
      this.buckets[index] = bucket;
    });
    this.stash.length = 0;
    this.stash.push(...preparedStash);
    this.state = preparedState;
  }

  // ── The client-facing API ────────────────────────────────────────────────

  /** Read one complete root-to-leaf path. */
  readPath(leaf: number): SealedEnvelope[][] {
    const ids = pathBuckets(leaf);
    const result = ids.map((id, level) => {
      const bucket = this.buckets[id];
      if (!bucket || bucket.length !== STORE_Z) {
        throw new StoreProtocolError(`Bucket ${id} at level ${level} is not provisioned.`);
      }
      return bucket.map((slot, slotIndex) =>
        copySealed(slot, `bucket ${id} slot ${slotIndex}`, this.clients),
      );
    });
    this.events.push({ kind: 'path', operation: 'read', leaf, slots: ids.length * STORE_Z });
    return result;
  }

  /**
   * Replace one complete path atomically. The whole payload is validated and
   * copied before any bucket changes, so a malformed later bucket cannot leave
   * a half-written tree.
   */
  writePath(leaf: number, buckets: SealedEnvelope[][]): void {
    const ids = pathBuckets(leaf);
    if (!Array.isArray(buckets) || buckets.length !== ids.length) {
      throw new StoreProtocolError(`A path write needs exactly ${ids.length} buckets.`);
    }
    const prepared = buckets.map((bucket, level) => {
      if (!Array.isArray(bucket) || bucket.length !== STORE_Z) {
        throw new StoreProtocolError(`Bucket at level ${level} must hold exactly ${STORE_Z} slots.`);
      }
      return bucket.map((slot, slotIndex) =>
        copySealed(slot, `bucket at level ${level} slot ${slotIndex}`, this.clients),
      );
    });
    ids.forEach((id, level) => {
      this.buckets[id] = prepared[level] as SealedEnvelope[];
    });
    this.events.push({ kind: 'path', operation: 'write', leaf, slots: ids.length * STORE_Z });
  }

  /** Read the shared stash in full. Always every slot. */
  readStash(): SealedEnvelope[] {
    if (this.stash.length !== STORE_STASH_SLOTS) {
      throw new StoreProtocolError('The shared stash is not provisioned.');
    }
    const result = this.stash.map((slot, index) =>
      copySealed(slot, `stash slot ${index}`, this.clients),
    );
    this.events.push({ kind: 'stash', operation: 'read', slots: STORE_STASH_SLOTS });
    return result;
  }

  /** Replace the shared stash in full. */
  writeStash(slots: SealedEnvelope[]): void {
    if (!Array.isArray(slots) || slots.length !== STORE_STASH_SLOTS) {
      throw new StoreProtocolError(`A stash write needs exactly ${STORE_STASH_SLOTS} slots.`);
    }
    const prepared = slots.map((slot, index) =>
      copySealed(slot, `stash slot ${index}`, this.clients),
    );
    this.stash.length = 0;
    this.stash.push(...prepared);
    this.events.push({ kind: 'stash', operation: 'write', slots: STORE_STASH_SLOTS });
  }

  /** Read the opaque shared-state blob (the leaf map). */
  readState(): SealedBlob {
    if (!this.state) throw new StoreProtocolError('The shared state is not provisioned.');
    const result = copyBlob(this.state, 'shared state', this.stateCiphertextSize);
    this.events.push({ kind: 'state', operation: 'read', slots: 1 });
    return result;
  }

  /** Replace the opaque shared-state blob. */
  writeState(blob: SealedBlob): void {
    this.state = copyBlob(blob, 'shared state', this.stateCiphertextSize);
    this.events.push({ kind: 'state', operation: 'write', slots: 1 });
  }

  /**
   * The last appended record, or `null`. The store does NOT compute the chain
   * digest: clients hash the records they read themselves, so a store that
   * lied about the head would be lying about something no client trusts it
   * for.
   */
  lastLogRecord(): UploadLogRecord | null {
    const last = this.log[this.log.length - 1];
    return last ? this.copyRecord(last) : null;
  }

  /** The sequence number the next appended record will carry. */
  nextLogSeq(): number {
    return this.log.length + 1;
  }

  /**
   * Append one client-signed upload record. Append-only: the store refuses a
   * record that does not continue the sequence. It cannot verify the signature
   * - it has no client public keys - so a malicious store could still forge or
   * drop records. Detecting that is the clients' job, in `client.ts`.
   */
  appendLog(record: UploadLogRecord): void {
    if (record.seq !== this.nextLogSeq()) {
      throw new StoreProtocolError(
        `Upload log is append-only: expected sequence ${this.nextLogSeq()}, got ${record.seq}.`,
      );
    }
    this.log.push(this.copyRecord(record));
    this.events.push({ kind: 'log', operation: 'write', slots: 1 });
  }

  private copyRecord(record: UploadLogRecord): UploadLogRecord {
    return {
      seq: record.seq,
      writerId: record.writerId,
      leaf: record.leaf,
      pathDigest: new Uint8Array(record.pathDigest),
      prevDigest: new Uint8Array(record.prevDigest),
      signature: new Uint8Array(record.signature),
      path: record.path.map((bucket) =>
        bucket.map((slot) => ({
          nonce: new Uint8Array(slot.nonce),
          ciphertext: new Uint8Array(slot.ciphertext),
        })),
      ),
    };
  }

  /** Read the upload log from `fromSeq` onward. */
  readLog(fromSeq = 1): UploadLogRecord[] {
    const result = this.log
      .filter((record) => record.seq >= fromSeq)
      .map((record) => this.copyRecord(record));
    this.events.push({ kind: 'log', operation: 'read', slots: 1 });
    return result;
  }

  /** How many records the upload log holds. */
  logLength(): number {
    return this.log.length;
  }

  // ── The adversary view, and nothing more ────────────────────────────────

  /** Every server-visible event, in order. */
  transcript(): StoreEvent[] {
    return this.events.map((event) => ({ ...event }));
  }

  /** Discard the transcript so one scenario's trace is not read as another's. */
  clearTranscript(): void {
    this.events.length = 0;
  }

  /** Total encrypted slots transferred so far, by direction. */
  traffic(): { readSlots: number; writeSlots: number } {
    let readSlots = 0;
    let writeSlots = 0;
    for (const event of this.events) {
      if (event.operation === 'read') readSlots += event.slots;
      else writeSlots += event.slots;
    }
    return { readSlots, writeSlots };
  }

  /**
   * Replace one stored slot with arbitrary bytes, as a malicious or faulty
   * server would. Used only by the tampering controls; it records no event
   * because a client never performs it.
   */
  forceSlot(bucketId: number, slotIndex: number, sealed: SealedEnvelope): void {
    const bucket = this.buckets[bucketId];
    if (!bucket) throw new StoreProtocolError(`Bucket ${bucketId} does not exist.`);
    if (slotIndex < 0 || slotIndex >= STORE_Z) {
      throw new StoreProtocolError(`Slot ${slotIndex} is out of range.`);
    }
    bucket[slotIndex] = copySealed(sealed, 'forced slot', this.clients);
  }

  /** A deep snapshot of every stored slot, for rollback controls and tests. */
  snapshot(): { buckets: SealedEnvelope[][]; stash: SealedEnvelope[]; state: SealedBlob } {
    if (!this.state) throw new StoreProtocolError('The shared state is not provisioned.');
    return {
      buckets: this.buckets.map((bucket) =>
        bucket.map((slot) => ({
          nonce: new Uint8Array(slot.nonce),
          ciphertext: new Uint8Array(slot.ciphertext),
        })),
      ),
      stash: this.stash.map((slot) => ({
        nonce: new Uint8Array(slot.nonce),
        ciphertext: new Uint8Array(slot.ciphertext),
      })),
      state: {
        nonce: new Uint8Array(this.state.nonce),
        ciphertext: new Uint8Array(this.state.ciphertext),
      },
    };
  }

  /**
   * Put the stored bytes back to a snapshot WITHOUT rewinding the upload log.
   * That is precisely a rollback attack by the storage provider: the data is
   * old, every signature on it is genuine, and the log still says newer
   * uploads happened. `client.ts` is what has to notice.
   */
  rollbackTo(snapshot: { buckets: SealedEnvelope[][]; stash: SealedEnvelope[]; state: SealedBlob }): void {
    snapshot.buckets.forEach((bucket, index) => {
      this.buckets[index] = bucket.map((slot) => ({
        nonce: new Uint8Array(slot.nonce),
        ciphertext: new Uint8Array(slot.ciphertext),
      }));
    });
    this.stash.length = 0;
    this.stash.push(
      ...snapshot.stash.map((slot) => ({
        nonce: new Uint8Array(slot.nonce),
        ciphertext: new Uint8Array(slot.ciphertext),
      })),
    );
    this.state = {
      nonce: new Uint8Array(snapshot.state.nonce),
      ciphertext: new Uint8Array(snapshot.state.ciphertext),
    };
  }
}
