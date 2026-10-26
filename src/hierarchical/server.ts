/**
 * Untrusted storage for the bounded hierarchical-ORAM lesson.
 *
 * The API accepts only physical level/bucket coordinates and fixed-size
 * encrypted slots. Logical block ids, hash keys, hit/miss state, dummy labels,
 * and plaintext never cross this boundary.
 */

import type { EncryptedBlock } from '../server/oram-server.js';

export type HierarchicalPhase = 'setup' | 'lookup' | 'rebuild';

export interface HierarchicalLevelShape {
  level: number;
  logicalCapacity: number;
  bucketCount: number;
  bucketSize: number;
}

export interface HierarchicalServerEvent {
  phase: HierarchicalPhase;
  operation: 'read' | 'write';
  level: number;
  bucket: number | null;
  slotCount: number;
}

export interface HierarchicalServerView {
  totalReadSlots: number;
  totalWriteSlots: number;
  events: HierarchicalServerEvent[];
}

const NONCE_BYTES = 12;
const CIPHERTEXT_BYTES = 4 + 32 + 16;

function assertInteger(name: string, value: number, min: number, max: number): void {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new RangeError(`${name} must be an integer in [${min}, ${max}].`);
  }
}

function copyBlock(block: EncryptedBlock, context: string): EncryptedBlock {
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

function copyBucket(
  bucket: EncryptedBlock[],
  shape: HierarchicalLevelShape,
  context: string,
): EncryptedBlock[] {
  if (!Array.isArray(bucket) || bucket.length !== shape.bucketSize) {
    throw new RangeError(`${context} must contain exactly ${shape.bucketSize} encrypted slots.`);
  }
  return bucket.map((block, slot) => copyBlock(block, `${context} slot ${slot}`));
}

/** Independent server instance so Path ORAM and the hierarchy can run together. */
export class HierarchicalServer {
  readonly #shapes: HierarchicalLevelShape[];
  #levels: EncryptedBlock[][][];
  #events: HierarchicalServerEvent[] = [];
  #totalReadSlots = 0;
  #totalWriteSlots = 0;

  constructor(shapes: HierarchicalLevelShape[]) {
    if (!Array.isArray(shapes) || shapes.length < 2) {
      throw new RangeError('The bounded hierarchy requires a cache and at least one hashed level.');
    }
    this.#shapes = shapes.map((shape, index) => {
      if (shape.level !== index) throw new RangeError('Hierarchy levels must be consecutive from zero.');
      assertInteger('logical capacity', shape.logicalCapacity, 1, 1 << 16);
      assertInteger('bucket count', shape.bucketCount, 1, 1 << 16);
      assertInteger('bucket size', shape.bucketSize, 1, 1 << 16);
      return { ...shape };
    });
    this.#levels = this.#shapes.map((shape) =>
      Array.from({ length: shape.bucketCount }, () => []),
    );
  }

  getShapes(): HierarchicalLevelShape[] {
    return this.#shapes.map((shape) => ({ ...shape }));
  }

  physicalSlotCount(): number {
    return this.#shapes.reduce(
      (total, shape) => total + shape.bucketCount * shape.bucketSize,
      0,
    );
  }

  traceLength(): number {
    return this.#events.length;
  }

  clearTrace(): void {
    this.#events = [];
    this.#totalReadSlots = 0;
    this.#totalWriteSlots = 0;
  }

  getView(fromEvent = 0): HierarchicalServerView {
    assertInteger('fromEvent', fromEvent, 0, this.#events.length);
    const events = this.#events.slice(fromEvent).map((event) => ({ ...event }));
    return {
      totalReadSlots: events
        .filter((event) => event.operation === 'read')
        .reduce((total, event) => total + event.slotCount, 0),
      totalWriteSlots: events
        .filter((event) => event.operation === 'write')
        .reduce((total, event) => total + event.slotCount, 0),
      events,
    };
  }

  getTotals(): Omit<HierarchicalServerView, 'events'> {
    return {
      totalReadSlots: this.#totalReadSlots,
      totalWriteSlots: this.#totalWriteSlots,
    };
  }

  readBucket(
    level: number,
    bucket: number,
    phase: HierarchicalPhase,
  ): EncryptedBlock[] {
    const shape = this.#shape(level);
    assertInteger('bucket', bucket, 0, shape.bucketCount - 1);
    const stored = this.#levels[level]?.[bucket];
    if (!stored) throw new Error(`Missing level ${level}, bucket ${bucket}.`);
    const result = copyBucket(stored, shape, `Level ${level} bucket ${bucket}`);
    this.#record(phase, 'read', level, bucket, shape.bucketSize);
    return result;
  }

  writeBucket(
    level: number,
    bucket: number,
    blocks: EncryptedBlock[],
    phase: HierarchicalPhase,
  ): void {
    const shape = this.#shape(level);
    assertInteger('bucket', bucket, 0, shape.bucketCount - 1);
    const replacement = copyBucket(blocks, shape, `Level ${level} bucket ${bucket}`);
    const target = this.#levels[level];
    if (!target) throw new Error(`Missing level ${level}.`);
    target[bucket] = replacement;
    this.#record(phase, 'write', level, bucket, shape.bucketSize);
  }

  readLevel(level: number, phase: HierarchicalPhase): EncryptedBlock[][] {
    const shape = this.#shape(level);
    const stored = this.#levels[level];
    if (!stored || stored.length !== shape.bucketCount) {
      throw new Error(`Level ${level} is not provisioned.`);
    }
    const result = stored.map((bucket, index) =>
      copyBucket(bucket, shape, `Level ${level} bucket ${index}`),
    );
    const slots = shape.bucketCount * shape.bucketSize;
    this.#record(phase, 'read', level, null, slots);
    return result;
  }

  /** Validate the complete level before committing any of it. */
  replaceLevel(
    level: number,
    buckets: EncryptedBlock[][],
    phase: HierarchicalPhase,
  ): void {
    const shape = this.#shape(level);
    if (!Array.isArray(buckets) || buckets.length !== shape.bucketCount) {
      throw new RangeError(`Level ${level} must contain exactly ${shape.bucketCount} buckets.`);
    }
    const replacement = buckets.map((bucket, index) =>
      copyBucket(bucket, shape, `Level ${level} bucket ${index}`),
    );
    this.#levels[level] = replacement;
    const slots = shape.bucketCount * shape.bucketSize;
    this.#record(phase, 'write', level, null, slots);
  }

  #shape(level: number): HierarchicalLevelShape {
    assertInteger('level', level, 0, this.#shapes.length - 1);
    const shape = this.#shapes[level];
    if (!shape) throw new Error(`Missing shape for level ${level}.`);
    return shape;
  }

  #record(
    phase: HierarchicalPhase,
    operation: 'read' | 'write',
    level: number,
    bucket: number | null,
    slotCount: number,
  ): void {
    this.#events.push({ phase, operation, level, bucket, slotCount });
    if (operation === 'read') this.#totalReadSlots += slotCount;
    else this.#totalWriteSlots += slotCount;
  }
}
