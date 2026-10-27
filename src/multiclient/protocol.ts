/**
 * The Multi-Client ORAM protocol: a data owner, mutually distrustful clients,
 * and one untrusted shared store.
 *
 * THE DEFINITION THIS IMPLEMENTS. Maffei, Malavolta, Reinert and Schröder,
 * "GORAM" (IACR ePrint 2015/224) section 2.1 Definition 1, restated in
 * "Maliciously Secure Multi-Client ORAM" (IACR ePrint 2017/329) section 2.1
 * Definition 1 and rephrased in Chow, Fech, Lai and Malavolta (IACR ePrint
 * 2020/1551) section 5.1 Definition 15. Parties: a data owner `O`, clients
 * `C_1..C_k` each holding a capability `cap_i`, and a server `S`. An
 * access-control matrix `ACM(i, idx)` in `{none, read, readwrite}` decides
 * everything, and ePrint 2017/329 section 2.1 is explicit that it "is only
 * accessible to the data owner and not to any client".
 *
 * THE PROPERTIES, KEPT APART. This module implements four of them and refuses
 * to claim the other two.
 *
 *   SECRECY - "only users with at least read permissions on an entry can learn
 *   its content" (ePrint 2017/329 section 2.1). Enforced by the per-client
 *   wrap: a client without a real wrap for an entry cannot obtain `k_j`, so
 *   AES-GCM refuses its payload. Not a disabled control.
 *
 *   TAMPER RESISTANCE - only an authorised writer can change content "in a way
 *   that the updated entry is considered valid by honest clients", which "can
 *   in principle be achieved even if the server is malicious". Enforced by
 *   `verifyEntry` below, which every client runs on every envelope it parses.
 *
 *   ACCOUNTABLE INTEGRITY - an unauthorised change cannot happen "without
 *   being detected" (ePrint 2015/224 section 2.2). `blame` walks the signed
 *   upload log and names the client whose upload broke an entry.
 *
 *   NOT CLAIMED: INTEGRITY, in the sense of ePrint 2017/329 section 2.1 -
 *   "only users with write permissions on an entry can change its content".
 *   That property, the same source says, "requires an honest-but-curious
 *   server to perform access control", and THIS STORE PERFORMS NONE. It cannot:
 *   deciding whether a writer is authorised for entry `j` means knowing `j`,
 *   and `j` is inside an envelope the store cannot open. GORAM section 3 buys
 *   a server-side check with zero-knowledge proofs - the client proves it can
 *   decrypt `c_Auth` without revealing which entry - and A-GORAM section 4
 *   deliberately gives that up: "instead of letting the server check the
 *   correctness of client operations, we develop a technique that allows
 *   clients to detect a posteriori non-authorized changes on the database and
 *   blame the misbehaving party", so that "zero-knowledge proofs are no longer
 *   necessary". The consequence is visible and tested: an unauthorised write
 *   LANDS on the store, and is then rejected by every honest client and
 *   attributed by `blame`. It never becomes the entry's value for anyone.
 *
 *   NOT CLAIMED: OBLIVIOUSNESS AGAINST MALICIOUS CLIENTS. ePrint 2017/329
 *   section 2.2 Theorem 1: a multi-client ORAM that "accesses on average o(n)
 *   physical addresses for each read and write operation ... is not secure
 *   against malicious clients". One path access here touches `O(log n)`
 *   buckets, which is `o(n)`. Obliviousness is therefore claimed only against
 *   the non-colluding honest-but-curious server of ePrint 2015/224 section
 *   2.3, and `scenario.ts` exhibits a distinguisher the moment a client
 *   colludes with the server.
 *
 *   NOT CLAIMED: ANONYMITY. Writers sign their own updates, so any client that
 *   can open an envelope learns who last wrote it. ePrint 2015/224 section 4.2
 *   concedes exactly this for its accountable variant.
 *
 * CONCURRENCY IS REFUSED, NOT SERIALISED AWAY. See `ConcurrencyRefusedError`.
 */

import {
  AccessDeniedError,
  DUMMY_INDEX,
  GCM_NONCE,
  GCM_TAG,
  LOG_SIG_LABEL,
  OWNER_WRITER,
  PAYLOAD_SIZE,
  SIGNATURE_SIZE,
  capabilitySigningInput,
  entrySigningInput,
  freshDataKey,
  generateAesKey,
  normalizePayload,
  openEnvelope,
  openPayload,
  sealDummy,
  sealEnvelope,
  sealPayload,
  unwrapDataKey,
  wrapDataKey,
  type Bytes,
  type EnvelopeContent,
  type SealedEnvelope,
} from './envelope.js';
import {
  MultiClientStore,
  STORE_L,
  STORE_LEAVES,
  STORE_N,
  STORE_STASH_SLOTS,
  STORE_Z,
  intersects,
  pathBuckets,
  type SealedBlob,
  type UploadLogRecord,
} from './store.js';

/** `ACM(i, idx)`: no access, read-only, read-write. */
export type AccessMode = 'none' | 'read' | 'readwrite';

const STATE_AAD = new TextEncoder().encode('mcoram/leafmap/v1');
/** The leaf map is one octet per entry, so its blob length never varies. */
const STATE_PLAINTEXT = STORE_N;
const STATE_CIPHERTEXT = STATE_PLAINTEXT + GCM_TAG;

export class EntryVerificationError extends Error {
  constructor(
    readonly index: number,
    detail: string,
  ) {
    super(`Entry ${index} failed verification: ${detail}`);
    this.name = 'EntryVerificationError';
  }
}

export class StaleEntryError extends Error {
  constructor(
    readonly index: number,
    readonly servedVersion: number,
    readonly knownVersion: number,
  ) {
    super(
      `Entry ${index} was served at version ${servedVersion}, but this client has already ` +
        `seen version ${knownVersion}. The store is serving stale or rolled-back data.`,
    );
    this.name = 'StaleEntryError';
  }
}

export class LogChainError extends Error {
  constructor(detail: string) {
    super(`The signed upload log does not continue from what this client last saw: ${detail}`);
    this.name = 'LogChainError';
  }
}

export class EntryUnavailableError extends Error {
  constructor(readonly index: number) {
    super(
      `Entry ${index} was not present in the authenticated path or shared stash. The store's ` +
        'response is incomplete, stale, or corrupt.',
    );
    this.name = 'EntryUnavailableError';
  }
}

export class DuplicateEntryError extends Error {
  constructor(readonly index: number) {
    super(`Entry ${index} appeared more than once across the path and the shared stash.`);
    this.name = 'DuplicateEntryError';
  }
}

export class StashOverflowError extends Error {
  constructor(readonly needed: number) {
    super(
      `Eviction needed ${needed} shared stash slots but only ${STORE_STASH_SLOTS} exist. ` +
        'The access fails closed rather than silently discarding an entry.',
    );
    this.name = 'StashOverflowError';
  }
}

/**
 * A second access was attempted while one was still in flight.
 *
 * This is a refusal, not a queue, and it is deliberate. GORAM does not address
 * concurrency at all. ePrint 2017/329 section 3.2 permits concurrent reads and
 * stack appends but not concurrent flushes, "since the database is entirely
 * updated, which might lead to inconsistent results when reading from the
 * database". Full concurrency appears in that line of work only through the
 * trusted proxy of its section 5, or outside it in ConcurORAM
 * (arXiv:1811.04366v4). Two overlapping accesses to this shared tree race on
 * the leaf map and the path write-back and the loser's update is lost, so this
 * lesson refuses rather than pretending to be linearizable.
 */
export class ConcurrencyRefusedError extends Error {
  constructor() {
    super(
      'A multi-client access is already in flight on this store. The selected construction ' +
        'provides no concurrency control, so a second overlapping access is refused rather ' +
        'than racing. See docs/multi-client-design.md section 8.',
    );
    this.name = 'ConcurrencyRefusedError';
  }
}

// ── Small helpers ───────────────────────────────────────────────────────────

const te = new TextEncoder();

function concat(...parts: Bytes[]): Bytes {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

function u16(value: number): Bytes {
  const out = new Uint8Array(2);
  new DataView(out.buffer).setUint16(0, value, false);
  return out;
}

function u32(value: number): Bytes {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

async function sha256(data: Bytes): Promise<Bytes> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

function bytesEqual(a: Bytes, b: Bytes): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}

function randomLeaf(): number {
  const sample = new Uint32Array(1);
  crypto.getRandomValues(sample);
  return (sample[0] as number) & (STORE_LEAVES - 1);
}

const ECDSA = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const ECDSA_SIGN = { name: 'ECDSA', hash: 'SHA-256' } as const;

async function generateSigningPair(): Promise<CryptoKeyPair> {
  return (await crypto.subtle.generateKey(ECDSA, false, ['sign', 'verify'])) as CryptoKeyPair;
}

async function sign(key: CryptoKey, data: Bytes): Promise<Bytes> {
  const signature = new Uint8Array(await crypto.subtle.sign(ECDSA_SIGN, key, data));
  if (signature.length !== SIGNATURE_SIZE) {
    throw new Error(`Expected a ${SIGNATURE_SIZE}-byte P-256 signature, got ${signature.length}.`);
  }
  return signature;
}

async function verify(key: CryptoKey, signature: Bytes, data: Bytes): Promise<boolean> {
  if (signature.length !== SIGNATURE_SIZE) return false;
  return crypto.subtle.verify(ECDSA_SIGN, key, signature, data);
}

// ── Capabilities ────────────────────────────────────────────────────────────

/**
 * `cap_i`: everything one client holds. The access-control matrix is NOT in
 * here, and neither is any other client's wrap key or signing key.
 */
export interface ClientCapability {
  readonly clientId: number;
  readonly label: string;
  /** `rk_i`, the key this client's wrap slots are encrypted under. */
  readonly wrapKey: CryptoKey;
  readonly signingKey: CryptoKey;
  /** The shared outer store key `K`. */
  readonly storeKey: CryptoKey;
  readonly ownerVerifyKey: CryptoKey;
  /** Published client verification keys, so any client can check any writer. */
  readonly roster: ReadonlyMap<number, CryptoKey>;
  /** Owner-signed write capabilities this client holds, by entry index. */
  readonly writeCaps: Map<number, Bytes>;
  /** This client's own memory: the log position and version watermarks it has seen. */
  readonly memory: ClientMemory;
}

/** The small amount of state a client must keep to detect a rollback. */
export interface ClientMemory {
  logSeqSeen: number;
  logDigestSeen: Bytes;
  versionSeen: Map<number, number>;
}

export function freshMemory(): ClientMemory {
  return { logSeqSeen: 0, logDigestSeen: new Uint8Array(32), versionSeen: new Map() };
}

// ── The data owner ──────────────────────────────────────────────────────────

export interface DataOwner {
  readonly storeKey: CryptoKey;
  readonly signingKey: CryptoKey;
  readonly verifyKey: CryptoKey;
  readonly clientLabels: readonly string[];
  readonly wrapKeys: readonly CryptoKey[];
  readonly signingPairs: readonly CryptoKeyPair[];
  readonly roster: Map<number, CryptoKey>;
  /** `ACM`, owner-only. Index: `acm[clientId].get(entryIndex)`. */
  readonly acm: Array<Map<number, AccessMode>>;
  /** The owner's own record of each entry's current per-entry data key. */
  readonly dataKeys: Map<number, Bytes>;
  /** The owner's own record of each entry's current version. */
  readonly versions: Map<number, number>;
}

/** `gen(1^λ, n)`: generate the owner's material and register `labels.length` clients. */
export async function createOwner(labels: readonly string[]): Promise<DataOwner> {
  if (labels.length < 1 || labels.length > 32) {
    throw new RangeError('A multi-client store supports 1 to 32 registered clients.');
  }
  const storeKey = await generateAesKey();
  const ownerPair = await generateSigningPair();
  const wrapKeys: CryptoKey[] = [];
  const signingPairs: CryptoKeyPair[] = [];
  const roster = new Map<number, CryptoKey>();
  for (let clientId = 0; clientId < labels.length; clientId++) {
    wrapKeys.push(await generateAesKey());
    const pair = await generateSigningPair();
    signingPairs.push(pair);
    roster.set(clientId, pair.publicKey);
  }
  roster.set(OWNER_WRITER, ownerPair.publicKey);
  return {
    storeKey,
    signingKey: ownerPair.privateKey,
    verifyKey: ownerPair.publicKey,
    clientLabels: [...labels],
    wrapKeys,
    signingPairs,
    roster,
    acm: labels.map(() => new Map<number, AccessMode>()),
    dataKeys: new Map(),
    versions: new Map(),
  };
}

/** `chMode(cap_O, a, j)`: set one client's mode on one entry, before provisioning. */
export function setMode(
  owner: DataOwner,
  clientId: number,
  index: number,
  mode: AccessMode,
): void {
  const row = owner.acm[clientId];
  if (!row) throw new RangeError(`No such client: ${clientId}.`);
  if (!Number.isSafeInteger(index) || index < 0 || index >= STORE_N) {
    throw new RangeError(`index must be an integer in [0, ${STORE_N - 1}].`);
  }
  row.set(index, mode);
}

export function modeOf(owner: DataOwner, clientId: number, index: number): AccessMode {
  return owner.acm[clientId]?.get(index) ?? 'none';
}

async function buildEnvelope(
  owner: DataOwner,
  index: number,
  payload: Bytes,
  version: number,
  writerId: number,
  writerSigningKey: CryptoKey,
): Promise<EnvelopeContent> {
  const dataKey = owner.dataKeys.get(index);
  if (!dataKey) throw new Error(`No data key recorded for entry ${index}.`);
  const { dataNonce, data } = await sealPayload(dataKey, payload, index, version);
  const slots: Bytes[] = [];
  for (let clientId = 0; clientId < owner.clientLabels.length; clientId++) {
    const mode = modeOf(owner, clientId, index);
    slots.push(
      await wrapDataKey(
        owner.wrapKeys[clientId] as CryptoKey,
        dataKey,
        index,
        clientId,
        mode !== 'none',
      ),
    );
  }
  return {
    index,
    version,
    writerId,
    dataNonce,
    data,
    writerSig: await sign(
      writerSigningKey,
      await entrySigningInput(index, version, dataNonce, data),
    ),
    capSig: await sign(owner.signingKey, capabilitySigningInput(writerId, index)),
    slots,
  };
}

async function sealState(owner: DataOwner, leafMap: Bytes): Promise<SealedBlob> {
  const nonce = new Uint8Array(GCM_NONCE);
  crypto.getRandomValues(nonce);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: STATE_AAD },
    owner.storeKey,
    leafMap,
  );
  return { nonce, ciphertext: new Uint8Array(ciphertext) };
}

async function openState(storeKey: CryptoKey, blob: SealedBlob): Promise<Bytes> {
  const plaintext = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: blob.nonce, additionalData: STATE_AAD },
      storeKey,
      blob.ciphertext,
    ),
  );
  if (plaintext.length !== STATE_PLAINTEXT) {
    throw new Error('The shared leaf map has the wrong length.');
  }
  return plaintext;
}

export interface ProvisionedSystem {
  owner: DataOwner;
  store: MultiClientStore;
  capabilities: ClientCapability[];
  /** The owner's retained plaintext mirror, for the integrity experiment. */
  reference: Map<number, Bytes>;
}

/**
 * `addE` for every entry, then install the tree.
 *
 * Entries are placed on their assigned leaves root-to-leaf, deepest eligible
 * bucket first, exactly as a Path ORAM write-back would, with every remaining
 * slot filled by a dummy envelope of identical length.
 */
export async function provision(
  owner: DataOwner,
  initial: ReadonlyMap<number, Bytes>,
): Promise<ProvisionedSystem> {
  const clients = owner.clientLabels.length;
  const store = new MultiClientStore(clients, STATE_CIPHERTEXT);
  const leafMap = new Uint8Array(STORE_N);
  const reference = new Map<number, Bytes>();
  const envelopes: EnvelopeContent[] = [];

  for (let index = 0; index < STORE_N; index++) {
    const payload = normalizePayload(initial.get(index) ?? new Uint8Array(PAYLOAD_SIZE));
    owner.dataKeys.set(index, freshDataKey());
    owner.versions.set(index, 1);
    leafMap[index] = randomLeaf();
    reference.set(index, new Uint8Array(payload));
    envelopes.push(await buildEnvelope(owner, index, payload, 1, OWNER_WRITER, owner.signingKey));
  }

  // Greedy placement: deepest eligible bucket on each entry's own path.
  const buckets: Array<EnvelopeContent[]> = Array.from({ length: (1 << (STORE_L + 1)) - 1 }, () => []);
  const leftover: EnvelopeContent[] = [];
  for (const envelope of envelopes) {
    const leaf = leafMap[envelope.index] as number;
    const ids = pathBuckets(leaf);
    let placed = false;
    for (let level = STORE_L; level >= 0 && !placed; level--) {
      const bucket = buckets[ids[level] as number] as EnvelopeContent[];
      if (bucket.length < STORE_Z) {
        bucket.push(envelope);
        placed = true;
      }
    }
    if (!placed) leftover.push(envelope);
  }
  if (leftover.length > STORE_STASH_SLOTS) throw new StashOverflowError(leftover.length);

  const sealedBuckets: SealedEnvelope[][] = [];
  for (const bucket of buckets) {
    const slots: SealedEnvelope[] = [];
    for (const envelope of bucket) slots.push(await sealEnvelope(owner.storeKey, envelope));
    while (slots.length < STORE_Z) slots.push(await sealDummy(owner.storeKey, clients));
    sealedBuckets.push(slots);
  }
  const sealedStash: SealedEnvelope[] = [];
  for (const envelope of leftover) sealedStash.push(await sealEnvelope(owner.storeKey, envelope));
  while (sealedStash.length < STORE_STASH_SLOTS) {
    sealedStash.push(await sealDummy(owner.storeKey, clients));
  }

  store.provision(sealedBuckets, sealedStash, await sealState(owner, leafMap));

  const capabilities: ClientCapability[] = [];
  for (let clientId = 0; clientId < clients; clientId++) {
    const writeCaps = new Map<number, Bytes>();
    for (let index = 0; index < STORE_N; index++) {
      if (modeOf(owner, clientId, index) === 'readwrite') {
        writeCaps.set(index, await sign(owner.signingKey, capabilitySigningInput(clientId, index)));
      }
    }
    capabilities.push({
      clientId,
      label: owner.clientLabels[clientId] as string,
      wrapKey: owner.wrapKeys[clientId] as CryptoKey,
      signingKey: (owner.signingPairs[clientId] as CryptoKeyPair).privateKey,
      storeKey: owner.storeKey,
      ownerVerifyKey: owner.verifyKey,
      roster: owner.roster,
      writeCaps,
      memory: freshMemory(),
    });
  }
  return { owner, store, capabilities, reference };
}

// ── Entry verification: the shape of A-GORAM Algorithm 9 ───────────────────

/**
 * Verify one decrypted envelope against the owner's verification key and the
 * published client roster.
 *
 * A-GORAM Algorithm 9 checks a chameleon tag and the owner's signature on it,
 * and its section 4.2 concludes that "verifying the signature and the
 * chameleon hash suffices to make sure that the entry has been only modified
 * by authorized clients". This lesson checks the two signatures that carry the
 * same information in the substitute construction:
 *
 *   1. the OWNER authorised this writer for this entry  (`capSig`), and
 *   2. this writer produced this exact version          (`writerSig`).
 *
 * Together they establish that the entry was last changed by a client the
 * owner had granted write access to - which is tamper resistance, checkable by
 * any client without the server's help.
 */
export async function verifyEntry(
  envelope: EnvelopeContent,
  ownerVerifyKey: CryptoKey,
  roster: ReadonlyMap<number, CryptoKey>,
): Promise<void> {
  const writerKey = roster.get(envelope.writerId);
  if (!writerKey) {
    throw new EntryVerificationError(envelope.index, `writer ${envelope.writerId} is not on the roster`);
  }
  const capOk = await verify(
    ownerVerifyKey,
    envelope.capSig,
    capabilitySigningInput(envelope.writerId, envelope.index),
  );
  if (!capOk) {
    throw new EntryVerificationError(
      envelope.index,
      `the owner did not authorise writer ${envelope.writerId} for this entry`,
    );
  }
  const entryOk = await verify(
    writerKey,
    envelope.writerSig,
    await entrySigningInput(envelope.index, envelope.version, envelope.dataNonce, envelope.data),
  );
  if (!entryOk) {
    throw new EntryVerificationError(
      envelope.index,
      `writer ${envelope.writerId} did not sign version ${envelope.version} of this ciphertext`,
    );
  }
}

// ── The signed upload log ──────────────────────────────────────────────────

function logSigningInput(
  seq: number,
  writerId: number,
  leaf: number,
  pathDigest: Bytes,
  prevDigest: Bytes,
): Bytes {
  return concat(
    LOG_SIG_LABEL,
    u32(seq),
    new Uint8Array([writerId]),
    u16(leaf),
    pathDigest,
    prevDigest,
  );
}

async function recordDigest(record: UploadLogRecord): Promise<Bytes> {
  return sha256(
    concat(
      u32(record.seq),
      new Uint8Array([record.writerId]),
      u16(record.leaf),
      record.pathDigest,
      record.prevDigest,
      record.signature,
    ),
  );
}

async function pathDigestOf(path: SealedEnvelope[][]): Promise<Bytes> {
  const parts: Bytes[] = [];
  for (const bucket of path) {
    for (const slot of bucket) parts.push(slot.nonce, slot.ciphertext);
  }
  return sha256(concat(...parts));
}

/**
 * Verify the log continues from what this client last saw, and advance its
 * memory.
 *
 * This is the freshness mechanism, and it is a narrowing. ePrint 2017/329
 * section 3 requires an OBLIVIOUS gossiping protocol so that finding the
 * freshest version leaks nothing, and its footnote 1 states the need:
 * "Gossiping is necessary since we do not trust the server for consistency."
 * The chain below is A-GORAM section 4.1's signed upload log, read directly -
 * so a store that truncates or forges records is caught, but the act of
 * reading the log is itself visible. See docs/multi-client-design.md section 7.
 */
async function verifyLogFrom(
  cap: ClientCapability,
  records: readonly UploadLogRecord[],
): Promise<Bytes> {
  let expectedSeq = cap.memory.logSeqSeen + 1;
  let expectedPrev = cap.memory.logDigestSeen;
  for (const record of records) {
    if (record.seq !== expectedSeq) {
      throw new LogChainError(`expected sequence ${expectedSeq}, got ${record.seq}`);
    }
    if (!bytesEqual(record.prevDigest, expectedPrev)) {
      throw new LogChainError(`record ${record.seq} does not chain to the previous digest`);
    }
    const writerKey = cap.roster.get(record.writerId);
    if (!writerKey) {
      throw new LogChainError(`record ${record.seq} names an unknown writer ${record.writerId}`);
    }
    const ok = await verify(
      writerKey,
      record.signature,
      logSigningInput(record.seq, record.writerId, record.leaf, record.pathDigest, record.prevDigest),
    );
    if (!ok) throw new LogChainError(`record ${record.seq} carries an invalid signature`);
    if (!bytesEqual(await pathDigestOf(record.path), record.pathDigest)) {
      throw new LogChainError(`record ${record.seq} does not commit to the path stored with it`);
    }
    expectedPrev = await recordDigest(record);
    expectedSeq += 1;
  }
  return expectedPrev;
}

// ── The access protocol ────────────────────────────────────────────────────

export type ConcurrencyPolicy = 'refuse' | 'unsafe-parallel';

const inFlight = new WeakMap<MultiClientStore, number>();

export interface AccessOptions {
  /** Default `refuse`: overlapping accesses are rejected, not queued. */
  concurrency?: ConcurrencyPolicy;
  /**
   * Skip the version watermark comparison. Used only by the negative control
   * that shows what a rollback costs when freshness is not checked.
   */
  skipFreshnessCheck?: boolean;
  /**
   * Skip per-entry verification. Used only by the negative control that shows
   * what tampering costs when nobody verifies.
   */
  skipVerification?: boolean;
}

export interface AccessResult {
  payload: Bytes;
  index: number;
  version: number;
  /** The leaf the path access used, which the server also sees. */
  leaf: number;
  /** Entries this access incidentally decrypted the envelope header of. */
  envelopesSeen: number;
  /** Entries whose PAYLOAD this client could actually open. */
  payloadsReadable: number[];
}

/**
 * `read`/`write` of Definition 1, over the shared tree.
 *
 * Every well-formed access reads exactly one root-to-leaf path and writes
 * exactly one back, plus the shared stash and the shared leaf map, in the same
 * order and with the same slot counts, whatever the entry, whatever the
 * client, whichever operation, and whether authorization succeeds. An
 * authorization refusal is returned only after the no-op write-back. That
 * fixed shape is the access-pattern protection, and
 * `tests/multiclient-trace.test.ts` asserts it from the store's own transcript.
 * Malformed, stale, tampered and concurrent requests still fail closed rather
 * than being padded; those are explicitly outside this trace claim.
 */
export async function access(
  cap: ClientCapability,
  store: MultiClientStore,
  op: 'read' | 'write',
  index: number,
  data?: Bytes,
  options: AccessOptions = {},
): Promise<AccessResult> {
  if (op !== 'read' && op !== 'write') throw new TypeError('op must be read or write.');
  if (!Number.isSafeInteger(index) || index < 0 || index >= STORE_N) {
    throw new RangeError(`index must be an integer in [0, ${STORE_N - 1}].`);
  }
  const policy = options.concurrency ?? 'refuse';
  const depth = inFlight.get(store) ?? 0;
  if (depth > 0 && policy === 'refuse') throw new ConcurrencyRefusedError();
  inFlight.set(store, depth + 1);
  try {
    return await runAccess(cap, store, op, index, data, options);
  } finally {
    const current = inFlight.get(store) ?? 1;
    if (current <= 1) inFlight.delete(store);
    else inFlight.set(store, current - 1);
  }
}

async function runAccess(
  cap: ClientCapability,
  store: MultiClientStore,
  op: 'read' | 'write',
  index: number,
  data: Bytes | undefined,
  options: AccessOptions,
): Promise<AccessResult> {
  const writePayload = op === 'write' ? normalizePayload(requireData(data)) : null;

  // 1. Freshness: the signed log must continue from what this client last saw.
  const records = store.readLog(cap.memory.logSeqSeen + 1);
  const headDigest = await verifyLogFrom(cap, records);
  const headSeq = cap.memory.logSeqSeen + records.length;

  // And the head this client derived must be the digest of the record the
  // store actually holds last. Verifying only the UNSEEN records is not
  // enough: a client that read no new records would chain its next upload to
  // whatever it happens to remember, so a store that replaced its last record
  // - or a client whose memory was corrupted - would go unnoticed. This check
  // is what makes the chain a chain rather than a per-client habit.
  const lastStored = store.lastLogRecord();
  const storedHead = lastStored ? await recordDigest(lastStored) : new Uint8Array(32);
  if (!bytesEqual(storedHead, headDigest)) {
    throw new LogChainError(
      'the head this client derived is not the digest of the store’s last upload record',
    );
  }

  // 2. The shared leaf map.
  const stateBlob = store.readState();
  const leafMap = await openState(cap.storeKey, stateBlob);
  const leaf = leafMap[index] as number;
  leafMap[index] = randomLeaf();

  // 3. One whole path, and the whole shared stash.
  const sealedPath = store.readPath(leaf);
  const sealedStash = store.readStash();

  // 4. Open everything this access legitimately transfers.
  const live = new Map<number, EnvelopeContent>();
  let envelopesSeen = 0;
  for (const bucket of sealedPath) {
    for (const slot of bucket) await absorb(slot);
  }
  for (const slot of sealedStash) await absorb(slot);

  async function absorb(slot: SealedEnvelope): Promise<void> {
    const envelope = await openEnvelope(cap.storeKey, slot, store.clients);
    if (envelope.index === DUMMY_INDEX) return;
    envelopesSeen += 1;
    if (live.has(envelope.index)) throw new DuplicateEntryError(envelope.index);
    if (!options.skipVerification) {
      await verifyEntry(envelope, cap.ownerVerifyKey, cap.roster);
    }
    if (!options.skipFreshnessCheck) {
      const known = cap.memory.versionSeen.get(envelope.index);
      if (known !== undefined && envelope.version < known) {
        throw new StaleEntryError(envelope.index, envelope.version, known);
      }
    }
    live.set(envelope.index, envelope);
  }

  const target = live.get(index);
  if (!target) throw new EntryUnavailableError(index);

  // 5. Honest-client authorisation. Reads require the entry key. Ordinary
  // writes require possession of an owner-issued token; in this accountable
  // adaptation a maliciously submitted invalid token is detected by readers
  // after upload rather than blocked by the server.
  let result: Bytes | null = null;
  let authorizationFailure: AccessDeniedError | null = null;
  let finalVersion = target.version;
  if (op === 'read') {
    try {
      result = await openOwnPayload(cap, target, 'read');
    } catch (caught) {
      if (!(caught instanceof AccessDeniedError)) throw caught;
      authorizationFailure = caught;
    }
  } else {
    const capSig = cap.writeCaps.get(index);
    if (!capSig) {
      authorizationFailure = new AccessDeniedError(
        cap.clientId,
        index,
        'write',
        'this client holds no owner-signed write capability for it',
      );
    } else {
      try {
        const dataKey = await unwrapOwnKey(cap, target, 'write');
        finalVersion = target.version + 1;
        const sealed = await sealPayload(dataKey, writePayload as Bytes, index, finalVersion);
        const updated: EnvelopeContent = {
          index,
          version: finalVersion,
          writerId: cap.clientId,
          dataNonce: sealed.dataNonce,
          data: sealed.data,
          writerSig: await sign(
            cap.signingKey,
            await entrySigningInput(index, finalVersion, sealed.dataNonce, sealed.data),
          ),
          capSig: new Uint8Array(capSig),
          // Unchanged by an authorised write - A-GORAM section 4.2, "cKey and
          // cData are unchanged" except for the payload. A writer does not hold
          // the other clients' wrap keys and does not need them.
          slots: target.slots.map((slot) => new Uint8Array(slot)),
        };
        live.set(index, updated);
        result = new Uint8Array(writePayload as Bytes);
      } catch (caught) {
        if (!(caught instanceof AccessDeniedError)) throw caught;
        authorizationFailure = caught;
      }
    }
  }

  // 6. Which payloads this client could actually open, for the teaching view.
  const payloadsReadable: number[] = [];
  for (const [entryIndex, envelope] of live) {
    try {
      await unwrapOwnKey(cap, envelope, 'read');
      payloadsReadable.push(entryIndex);
    } catch {
      // Not readable by this client. That is the point of the inner layer.
    }
  }
  payloadsReadable.sort((a, b) => a - b);

  // 7. Greedy eviction and write-back of exactly one path.
  const ids = pathBuckets(leaf);
  const placed = new Set<number>();
  const bucketContents: EnvelopeContent[][] = ids.map(() => []);
  for (let level = STORE_L; level >= 0; level--) {
    const bucket = bucketContents[level] as EnvelopeContent[];
    for (const [entryIndex, envelope] of live) {
      if (bucket.length >= STORE_Z) break;
      if (placed.has(entryIndex)) continue;
      if (intersects(leafMap[entryIndex] as number, leaf, level)) {
        bucket.push(envelope);
        placed.add(entryIndex);
      }
    }
  }
  const remaining = [...live.entries()].filter(([entryIndex]) => !placed.has(entryIndex));
  if (remaining.length > STORE_STASH_SLOTS) throw new StashOverflowError(remaining.length);

  const sealedOut: SealedEnvelope[][] = [];
  for (const bucket of bucketContents) {
    const slots: SealedEnvelope[] = [];
    for (const envelope of bucket) slots.push(await sealEnvelope(cap.storeKey, envelope));
    while (slots.length < STORE_Z) slots.push(await sealDummy(cap.storeKey, store.clients));
    sealedOut.push(slots);
  }
  const stashOut: SealedEnvelope[] = [];
  for (const [, envelope] of remaining) stashOut.push(await sealEnvelope(cap.storeKey, envelope));
  while (stashOut.length < STORE_STASH_SLOTS) {
    stashOut.push(await sealDummy(cap.storeKey, store.clients));
  }

  store.writePath(leaf, sealedOut);
  store.writeStash(stashOut);
  store.writeState(await sealStateWith(cap.storeKey, leafMap));

  // 8. Sign the upload into the append-only log.
  const seq = store.nextLogSeq();
  const pathDigest = await pathDigestOf(sealedOut);
  const signature = await sign(
    cap.signingKey,
    logSigningInput(seq, cap.clientId, leaf, pathDigest, headDigest),
  );
  const appended: UploadLogRecord = {
    seq,
    writerId: cap.clientId,
    leaf,
    pathDigest,
    prevDigest: headDigest,
    signature,
    path: sealedOut.map((bucket) =>
      bucket.map((slot) => ({
        nonce: new Uint8Array(slot.nonce),
        ciphertext: new Uint8Array(slot.ciphertext),
      })),
    ),
  };
  store.appendLog(appended);

  // 9. Advance this client's memory.
  cap.memory.logSeqSeen = headSeq + 1;
  cap.memory.logDigestSeen = await recordDigest(appended);
  for (const [entryIndex, envelope] of live) {
    const known = cap.memory.versionSeen.get(entryIndex) ?? 0;
    cap.memory.versionSeen.set(entryIndex, Math.max(known, envelope.version));
  }

  // A denial is deliberately delayed until the same path/stash/state/log
  // transcript as an authorised request has completed. Otherwise the server
  // could distinguish denied logical addresses merely by observing that the
  // write-back half of the access disappeared.
  if (authorizationFailure) throw authorizationFailure;
  if (result === null) throw new Error('The access completed without a result or a refusal.');
  return { payload: result, index, version: finalVersion, leaf, envelopesSeen, payloadsReadable };
}

function requireData(data: Bytes | undefined): Bytes {
  if (data === undefined) throw new TypeError('A write needs data.');
  return data;
}

async function unwrapOwnKey(
  cap: ClientCapability,
  envelope: EnvelopeContent,
  mode: 'read' | 'write',
): Promise<Bytes> {
  const slot = envelope.slots[cap.clientId];
  if (!slot) {
    throw new AccessDeniedError(cap.clientId, envelope.index, mode, 'it carries no slot for this client');
  }
  const key = await unwrapDataKey(cap.wrapKey, slot, envelope.index, cap.clientId);
  // A dummy wrap unwraps to random bytes rather than failing, so the real
  // refusal happens here: the payload's GCM tag rejects the wrong key.
  await openPayload(key, envelope.dataNonce, envelope.data, envelope.index, envelope.version).catch(
    () => {
      throw new AccessDeniedError(
        cap.clientId,
        envelope.index,
        mode,
        'its wrap slot does not carry the entry key',
      );
    },
  );
  return key;
}

async function openOwnPayload(
  cap: ClientCapability,
  envelope: EnvelopeContent,
  mode: 'read' | 'write',
): Promise<Bytes> {
  const key = await unwrapOwnKey(cap, envelope, mode);
  return openPayload(key, envelope.dataNonce, envelope.data, envelope.index, envelope.version);
}

async function sealStateWith(storeKey: CryptoKey, leafMap: Bytes): Promise<SealedBlob> {
  const nonce = new Uint8Array(GCM_NONCE);
  crypto.getRandomValues(nonce);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: STATE_AAD },
    storeKey,
    leafMap,
  );
  return { nonce, ciphertext: new Uint8Array(ciphertext) };
}

// ── Owner-side key rotation, the honest half of revocation ────────────────

export interface RotationResult {
  index: number;
  version: number;
  /** Clients whose wrap now carries the new key. */
  readers: number[];
}

/**
 * Downgrade a client's rights and rotate the entry key.
 *
 * ePrint 2020/1551 section 5.1 notes of `ChMod` that "The basic model only
 * allows granting additional rights", and neither that paper nor GORAM gives
 * forward secrecy for a key a client has already seen. So this rotates `k_j`,
 * re-wraps for the remaining readers, re-signs as the owner and bumps the
 * version - which stops FUTURE reads and does not retract anything the
 * downgraded client already learned. The exhibit says so in those words.
 */
export async function rotateEntryKey(
  owner: DataOwner,
  store: MultiClientStore,
  index: number,
  payload: Bytes,
): Promise<RotationResult> {
  const previous = owner.versions.get(index) ?? 1;
  const version = previous + 1;
  owner.dataKeys.set(index, freshDataKey());
  owner.versions.set(index, version);

  const envelope = await buildEnvelope(
    owner,
    index,
    normalizePayload(payload),
    version,
    OWNER_WRITER,
    owner.signingKey,
  );

  // Place the rewritten entry through an ordinary path access so the store
  // sees nothing unusual: read its path, replace the entry, write it back.
  const stateBlob = store.readState();
  const leafMap = await openState(owner.storeKey, stateBlob);
  const leaf = leafMap[index] as number;
  const sealedPath = store.readPath(leaf);
  const sealedStash = store.readStash();
  const live = new Map<number, EnvelopeContent>();
  for (const bucket of sealedPath) {
    for (const slot of bucket) {
      const opened = await openEnvelope(owner.storeKey, slot, store.clients);
      if (opened.index !== DUMMY_INDEX) live.set(opened.index, opened);
    }
  }
  for (const slot of sealedStash) {
    const opened = await openEnvelope(owner.storeKey, slot, store.clients);
    if (opened.index !== DUMMY_INDEX) live.set(opened.index, opened);
  }
  live.set(index, envelope);
  leafMap[index] = randomLeaf();

  const ids = pathBuckets(leaf);
  const placed = new Set<number>();
  const bucketContents: EnvelopeContent[][] = ids.map(() => []);
  for (let level = STORE_L; level >= 0; level--) {
    const bucket = bucketContents[level] as EnvelopeContent[];
    for (const [entryIndex, content] of live) {
      if (bucket.length >= STORE_Z) break;
      if (placed.has(entryIndex)) continue;
      if (intersects(leafMap[entryIndex] as number, leaf, level)) {
        bucket.push(content);
        placed.add(entryIndex);
      }
    }
  }
  const remaining = [...live.entries()].filter(([entryIndex]) => !placed.has(entryIndex));
  if (remaining.length > STORE_STASH_SLOTS) throw new StashOverflowError(remaining.length);

  const sealedOut: SealedEnvelope[][] = [];
  for (const bucket of bucketContents) {
    const slots: SealedEnvelope[] = [];
    for (const content of bucket) slots.push(await sealEnvelope(owner.storeKey, content));
    while (slots.length < STORE_Z) slots.push(await sealDummy(owner.storeKey, store.clients));
    sealedOut.push(slots);
  }
  const stashOut: SealedEnvelope[] = [];
  for (const [, content] of remaining) stashOut.push(await sealEnvelope(owner.storeKey, content));
  while (stashOut.length < STORE_STASH_SLOTS) {
    stashOut.push(await sealDummy(owner.storeKey, store.clients));
  }
  store.writePath(leaf, sealedOut);
  store.writeStash(stashOut);
  store.writeState(await sealState(owner, leafMap));

  const seq = store.nextLogSeq();
  const pathDigest = await pathDigestOf(sealedOut);
  const last = store.lastLogRecord();
  const prevDigest = last ? await recordDigest(last) : new Uint8Array(32);
  store.appendLog({
    seq,
    writerId: OWNER_WRITER,
    leaf,
    pathDigest,
    prevDigest,
    signature: await sign(
      owner.signingKey,
      logSigningInput(seq, OWNER_WRITER, leaf, pathDigest, prevDigest),
    ),
    path: sealedOut.map((bucket) =>
      bucket.map((slot) => ({
        nonce: new Uint8Array(slot.nonce),
        ciphertext: new Uint8Array(slot.ciphertext),
      })),
    ),
  });

  const readers: number[] = [];
  for (let clientId = 0; clientId < owner.clientLabels.length; clientId++) {
    if (modeOf(owner, clientId, index) !== 'none') readers.push(clientId);
  }
  return { index, version, readers };
}

/** Revoke one client's write capability. The owner stops re-issuing it. */
export function revokeWrite(cap: ClientCapability, index: number): void {
  cap.writeCaps.delete(index);
}

// ── Accountability ─────────────────────────────────────────────────────────

export interface BlameResult {
  index: number;
  /** The client whose signed upload first carried the invalid entry. */
  blamed: number | null;
  /** The last log sequence at which the entry verified. */
  lastGoodSeq: number;
  /** The sequence at which it stopped verifying. */
  brokeAtSeq: number | null;
  detail: string;
}

/**
 * `blame(cap_i, Log, j)` of A-GORAM section 4.2.
 *
 * "the client ... parses backwards the history of modifications by decrypting
 * the paths present in the Log. The client stops only when she finds the
 * desired entry indexed by j in a consistent state ... At this point the
 * client moves forwards on the Log until she finds an uploaded path where the
 * entry j is supposed to lay on ... The signature on the path uniquely
 * identifies the client".
 */
export async function blame(
  cap: ClientCapability,
  store: MultiClientStore,
  index: number,
): Promise<BlameResult> {
  const records = store.readLog(1);
  let lastGoodSeq = 0;
  let brokeAtSeq: number | null = null;
  let blamed: number | null = null;

  for (const record of records) {
    let sawEntry = false;
    let verified = false;
    for (const bucket of record.path) {
      for (const slot of bucket) {
        let opened: EnvelopeContent;
        try {
          opened = await openEnvelope(cap.storeKey, slot, store.clients);
        } catch {
          continue;
        }
        if (opened.index !== index) continue;
        sawEntry = true;
        try {
          await verifyEntry(opened, cap.ownerVerifyKey, cap.roster);
          verified = true;
        } catch {
          verified = false;
        }
      }
    }
    if (!sawEntry) continue;
    if (verified) {
      lastGoodSeq = record.seq;
      continue;
    }
    brokeAtSeq = record.seq;
    blamed = record.writerId;
    break;
  }

  return {
    index,
    blamed,
    lastGoodSeq,
    brokeAtSeq,
    detail:
      blamed === null
        ? `Entry ${index} verifies in every retained upload; no client is accountable.`
        : `Entry ${index} last verified at upload ${lastGoodSeq} and failed at upload ` +
          `${brokeAtSeq}, which was signed by client ${blamed}.`,
  };
}

/** Owner-side check of the whole store against its retained plaintext mirror. */
export async function auditAgainstReference(
  owner: DataOwner,
  store: MultiClientStore,
  reference: ReadonlyMap<number, Bytes>,
): Promise<{ index: number; expected: string; actual: string | null }[]> {
  const mismatches: { index: number; expected: string; actual: string | null }[] = [];
  const stateBlob = store.readState();
  const leafMap = await openState(owner.storeKey, stateBlob);
  const found = new Map<number, EnvelopeContent>();
  for (let leaf = 0; leaf < STORE_LEAVES; leaf++) {
    for (const bucket of store.readPath(leaf)) {
      for (const slot of bucket) {
        const opened = await openEnvelope(owner.storeKey, slot, store.clients);
        if (opened.index !== DUMMY_INDEX) found.set(opened.index, opened);
      }
    }
  }
  for (const slot of store.readStash()) {
    const opened = await openEnvelope(owner.storeKey, slot, store.clients);
    if (opened.index !== DUMMY_INDEX) found.set(opened.index, opened);
  }
  void leafMap;
  for (const [index, expected] of reference) {
    const envelope = found.get(index);
    let actual: string | null = null;
    if (envelope) {
      const dataKey = owner.dataKeys.get(index);
      if (dataKey) {
        actual = await openPayload(
          dataKey,
          envelope.dataNonce,
          envelope.data,
          index,
          envelope.version,
        )
          .then((bytes) => hex(bytes))
          .catch(() => null);
      }
    }
    if (actual !== hex(expected)) {
      mismatches.push({ index, expected: hex(expected), actual });
    }
  }
  return mismatches;
}

export function hex(bytes: Bytes): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function textPayload(text: string): Bytes {
  return normalizePayload(te.encode(text));
}

export function payloadText(bytes: Bytes): string {
  let end = bytes.length;
  while (end > 0 && bytes[end - 1] === 0) end -= 1;
  return new TextDecoder().decode(bytes.subarray(0, end));
}
