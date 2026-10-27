/**
 * The multi-client entry envelope: the structure that carries one logical
 * database entry plus everything needed to decide who may read it, who may
 * change it, and whether the copy in front of you is the current one.
 *
 * This is the layered structure of A-GORAM (Maffei, Malavolta, Reinert and
 * Schröder, "GORAM - Group ORAM for Privacy and Access Control in Outsourced
 * Personal Records", IACR ePrint 2015/224, 25 August 2015, section 4.2 and
 * Figure 2), specialised to client-based read/write permissions as S-GORAM
 * does in section 5 of the same paper.
 *
 * TWO LAYERS, AND THE DISTINCTION IS THE WHOLE POINT:
 *
 *   OUTER — one store key `K`, held by the data owner and every registered
 *   client. A-GORAM section 4.2: "An entry E is protected by a top-level
 *   private-key encryption scheme with a key K that is shared by the data
 *   owner O and all clients". This layer hides everything from the SERVER and
 *   nothing from a fellow client.
 *
 *   INNER — per-entry data key `k_j`, delivered to each client in its own wrap
 *   slot. This layer is what separates clients FROM EACH OTHER, and it is the
 *   only reason the shared outer key is not a security hole. A shared key with
 *   no inner layer is exactly the design Backes, Herzberg, Kate and Pryvalov
 *   reject in "Anonymous RAM" (IACR ePrint 2016/678) section 3.1: with one
 *   ORAM and one key "all users will have to use the same private key ...
 *   However, this allows Eve, an HbC user, to break privacy of honest users,
 *   by observing the values in cells (allocated to honest users) which she
 *   downloaded and decrypted as a part of her legitimate ORAM requests."
 *   `naive.ts` executes that failure against this lab's single-client Path
 *   ORAM; this module is the layer that prevents it.
 *
 * EVERY ENVELOPE IS THE SAME NUMBER OF BYTES. There is one wrap slot per
 * REGISTERED client, whether or not that client may read the entry, and an
 * unauthorised client's slot holds an indistinguishable wrap of random bytes.
 * Without that, the envelope length would count the authorised readers.
 * S-GORAM obtains constant-size ciphertexts from Gentry-Waters broadcast
 * encryption (ePrint 2015/224 reference [24]); this lesson uses the trivial
 * one-wrap-per-client instantiation, which is the "linear in the number of
 * clients" regime section 5 names, and pads to keep the length constant.
 *
 * WHAT IS NOT HERE. There is no chameleon hash. A-GORAM keeps the owner's
 * signature valid across authorised writes by having the writer compute a
 * chameleon collision, which hides the writer's identity; that needs a
 * key-exposure-free chameleon hash (ePrint 2015/224 reference [22], Ateniese
 * and de Medeiros, SCN 2004), and the textbook discrete-log construction is
 * not key-exposure free - one published collision reveals the trapdoor.
 * Instead each writer signs its own update, which is the mechanism
 * "Maliciously Secure Multi-Client ORAM" (IACR ePrint 2017/329) section 3
 * specifies for PIR-MCORAM: "Tamper-resistance ... is achieved by letting each
 * client sign the modified entry so that others can check that this entry was
 * produced by a client with write access." The cost is anonymity, which this
 * lesson therefore never claims. See `docs/multi-client-design.md` section 7.
 */

/**
 * A `Uint8Array` backed by a plain `ArrayBuffer`, which is what Web Crypto
 * accepts. The default `Uint8Array` admits a `SharedArrayBuffer` and is
 * therefore not assignable to `BufferSource` under this project's TypeScript
 * settings.
 */
export type Bytes = Uint8Array<ArrayBuffer>;

const te = new TextEncoder();

/** Domain separation for the outer store encryption. */
const OUTER_AAD = te.encode('mcoram/envelope/v1');
/** Domain separation for a per-client key wrap. */
const WRAP_LABEL = te.encode('mcoram/wrap/v1');
/** Domain separation for the payload encryption under the per-entry key. */
const DATA_LABEL = te.encode('mcoram/data/v1');
/** Domain separation for a writer's signature over an entry version. */
export const ENTRY_SIG_LABEL = te.encode('mcoram/entry/v1');
/** Domain separation for the owner's write-capability signature. */
export const CAP_SIG_LABEL = te.encode('mcoram/write-cap/v1');
/** Domain separation for an append-only upload-log record. */
export const LOG_SIG_LABEL = te.encode('mcoram/upload-log/v1');

export const GCM_NONCE = 12;
export const GCM_TAG = 16;
export const PAYLOAD_SIZE = 32;
export const DATA_KEY_SIZE = 32;
export const SIGNATURE_SIZE = 64;

/** `0xFFFF` marks a slot that carries no logical entry. */
export const DUMMY_INDEX = 0xffff;
/** `0xFF` marks an entry written by the data owner rather than by a client. */
export const OWNER_WRITER = 0xff;

const OFF_INDEX = 0;
const OFF_VERSION = 2;
const OFF_WRITER = 6;
const OFF_RESERVED = 7;
const OFF_DATA_NONCE = 8;
const OFF_DATA = OFF_DATA_NONCE + GCM_NONCE;
const OFF_WRITER_SIG = OFF_DATA + PAYLOAD_SIZE + GCM_TAG;
const OFF_CAP_SIG = OFF_WRITER_SIG + SIGNATURE_SIZE;
export const HEADER_SIZE = OFF_CAP_SIG + SIGNATURE_SIZE;
/** One wrap slot: its own nonce plus an authenticated 32-byte key. */
export const SLOT_SIZE = GCM_NONCE + DATA_KEY_SIZE + GCM_TAG;

/** The fixed plaintext length of an envelope for a store with `clients` clients. */
export function envelopeSize(clients: number): number {
  assertClientCount(clients);
  return HEADER_SIZE + clients * SLOT_SIZE;
}

function assertClientCount(clients: number): void {
  if (!Number.isSafeInteger(clients) || clients < 1 || clients > 32) {
    throw new RangeError('A multi-client store supports 1 to 32 registered clients.');
  }
}

function assertBytes(name: string, value: Bytes, length: number): void {
  if (!(value instanceof Uint8Array)) throw new TypeError(`${name} must be a Bytes.`);
  if (value.length !== length) {
    throw new RangeError(`${name} must be exactly ${length} bytes, got ${value.length}.`);
  }
}

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

function randomBytes(length: number): Bytes {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

export class EnvelopeFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EnvelopeFormatError';
  }
}

export class EnvelopeAuthError extends Error {
  constructor(message = 'Envelope failed AES-GCM authentication.') {
    super(message);
    this.name = 'EnvelopeAuthError';
  }
}

export class AccessDeniedError extends Error {
  constructor(
    readonly clientId: number,
    readonly index: number,
    readonly mode: 'read' | 'write',
    detail: string,
  ) {
    super(`Client ${clientId} may not ${mode} entry ${index}: ${detail}`);
    this.name = 'AccessDeniedError';
  }
}

/** A 256-bit AES-GCM key, generated and used only inside this module's callers. */
export async function generateAesKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt',
  ]);
}

async function gcmEncrypt(
  key: CryptoKey,
  plaintext: Bytes,
  aad: Bytes,
): Promise<{ nonce: Bytes; ciphertext: Bytes }> {
  const nonce = randomBytes(GCM_NONCE);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: aad },
    key,
    plaintext,
  );
  return { nonce, ciphertext: new Uint8Array(ciphertext) };
}

async function gcmDecrypt(
  key: CryptoKey,
  nonce: Bytes,
  ciphertext: Bytes,
  aad: Bytes,
): Promise<Bytes> {
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: aad },
      key,
      ciphertext,
    );
    return new Uint8Array(plaintext);
  } catch {
    throw new EnvelopeAuthError();
  }
}

/**
 * The bytes a writer signs for one entry version.
 *
 * It binds the index, the version and the exact ciphertext, so a signature
 * cannot be lifted onto a different entry, replayed at a different version, or
 * kept while the payload is swapped.
 */
export async function entrySigningInput(
  index: number,
  version: number,
  dataNonce: Bytes,
  data: Bytes,
): Promise<Bytes> {
  const digest = await crypto.subtle.digest('SHA-256', concat(dataNonce, data));
  return concat(ENTRY_SIG_LABEL, u16(index), u32(version), new Uint8Array(digest));
}

/** The bytes the owner signs to authorise one client to write one entry. */
export function capabilitySigningInput(clientId: number, index: number): Bytes {
  return concat(CAP_SIG_LABEL, new Uint8Array([clientId]), u16(index));
}

/**
 * The AAD that binds a per-client wrap to one entry and one client.
 *
 * Deliberately NOT bound to the version. A-GORAM section 4.2 is explicit that
 * an authorised write changes only the payload: "cKey and cData are
 * unchanged" except for the data itself. The per-entry key `k_j` therefore
 * survives a write, and so do the wraps - which is what lets a writer update
 * an entry without holding every other client's wrap key. Rotating `k_j` is an
 * owner operation (`rotateEntryKey`), and only the owner can re-wrap.
 */
function wrapAad(index: number, clientId: number): Bytes {
  return concat(WRAP_LABEL, u16(index), new Uint8Array([clientId]));
}

/** The AAD that binds a payload ciphertext to its entry and version. */
function dataAad(index: number, version: number): Bytes {
  return concat(DATA_LABEL, u16(index), u32(version));
}

export interface EnvelopeContent {
  index: number;
  version: number;
  writerId: number;
  dataNonce: Bytes;
  /** AES-GCM of the 32-byte payload under the per-entry key `k_j`. */
  data: Bytes;
  writerSig: Bytes;
  capSig: Bytes;
  /** One wrap per registered client, in client-id order. */
  slots: Bytes[];
}

/** Serialise envelope content to its fixed-length plaintext. */
export function packEnvelope(content: EnvelopeContent): Bytes {
  const out = new Uint8Array(envelopeSize(content.slots.length));
  const view = new DataView(out.buffer);
  if (!Number.isSafeInteger(content.index) || content.index < 0 || content.index > DUMMY_INDEX) {
    throw new RangeError(`Envelope index must be in [0, ${DUMMY_INDEX}].`);
  }
  if (!Number.isSafeInteger(content.version) || content.version < 0 || content.version > 0xffffffff) {
    throw new RangeError('Envelope version must be a 32-bit unsigned integer.');
  }
  if (!Number.isSafeInteger(content.writerId) || content.writerId < 0 || content.writerId > 0xff) {
    throw new RangeError('Envelope writerId must be a single octet.');
  }
  assertBytes('dataNonce', content.dataNonce, GCM_NONCE);
  assertBytes('data', content.data, PAYLOAD_SIZE + GCM_TAG);
  assertBytes('writerSig', content.writerSig, SIGNATURE_SIZE);
  assertBytes('capSig', content.capSig, SIGNATURE_SIZE);

  view.setUint16(OFF_INDEX, content.index, false);
  view.setUint32(OFF_VERSION, content.version, false);
  out[OFF_WRITER] = content.writerId;
  out[OFF_RESERVED] = 0;
  out.set(content.dataNonce, OFF_DATA_NONCE);
  out.set(content.data, OFF_DATA);
  out.set(content.writerSig, OFF_WRITER_SIG);
  out.set(content.capSig, OFF_CAP_SIG);
  content.slots.forEach((slot, clientId) => {
    assertBytes(`slot ${clientId}`, slot, SLOT_SIZE);
    out.set(slot, HEADER_SIZE + clientId * SLOT_SIZE);
  });
  return out;
}

/** Parse a fixed-length envelope plaintext. Refuses any other length. */
export function unpackEnvelope(plaintext: Bytes, clients: number): EnvelopeContent {
  const expected = envelopeSize(clients);
  if (plaintext.length !== expected) {
    throw new EnvelopeFormatError(
      `Envelope plaintext must be exactly ${expected} bytes for ${clients} clients, got ${plaintext.length}.`,
    );
  }
  if (plaintext[OFF_RESERVED] !== 0) {
    throw new EnvelopeFormatError('Envelope reserved octet must be zero.');
  }
  const view = new DataView(plaintext.buffer, plaintext.byteOffset, plaintext.byteLength);
  const slots: Bytes[] = [];
  for (let clientId = 0; clientId < clients; clientId++) {
    const at = HEADER_SIZE + clientId * SLOT_SIZE;
    slots.push(plaintext.slice(at, at + SLOT_SIZE));
  }
  return {
    index: view.getUint16(OFF_INDEX, false),
    version: view.getUint32(OFF_VERSION, false),
    writerId: plaintext[OFF_WRITER] as number,
    dataNonce: plaintext.slice(OFF_DATA_NONCE, OFF_DATA_NONCE + GCM_NONCE),
    data: plaintext.slice(OFF_DATA, OFF_WRITER_SIG),
    writerSig: plaintext.slice(OFF_WRITER_SIG, OFF_CAP_SIG),
    capSig: plaintext.slice(OFF_CAP_SIG, HEADER_SIZE),
    slots,
  };
}

/**
 * One stored slot: an outer-encrypted envelope. The server sees exactly this
 * and nothing else - a nonce and a ciphertext of a length that does not depend
 * on the entry, the version, the writer, or how many clients may read it.
 */
export interface SealedEnvelope {
  nonce: Bytes;
  ciphertext: Bytes;
}

export function sealedSize(clients: number): number {
  return envelopeSize(clients) + GCM_TAG;
}

/** Outer-encrypt an envelope under the shared store key. */
export async function sealEnvelope(
  storeKey: CryptoKey,
  content: EnvelopeContent,
): Promise<SealedEnvelope> {
  return gcmEncrypt(storeKey, packEnvelope(content), OUTER_AAD);
}

/** Outer-decrypt a stored slot. A failed tag throws rather than returning junk. */
export async function openEnvelope(
  storeKey: CryptoKey,
  sealed: SealedEnvelope,
  clients: number,
): Promise<EnvelopeContent> {
  if (!(sealed?.nonce instanceof Uint8Array) || !(sealed?.ciphertext instanceof Uint8Array)) {
    throw new EnvelopeFormatError('A sealed envelope needs a nonce and a ciphertext.');
  }
  if (sealed.nonce.length !== GCM_NONCE) {
    throw new EnvelopeFormatError(`Sealed nonce must be ${GCM_NONCE} bytes.`);
  }
  if (sealed.ciphertext.length !== sealedSize(clients)) {
    throw new EnvelopeFormatError(
      `Sealed ciphertext must be exactly ${sealedSize(clients)} bytes for ${clients} clients.`,
    );
  }
  return unpackEnvelope(await gcmDecrypt(storeKey, sealed.nonce, sealed.ciphertext, OUTER_AAD), clients);
}

/**
 * Wrap the per-entry data key for one client.
 *
 * `authorised` false produces a wrap of fresh random bytes: the same length,
 * the same ciphertext distribution, and a client that unwraps it obtains 32
 * bytes that are not `k_j`, so its payload decryption fails the GCM tag. The
 * refusal is the cipher's, not a flag's.
 */
export async function wrapDataKey(
  clientKey: CryptoKey,
  dataKey: Bytes,
  index: number,
  clientId: number,
  authorised: boolean,
): Promise<Bytes> {
  assertBytes('dataKey', dataKey, DATA_KEY_SIZE);
  const payload = authorised ? dataKey : randomBytes(DATA_KEY_SIZE);
  const { nonce, ciphertext } = await gcmEncrypt(clientKey, payload, wrapAad(index, clientId));
  return concat(nonce, ciphertext);
}

/** Unwrap a slot. Throws `EnvelopeAuthError` if the slot is not for this client. */
export async function unwrapDataKey(
  clientKey: CryptoKey,
  slot: Bytes,
  index: number,
  clientId: number,
): Promise<Bytes> {
  assertBytes('slot', slot, SLOT_SIZE);
  return gcmDecrypt(
    clientKey,
    slot.slice(0, GCM_NONCE),
    slot.slice(GCM_NONCE),
    wrapAad(index, clientId),
  );
}

/** Encrypt a 32-byte payload under the per-entry key. */
export async function sealPayload(
  dataKey: Bytes,
  payload: Bytes,
  index: number,
  version: number,
): Promise<{ dataNonce: Bytes; data: Bytes }> {
  assertBytes('dataKey', dataKey, DATA_KEY_SIZE);
  assertBytes('payload', payload, PAYLOAD_SIZE);
  const key = await crypto.subtle.importKey('raw', dataKey, 'AES-GCM', false, ['encrypt']);
  const { nonce, ciphertext } = await gcmEncrypt(key, payload, dataAad(index, version));
  return { dataNonce: nonce, data: ciphertext };
}

/** Decrypt a payload. A wrong key or a tampered ciphertext throws. */
export async function openPayload(
  dataKey: Bytes,
  dataNonce: Bytes,
  data: Bytes,
  index: number,
  version: number,
): Promise<Bytes> {
  assertBytes('dataKey', dataKey, DATA_KEY_SIZE);
  const key = await crypto.subtle.importKey('raw', dataKey, 'AES-GCM', false, ['decrypt']);
  return gcmDecrypt(key, dataNonce, data, dataAad(index, version));
}

/** A fresh per-entry data key. Random, never derived from the store key. */
export function freshDataKey(): Bytes {
  return randomBytes(DATA_KEY_SIZE);
}

/** Pad or copy caller data to the fixed payload width without truncating. */
export function normalizePayload(data: Bytes): Bytes {
  if (!(data instanceof Uint8Array)) throw new TypeError('Payload must be a Bytes.');
  if (data.length > PAYLOAD_SIZE) {
    throw new RangeError(`Payload must be at most ${PAYLOAD_SIZE} bytes.`);
  }
  const out = new Uint8Array(PAYLOAD_SIZE);
  out.set(data);
  return out;
}

/**
 * A dummy envelope: index `0xFFFF`, random everywhere else, exactly the same
 * length as a real one. Buckets are filled with these so the server cannot
 * count how many logical entries a path carries.
 */
export async function sealDummy(storeKey: CryptoKey, clients: number): Promise<SealedEnvelope> {
  return sealEnvelope(storeKey, {
    index: DUMMY_INDEX,
    version: 0,
    writerId: OWNER_WRITER,
    dataNonce: randomBytes(GCM_NONCE),
    data: randomBytes(PAYLOAD_SIZE + GCM_TAG),
    writerSig: randomBytes(SIGNATURE_SIZE),
    capSig: randomBytes(SIGNATURE_SIZE),
    slots: Array.from({ length: clients }, () => randomBytes(SLOT_SIZE)),
  });
}
