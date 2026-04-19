/**
 * All encryption happens CLIENT-side.
 * Key never leaves client. Nonces are fresh per encryption.
 */

import type { EncryptedBlock } from '../server/oram-server.js';

export type { EncryptedBlock };

export interface ClientKey {
  rawKey: Uint8Array; // 32 bytes
  cryptoKey: CryptoKey; // Web Crypto key handle
}

// Block ID is encoded as a 4-byte big-endian uint32 at the start of plaintext.
// Then 32 bytes of data follow.
const BLOCK_ID_SIZE = 4;
const DATA_SIZE = 32;
const PLAINTEXT_SIZE = BLOCK_ID_SIZE + DATA_SIZE; // 36 bytes

const DUMMY_BLOCK_ID = 0xffffffff; // sentinel: not a real block

/**
 * Generate a fresh 256-bit key.
 */
export async function generateClientKey(): Promise<ClientKey> {
  const cryptoKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true, // extractable so we can get rawKey
    ['encrypt', 'decrypt'],
  );
  const raw = await crypto.subtle.exportKey('raw', cryptoKey);
  return {
    rawKey: new Uint8Array(raw),
    cryptoKey,
  };
}

/**
 * Encrypt a (block_id, data) pair with AES-256-GCM.
 * Fresh nonce each time so identical blocks encrypt to different ciphertexts.
 */
export async function encryptBlock(
  blockId: number,
  data: Uint8Array,
  key: ClientKey,
): Promise<EncryptedBlock> {
  const nonce = new Uint8Array(12);
  crypto.getRandomValues(nonce);

  const plaintext = new Uint8Array(PLAINTEXT_SIZE);
  const view = new DataView(plaintext.buffer);
  view.setUint32(0, blockId, false); // big-endian
  plaintext.set(data.slice(0, DATA_SIZE), BLOCK_ID_SIZE);

  const ciphertextBuf = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce },
    key.cryptoKey,
    plaintext,
  );

  return {
    ciphertext: new Uint8Array(ciphertextBuf),
    nonce,
  };
}

/**
 * Decrypt an encrypted block.
 * Returns null if decryption fails or payload is a dummy block.
 */
export async function decryptBlock(
  encrypted: EncryptedBlock,
  key: ClientKey,
): Promise<{ blockId: number; data: Uint8Array } | null> {
  let plaintextBuf: ArrayBuffer;
  try {
    const nonceCopy = new Uint8Array(encrypted.nonce.length);
    nonceCopy.set(encrypted.nonce);
    const cipherCopy = new Uint8Array(encrypted.ciphertext.length);
    cipherCopy.set(encrypted.ciphertext);
    plaintextBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonceCopy },
      key.cryptoKey,
      cipherCopy,
    );
  } catch {
    // Authentication tag mismatch — tampered or dummy encrypted with different key
    return null;
  }

  const plaintext = new Uint8Array(plaintextBuf);
  if (plaintext.length < PLAINTEXT_SIZE) return null;

  const view = new DataView(plaintext.buffer);
  const blockId = view.getUint32(0, false);

  // Dummy blocks have sentinel block ID
  if (blockId === DUMMY_BLOCK_ID) return null;

  const data = plaintext.slice(BLOCK_ID_SIZE, BLOCK_ID_SIZE + DATA_SIZE);
  return { blockId, data };
}

/**
 * Create a dummy encrypted block (encryption of zeros with sentinel ID).
 * On the server, this is byte-indistinguishable from a real block.
 */
export async function createDummyBlock(key: ClientKey): Promise<EncryptedBlock> {
  const nonce = new Uint8Array(12);
  crypto.getRandomValues(nonce);

  const plaintext = new Uint8Array(PLAINTEXT_SIZE); // all zeros
  const view = new DataView(plaintext.buffer);
  view.setUint32(0, DUMMY_BLOCK_ID, false); // sentinel

  const ciphertextBuf = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce },
    key.cryptoKey,
    plaintext,
  );

  return {
    ciphertext: new Uint8Array(ciphertextBuf),
    nonce,
  };
}

/**
 * Re-encrypt a block with a fresh nonce.
 * Same plaintext, different ciphertext — server cannot tell it's the
 * same block coming back.
 */
export async function refreshEncryption(
  block: { blockId: number; data: Uint8Array },
  key: ClientKey,
): Promise<EncryptedBlock> {
  return encryptBlock(block.blockId, block.data, key);
}
