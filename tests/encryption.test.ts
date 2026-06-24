import { describe, it, expect } from 'vitest';
import {
  generateClientKey,
  encryptBlock,
  decryptBlock,
  createDummyBlock,
  refreshEncryption,
} from '../src/client/encryption.js';

function bytes(...vals: number[]): Uint8Array {
  return new Uint8Array(vals);
}

describe('AES-256-GCM block encryption', () => {
  it('round-trips a (blockId, data) pair', async () => {
    const key = await generateClientKey();
    const data = bytes(1, 2, 3, 4, 5);
    const enc = await encryptBlock(7, data, key);
    const dec = await decryptBlock(enc, key);

    expect(dec).not.toBeNull();
    expect(dec!.blockId).toBe(7);
    // Data is zero-padded to the 32-byte block size.
    expect(dec!.data.length).toBe(32);
    expect(Array.from(dec!.data.slice(0, 5))).toEqual([1, 2, 3, 4, 5]);
  });

  it('uses a fresh 96-bit nonce every time (no nonce reuse)', async () => {
    const key = await generateClientKey();
    const data = bytes(42);
    const a = await encryptBlock(1, data, key);
    const b = await encryptBlock(1, data, key);

    expect(a.nonce.length).toBe(12);
    // Identical plaintext + key but ciphertext and nonce must differ, otherwise
    // the server could link a block across accesses.
    expect(Array.from(a.nonce)).not.toEqual(Array.from(b.nonce));
    expect(Array.from(a.ciphertext)).not.toEqual(Array.from(b.ciphertext));
  });

  it('re-encryption keeps the plaintext but changes the ciphertext', async () => {
    const key = await generateClientKey();
    const enc1 = await encryptBlock(3, bytes(9, 9, 9), key);
    const dec1 = await decryptBlock(enc1, key);
    const enc2 = await refreshEncryption(dec1!, key);
    const dec2 = await decryptBlock(enc2, key);

    expect(Array.from(enc1.ciphertext)).not.toEqual(Array.from(enc2.ciphertext));
    expect(dec2!.blockId).toBe(3);
    expect(Array.from(dec2!.data)).toEqual(Array.from(dec1!.data));
  });

  it('treats dummy blocks as undecryptable (returns null)', async () => {
    const key = await generateClientKey();
    const dummy = await createDummyBlock(key);
    expect(await decryptBlock(dummy, key)).toBeNull();
  });

  it('dummy blocks are byte-shaped like real blocks (same ciphertext length)', async () => {
    const key = await generateClientKey();
    const real = await encryptBlock(5, bytes(1, 2, 3), key);
    const dummy = await createDummyBlock(key);
    expect(dummy.ciphertext.length).toBe(real.ciphertext.length);
    expect(dummy.nonce.length).toBe(real.nonce.length);
  });

  it('rejects tampered ciphertext (GCM auth tag mismatch)', async () => {
    const key = await generateClientKey();
    const enc = await encryptBlock(2, bytes(7, 7, 7), key);
    enc.ciphertext[0] ^= 0xff; // flip a byte
    expect(await decryptBlock(enc, key)).toBeNull();
  });

  it('rejects a block encrypted under a different key', async () => {
    const keyA = await generateClientKey();
    const keyB = await generateClientKey();
    const enc = await encryptBlock(4, bytes(1), keyA);
    expect(await decryptBlock(enc, keyB)).toBeNull();
  });

  it('truncates oversized data to the 32-byte block size', async () => {
    const key = await generateClientKey();
    const big = new Uint8Array(64).fill(0xab);
    const enc = await encryptBlock(1, big, key);
    const dec = await decryptBlock(enc, key);
    expect(dec!.data.length).toBe(32);
    expect(dec!.data.every((b) => b === 0xab)).toBe(true);
  });

  it('generates a 256-bit key', async () => {
    const key = await generateClientKey();
    expect(key.rawKey.length).toBe(32);
  });
});
