import { describe, it, expect } from 'vitest';
import {
  generateClientKey,
  encryptBlock,
  decryptBlock,
  createDummyBlock,
  refreshEncryption,
  BlockAuthenticationError,
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
    await expect(decryptBlock(enc, key)).rejects.toBeInstanceOf(BlockAuthenticationError);
  });

  it('rejects a block encrypted under a different key', async () => {
    const keyA = await generateClientKey();
    const keyB = await generateClientKey();
    const enc = await encryptBlock(4, bytes(1), keyA);
    await expect(decryptBlock(enc, keyB)).rejects.toBeInstanceOf(BlockAuthenticationError);
  });

  it('rejects oversized data instead of silently truncating it', async () => {
    const key = await generateClientKey();
    const big = new Uint8Array(64).fill(0xab);
    await expect(encryptBlock(1, big, key)).rejects.toThrow(/at most 32 bytes/i);
  });

  it('generates a non-extractable 256-bit key', async () => {
    const key = await generateClientKey();
    expect(key.cryptoKey.extractable).toBe(false);
    expect((key.cryptoKey.algorithm as AesKeyAlgorithm).length).toBe(256);
  });

  it('rejects reserved or non-integer block ids', async () => {
    const key = await generateClientKey();
    await expect(encryptBlock(-1, bytes(1), key)).rejects.toThrow(/blockId/i);
    await expect(encryptBlock(1.5, bytes(1), key)).rejects.toThrow(/blockId/i);
    await expect(encryptBlock(0xffffffff, bytes(1), key)).rejects.toThrow(/blockId/i);
  });

  it('rejects malformed encrypted block lengths before Web Crypto', async () => {
    const key = await generateClientKey();
    await expect(decryptBlock({
      nonce: new Uint8Array(11),
      ciphertext: new Uint8Array(52),
    }, key)).rejects.toThrow(/nonce.*12 bytes/i);
    await expect(decryptBlock({
      nonce: new Uint8Array(12),
      ciphertext: new Uint8Array(51),
    }, key)).rejects.toThrow(/ciphertext.*52 bytes/i);
  });

  it('does not repeat a nonce across a large per-key sample', async () => {
    const key = await generateClientKey();
    const seen = new Set<string>();
    for (let i = 0; i < 512; i++) {
      const encrypted = await encryptBlock(i, bytes(i & 0xff), key);
      const encoded = Array.from(encrypted.nonce).join(',');
      expect(seen.has(encoded)).toBe(false);
      seen.add(encoded);
    }
  });
});
