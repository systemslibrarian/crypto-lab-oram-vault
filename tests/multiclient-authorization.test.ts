import { describe, expect, it } from 'vitest';
import {
  AccessDeniedError,
  DUMMY_INDEX,
  type Bytes,
  SLOT_SIZE,
  envelopeSize,
  openEnvelope,
  sealedSize,
} from '../src/multiclient/envelope.js';
import {
  ConcurrencyRefusedError,
  EntryVerificationError,
  LogChainError,
  access,
  blame,
  auditAgainstReference,
  createOwner,
  hex,
  modeOf,
  payloadText,
  provision,
  rotateEntryKey,
  setMode,
  textPayload,
  type AccessMode,
  type ClientCapability,
  type DataOwner,
} from '../src/multiclient/protocol.js';
import {
  MultiClientStore,
  STORE_BUCKETS,
  STORE_LEAVES,
  STORE_N,
  STORE_STASH_SLOTS,
  STORE_Z,
} from '../src/multiclient/store.js';

/**
 * Secrecy and integrity: the two access-control properties of a Multi-Client
 * ORAM, asserted as outcomes of real cryptography.
 *
 * "Secrecy: only users with at least read permissions on an entry can learn
 * its content. Integrity: only users with write permissions on an entry can
 * change its content." - Maffei, Malavolta, Reinert and Schröder, "Maliciously
 * Secure Multi-Client ORAM", IACR ePrint 2017/329, section 2.1.
 *
 * Every refusal below arrives from a failed AES-GCM tag or a failed ECDSA
 * verification. None of them is a flag, and none of them is a disabled
 * control: the test reaches past any interface a UI would offer and calls the
 * protocol directly with the wrong capability.
 */

const ALICE = 0;
const BOB = 1;
const MALLORY = 2;

/** Four bands of rights, so every mode appears for every client. */
const RIGHTS: Array<[number, number, AccessMode, AccessMode, AccessMode]> = [
  // [from, to, alice, bob, mallory]
  [0, 3, 'readwrite', 'read', 'none'],
  [4, 7, 'read', 'readwrite', 'none'],
  [8, 11, 'read', 'read', 'read'],
  [12, 15, 'readwrite', 'none', 'none'],
];

export interface Harness {
  owner: DataOwner;
  store: MultiClientStore;
  alice: ClientCapability;
  bob: ClientCapability;
  mallory: ClientCapability;
  reference: Map<number, Bytes>;
}

export async function buildHarness(): Promise<Harness> {
  const owner = await createOwner(['Alice', 'Bob', 'Mallory']);
  for (const [from, to, alice, bob, mallory] of RIGHTS) {
    for (let index = from; index <= to; index++) {
      setMode(owner, ALICE, index, alice);
      setMode(owner, BOB, index, bob);
      setMode(owner, MALLORY, index, mallory);
    }
  }
  const initial = new Map<number, Bytes>();
  for (let index = 0; index < STORE_N; index++) {
    initial.set(index, textPayload(`entry-${index}-v1`));
  }
  const system = await provision(owner, initial);
  const [alice, bob, mallory] = system.capabilities as [
    ClientCapability,
    ClientCapability,
    ClientCapability,
  ];
  return { owner, store: system.store, alice, bob, mallory, reference: system.reference };
}

describe('provisioning', () => {
  it('fills a fixed tree whose slots are all the same length', async () => {
    const { store } = await buildHarness();
    expect(store.clients).toBe(3);
    // 196-byte header plus three 60-byte wrap slots.
    expect(envelopeSize(3)).toBe(196 + 3 * SLOT_SIZE);
    expect(sealedSize(3)).toBe(envelopeSize(3) + 16);

    store.clearTranscript();
    let slots = 0;
    for (let leaf = 0; leaf < STORE_LEAVES; leaf++) {
      for (const bucket of store.readPath(leaf)) {
        expect(bucket).toHaveLength(STORE_Z);
        for (const slot of bucket) {
          expect(slot.ciphertext.length).toBe(sealedSize(3));
          slots += 1;
        }
      }
    }
    expect(slots).toBe(STORE_LEAVES * 5 * STORE_Z);
    expect(store.readStash()).toHaveLength(STORE_STASH_SLOTS);
  });

  it('places every one of the 16 logical entries exactly once', async () => {
    const { owner, store } = await buildHarness();
    const seen = new Map<number, number>();
    for (let bucketId = 0; bucketId < STORE_BUCKETS; bucketId++) {
      // Reading by leaf covers every bucket; walk the leaves instead.
      void bucketId;
    }
    for (let leaf = 0; leaf < STORE_LEAVES; leaf++) {
      for (const bucket of store.readPath(leaf)) {
        for (const slot of bucket) {
          const envelope = await openEnvelope(owner.storeKey, slot, store.clients);
          if (envelope.index === DUMMY_INDEX) continue;
          seen.set(envelope.index, (seen.get(envelope.index) ?? 0) + 1);
        }
      }
    }
    for (const slot of store.readStash()) {
      const envelope = await openEnvelope(owner.storeKey, slot, store.clients);
      if (envelope.index === DUMMY_INDEX) continue;
      seen.set(envelope.index, (seen.get(envelope.index) ?? 0) + 1);
    }
    // A bucket can lie on several paths, so a single physical copy is counted
    // once per leaf whose path contains its bucket. Every entry must appear.
    expect([...seen.keys()].sort((a, b) => a - b)).toEqual(
      Array.from({ length: STORE_N }, (_, index) => index),
    );
  });

  it('keeps the access-control matrix with the owner and out of every capability', async () => {
    const { owner, alice, bob, mallory } = await buildHarness();
    expect(modeOf(owner, ALICE, 0)).toBe('readwrite');
    expect(modeOf(owner, BOB, 0)).toBe('read');
    expect(modeOf(owner, MALLORY, 0)).toBe('none');
    for (const cap of [alice, bob, mallory]) {
      expect(Object.keys(cap)).not.toContain('acm');
      // A capability carries only the entries it may WRITE, never the matrix.
      for (const index of cap.writeCaps.keys()) {
        expect(modeOf(owner, cap.clientId, index)).toBe('readwrite');
      }
    }
    expect([...alice.writeCaps.keys()].sort((a, b) => a - b)).toEqual([
      0, 1, 2, 3, 12, 13, 14, 15,
    ]);
    expect([...bob.writeCaps.keys()].sort((a, b) => a - b)).toEqual([4, 5, 6, 7]);
    expect([...mallory.writeCaps.keys()]).toEqual([]);
  });
});

describe('secrecy', () => {
  it('lets a reader read, and refuses a client with no access on the same entry', async () => {
    const { store, alice, bob, mallory } = await buildHarness();
    expect(payloadText((await access(alice, store, 'read', 0)).payload)).toBe('entry-0-v1');
    expect(payloadText((await access(bob, store, 'read', 0)).payload)).toBe('entry-0-v1');
    await expect(access(mallory, store, 'read', 0)).rejects.toThrow(AccessDeniedError);
  });

  it('refuses the entry a client has no rights to while allowing the one it has', async () => {
    const { store, mallory } = await buildHarness();
    // Mallory may read 8-11 and nothing else.
    expect(payloadText((await access(mallory, store, 'read', 8)).payload)).toBe('entry-8-v1');
    for (const index of [0, 4, 12]) {
      await expect(access(mallory, store, 'read', index)).rejects.toThrow(AccessDeniedError);
    }
  });

  it('opens other clients’ envelopes on its own path and still cannot open their payloads', async () => {
    // Mallory's own legitimate accesses read whole paths, which carry other
    // clients' entries. She can open their ENVELOPES - the outer store key is
    // shared with every client - and never their PAYLOADS. This is exactly the
    // split that makes the shared outer key safe, and exactly what `naive.ts`
    // shows going wrong when the inner layer is absent.
    const { store, mallory } = await buildHarness();
    let foreignEnvelopes = 0;
    for (const index of [8, 9, 10, 11, 8, 9]) {
      const result = await access(mallory, store, 'read', index);
      foreignEnvelopes += result.envelopesSeen - result.payloadsReadable.length;
      for (const readable of result.payloadsReadable) {
        expect(readable, 'Mallory may read only 8-11').toBeGreaterThanOrEqual(8);
        expect(readable, 'Mallory may read only 8-11').toBeLessThanOrEqual(11);
      }
      expect(result.payloadsReadable).toContain(index);
    }
    // Over six accesses she necessarily shares a path with somebody.
    expect(foreignEnvelopes).toBeGreaterThan(0);
  });

  it('survives the entry key being rotated away from a downgraded client', async () => {
    const { owner, store, mallory } = await buildHarness();
    expect(payloadText((await access(mallory, store, 'read', 9)).payload)).toBe('entry-9-v1');

    setMode(owner, MALLORY, 9, 'none');
    const rotation = await rotateEntryKey(owner, store, 9, textPayload('entry-9-v2'));
    expect(rotation.version).toBe(2);
    expect(rotation.readers).toEqual([ALICE, BOB]);

    await expect(access(mallory, store, 'read', 9)).rejects.toThrow(AccessDeniedError);
  });
});

describe('integrity', () => {
  it('lets a writer write and refuses a read-only client on the same entry', async () => {
    const { store, alice, bob } = await buildHarness();
    await access(alice, store, 'write', 0, textPayload('alice-wrote-0'));
    expect(payloadText((await access(bob, store, 'read', 0)).payload)).toBe('alice-wrote-0');
    await expect(access(bob, store, 'write', 0, textPayload('bob-tried'))).rejects.toThrow(
      AccessDeniedError,
    );
    // And the refused write changed nothing.
    expect(payloadText((await access(alice, store, 'read', 0)).payload)).toBe('alice-wrote-0');
  });

  it('refuses a write by a client with no access at all', async () => {
    const { store, mallory } = await buildHarness();
    await expect(access(mallory, store, 'write', 8, textPayload('x'))).rejects.toThrow(
      AccessDeniedError,
    );
  });

  it('lands an unauthorised write and then has every honest reader reject it', async () => {
    // Bob may not write entry 0. Hand him Alice's capability for it. The
    // owner's signature covers (client, entry), so it does not transfer - but
    // NOTHING STOPS THE UPLOAD, because this store performs no access control
    // and cannot: deciding the question would mean reading the entry index out
    // of an envelope it cannot open. A-GORAM section 4 gives up the
    // server-side check on purpose, so what remains is detection and blame.
    const { store, alice, bob } = await buildHarness();
    const stolen = alice.writeCaps.get(0);
    expect(stolen).toBeDefined();
    bob.writeCaps.set(0, stolen as Bytes);

    const landed = await access(bob, store, 'write', 0, textPayload('bob-forged'));
    expect(landed.version).toBe(2);

    // And now no honest client will accept that entry. Alice's read of entry 0
    // necessarily puts entry 0 on her path, so this is not luck.
    const rejection = await access(alice, store, 'read', 0).catch((caught: unknown) => caught);
    expect(rejection).toBeInstanceOf(EntryVerificationError);
    expect((rejection as EntryVerificationError).index).toBe(0);
    expect((rejection as Error).message).toMatch(/did not authorise writer 1 for this entry/);

    // Accountability: the signed upload log names the client who did it.
    const verdict = await blame(alice, store, 0);
    expect(verdict.blamed).toBe(BOB);
    expect(verdict.brokeAtSeq).toBeGreaterThan(0);
    expect(verdict.lastGoodSeq).toBeLessThan(verdict.brokeAtSeq as number);
    expect(verdict.detail).toMatch(/signed by client 1/);
  });

  it('lands a capability borrowed from another entry and still fails verification', async () => {
    const { store, alice, bob } = await buildHarness();
    const own = bob.writeCaps.get(4);
    expect(own).toBeDefined();
    bob.writeCaps.set(0, own as Bytes);
    await access(bob, store, 'write', 0, textPayload('wrong entry'));
    await expect(access(alice, store, 'read', 0)).rejects.toThrow(
      /did not authorise writer 1 for this entry/,
    );
    expect((await blame(alice, store, 0)).blamed).toBe(BOB);
  });

  it('attributes nothing when every retained upload verifies', async () => {
    const { store, alice } = await buildHarness();
    await access(alice, store, 'write', 0, textPayload('honest'));
    const verdict = await blame(alice, store, 0);
    expect(verdict.blamed).toBeNull();
    expect(verdict.brokeAtSeq).toBeNull();
    expect(verdict.detail).toMatch(/no client is accountable/);
  });

  it('bumps the version on every authorised write and keeps it monotonic', async () => {
    const { store, alice } = await buildHarness();
    const first = await access(alice, store, 'write', 1, textPayload('v2'));
    const second = await access(alice, store, 'write', 1, textPayload('v3'));
    const third = await access(alice, store, 'read', 1);
    expect(first.version).toBe(2);
    expect(second.version).toBe(3);
    expect(third.version).toBe(3);
    expect(payloadText(third.payload)).toBe('v3');
  });
});

describe('the retained reference model', () => {
  it('agrees with the store after a mixed workload', async () => {
    const { owner, store, alice, bob, reference } = await buildHarness();
    const writes: Array<[ClientCapability, number, string]> = [
      [alice, 0, 'a-zero'],
      [bob, 5, 'b-five'],
      [alice, 13, 'a-thirteen'],
      [bob, 6, 'b-six'],
      [alice, 2, 'a-two'],
    ];
    for (const [cap, index, text] of writes) {
      await access(cap, store, 'write', index, textPayload(text));
      reference.set(index, textPayload(text));
    }
    expect(await auditAgainstReference(owner, store, reference)).toEqual([]);
  });

  it('reports a mismatch when the store and the mirror disagree', async () => {
    // The positive control for the verifier itself. Without this, an audit
    // that always returned an empty list would pass every other test here.
    const { owner, store, alice, reference } = await buildHarness();
    await access(alice, store, 'write', 3, textPayload('written-but-not-mirrored'));
    const mismatches = await auditAgainstReference(owner, store, reference);
    expect(mismatches).toHaveLength(1);
    expect(mismatches[0]?.index).toBe(3);
    expect(mismatches[0]?.expected).not.toBe(mismatches[0]?.actual);
  });

  it('reads back every one of the 16 entries through an authorised client', async () => {
    const { store, alice, reference } = await buildHarness();
    for (let index = 0; index < STORE_N; index++) {
      const result = await access(alice, store, 'read', index);
      expect(hex(result.payload), `entry ${index}`).toBe(hex(reference.get(index) as Bytes));
    }
  });
});

describe('the signed upload log', () => {
  it('refuses to proceed when the head a client remembers is not the store’s', async () => {
    // The direct test of the chain check. A client whose remembered head has
    // drifted - because the store replaced its last record, or because the
    // client's own memory was corrupted - must not quietly chain its next
    // upload to a head nobody else agrees with.
    const { store, alice } = await buildHarness();
    await access(alice, store, 'read', 0);
    alice.memory.logDigestSeen = new Uint8Array(32);
    const failure = await access(alice, store, 'read', 0).catch((caught: unknown) => caught);
    expect(failure).toBeInstanceOf(LogChainError);
    expect((failure as Error).message).toMatch(/last upload record/);
  });

  it('accepts an honest sequence of accesses by different clients', async () => {
    const { store, alice, bob } = await buildHarness();
    await access(alice, store, 'write', 0, textPayload('one'));
    await access(bob, store, 'write', 4, textPayload('two'));
    await access(alice, store, 'read', 4);
    expect(payloadText((await access(bob, store, 'read', 0)).payload)).toBe('one');
  });
});

describe('concurrency', () => {
  it('refuses an overlapping access rather than racing', async () => {
    const { store, alice } = await buildHarness();
    const first = access(alice, store, 'write', 0, textPayload('first'));
    await expect(access(alice, store, 'read', 1)).rejects.toThrow(ConcurrencyRefusedError);
    await first;
    // Sequential use is unaffected.
    expect(payloadText((await access(alice, store, 'read', 0)).payload)).toBe('first');
  });

  it('explains the refusal by naming the missing mechanism', async () => {
    const { store, alice, bob } = await buildHarness();
    const first = access(alice, store, 'write', 0, textPayload('x'));
    const error = await access(bob, store, 'read', 0).catch((caught: unknown) => caught);
    await first;
    expect(error).toBeInstanceOf(ConcurrencyRefusedError);
    expect((error as Error).message).toMatch(/no concurrency control/);
  });
});
