/**
 * The four states of the exhibit, plus every negative control, each computed
 * from one run of the real protocol.
 *
 *   1. `runBaseline`      - honest multi-client use, rights enforced
 *   2. `runNaive`          - re-exported from `naive.ts`: the deployment that fails
 *   3. `runCollusion`      - obliviousness breaks when a client colludes
 *   4. `runRepaired`       - the construction inside its own stated model
 *
 * and the controls: tampering, rollback, stale state, concurrency, the
 * integrity experiment of ePrint 2020/1551 Figure 3, and the access-shape
 * trace.
 *
 * NOTHING HERE IS A STORED EXPECTED ANSWER. Every figure the exhibit shows is
 * returned by one of these functions, from the state the protocol actually
 * reached on that run.
 */

import {
  AccessDeniedError,
  DUMMY_INDEX,
  GCM_NONCE,
  openEnvelope,
  sealedSize,
  type Bytes,
  type SealedEnvelope,
} from './envelope.js';
import {
  ConcurrencyRefusedError,
  EntryVerificationError,
  StaleEntryError,
  access,
  auditAgainstReference,
  blame,
  createOwner,
  modeOf,
  payloadText,
  provision,
  rotateEntryKey,
  setMode,
  textPayload,
  type AccessMode,
  type ClientCapability,
  type DataOwner,
} from './protocol.js';
import {
  MultiClientStore,
  STORE_LEAVES,
  STORE_N,
  STORE_STASH_SLOTS,
  STORE_Z,
  type StoreEvent,
} from './store.js';
import { runNaiveSharing, type NaiveReport } from './naive.js';

export { runNaiveSharing };
export type { NaiveReport };

export const CLIENT_LABELS = ['Clinician', 'Billing', 'Contractor'] as const;
export const CLINICIAN = 0;
export const BILLING = 1;
export const CONTRACTOR = 2;

/**
 * The access-control matrix this lesson ships. Every mode appears for every
 * client, so no client is a special case and no refusal can be read as "that
 * client is just switched off".
 */
export const RIGHTS: ReadonlyArray<{
  from: number;
  to: number;
  label: string;
  modes: [AccessMode, AccessMode, AccessMode];
}> = [
  { from: 0, to: 3, label: 'Clinical notes', modes: ['readwrite', 'read', 'none'] },
  { from: 4, to: 7, label: 'Billing codes', modes: ['read', 'readwrite', 'none'] },
  { from: 8, to: 11, label: 'Shared summary', modes: ['read', 'read', 'read'] },
  { from: 12, to: 15, label: 'Private annotations', modes: ['readwrite', 'none', 'none'] },
];

export interface System {
  owner: DataOwner;
  store: MultiClientStore;
  capabilities: ClientCapability[];
  reference: Map<number, Bytes>;
}

/** `gen` + `addCl` + `addE` for the shipped rights table. */
export async function buildSystem(): Promise<System> {
  const owner = await createOwner([...CLIENT_LABELS]);
  for (const band of RIGHTS) {
    for (let index = band.from; index <= band.to; index++) {
      band.modes.forEach((mode, clientId) => setMode(owner, clientId, index, mode));
    }
  }
  const initial = new Map<number, Bytes>();
  for (let index = 0; index < STORE_N; index++) {
    initial.set(index, textPayload(`record-${index}`));
  }
  const system = await provision(owner, initial);
  system.store.clearTranscript();
  return {
    owner: system.owner,
    store: system.store,
    capabilities: system.capabilities,
    reference: system.reference,
  };
}

/** The rights table as the omniscient teaching view shows it. */
export function rightsTable(owner: DataOwner): Array<{
  band: string;
  range: string;
  modes: AccessMode[];
}> {
  return RIGHTS.map((band) => ({
    band: band.label,
    range: `${band.from}-${band.to}`,
    modes: CLIENT_LABELS.map((_, clientId) => modeOf(owner, clientId, band.from)),
  }));
}

// ── 1. Honest baseline ──────────────────────────────────────────────────────

export interface AttemptRow {
  client: string;
  clientId: number;
  operation: 'read' | 'write';
  index: number;
  mode: AccessMode;
  /** `released` for a successful read/write, otherwise the refusal class. */
  outcome: 'released' | 'refused';
  detail: string;
  /** The leaf the access used, which is what the server saw. */
  leaf: number | null;
  version: number | null;
}

export interface BaselineReport {
  rows: AttemptRow[];
  /** Mismatches against the retained plaintext mirror. Empty when correct. */
  referenceMismatches: Array<{ index: number; expected: string; actual: string | null }>;
  traffic: { readSlots: number; writeSlots: number };
  accesses: number;
}

const BASELINE_ATTEMPTS: ReadonlyArray<[number, 'read' | 'write', number, string]> = [
  [CLINICIAN, 'read', 0, ''],
  [CLINICIAN, 'write', 0, 'note-updated'],
  [BILLING, 'read', 0, ''],
  [BILLING, 'write', 0, 'billing-edit'],
  [BILLING, 'write', 5, 'code-updated'],
  [CLINICIAN, 'write', 5, 'clinician-edit'],
  [CONTRACTOR, 'read', 9, ''],
  [CONTRACTOR, 'read', 0, ''],
  [CONTRACTOR, 'write', 9, 'contractor-edit'],
  [CLINICIAN, 'write', 13, 'private-note'],
  [BILLING, 'read', 13, ''],
];

/**
 * Every client tries what it may and what it may not, and the refusals come
 * from payload authentication or the absence of an owner-issued write token,
 * rather than from a UI flag.
 *
 * A refused WRITE is worth reading carefully: this construction has no
 * server-side access control, so some unauthorised writes land and are then
 * rejected by every honest reader. The `detail` column says which happened.
 */
export async function runBaseline(system?: System): Promise<BaselineReport> {
  const { owner, store, capabilities, reference } = system ?? (await buildSystem());
  const rows: AttemptRow[] = [];
  let accesses = 0;

  for (const [clientId, operation, index, value] of BASELINE_ATTEMPTS) {
    const cap = capabilities[clientId] as ClientCapability;
    const mode = modeOf(owner, clientId, index);
    try {
      const result =
        operation === 'read'
          ? await access(cap, store, 'read', index)
          : await access(cap, store, 'write', index, textPayload(value));
      accesses += 1;
      if (operation === 'write') reference.set(index, textPayload(value));
      rows.push({
        client: cap.label,
        clientId,
        operation,
        index,
        mode,
        outcome: 'released',
        detail:
          operation === 'read'
            ? `read "${payloadText(result.payload)}" at version ${result.version}`
            : `wrote "${value}" as version ${result.version}`,
        leaf: result.leaf,
        version: result.version,
      });
    } catch (caught) {
      const error = caught as Error;
      rows.push({
        client: cap.label,
        clientId,
        operation,
        index,
        mode,
        outcome: 'refused',
        detail: `${error.name}: ${error.message}`,
        leaf: null,
        version: null,
      });
    }
  }

  return {
    rows,
    referenceMismatches: await auditAgainstReference(owner, store, reference),
    traffic: store.dataTraffic(),
    accesses,
  };
}

// ── 3. Obliviousness breaks the moment a client colludes ───────────────────

export interface CollusionObservation {
  leafObserved: number;
  candidates: number[];
  actualIndex: number;
  uniquelyIdentified: boolean;
}

export interface CollusionReport {
  trials: number;
  /** Trials where the candidate set was exactly the accessed entry. */
  uniquelyIdentified: number;
  /** Trials where the accessed entry was among the candidates. Always all of them. */
  actualInCandidates: number;
  /** Mean candidate-set size, out of 16 entries. */
  meanCandidates: number;
  /** A uniform guess over all 16 entries. */
  baselineRate: number;
  /** Guessing uniformly from the candidate set instead. */
  collusionRate: number;
  observations: CollusionObservation[];
  method: string;
}

/**
 * The corrupted client and the server, together.
 *
 * No statistics are needed. The shared leaf map has to live on the server so
 * that every client can use the one tree - GORAM section 3.1 - and it is
 * encrypted under the store key that every registered client holds. So a
 * registered client can DECRYPT THE LEAF MAP. Pair that with the one thing the
 * server genuinely observes, the leaf of each path access, and the pair knows
 * exactly which entry an honest client touched.
 *
 * WHAT IS AND IS NOT CLAIMED. The candidate set always contains the accessed
 * entry, because the map is exact. It is not always a single entry: sixteen
 * entries over sixteen leaves collide often, so a leaf typically names two or
 * three. The break is therefore "sixteen possibilities reduced to a handful,
 * always including the right one", measured and reported as such - not
 * "identified outright".
 *
 * This is evidence consistent with ePrint 2017/329 section 2.2 Theorem 1: a
 * multi-client ORAM that "accesses on average o(n) physical addresses for each
 * read and write operation ... is not secure against malicious clients". One
 * path access here touches five buckets out of thirty-one, which is o(n). The
 * lab does not prove the theorem; it shows a concrete break at the access cost
 * the theorem rules out, and the exhibit says which of those two it is.
 */
export async function runCollusion(trials = 8): Promise<CollusionReport> {
  const { store, capabilities } = await buildSystem();
  const honest = capabilities[CLINICIAN] as ClientCapability;
  const corrupted = capabilities[CONTRACTOR] as ClientCapability;
  const observations: CollusionObservation[] = [];

  for (let trial = 0; trial < trials; trial++) {
    // The corrupted client reads the shared state - an ordinary protocol step -
    // and decrypts the leaf map with the key it was issued.
    const snapshot = await decryptLeafMap(corrupted, store);

    const actualIndex = trial % 4; // one of the clinician's own entries
    store.clearTranscript();
    await access(honest, store, 'read', actualIndex);

    // What the server saw.
    const pathRead = store.transcript().find((event) => event.kind === 'path' && event.operation === 'read');
    const leafObserved = pathRead?.leaf ?? -1;
    const candidates: number[] = [];
    snapshot.forEach((leaf, index) => {
      if (leaf === leafObserved) candidates.push(index);
    });

    observations.push({
      leafObserved,
      candidates,
      actualIndex,
      uniquelyIdentified: candidates.length === 1 && candidates[0] === actualIndex,
    });
  }

  const sizes = observations.map((o) => o.candidates.length);
  const meanCandidates = sizes.reduce((sum, size) => sum + size, 0) / (sizes.length || 1);
  return {
    trials,
    uniquelyIdentified: observations.filter((o) => o.uniquelyIdentified).length,
    actualInCandidates: observations.filter((o) => o.candidates.includes(o.actualIndex)).length,
    meanCandidates,
    baselineRate: 1 / STORE_N,
    collusionRate: meanCandidates > 0 ? 1 / meanCandidates : 0,
    observations,
    method:
      'The corrupted client decrypts the shared leaf map with the store key it was issued, and ' +
      'the server contributes the leaf of the path access. No statistics are involved: the pair ' +
      'reads the candidate set straight off the map. Several entries can share a leaf in a ' +
      '16-leaf tree, so the set is not always a single entry - but it always CONTAINS the ' +
      'accessed entry, and it is a handful out of sixteen rather than sixteen.',
  };
}

async function decryptLeafMap(cap: ClientCapability, store: MultiClientStore): Promise<Uint8Array> {
  const blob = store.readState();
  const plaintext = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: blob.nonce,
      additionalData: new TextEncoder().encode('mcoram/leafmap/v1'),
    },
    cap.storeKey,
    blob.ciphertext,
  );
  return new Uint8Array(plaintext);
}

// ── Controls: tampering ─────────────────────────────────────────────────────

export interface TamperReport {
  /** Random bytes in a stored slot: the outer AES-GCM tag refuses them. */
  ciphertextTamper: { error: string; message: string };
  /** A genuinely signed but unauthorised write: verification refuses it. */
  unauthorisedWrite: {
    landed: boolean;
    readerError: string;
    readerMessage: string;
    blamed: number | null;
    blameDetail: string;
  };
  /** Verification switched off, so the same forged entry is accepted. */
  withoutVerification: { accepted: boolean; value: string | null };
}

export async function runTamperControls(): Promise<TamperReport> {
  // (a) A storage provider writes rubbish into one slot.
  const first = await buildSystem();
  const rubbish: SealedEnvelope = {
    nonce: new Uint8Array(GCM_NONCE),
    ciphertext: new Uint8Array(sealedSize(first.store.clients)),
  };
  crypto.getRandomValues(rubbish.nonce);
  crypto.getRandomValues(rubbish.ciphertext);
  // The root bucket is on every path, so this is seen by the next access.
  first.store.forceSlot(0, 0, rubbish);
  const ciphertextTamper = await (async () => {
    try {
      await access(first.capabilities[CLINICIAN] as ClientCapability, first.store, 'read', 0);
      return { error: 'none', message: 'the tampered slot was accepted' };
    } catch (caught) {
      return { error: (caught as Error).name, message: (caught as Error).message };
    }
  })();

  // (b) A client writes an entry it is not authorised for, signing honestly.
  const second = await buildSystem();
  const billing = second.capabilities[BILLING] as ClientCapability;
  const clinician = second.capabilities[CLINICIAN] as ClientCapability;
  // Billing legitimately owns this capability for entry 4. Reusing it on
  // entry 0 is a malicious protocol input, but it reads no honest client's
  // hidden material; the owner's signature still binds it to the wrong entry.
  const mismatched = billing.writeCaps.get(4);
  let landed = false;
  if (mismatched) {
    billing.writeCaps.set(0, new Uint8Array(mismatched));
    await access(billing, second.store, 'write', 0, textPayload('forged-by-billing'));
    landed = true;
  }
  const readerFailure = await access(clinician, second.store, 'read', 0).then(
    () => ({ name: 'none', message: 'the forged entry was accepted' }),
    (caught: unknown) => ({ name: (caught as Error).name, message: (caught as Error).message }),
  );
  const verdict = await blame(clinician, second.store, 0);

  // (c) The same store, read with verification switched off.
  const unverified = await access(clinician, second.store, 'read', 0, undefined, {
    skipVerification: true,
  }).then(
    (result) => ({ accepted: true, value: payloadText(result.payload) }),
    () => ({ accepted: false, value: null }),
  );

  return {
    ciphertextTamper,
    unauthorisedWrite: {
      landed,
      readerError: readerFailure.name,
      readerMessage: readerFailure.message,
      blamed: verdict.blamed,
      blameDetail: verdict.detail,
    },
    withoutVerification: unverified,
  };
}

// ── Controls: rollback and stale state ─────────────────────────────────────

export interface RollbackReport {
  writtenValue: string;
  /** With the freshness check engaged. */
  refusedError: string;
  refusedMessage: string;
  /** A different reader with no watermark accepts the genuine old version. */
  firstContactValue: string | null;
  firstContactVersion: number | null;
  /** With the freshness check switched off: the stale value comes back. */
  staleValue: string | null;
  staleVersion: number | null;
}

/**
 * The storage provider puts the bytes back and keeps the log.
 *
 * Every signature on the restored data is genuine, so no amount of signature
 * checking notices. What notices is the client's own watermark: it has already
 * seen a higher version of that entry. That is the freshness mechanism, and
 * it is the honest version of ePrint 2017/329 footnote 1 - "Gossiping is
 * necessary since we do not trust the server for consistency" - with the
 * narrowing recorded in `docs/multi-client-design.md` section 7.
 */
export async function runRollbackControl(): Promise<RollbackReport> {
  const { store, capabilities } = await buildSystem();
  const clinician = capabilities[CLINICIAN] as ClientCapability;
  const billing = capabilities[BILLING] as ClientCapability;

  await access(clinician, store, 'read', 0);
  const before = store.snapshot();
  const writtenValue = 'version-two';
  await access(clinician, store, 'write', 0, textPayload(writtenValue));

  // The provider restores the old bytes and leaves the upload log alone.
  store.rollbackTo(before);

  const refused = await access(clinician, store, 'read', 0).then(
    () => ({ name: 'none', message: 'the rolled-back entry was accepted' }),
    (caught: unknown) => ({ name: (caught as Error).name, message: (caught as Error).message }),
  );

  // Billing may read entry 0 but has never seen its version. It verifies the
  // complete signed upload log and still cannot infer the current per-entry
  // version from that path-only log. This is the concrete first-contact limit
  // of client-local watermarks; there is no owner-signed global version head.
  const firstContact = await access(billing, store, 'read', 0).then(
    (result) => ({ value: payloadText(result.payload), version: result.version }),
    () => ({ value: null, version: null }),
  );

  const stale = await access(clinician, store, 'read', 0, undefined, {
    skipFreshnessCheck: true,
  }).then(
    (result) => ({ value: payloadText(result.payload), version: result.version }),
    () => ({ value: null, version: null }),
  );

  return {
    writtenValue,
    refusedError: refused.name,
    refusedMessage: refused.message,
    firstContactValue: firstContact.value,
    firstContactVersion: firstContact.version,
    staleValue: stale.value,
    staleVersion: stale.version,
  };
}

// ── Controls: concurrency ──────────────────────────────────────────────────

export interface ConcurrencyReport {
  refusedError: string;
  refusedMessage: string;
  /** With the refusal lifted: what the interleaving actually costs. */
  unsafe: {
    firstValue: string;
    secondValue: string;
    observedAfter: string | null;
    lostUpdate: boolean;
    error: string | null;
  };
}

export async function runConcurrencyControl(): Promise<ConcurrencyReport> {
  const guarded = await buildSystem();
  const clinicianA = guarded.capabilities[CLINICIAN] as ClientCapability;
  const inFlight = access(clinicianA, guarded.store, 'write', 0, textPayload('first'));
  const refused = await access(clinicianA, guarded.store, 'read', 1).then(
    () => ({ name: 'none', message: 'the overlapping access was allowed' }),
    (caught: unknown) => ({ name: (caught as Error).name, message: (caught as Error).message }),
  );
  await inFlight;

  // Now lift the refusal and let two writes overlap on purpose.
  const open = await buildSystem();
  const clinician = open.capabilities[CLINICIAN] as ClientCapability;
  const firstValue = 'clinician-A';
  const secondValue = 'clinician-B';
  let error: string | null = null;
  const both = await Promise.allSettled([
    access(clinician, open.store, 'write', 0, textPayload(firstValue), {
      concurrency: 'unsafe-parallel',
    }),
    access(clinician, open.store, 'write', 1, textPayload(secondValue), {
      concurrency: 'unsafe-parallel',
    }),
  ]);
  for (const settled of both) {
    if (settled.status === 'rejected') error = (settled.reason as Error).name;
  }

  const observed = await access(clinician, open.store, 'read', 0, undefined, {
    skipFreshnessCheck: true,
    skipVerification: true,
  }).then(
    (result) => payloadText(result.payload),
    () => null,
  );

  return {
    refusedError: refused.name,
    refusedMessage: refused.message,
    unsafe: {
      firstValue,
      secondValue,
      observedAfter: observed,
      lostUpdate: observed !== firstValue,
      error,
    },
  };
}

// ── Controls: revocation by key rotation ───────────────────────────────────

export interface RevocationReport {
  entry: number;
  beforeValue: string;
  rotatedVersion: number;
  remainingReaders: number[];
  afterError: string;
  afterMessage: string;
  /** Stated, not demonstrated: rotation does not retract what was learned. */
  retainedByRevokedClient: string;
}

export async function runRevocationControl(): Promise<RevocationReport> {
  const { owner, store, capabilities } = await buildSystem();
  const contractor = capabilities[CONTRACTOR] as ClientCapability;
  const entry = 9;
  const beforeValue = payloadText((await access(contractor, store, 'read', entry)).payload);

  setMode(owner, CONTRACTOR, entry, 'none');
  const rotation = await rotateEntryKey(owner, store, entry, textPayload('summary-rotated'));

  const after = await access(contractor, store, 'read', entry).then(
    () => ({ name: 'none', message: 'the revoked client still read the entry' }),
    (caught: unknown) => ({ name: (caught as Error).name, message: (caught as Error).message }),
  );

  return {
    entry,
    beforeValue,
    rotatedVersion: rotation.version,
    remainingReaders: rotation.readers,
    afterError: after.name,
    afterMessage: after.message,
    retainedByRevokedClient: beforeValue,
  };
}

// ── The integrity experiment of ePrint 2020/1551 Figure 3 ──────────────────

export interface IntegrityExperimentReport {
  /** `b0`: the adversary names a client with read access to `a*`. */
  readerHasReadAccess: boolean;
  /** `b1`: no corrupted client holds write access to `a*`. */
  noCorruptedWriter: boolean;
  /** `b2`: the plaintext mirror disagrees with what the read returns. */
  mirrorDisagrees: boolean;
  /** The adversary wins iff all three hold. True for this accountable-only adaptation. */
  adversaryWins: boolean;
  /** The malformed but client-signed update reached the honest server. */
  attackLanded: boolean;
  targetIndex: number;
  corrupted: number[];
  mirrorValue: string;
  observed: string | null;
  observedError: string | null;
}

/**
 * The integrity game of Chow, Fech, Lai and Malavolta, ePrint 2020/1551
 * section 5.2 Definition 16 and Figure 3, run as a test rather than quoted.
 *
 * The experiment maintains a plaintext mirror `M'`, lets the adversary corrupt
 * clients and access data, and the adversary wins if the mirror ends up
 * inconsistent with what an authorised reader gets back. Figure 3's winning
 * condition is `b0 and b1 and b2` where `b0` is that the reader has read
 * access, `b1` that no corrupted client has write access to the target, and
 * `b2` that the mirror and the read disagree.
 *
 * Here the corrupted client is Billing, who may read but not write the target.
 * It supplies its genuine capability for a different entry and signs the
 * resulting update itself. The selected accountable construction deliberately
 * has no server-side authorization proof, so that malformed update lands. An
 * honest reader then rejects it. A refusal counts as a WIN for the adversary,
 * because a reader with read access that cannot obtain the mirror's value is
 * exactly `b2`. This executable win is why the lesson claims accountable
 * integrity, not Definition 16 integrity.
 */
export async function runIntegrityExperiment(): Promise<IntegrityExperimentReport> {
  const { owner, store, capabilities, reference } = await buildSystem();
  const clinician = capabilities[CLINICIAN] as ClientCapability;
  const billing = capabilities[BILLING] as ClientCapability;
  const targetIndex = 0;

  // Honest traffic, mirrored.
  await access(clinician, store, 'write', targetIndex, textPayload('mirror-truth'));
  reference.set(targetIndex, textPayload('mirror-truth'));

  // Billing owns a genuine write capability for entry 4, but not for target 0.
  // A malicious client may submit that mismatched signature as protocol input;
  // it never reads another client's hidden key or capability. The honest-but-
  // curious server in this selected construction performs no authorization
  // proof, so the invalid update reaches the store and is detected a-posteriori.
  const mismatched = billing.writeCaps.get(4);
  if (!mismatched) throw new Error('The integrity experiment needs Billing’s entry-4 capability.');
  billing.writeCaps.set(targetIndex, new Uint8Array(mismatched));
  const attackLanded = await access(
    billing,
    store,
    'write',
    targetIndex,
    textPayload('billing-forged'),
  ).then(
    () => true,
    () => false,
  );

  const observedResult = await access(clinician, store, 'read', targetIndex).then(
    (result) => ({ value: payloadText(result.payload), error: null as string | null }),
    (caught: unknown) => ({ value: null, error: (caught as Error).name }),
  );

  const mirrorValue = payloadText(reference.get(targetIndex) as Bytes);
  const readerHasReadAccess = modeOf(owner, CLINICIAN, targetIndex) !== 'none';
  const noCorruptedWriter = modeOf(owner, BILLING, targetIndex) !== 'readwrite';
  const mirrorDisagrees = observedResult.value !== mirrorValue;

  return {
    readerHasReadAccess,
    noCorruptedWriter,
    mirrorDisagrees,
    adversaryWins: readerHasReadAccess && noCorruptedWriter && mirrorDisagrees,
    attackLanded,
    targetIndex,
    corrupted: [BILLING],
    mirrorValue,
    observed: observedResult.value,
    observedError: observedResult.error,
  };
}

// ── The server-visible access shape ────────────────────────────────────────

export interface TraceReport {
  /** One entry per access, each the complete server view of that access. */
  perAccess: Array<{
    client: string;
    operation: 'read' | 'write';
    index: number;
    outcome: 'released' | 'refused';
    error: string | null;
    events: StoreEvent[];
    readSlots: number;
    writeSlots: number;
    /** Signed path records returned by synchronization reads. */
    logRecordsRead: number;
    leaf: number;
  }>;
  /** True when every access produced the identical non-log data shape. */
  uniformShape: boolean;
  /** False when real log catch-up size or starting sequence differs. */
  fullShapeUniform: boolean;
  shapeSignature: string;
  fullShapeCount: number;
  /** Distinct leaves used, to show the path is re-randomised. */
  distinctLeaves: number;
}

function signature(events: readonly StoreEvent[], includeLog: boolean): string {
  return events
    .filter((event) => includeLog || event.kind !== 'log')
    .map(
      (event) =>
        `${event.kind}:${event.operation}:${event.slots}` +
        (event.fromSeq === undefined ? '' : `:from-${event.fromSeq}`) +
        (event.writerId === undefined ? '' : `:writer-${event.writerId}`),
    )
    .join('|');
}

/**
 * Drive reads and writes by different clients on different entries and record
 * what the store saw each time.
 *
 * The claim being tested is narrow and checkable: the server-visible event
 * sequence and slot counts of the ORAM DATA EVENTS are identical for a read
 * and a write, for any entry, by any client, including an authorization
 * refusal. The leaf differs, and the leaf is the only data-event field that
 * differs - which is also exactly what the colluding client exploits.
 *
 * The full transcript is deliberately NOT uniform: log catch-up returns every
 * record a client has not seen, and the requested starting sequence is visible.
 * That is the concrete cost of substituting a directly read upload log for
 * P1's oblivious gossip. Tampered, stale, malformed and concurrent requests
 * fail closed and are outside the data-padding claim.
 */
export async function runTraceShape(): Promise<TraceReport> {
  const { store, capabilities } = await buildSystem();
  const plan: Array<[number, 'read' | 'write', number, 'released' | 'refused']> = [
    [CLINICIAN, 'read', 0, 'released'],
    [CLINICIAN, 'write', 1, 'released'],
    [BILLING, 'read', 4, 'released'],
    [BILLING, 'write', 5, 'released'],
    [CONTRACTOR, 'read', 8, 'released'],
    [CLINICIAN, 'write', 12, 'released'],
    [CLINICIAN, 'read', 3, 'released'],
    [BILLING, 'read', 10, 'released'],
    [CONTRACTOR, 'read', 0, 'refused'],
    [BILLING, 'write', 0, 'refused'],
    [CONTRACTOR, 'write', 9, 'refused'],
    [BILLING, 'read', 13, 'refused'],
  ];
  const perAccess: TraceReport['perAccess'] = [];
  const leaves = new Set<number>();

  for (const [clientId, operation, index, expectedOutcome] of plan) {
    const cap = capabilities[clientId] as ClientCapability;
    store.clearTranscript();
    let outcome: 'released' | 'refused' = 'released';
    let error: string | null = null;
    let resultLeaf: number | null = null;
    try {
      const result =
        operation === 'read'
          ? await access(cap, store, 'read', index)
          : await access(cap, store, 'write', index, textPayload(`trace-${index}`));
      resultLeaf = result.leaf;
    } catch (caught) {
      if (!(caught instanceof AccessDeniedError)) throw caught;
      outcome = 'refused';
      error = caught.name;
    }
    const events = store.transcript();
    const traffic = store.dataTraffic();
    const logRecordsRead = events
      .filter((event) => event.kind === 'log' && event.operation === 'read')
      .reduce((sum, event) => sum + event.slots, 0);
    const pathRead = events.find((event) => event.kind === 'path' && event.operation === 'read');
    const leaf = resultLeaf ?? pathRead?.leaf ?? -1;
    if (outcome !== expectedOutcome) {
      throw new Error(
        `${cap.label} ${operation} entry ${index} was ${outcome}, expected ${expectedOutcome}.`,
      );
    }
    leaves.add(leaf);
    perAccess.push({
      client: cap.label,
      operation,
      index,
      outcome,
      error,
      events,
      readSlots: traffic.readSlots,
      writeSlots: traffic.writeSlots,
      logRecordsRead,
      leaf,
    });
  }

  const signatures = new Set(perAccess.map((row) => signature(row.events, false)));
  const fullSignatures = new Set(perAccess.map((row) => signature(row.events, true)));
  return {
    perAccess,
    uniformShape: signatures.size === 1,
    fullShapeUniform: fullSignatures.size === 1,
    shapeSignature: [...signatures][0] ?? '',
    fullShapeCount: fullSignatures.size,
    distinctLeaves: leaves.size,
  };
}

// ── 4. The repaired case, inside the stated model ──────────────────────────

export interface RepairedReport {
  baseline: BaselineReport;
  trace: TraceReport;
  integrity: IntegrityExperimentReport;
  rollback: RollbackReport;
  tamper: TamperReport;
  concurrency: ConcurrencyReport;
  revocation: RevocationReport;
  /** The standing limit: the collusion attack is NOT repaired. */
  unrepaired: string;
}

export async function runRepaired(): Promise<RepairedReport> {
  return {
    baseline: await runBaseline(),
    trace: await runTraceShape(),
    integrity: await runIntegrityExperiment(),
    rollback: await runRollbackControl(),
    tamper: await runTamperControls(),
    concurrency: await runConcurrencyControl(),
    revocation: await runRevocationControl(),
    unrepaired:
      'The colluding-client break is not repaired and cannot be at this access cost. ePrint ' +
      '2017/329 Theorem 1 rules out obliviousness against malicious clients for any scheme ' +
      'touching o(n) addresses per access, and one path access here touches five buckets of ' +
      'thirty-one. Closing it means the Omega(n) constructions of that paper, or its trusted ' +
      'proxy - neither of which this lesson implements.',
  };
}

export {
  AccessDeniedError,
  ConcurrencyRefusedError,
  DUMMY_INDEX,
  EntryVerificationError,
  STORE_LEAVES,
  STORE_N,
  STORE_STASH_SLOTS,
  STORE_Z,
  StaleEntryError,
  openEnvelope,
};
