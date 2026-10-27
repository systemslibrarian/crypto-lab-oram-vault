/**
 * What happens when you share a single-client ORAM between clients who do not
 * trust each other.
 *
 * Every failure in this module is produced by THIS LAB'S EXISTING PATH ORAM,
 * unmodified, from `src/client/oram-client.ts`. There is no attack code here:
 * the outcomes are side effects of running the shipped protocol in a
 * deployment it was not designed for. That matters, because a scenario that
 * needed an attacker to do something clever would be a weaker argument than
 * one where the honest protocol does the damage by itself.
 *
 * THE DEPLOYMENT, AND ITS PRIMARY SOURCE. Backes, Herzberg, Kate and Pryvalov,
 * "Anonymous RAM" (IACR ePrint 2016/678) section 3.1 enumerates the obvious
 * ways to turn a single-user ORAM into a multi-user one and why each fails.
 * The second is the one reproduced here:
 *
 *   "One may try to overcome this problem using a shared (M*N)-cell ... ORAM
 *   containing M cells for each of N users, and assuming that every user
 *   executes her ORAM requests via an anonymous channel. In this case, all
 *   users will have to use the same private key in the symmetric encryption
 *   scheme employed in the ORAM protocol to hide their cells from the server.
 *   However, this allows Eve, an HbC user, to break privacy of honest users,
 *   by observing the values in cells (allocated to honest users) which she
 *   downloaded and decrypted as a part of her legitimate ORAM requests."
 *
 * And the consistency half, from ConcurORAM (arXiv:1811.04366v4) section I:
 * deploying existing schemes for multiple clients "by sharing ORAM credentials
 * and storing [state] that would normally be maintained client-side (e.g. the
 * position map in the case of a tree [ORAM]) [on] the server to ensure state
 * consistency" forces "only one client ... to access the [server-hosted data]
 * structures at any one time."
 *
 * The ACM critique of the practice is Bindschaedler, Naveed, Pan, Wang and
 * Huang, "Practicing Oblivious Access on Cloud Storage: The Gap, the Fallacy,
 * and the New Way Forward", CCS 2015, pp. 837-849 - cited in ePrint 2017/329
 * as its reference [6]. It is named here as the paper that named the fallacy;
 * nothing below is attributed to its text, which was not read.
 *
 * THREE OUTCOMES, all computed:
 *
 *   1. CROSS-CLIENT PLAINTEXT EXPOSURE. One shared key, and a second client's
 *      own legitimate access decrypts the first client's blocks straight into
 *      its stash. That is Eve, executed.
 *   2. AN UNUSABLE CLIENT. Give each client only its own entries in its
 *      position map and the shipped `decryptPath` refuses the path outright,
 *      because it decrypted a real block it has never heard of.
 *   3. A LOST UPDATE. Give each client a full but independent copy of the
 *      position map and the second write-back re-places the first client's
 *      entry according to a map that has moved on. The entry becomes
 *      unreachable at the leaf its owner believes it is at.
 */

import {
  BlockUnavailableError,
  access as pathAccess,
  initializeORAM,
  type ORAMClient,
} from '../client/oram-client.js';
import { BLOCK_DATA_SIZE, decryptBlock } from '../client/encryption.js';
import { serverReadPath } from '../server/oram-server.js';

const te = new TextEncoder();

export const NAIVE_N = 16;
export const NAIVE_Z = 4;

/** Entries notionally belonging to each of the two clients. */
export const CLINICIAN_ENTRIES = [0, 1, 2, 3, 4, 5, 6, 7];
export const BILLING_ENTRIES = [8, 9, 10, 11, 12, 13, 14, 15];

function payload(text: string): Uint8Array {
  const out = new Uint8Array(BLOCK_DATA_SIZE);
  out.set(te.encode(text).slice(0, BLOCK_DATA_SIZE));
  return out;
}

function text(bytes: Uint8Array): string {
  let end = bytes.length;
  while (end > 0 && bytes[end - 1] === 0) end -= 1;
  return new TextDecoder().decode(bytes.subarray(0, end));
}

/**
 * A second handle on the same tree, with the same key.
 *
 * This is the naive provisioning step: the owner hands every client the one
 * ORAM key and tells it which entries are its own. `view` decides whether that
 * client is told about every entry or only its own - the two sub-variants
 * ePrint 2016/678 section 3.1 and ConcurORAM section I describe.
 */
export function shareClient(
  base: ORAMClient,
  ownEntries: readonly number[],
  view: 'own-entries' | 'full-copy',
): ORAMClient {
  const positionMap = new Map<number, number>();
  if (view === 'full-copy') {
    for (const [blockId, leaf] of base.positionMap) positionMap.set(blockId, leaf);
  } else {
    for (const blockId of ownEntries) {
      const leaf = base.positionMap.get(blockId);
      if (leaf === undefined) throw new Error(`Entry ${blockId} is absent from the base map.`);
      positionMap.set(blockId, leaf);
    }
  }
  return {
    L: base.L,
    Z: base.Z,
    N: base.N,
    // The same key. That is the whole point of the failure.
    key: base.key,
    positionMap,
    stash: new Map(),
    maxStashSize: 0,
    lastWriteBack: null,
    serverGeneration: base.serverGeneration,
  };
}

export interface ExposureOutcome {
  /** Entries the second client decrypted that are not its own. */
  foreignEntriesDecrypted: number[];
  /** Their plaintext, as recovered from the second client's own stash. */
  foreignPlaintext: Array<{ entry: number; value: string }>;
  /** The entry the second client was legitimately accessing. */
  accessed: number;
}

/**
 * Outcome 1: one shared key, and a legitimate access hands over somebody
 * else's plaintext.
 *
 * The billing client reads an entry it owns. A Path ORAM read transfers the
 * WHOLE root-to-leaf path, and the shipped client decrypts every real block on
 * it - `decryptPath` in `src/client/oram-client.ts` calls `decryptBlock` on
 * each slot and merges the result into the caller's stash. With one shared
 * key, whatever the clinician's entries happen to share that path with is
 * therefore plaintext in billing's hands.
 *
 * The exposure is measured on the bytes the access itself transferred, with
 * the same two calls the shipped client makes on them - `serverReadPath`
 * followed by `decryptBlock` under the key billing was given. It is observed
 * rather than inferred because `writeBackPath` clears the stash again at the
 * end of the access, so by the time `access` returns the evidence has already
 * been re-encrypted and written back. Nothing here is an attack: a client that
 * holds the key can read what it is sent, and it was sent this.
 */
export async function runCrossClientExposure(): Promise<ExposureOutcome> {
  const owner = await initializeORAM(NAIVE_N, NAIVE_Z);
  for (const entry of CLINICIAN_ENTRIES) {
    await pathAccess(owner, 'write', entry, payload(`clinical-note-${entry}`));
  }
  for (const entry of BILLING_ENTRIES) {
    await pathAccess(owner, 'write', entry, payload(`invoice-${entry}`));
  }

  // Billing is handed the key and a full map, which is what lets it run at all.
  const billing = shareClient(owner, BILLING_ENTRIES, 'full-copy');
  const own = new Set<number>(BILLING_ENTRIES);

  let accessed = BILLING_ENTRIES[0] as number;
  const foreign = new Map<number, string>();
  for (const entry of BILLING_ENTRIES) {
    accessed = entry;
    const leaf = billing.positionMap.get(entry);
    if (leaf === undefined) continue;
    // Exactly what the access transfers, and exactly what the client does to it.
    for (const bucket of serverReadPath(leaf)) {
      for (const encrypted of bucket.blocks) {
        if (encrypted.ciphertext.length === 0) continue;
        const block = await decryptBlock(encrypted, billing.key);
        if (block === null) continue;
        if (!own.has(block.blockId)) foreign.set(block.blockId, text(block.data));
      }
    }
    // And the access itself completes normally, as an authorised access must.
    await pathAccess(billing, 'read', entry);
    if (foreign.size > 0) break;
  }

  const foreignEntriesDecrypted = [...foreign.keys()].sort((a, b) => a - b);
  return {
    foreignEntriesDecrypted,
    foreignPlaintext: foreignEntriesDecrypted.map((entry) => ({
      entry,
      value: foreign.get(entry) as string,
    })),
    accessed,
  };
}

export interface UnusableOutcome {
  accessed: number;
  /** The error class the shipped protocol raised. */
  error: string;
  message: string;
  /** The foreign entry whose presence on the path caused it. */
  offendingEntry: number | null;
}

/**
 * Outcome 2: tell each client only about its own entries, and the shipped
 * client refuses to run.
 *
 * `decryptPath` throws `BlockUnavailableError` the moment it authenticates a
 * real block whose id is absent from the caller's position map. In a
 * single-client ORAM that is a sound integrity check - such a block should be
 * impossible. Shared between clients it fires on correct, honest data, because
 * the path legitimately carries entries this client was never told about.
 */
export async function runUnusableClient(): Promise<UnusableOutcome> {
  const owner = await initializeORAM(NAIVE_N, NAIVE_Z);
  for (let entry = 0; entry < NAIVE_N; entry++) {
    await pathAccess(owner, 'write', entry, payload(`entry-${entry}`));
  }
  const billing = shareClient(owner, BILLING_ENTRIES, 'own-entries');

  for (const entry of [...BILLING_ENTRIES, ...BILLING_ENTRIES]) {
    try {
      await pathAccess(billing, 'read', entry);
    } catch (caught) {
      const error = caught as Error;
      const offending = /^Block (\d+) /.exec(error.message);
      return {
        accessed: entry,
        error: error.name,
        message: error.message,
        offendingEntry: offending ? Number(offending[1]) : null,
      };
    }
  }
  return {
    accessed: -1,
    error: 'none',
    message:
      'Every sampled path happened to carry only this client’s own entries. The deployment is ' +
      'still broken; this run simply did not land on a shared bucket.',
    offendingEntry: null,
  };
}

export interface LostUpdateOutcome {
  /** The entry the two maps disagree about. */
  entry: number;
  /** What the clinician wrote and believes is stored. */
  expected: string;
  /** The leaf each client believes the entry is at. These always differ. */
  clinicianLeaf: number;
  billingLeaf: number;
  /**
   * What happens when the OTHER client looks the entry up through its own
   * stale map. Both outcomes are failures of the deployment:
   *   `not-found`               - it looks on the wrong path and the entry is
   *                               not there, so the shipped client fails closed;
   *   `read-foreign-plaintext`  - the entry happened to be in a bucket the two
   *                               paths share, so it reads the clinician's new
   *                               private value instead.
   */
  billingOutcome: 'not-found' | 'read-foreign-plaintext';
  billingDetail: string;
  /** What the clinician gets back after billing has worked through its entries. */
  clinicianObserved: string;
  /** Reported, not asserted: whether the clinician's own update survived. */
  clinicianLost: boolean;
}

/**
 * Outcome 3: two independent copies of the position map, and they diverge on
 * the first write.
 *
 * Both clients re-randomise leaves in their own copy, so one write is enough
 * to make the two copies disagree about where an entry is. After that, at most
 * one of the two clients can find it, and whichever one looks on the wrong
 * path either fails closed or - if the entry happens to sit in a bucket the
 * two paths share - reads the other client's data instead.
 *
 * This is the state divergence ConcurORAM section I says forces single-client
 * serialisation on the whole structure, reproduced with no concurrency at all:
 * sequential accesses are enough, because the maps are separate.
 */
export async function runLostUpdate(): Promise<LostUpdateOutcome> {
  const owner = await initializeORAM(NAIVE_N, NAIVE_Z);
  for (let entry = 0; entry < NAIVE_N; entry++) {
    await pathAccess(owner, 'write', entry, payload(`entry-${entry}`));
  }
  const clinician = shareClient(owner, CLINICIAN_ENTRIES, 'full-copy');
  const billing = shareClient(owner, BILLING_ENTRIES, 'full-copy');

  const target = CLINICIAN_ENTRIES[0] as number;
  const expected = 'clinical-note-after-divergence';
  await pathAccess(clinician, 'write', target, payload(expected));

  // The clinician's write re-randomised the entry's leaf in ITS copy of the
  // map and nowhere else. Billing's copy still records the old leaf, so the
  // two clients now disagree about where the entry is. That divergence is
  // deterministic: it is created by the write, not by chance.
  const clinicianLeaf = clinician.positionMap.get(target) ?? -1;
  const billingLeaf = billing.positionMap.get(target) ?? -1;

  // There is no access control in this deployment - billing holds the one key
  // and a full map - so it can look the entry up. Both results are failures.
  let billingOutcome: LostUpdateOutcome['billingOutcome'];
  let billingDetail: string;
  try {
    const value = text(await pathAccess(billing, 'read', target));
    billingOutcome = 'read-foreign-plaintext';
    billingDetail =
      `Billing read the clinician's entry ${target} and obtained "${value}". The entry sat in a ` +
      'bucket the two stale paths share, so the lookup succeeded - on somebody else’s data.';
  } catch (caught) {
    billingOutcome = 'not-found';
    billingDetail =
      `Billing looked for entry ${target} on leaf ${billingLeaf}, where its stale map says the ` +
      `entry is. The clinician had already moved it to leaf ${clinicianLeaf}. ` +
      `${(caught as Error).name}: ${(caught as Error).message}`;
  }

  // And now billing works through its own entries, re-placing whatever it
  // finds according to its own, now-stale, copy of the map.
  for (const entry of BILLING_ENTRIES) {
    await pathAccess(billing, 'write', entry, payload(`invoice-${entry}`)).catch(() => undefined);
  }

  let clinicianObserved: string;
  try {
    clinicianObserved = text(await pathAccess(clinician, 'read', target));
  } catch (caught) {
    clinicianObserved = `${(caught as Error).name}: ${(caught as Error).message}`;
  }

  return {
    entry: target,
    expected,
    clinicianLeaf,
    billingLeaf,
    billingOutcome,
    billingDetail,
    clinicianObserved,
    clinicianLost: clinicianObserved !== expected,
  };
}

export interface NaiveReport {
  exposure: ExposureOutcome;
  unusable: UnusableOutcome;
  lostUpdate: LostUpdateOutcome;
}

/**
 * All three outcomes, each from its own freshly provisioned tree.
 *
 * Note that each call replaces this lab's singleton Path ORAM server, which is
 * why the multi-client construction in `store.ts` uses its own instance-based
 * store and cannot disturb the other exhibits.
 */
export async function runNaiveSharing(): Promise<NaiveReport> {
  const exposure = await runCrossClientExposure();
  const unusable = await runUnusableClient();
  const lostUpdate = await runLostUpdate();
  return { exposure, unusable, lostUpdate };
}

export { BlockUnavailableError };
