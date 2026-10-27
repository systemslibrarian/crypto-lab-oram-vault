#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const vitest = join(root, 'node_modules', '.bin', 'vitest');

const mutations = [
  {
    name: 'level buckets stop carrying the declared bounded capacity',
    file: 'src/hierarchical/client.ts',
    from: '      bucketSize: capacity,',
    to: '      bucketSize: 1,',
    spec: 'tests/hierarchical-oram.test.ts',
    test: 'fixes N=16 and exposes the deliberately overprovisioned level geometry',
  },
  {
    name: 'HMAC placement collapses every lookup to bucket zero',
    file: 'src/hierarchical/client.ts',
    from: '  return word & (bucketCount - 1);',
    to: '  return word * 0;',
    spec: 'tests/hierarchical-oram.test.ts',
    test: 'maps an RFC 4231 HMAC-SHA-256 vector without modulo bias',
  },
  {
    name: 'a hashed level silently reuses its previous placement key',
    file: 'src/hierarchical/client.ts',
    from: '  if (level > 0) state.hashKey = await freshHashKey(client);',
    to: '  if (level > 0 && state.hashKey === null) state.hashKey = await freshHashKey(client);',
    spec: 'tests/hierarchical-oram.test.ts',
    test: 'rotates a hashed level key whenever that level is rebuilt',
  },
  {
    name: 'post-hit lookups keep using the real label instead of a dummy',
    file: 'src/hierarchical/client.ts',
    from: "      const kind: ProbeKind = level === 0 ? 'cache' : found === null ? 'real' : 'dummy';",
    to: "      const kind: ProbeKind = level === 0 ? 'cache' : 'real';",
    spec: 'tests/hierarchical-oram.test.ts',
    test: 'probes every level, then uses a unique dummy probe after a cache hit',
  },
  {
    name: 'the fixed policy stops probing after an early hit',
    file: 'src/hierarchical/client.ts',
    from: "      if (policy === 'skip-after-hit' && found !== null && level > 0) break;",
    to: "      if (policy === 'all-levels' && found !== null && level > 0) break;",
    spec: 'tests/hierarchical-oram.test.ts',
    test: 'probes every level, then uses a unique dummy probe after a cache hit',
  },
  {
    name: 'dummy labels drop the per-access uniqueness component',
    file: 'src/hierarchical/client.ts',
    from: '  new DataView(label.buffer).setUint32(1, accessNumber, false);',
    to: '  new DataView(label.buffer).setUint32(1, accessNumber * 0, false);',
    spec: 'tests/hierarchical-oram.test.ts',
    test: 'changes a later-level dummy lookup on each access within one key epoch',
  },
  {
    name: 'the dummy-label counter is allowed to wrap once',
    file: 'src/hierarchical/client.ts',
    from: '    if (client.accessCount >= MAX_ACCESS_NUMBER) {',
    to: '    if (client.accessCount > MAX_ACCESS_NUMBER) {',
    spec: 'tests/hierarchical-oram.test.ts',
    test: 'refuses before the 32-bit dummy-label counter can wrap or issue traffic',
  },
  {
    name: 'a found copy is left behind before reinsertion',
    file: 'src/hierarchical/client.ts',
    from: '          decoded[slot] = null;',
    to: '          decoded[slot] = clonePlain(item);',
    spec: 'tests/hierarchical-oram.test.ts',
    test: 'executes the binary-carry rebuild cadence and records real traffic spikes',
  },
  {
    name: 'empty levels are incorrectly marked occupied',
    file: 'src/hierarchical/client.ts',
    from: '  state.occupied = blocks.length > 0;',
    to: '  state.occupied = blocks.length >= 0;',
    spec: 'tests/hierarchical-oram.test.ts',
    test: 'executes the binary-carry rebuild cadence and records real traffic spikes',
  },
  {
    name: 'Path traffic counts buckets as if each held only one slot',
    file: 'src/hierarchical/comparison.ts',
    from: '  const readSlots = (after.totalReads - before.totalReads) * Z;',
    to: '  const readSlots = after.totalReads - before.totalReads;',
    spec: 'tests/hierarchical-comparison.test.ts',
    test: 'derives both cost traces from real executions and verifies the full logical state',
  },
  {
    name: 'the ordinary comparison secretly uses the skipped-probe policy',
    file: 'src/hierarchical/comparison.ts',
    from: '      const hierarchyReadResult = await hierarchicalRead(hierarchy, item.blockId);',
    to: "      const hierarchyReadResult = await hierarchicalRead(hierarchy, item.blockId, 'skip-after-hit');",
    spec: 'tests/hierarchical-comparison.test.ts',
    test: 'derives both cost traces from real executions and verifies the full logical state',
  },
  {
    name: 'the negative control stops running the insecure policy',
    file: 'src/hierarchical/comparison.ts',
    from: "  const skippedRepeat = await hierarchicalRead(skipped, blockId, 'skip-after-hit');",
    to: '  const skippedRepeat = await hierarchicalRead(skipped, blockId);',
    spec: 'tests/hierarchical-comparison.test.ts',
    test: 'shows that skipping post-hit probes leaks depth despite returning the same data',
  },

  // ── Multi-client ORAM (L-R-13) ──────────────────────────────────────────
  //
  // Each `to` keeps every binding referenced on purpose: this project compiles
  // with `noUnusedLocals` and `noUnusedParameters`, so a mutation that simply
  // deleted an argument would fail to BUILD, and a mutation that fails to
  // build is indistinguishable from one nothing caught.
  {
    name: 'read authorization removed: every client gets a real key wrap',
    file: 'src/multiclient/envelope.ts',
    from: '  const payload = authorised ? dataKey : randomBytes(DATA_KEY_SIZE);',
    to: '  const payload = authorised ? dataKey : dataKey;',
    spec: 'tests/multiclient-authorization.test.ts',
    test: 'lets a reader read, and refuses a client with no access on the same entry',
  },
  {
    name: 'write authorization unchecked: the owner capability signature is ignored',
    file: 'src/multiclient/protocol.ts',
    from: '  if (!capOk) {',
    to: '  if (!capOk && false) {',
    spec: 'tests/multiclient-authorization.test.ts',
    test: 'lands an unauthorised write and then has every honest reader reject it',
  },
  {
    name: 'a write capability stops binding the entry it was issued for',
    file: 'src/multiclient/envelope.ts',
    from: '  return concat(CAP_SIG_LABEL, new Uint8Array([clientId]), u16(index));',
    to: '  return concat(CAP_SIG_LABEL, new Uint8Array([clientId]), u16(index * 0));',
    spec: 'tests/multiclient-authorization.test.ts',
    test: 'lands a capability borrowed from another entry and still fails verification',
  },
  {
    name: 'state synchronization breaks: the signed log chain never advances',
    file: 'src/multiclient/protocol.ts',
    from: '  cap.memory.logDigestSeen = await recordDigest(appended);',
    to: '  cap.memory.logDigestSeen = cap.memory.logDigestSeen;',
    spec: 'tests/multiclient-authorization.test.ts',
    test: 'accepts an honest sequence of accesses by different clients',
  },
  {
    name: 'stale state accepted: the version watermark is no longer compared',
    file: 'src/multiclient/protocol.ts',
    from: '      if (known !== undefined && envelope.version < known) {',
    to: '      if (known !== undefined && false) {',
    spec: 'tests/multiclient-integrity.test.ts',
    test: 'refuses data the store rolled back under genuine signatures',
  },
  {
    name: 'the server transcript under-reports what a stash read transferred',
    file: 'src/multiclient/store.ts',
    from: "    this.events.push({ kind: 'stash', operation: 'read', slots: STORE_STASH_SLOTS });",
    to: "    this.events.push({ kind: 'stash', operation: 'read', slots: STORE_STASH_SLOTS - 1 });",
    spec: 'tests/multiclient-trace.test.ts',
    test: 'transfers the same number of slots whatever the operation',
  },
  {
    name: 'an authorization refusal exits before the fixed-shape write-back',
    file: 'src/multiclient/protocol.ts',
    from: '      authorizationFailure = new AccessDeniedError(',
    to: '      throw new AccessDeniedError(',
    spec: 'tests/multiclient-trace.test.ts',
    test: 'is identical for reads, writes and authorization refusals across clients',
  },
  {
    name: 'variable log catch-up is misreported as one fixed record',
    file: 'src/multiclient/store.ts',
    from: "    this.events.push({ kind: 'log', operation: 'read', slots: result.length, fromSeq });",
    to: "    this.events.push({ kind: 'log', operation: 'read', slots: 1, fromSeq });",
    spec: 'tests/multiclient-trace.test.ts',
    test: 'exposes variable direct-log catch-up instead of calling it oblivious',
  },
  {
    name: 'the Figure 3 adversary no longer submits its mismatched capability',
    file: 'src/multiclient/scenario.ts',
    from: '  billing.writeCaps.set(targetIndex, new Uint8Array(mismatched));',
    to: '  billing.writeCaps.delete(targetIndex);',
    spec: 'tests/multiclient-integrity.test.ts',
    test: 'executes the adversary win that separates accountability from integrity',
  },
  {
    name: 'reference verification compares the store against itself',
    file: 'src/multiclient/protocol.ts',
    from: '    if (actual !== hex(expected)) {',
    to: '    if (actual !== actual) {',
    spec: 'tests/multiclient-authorization.test.ts',
    test: 'reports a mismatch when the store and the mirror disagree',
  },
];

const touched = [...new Set(mutations.map((mutation) => join(root, mutation.file)))];
const originals = new Map(touched.map((file) => [file, readFileSync(file)]));
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');

function run(args) {
  return spawnSync(vitest, args, { cwd: root, encoding: 'utf8', stdio: 'pipe' });
}

function restoreAll() {
  for (const [file, bytes] of originals) writeFileSync(file, bytes);
}

function assertRestored() {
  for (const [file, bytes] of originals) {
    if (digest(readFileSync(file)) !== digest(bytes)) {
      throw new Error(`${relative(root, file)} was not restored byte for byte`);
    }
  }
}

let caught = 0;
try {
  const specs = [...new Set(mutations.map((mutation) => mutation.spec))];
  const baseline = run(['run', ...specs]);
  if (baseline.status !== 0) {
    process.stderr.write(baseline.stdout);
    process.stderr.write(baseline.stderr);
    throw new Error('baseline: unmutated copy FAILED; mutation results below would be meaningless');
  }
  console.log('baseline: unmutated copy PASSES');

  for (const mutation of mutations) {
    const file = join(root, mutation.file);
    const before = readFileSync(file, 'utf8');
    const occurrences = before.split(mutation.from).length - 1;
    if (occurrences !== 1) {
      throw new Error(`${mutation.name}: expected one source anchor, found ${occurrences}`);
    }
    writeFileSync(file, before.replace(mutation.from, mutation.to));
    const result = run(['run', mutation.spec, '-t', mutation.test]);
    writeFileSync(file, originals.get(file));
    if (result.status === 0) {
      process.stderr.write(result.stdout);
      process.stderr.write(result.stderr);
      throw new Error(`SURVIVED: ${mutation.name}`);
    }
    caught += 1;
    console.log(`caught ${caught}/${mutations.length}: ${mutation.name}`);
  }

  assertRestored();
  const finalBaseline = run(['run', ...specs]);
  if (finalBaseline.status !== 0) {
    process.stderr.write(finalBaseline.stdout);
    process.stderr.write(finalBaseline.stderr);
    throw new Error('restored source does not pass its clean baseline');
  }
  console.log(`all ${caught} mutation(s) caught; sources restored byte for byte`);
} finally {
  restoreAll();
  assertRestored();
}
