import { describe, expect, it } from 'vitest';
import {
  BILLING,
  CLINICIAN,
  CONTRACTOR,
  runBaseline,
  runConcurrencyControl,
  runIntegrityExperiment,
  runRevocationControl,
  runRollbackControl,
  runTamperControls,
} from '../src/multiclient/scenario.js';

/**
 * Integrity, freshness, tampering, concurrency and revocation, each asserted
 * as the outcome of a run.
 *
 * The integrity experiment is the one from Chow, Fech, Lai and Malavolta,
 * "Multi-client Oblivious RAM with Poly-logarithmic Communication", IACR
 * ePrint 2020/1551, section 5.2 Definition 16 and Figure 3 - "MCORAM's
 * Integrity against Malicious Clients and Honest-but-Curious Server". Its
 * winning condition is three conjuncts. This accountable-only adaptation
 * deliberately lets a malformed update reach the honest server, so the test
 * asserts a concrete win rather than disguising a weaker construction as
 * Definition 16 integrity.
 */

describe('the honest baseline', () => {
  it('releases exactly what the rights table allows and refuses the rest', async () => {
    const report = await runBaseline();
    const by = (clientId: number, operation: string, index: number) =>
      report.rows.find(
        (row) => row.clientId === clientId && row.operation === operation && row.index === index,
      );

    // Clinician owns entries 0-3 read-write.
    expect(by(CLINICIAN, 'read', 0)?.outcome).toBe('released');
    expect(by(CLINICIAN, 'write', 0)?.outcome).toBe('released');
    // Billing may read 0 and not write it.
    expect(by(BILLING, 'read', 0)?.outcome).toBe('released');
    expect(by(BILLING, 'write', 0)?.outcome).toBe('refused');
    // Billing owns 4-7 read-write; the clinician may not write them.
    expect(by(BILLING, 'write', 5)?.outcome).toBe('released');
    expect(by(CLINICIAN, 'write', 5)?.outcome).toBe('refused');
    // The contractor may read the shared summary and nothing else.
    expect(by(CONTRACTOR, 'read', 9)?.outcome).toBe('released');
    expect(by(CONTRACTOR, 'read', 0)?.outcome).toBe('refused');
    expect(by(CONTRACTOR, 'write', 9)?.outcome).toBe('refused');
    // Private annotations are the clinician's alone.
    expect(by(CLINICIAN, 'write', 13)?.outcome).toBe('released');
    expect(by(BILLING, 'read', 13)?.outcome).toBe('refused');
  }, 60_000);

  it('agrees with the retained plaintext mirror after the whole workload', async () => {
    const report = await runBaseline();
    expect(report.referenceMismatches).toEqual([]);
  }, 60_000);

  it('names a protocol reason for every refusal rather than a disabled UI flag', async () => {
    const report = await runBaseline();
    const refusals = report.rows.filter((row) => row.outcome === 'refused');
    expect(refusals.length).toBeGreaterThanOrEqual(5);
    for (const row of refusals) {
      expect(row.detail, `${row.client} ${row.operation} ${row.index}`).toMatch(
        /AccessDeniedError|EntryVerificationError|EnvelopeAuthError/,
      );
    }
  }, 60_000);

  it('moves real traffic in both directions', async () => {
    const report = await runBaseline();
    expect(report.traffic.readSlots).toBeGreaterThan(0);
    expect(report.traffic.writeSlots).toBeGreaterThan(0);
    expect(report.accesses).toBeGreaterThan(5);
  }, 60_000);
});

describe('the ePrint 2020/1551 Figure 3 integrity experiment', () => {
  it('executes the adversary win that separates accountability from integrity', async () => {
    const report = await runIntegrityExperiment();
    // The experiment's own preconditions must actually hold, or the result
    // would be vacuous.
    expect(report.readerHasReadAccess, 'b0: the reader has read access').toBe(true);
    expect(report.noCorruptedWriter, 'b1: no corrupted client may write the target').toBe(true);
    // The corrupted client submits only its own capability for a different
    // entry; no honest client's hidden material is read. The malformed update
    // lands because this construction has no server-side authorization proof.
    expect(report.attackLanded).toBe(true);
    expect(report.mirrorDisagrees, 'b2: the authorised read must now disagree or refuse').toBe(true);
    expect(report.adversaryWins).toBe(true);
    expect(report.observed).toBeNull();
    expect(report.observedError).toBe('EntryVerificationError');
    expect(report.corrupted).toEqual([BILLING]);
  }, 60_000);
});

describe('tampering', () => {
  it('refuses random bytes written into a stored slot', async () => {
    const report = await runTamperControls();
    expect(report.ciphertextTamper.error).toBe('EnvelopeAuthError');
    expect(report.ciphertextTamper.message).toMatch(/authentication/i);
  }, 60_000);

  it('lets an unauthorised write land, rejects it on read, and names the writer', async () => {
    const report = await runTamperControls();
    // This store performs no access control - see protocol.ts - so the upload
    // succeeds. What must not happen is any honest client accepting it.
    expect(report.unauthorisedWrite.landed).toBe(true);
    expect(report.unauthorisedWrite.readerError).toBe('EntryVerificationError');
    expect(report.unauthorisedWrite.readerMessage).toMatch(/did not authorise writer/);
    expect(report.unauthorisedWrite.blamed).toBe(BILLING);
    expect(report.unauthorisedWrite.blameDetail).toMatch(/signed by client 1/);
  }, 60_000);

  it('accepts the same forged entry once verification is switched off', async () => {
    // The negative control for the control: if the forged entry were rejected
    // even with verification disabled, the rejection above would be coming
    // from something other than verification.
    const report = await runTamperControls();
    expect(report.withoutVerification.accepted).toBe(true);
    expect(report.withoutVerification.value).toBe('forged-by-billing');
  }, 60_000);
});

describe('rollback and freshness', () => {
  it('refuses data the store rolled back under genuine signatures', async () => {
    const report = await runRollbackControl();
    expect(report.refusedError).toBe('StaleEntryError');
    expect(report.refusedMessage).toMatch(/stale or rolled-back/);
  }, 60_000);

  it('returns the stale value once the freshness check is switched off', async () => {
    // Which is what proves the refusal came from the watermark and not from a
    // signature: every signature on the rolled-back bytes is genuine.
    const report = await runRollbackControl();
    expect(report.staleValue).not.toBeNull();
    expect(report.staleValue).not.toBe(report.writtenValue);
    expect(report.staleVersion).toBe(1);
  }, 60_000);

  it('shows that a first-contact reader has no global freshness guarantee', async () => {
    const report = await runRollbackControl();
    expect(report.firstContactValue).not.toBeNull();
    expect(report.firstContactValue).not.toBe(report.writtenValue);
    expect(report.firstContactVersion).toBe(1);
  }, 60_000);
});

describe('concurrency', () => {
  it('refuses an overlapping access and says which mechanism is missing', async () => {
    const report = await runConcurrencyControl();
    expect(report.refusedError).toBe('ConcurrencyRefusedError');
    expect(report.refusedMessage).toMatch(/no concurrency control/);
  }, 60_000);

  it('loses an update when the refusal is lifted', async () => {
    const report = await runConcurrencyControl();
    // Either the interleaving corrupted the shared state outright, or the
    // first write is simply gone. Both are failures; neither is a silent
    // success.
    expect(report.unsafe.lostUpdate || report.unsafe.error !== null).toBe(true);
  }, 60_000);
});

describe('revocation by key rotation', () => {
  it('stops future reads and says plainly that it retracts nothing', async () => {
    const report = await runRevocationControl();
    expect(report.beforeValue).toBe('record-9');
    expect(report.rotatedVersion).toBe(2);
    expect(report.remainingReaders).toEqual([CLINICIAN, BILLING]);
    expect(report.afterError).toBe('AccessDeniedError');
    // The honest part: the revoked client still holds what it already read.
    expect(report.retainedByRevokedClient).toBe('record-9');
  }, 60_000);
});
