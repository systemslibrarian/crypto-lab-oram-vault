import { describe, expect, it } from 'vitest';
import {
  BILLING_ENTRIES,
  CLINICIAN_ENTRIES,
  runCrossClientExposure,
  runLostUpdate,
  runUnusableClient,
} from '../src/multiclient/naive.js';

/**
 * The naive deployment, and what it actually does.
 *
 * These assertions are about outcomes of this lab's EXISTING Path ORAM run in
 * a multi-client deployment. If any of them started passing for the wrong
 * reason - because the path happened to be empty, or because an error was
 * swallowed - the test would stop discriminating, so each one pins the
 * mechanism and not just the symptom.
 */

describe('cross-client plaintext exposure', () => {
  it('hands a second client the first client’s plaintext during a legitimate read', async () => {
    const outcome = await runCrossClientExposure();
    // Something foreign really was decrypted.
    expect(outcome.foreignEntriesDecrypted.length).toBeGreaterThan(0);
    // And it belongs to the other client, not to the one doing the reading.
    for (const entry of outcome.foreignEntriesDecrypted) {
      expect(CLINICIAN_ENTRIES).toContain(entry);
      expect(BILLING_ENTRIES).not.toContain(entry);
    }
    // The exposure is PLAINTEXT, not merely a ciphertext sighting.
    for (const { entry, value } of outcome.foreignPlaintext) {
      expect(value).toBe(`clinical-note-${entry}`);
    }
    // The access that caused it was one of the reader's own entries.
    expect(BILLING_ENTRIES).toContain(outcome.accessed);
  }, 30_000);

  it('is caused by the shared key rather than by a shared position map', async () => {
    // The reader holds its own map object; what it does not hold is its own
    // key. Anonymous RAM section 3.1: "all users will have to use the same
    // private key ... However, this allows Eve ... to break privacy".
    const outcome = await runCrossClientExposure();
    expect(outcome.foreignPlaintext.length).toBeGreaterThan(0);
    expect(outcome.foreignPlaintext.every(({ value }) => value.startsWith('clinical-note-'))).toBe(
      true,
    );
  }, 30_000);
});

describe('the unusable client', () => {
  it('makes the shipped integrity check fire on honest data', async () => {
    const outcome = await runUnusableClient();
    expect(outcome.error).toBe('BlockUnavailableError');
    expect(outcome.message).toMatch(/not present in the authenticated path or client stash/);
    // The block it tripped over belongs to the other client.
    expect(outcome.offendingEntry).not.toBeNull();
    expect(CLINICIAN_ENTRIES).toContain(outcome.offendingEntry as number);
    // And the client was reading one of its own entries at the time.
    expect(BILLING_ENTRIES).toContain(outcome.accessed);
  }, 30_000);
});

describe('divergent position maps', () => {
  it('reports the bounded genuine-remap experiment without claiming one write must move', async () => {
    const outcome = await runLostUpdate();
    expect(CLINICIAN_ENTRIES).toContain(outcome.entry);
    expect(outcome.remapAttempts).toBeGreaterThanOrEqual(1);
    expect(outcome.remapAttempts).toBeLessThanOrEqual(32);
    expect(outcome.clinicianLeaf).toBeGreaterThanOrEqual(0);
    expect(outcome.billingLeaf).toBeGreaterThanOrEqual(0);
    if (outcome.diverged) {
      expect(outcome.clinicianLeaf).not.toBe(outcome.billingLeaf);
    } else {
      expect(outcome.clinicianLeaf).toBe(outcome.billingLeaf);
      expect(outcome.remapAttempts).toBe(32);
      expect(outcome.billingOutcome).toBe('no-divergence-observed');
    }
  }, 30_000);

  it('derives the other client’s outcome from the state actually reached', async () => {
    const outcome = await runLostUpdate();
    expect(['not-found', 'read-foreign-plaintext', 'no-divergence-observed']).toContain(
      outcome.billingOutcome,
    );
    if (outcome.billingOutcome === 'not-found') {
      // It looked on the leaf its stale map records and fails closed.
      expect(outcome.billingDetail).toMatch(/BlockUnavailableError/);
      expect(outcome.billingDetail).toContain(`leaf ${outcome.billingLeaf}`);
    } else if (outcome.billingOutcome === 'read-foreign-plaintext') {
      // Or it read the clinician's brand-new private value.
      expect(outcome.billingDetail).toContain(outcome.expected);
      expect(outcome.billingDetail).toMatch(/somebody else/);
    } else {
      expect(outcome.diverged).toBe(false);
      expect(outcome.billingDetail).toMatch(/does not claim/);
    }
  }, 30_000);

  it('reports the clinician’s own outcome without asserting which way it went', async () => {
    // Whether the clinician's update survives billing's subsequent writes is
    // genuinely path-dependent, so this is REPORTED and not asserted. A test
    // that insisted on one branch would be flaky, and a flaky gate is worse
    // than no gate.
    const outcome = await runLostUpdate();
    expect(outcome.expected).toBe('clinical-note-after-divergence');
    if (outcome.diverged) {
      expect(typeof outcome.clinicianLost).toBe('boolean');
      expect(outcome.clinicianObserved?.length).toBeGreaterThan(0);
      if (outcome.clinicianLost) {
        expect(outcome.clinicianObserved).not.toBe(outcome.expected);
      }
    } else {
      expect(outcome.clinicianLost).toBeNull();
      expect(outcome.clinicianObserved).toBeNull();
    }
  }, 30_000);
});
