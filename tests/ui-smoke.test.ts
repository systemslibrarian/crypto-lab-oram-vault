// @vitest-environment happy-dom
import { describe, it, expect, beforeAll, vi } from 'vitest';

// Importing main.ts runs the full bootstrap (buildShell → setupTabs →
// wireButtons). wireButtons() resolves EVERY interactive element id via a
// throwing $() helper, so a successful import is itself proof that every wired
// control exists in the rendered shell — a missing id would crash on load.
beforeAll(async () => {
  document.body.innerHTML = '<div id="app"></div>';
  await import('../src/main.js');
});

describe('UI shell bootstraps without runtime errors', () => {
  it('renders all seven exhibit tabs', () => {
    const tabs = document.querySelectorAll('[role="tab"]');
    expect(tabs.length).toBe(7);
  });

  it('renders every wired control', () => {
    const ids = [
      'initBtn', 'stepBtn', 'autoBtn', 'serverViewBtn',
      'blockIdInput', 'blockValueInput', 'writeBlockBtn', 'readBlockBtn',
      'walkInitBtn', 'walkReadBtn', 'walkWriteBtn', 'walkNextBtn',
      'advInitBtn', 'advRunBtn', 'advClearBtn',
      'hierRunBtn', 'hierLeakBtn',
      'mcBaselineBtn', 'mcNaiveBtn', 'mcCollusionBtn', 'mcControlsBtn',
    ];
    for (const id of ids) {
      expect(document.getElementById(id), `#${id} should exist`).not.toBeNull();
    }
  });

  it('switches exhibits when a tab is clicked', () => {
    const tab2 = document.getElementById('tab2') as HTMLButtonElement;
    tab2.click();
    expect(tab2.getAttribute('aria-selected')).toBe('true');
    expect(document.getElementById('ex2')!.hasAttribute('hidden')).toBe(false);
    expect(document.getElementById('ex0')!.hasAttribute('hidden')).toBe(true);
  });
});

describe('Tree exhibit drives a real ORAM access end-to-end', () => {
  it('initializes, then a custom READ updates status and renders the tree', async () => {
    (document.getElementById('initBtn') as HTMLButtonElement).click();

    // Initialization is async (Web Crypto). Wait for the live status to confirm.
    await vi.waitFor(
      () => {
        const status = document.getElementById('treeStatus')!.textContent ?? '';
        expect(status).toMatch(/Initialized/i);
      },
      { timeout: 5000, interval: 25 },
    );

    // The server-view tree should now contain rendered bucket rectangles.
    expect(document.querySelectorAll('#serverTree rect.bucket-rect').length).toBeGreaterThan(0);

    // Drive a concrete READ through the UI and confirm the status reflects it.
    (document.getElementById('blockIdInput') as HTMLInputElement).value = '5';
    (document.getElementById('readBlockBtn') as HTMLButtonElement).click();
    await vi.waitFor(
      () => {
        const status = document.getElementById('treeStatus')!.textContent ?? '';
        expect(status).toMatch(/READ\(block 5\)/);
      },
      { timeout: 5000, interval: 25 },
    );
  });
});

describe('Hierarchy comparison drives both constructions end-to-end', () => {
  it('renders measured rows, a full-state verdict, and the skipped-probe leak', async () => {
    (document.getElementById('tab5') as HTMLButtonElement).click();
    (document.getElementById('hierRunBtn') as HTMLButtonElement).click();
    await vi.waitFor(
      () => {
        expect(document.getElementById('hierStatus')!.textContent)
          .toMatch(/8 workload operations measured and 16\/16 blocks independently verified/);
      },
      { timeout: 10_000, interval: 25 },
    );
    expect(document.querySelectorAll('#hierComparisonBody tr')).toHaveLength(8);
    expect(document.getElementById('hierSummary')!.textContent).toContain('16/16 blocks');

    (document.getElementById('hierLeakBtn') as HTMLButtonElement).click();
    await vi.waitFor(
      () => {
        expect(document.getElementById('hierLeakStatus')!.textContent)
          .toMatch(/fixed 31-slot and skipped 1-slot lookup traces/);
      },
      { timeout: 10_000, interval: 25 },
    );
    expect(document.getElementById('hierLeakResults')!.textContent).toContain('DEPTH-CONTROL');
  });
});

describe('Multi-client exhibit drives the real protocol end-to-end', () => {
  it('runs the honest baseline, renders live rows, and verifies the mirror', async () => {
    (document.getElementById('tab6') as HTMLButtonElement).click();
    expect(document.getElementById('ex6')!.hasAttribute('hidden')).toBe(false);

    (document.getElementById('mcBaselineBtn') as HTMLButtonElement).click();
    await vi.waitFor(
      () => {
        expect(document.getElementById('mcBaselineStatus')!.textContent).toMatch(
          /attempts: \d+ released, \d+ refused/,
        );
      },
      { timeout: 30_000, interval: 25 },
    );
    // Every attempt in the shipped plan has a row, and both outcomes occur.
    const rows = document.querySelectorAll('#mcBaselineBody tr');
    expect(rows.length).toBeGreaterThanOrEqual(10);
    const table = document.getElementById('mcBaselineTable')!.textContent ?? '';
    expect(table).toContain('released');
    expect(table).toContain('refused');
    expect(table).toContain('AccessDeniedError');
    // And the retained plaintext mirror agrees.
    expect(document.getElementById('mcBaselineStatus')!.textContent).toContain(
      'matches the retained plaintext mirror',
    );
  }, 40_000);

  it('retires the baseline when a different scenario is run', async () => {
    (document.getElementById('mcCollusionBtn') as HTMLButtonElement).click();
    await vi.waitFor(
      () => {
        expect(document.getElementById('mcCollusionStatus')!.textContent).toMatch(
          /mean candidate set/,
        );
      },
      { timeout: 30_000, interval: 25 },
    );
    // The collusion table is populated from this run...
    expect(document.querySelectorAll('#mcCollusionBody tr').length).toBeGreaterThan(1);
    expect(document.getElementById('mcCollusionNote')!.textContent).toContain('o(n)');
    // ...and the baseline's output is gone rather than left stale beside it.
    expect(document.getElementById('mcBaselineStatus')!.textContent).toMatch(/Retired/);
    expect(document.getElementById('mcBaselineBody')!.textContent).toMatch(/Retired/);
  }, 40_000);
});
