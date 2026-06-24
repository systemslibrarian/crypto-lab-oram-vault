// @vitest-environment happy-dom
import { describe, it, expect, beforeAll, vi } from 'vitest';

// Importing main.ts runs the full bootstrap (buildShell → setupTabs → setupTheme
// → wireButtons). wireButtons() resolves EVERY interactive element id via a
// throwing $() helper, so a successful import is itself proof that every wired
// control exists in the rendered shell — a missing id would crash on load.
beforeAll(async () => {
  document.body.innerHTML = '<div id="app"></div>';
  await import('../src/main.js');
});

describe('UI shell bootstraps without runtime errors', () => {
  it('renders all five exhibit tabs', () => {
    const tabs = document.querySelectorAll('[role="tab"]');
    expect(tabs.length).toBe(5);
  });

  it('renders every wired control', () => {
    const ids = [
      'initBtn', 'stepBtn', 'autoBtn', 'serverViewBtn',
      'blockIdInput', 'blockValueInput', 'writeBlockBtn', 'readBlockBtn',
      'walkInitBtn', 'walkReadBtn', 'walkWriteBtn', 'walkNextBtn',
      'advInitBtn', 'advRunBtn', 'advClearBtn',
      'themeToggle',
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
