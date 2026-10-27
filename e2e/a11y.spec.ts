import { test } from '@playwright/test';
import { boot, driveAllStates, expectBaselineNotStale, NARROW } from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * Each of the seven exhibits is opened through its own tab — never un-hidden —
 * and driven: the medical scenario replayed through a live ORAM, the tree
 * initialized and stepped, the client view collapsed to the server's, a block
 * written and read back, an out-of-range block id rejected, the seven-step
 * walkthrough run to completion in both READ and WRITE, twenty adversary
 * accesses run and their chi-square reported and then cleared, the costs table
 * and caveats reached both directly and through the cross-exhibit link; the
 * Path/hierarchy workload and skipped-probe control are run; the multi-client
 * exhibit is driven through its honest baseline, the shared-key deployment that
 * fails, the colluding-client attack and every negative control, including the
 * retired-output state no other exhibit has; and the stale-vault refusal is
 * provoked and then recovered from. Every one of those
 * states is scanned in the lab's pinned dark theme at desktop and phone width.
 *
 * See `gate.ts` for why nothing is injected into the page, why each scan
 * asserts its content first, and why `violations` is not the whole oracle.
 */

for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(900_000);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expectBaselineNotStale();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(900_000);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expectBaselineNotStale();
  });
}
