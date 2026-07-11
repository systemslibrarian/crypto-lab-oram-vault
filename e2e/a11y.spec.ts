import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are already gated on unit tests; this gates
 * them on accessibility the same way. The page is a 5-tab exhibit where only
 * one <section role="tabpanel"> is visible at a time, and several exhibits
 * inject dynamic result regions. Before scanning we reveal EVERY panel, drive
 * the live ORAM demos so their async output regions exist, expand any
 * collapsibles, and neutralize animations/transitions/opacity (mid-fade
 * opacity produces phantom contrast failures). We then scan in both themes.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function neutralizeMotion(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{
      animation:none!important;
      transition:none!important;
      opacity:1!important;
      scroll-behavior:auto!important;
    }`,
  });
}

/** Reveal every exhibit panel and expand all collapsibles so nothing is hidden. */
async function revealEverything(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const details of Array.from(document.querySelectorAll('details'))) {
      (details as HTMLDetailsElement).open = true;
    }
    // Un-hide every tab panel (they are mutually exclusive via [hidden]/.active).
    for (const panel of Array.from(
      document.querySelectorAll<HTMLElement>('[role="tabpanel"], section.exhibit')
    )) {
      panel.removeAttribute('hidden');
      panel.classList.add('active');
      panel.style.display = 'block';
    }
  });
}

/** Drive each interactive exhibit so dynamically-injected regions get scanned. */
async function driveDemos(page: Page): Promise<void> {
  // Exhibit 1 — tree visualization: initialize, then read/write a block.
  await page.locator('#initBtn').click();
  await expect(page.locator('#treeStatus')).toContainText('Initialized', {
    timeout: 15000,
  });
  await page.locator('#readBlockBtn').click();
  await page.locator('#writeBlockBtn').click();

  // Exhibit 2 — walkthrough: initialize, start a READ, step through.
  await page.locator('#walkInitBtn').click();
  await expect(page.locator('#walkStatus')).toContainText('Ready', {
    timeout: 15000,
  });
  await page.locator('#walkReadBtn').click();
  for (let i = 0; i < 7; i++) {
    const next = page.locator('#walkNextBtn');
    if (await next.isEnabled()) await next.click();
  }

  // Exhibit 3 — adversary: initialize, run accesses (fills logs + analysis).
  await page.locator('#advInitBtn').click();
  await expect(page.locator('#advStatus')).toContainText('Initialized', {
    timeout: 15000,
  });
  await page.locator('#advRunBtn').click();
  await expect(page.locator('#advStatus')).toContainText('Done', {
    timeout: 20000,
  });
}

async function scan(page: Page): Promise<void> {
  await revealEverything(page);
  await neutralizeMotion(page);
  // Park the pointer so no button sits in :hover (hover fills differ from base).
  await page.mouse.move(0, 0);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await revealEverything(page);
  await driveDemos(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await revealEverything(page);
  await driveDemos(page);
  await scan(page);
});
