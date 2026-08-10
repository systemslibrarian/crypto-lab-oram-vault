import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText, formatNonTextFailures, type NonTextFailure } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Three rules govern everything here:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN.
 *
 *  2. EVERY SCAN ASSERTS ITS CONTENT IS PRESENT FIRST, and there are scans well
 *     past first paint. axe over an empty container passes having checked
 *     nothing, and this lab hides almost everything at first paint. Four of its
 *     five exhibits carry the `hidden` attribute; the one that does not shows a
 *     static attack log and two "Press Replay" placeholders. Neither ORAM tree
 *     exists, the position map is a one-line caption, the stash is empty, the
 *     eviction-invariant list is a placeholder, the walkthrough's seven steps
 *     hold their default text, and the adversary log and its chi-square panel
 *     are empty. The headline claim — the server sees uniform, independent
 *     paths while the client reads whatever block it likes — cannot be scanned
 *     until an ORAM has actually been provisioned and driven.
 *
 *     This also means A GATE MUST NOT UN-HIDE PANELS TO SCAN THEM. The five
 *     exhibits are mutually exclusive; showing all five at once is a layout no
 *     user ever sees, and it hands axe a duplicate-landmark, duplicate-heading
 *     page that is not the page under test. Each is opened through its own tab.
 *
 *  3. `violations` IS NOT THE WHOLE ORACLE. See `scan`.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the
  // whole test timeout and reports nothing useful. 20s turns that silent hang
  // into a named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

  // Exhibit 1 is the only panel showing, and the four behind it are really
  // hidden — the state a reader is actually in.
  await expect(page.locator('#ex0')).toBeVisible();
  for (const id of ['#ex1', '#ex2', '#ex3', '#ex4']) {
    await expect(page.locator(id)).toBeHidden();
  }
  await expect(page.locator('#replayStatus')).toHaveText('Not yet run.');
  await expect(page.locator('#replayServerLog')).toContainText('Press "Replay"');

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this lab is a
 * plausible offender: it draws a 31-bucket binary tree behind a 600px floor,
 * prints `white-space: pre` monospace logs whose lines are fixed-width, lays a
 * three-column costs table out with `white-space: nowrap`, and puts every one
 * of those inside a two-column grid.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide table inside an `overflow-x: auto` wrapper has a huge bounding rect
    // but is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element. That
    // cost a run elsewhere in this fleet (a 980px table was reported while the
    // real overflow was 15px of something else), and this lab is full of such
    // decoys: `.tree-svg-wrap` has a 600px floor inside `.tree-container`, and
    // every `.scenario` is `min-width: fit-content` inside `.scenario-wrap`.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    // Prefer an unclipped culprit; fall back to the widest clipped one rather
    // than reporting nothing, so the message always names something to look at.
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 *
 * This lab has seven of them — the two tree containers, the five `.scenario-wrap`
 * boxes, the costs table wrapper, the position-map scroller and the two access
 * logs — and most only start scrolling once content lands in them or the
 * viewport narrows, which is why this runs after every driven state at both
 * widths rather than once at first paint.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Five assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - `violations` — the usual WCAG A/AA rule failures.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically. Everything else in that bucket is a real result
 *    axe simply could not finish — including `aria-prohibited-attr`, which is
 *    where an `aria-label` on a role-less div hides, a defect that never
 *    reaches the violations array at all.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no text
 * node. Both were being found by hand-sampling screenshot pixels, which does
 * not regress-test.
 *
 * The backlog is real, so this does not block on it — but a check that merely
 * logs is not a gate, and this sweep has spent its whole length deleting checks
 * that could not fail. So it ratchets instead: anything NOT in the baseline
 * fails, anything in the baseline that got WORSE fails, and anything in the
 * baseline that has been FIXED fails until its entry is deleted. That last rule
 * is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it. Opt-in via env, and the run is
  // deliberately left failing at the end by `expectBaselineNotStale` so a
  // capture pass can never be mistaken for a passing gate.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(
        `WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`
      );
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the point
 * — or the drive stopped reaching the state that shows it, which is a coverage
 * regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  expect(violations, `axe violations in state: ${label}`).toEqual([]);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  expect(unexplainedIncomplete, `axe incomplete results in state: ${label}`).toEqual([]);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  expect(contrast, `measured contrast failures in state: ${label}`).toEqual([]);

  await expectNoNewNonTextFailures(page, label);
  await expectScrollersReachable(page, label);
  await expectNoHorizontalOverflow(page, label);
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Five exhibits, each opened through its own tab rather than un-hidden, because
 * the mutually-exclusive panels are the layout the reader actually gets.
 *
 * The drive deliberately goes off the happy path in three places, each of which
 * paints ink no successful run does:
 *
 *   - an out-of-range block id, which is the exhibit's own input-validation
 *     branch and the only route to that status line;
 *   - the "server view" toggle, which collapses the client tree to the server's
 *     opaque rendering — a different set of SVG fills entirely;
 *   - the STALE VAULT state. All five exhibits share one server module, so
 *     pressing Initialize in exhibit 4 destroys the tree exhibit 2 was using.
 *     The next access there throws `StaleVaultError` and the exhibit parks
 *     itself with a long refusal message and four disabled buttons. That branch
 *     exists precisely because the alternative was a confident wrong answer, so
 *     it is worth scanning; the ordering below (exhibit 2 driven fully, THEN
 *     exhibits 3 and 4 initialized, THEN back to exhibit 2) is what reaches it.
 *
 * Every ORAM operation is real AES-GCM over a real path, so each stage waits on
 * its own completion signal — the status line, the rendered bucket count, the
 * chi-square verdict — never on a timeout.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);
  // Initializing writes all 16 blocks through real encrypted path accesses,
  // which runs well past the 20s default `boot` sets for ordinary clicks.
  const HEAVY = { timeout: 180_000 };

  const openTab = async (idx: number): Promise<void> => {
    await page.locator(`#tab${idx}`).click();
    await expect(page.locator(`#tab${idx}`)).toHaveAttribute('aria-selected', 'true');
    await expect(page.locator(`#ex${idx}`)).toBeVisible();
  };

  await scanAt('first paint');

  await page.locator('a.cl-skip-link').focus();
  await scanAt('shared skip link focused');
  await page.locator('a.skip-link').focus();
  await scanAt('lab skip link focused');

  // ── Exhibit 1: replay the medical scenario through a live ORAM ────────────
  await page.locator('#replayBtn').click(HEAVY);
  await expect(page.locator('#replayStatus')).toContainText('Done.', HEAVY);
  await expect(page.locator('#replayServerLog')).toContainText('READ path');
  await expect(page.locator('#replayClientLog')).toContainText('READ block');
  await scanAt('exhibit 1: scenario replayed through ORAM');

  // ── Exhibit 2: the tree ───────────────────────────────────────────────────
  await openTab(1);
  await expect(page.locator('#treeStatus')).toContainText('Click "Initialize ORAM"');
  await expect(page.locator('#serverTree svg')).toHaveCount(0);
  await scanAt('exhibit 2: opened, nothing initialized');

  await page.locator('#initBtn').click(HEAVY);
  await expect(page.locator('#treeStatus')).toContainText('Initialized:', HEAVY);
  // 31 buckets drawn in each of the two trees.
  await expect(page.locator('#serverTree rect.bucket-rect')).toHaveCount(31);
  await expect(page.locator('#clientTree rect.bucket-rect')).toHaveCount(31);
  await expect(page.locator('#treeStats .stat')).toHaveCount(6);
  await expect(page.locator('#positionMap .pm-table tbody tr')).toHaveCount(16);
  await scanAt('exhibit 2: ORAM initialized');

  // A random access highlights a path, pulses the moved block, re-randomises a
  // position-map row (struck-through old leaf beside the fresh one) and fills
  // the eviction-invariant list. None of that ink exists before this click.
  await page.locator('#stepBtn').click(HEAVY);
  await expect(page.locator('#treeStatus')).toContainText('re-randomised to leaf', HEAVY);
  await expect(page.locator('#serverTree rect.bucket-rect.on-path')).toHaveCount(5);
  await expect(page.locator('.pm-row.pm-focus')).toHaveCount(1);
  await expect(page.locator('#evictionInvariant .ei-row').first()).toBeVisible();
  await expect(page.locator('#stashDisplay')).not.toBeEmpty();
  await scanAt('exhibit 2: one random access');

  // The client tree collapses to the server's opaque rendering — a different
  // set of SVG fills, and the toggle's own pressed label.
  await page.locator('#serverViewBtn').click();
  await expect(page.locator('#serverViewBtn')).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('#serverViewBtn')).toHaveText('Reveal client block IDs');
  await scanAt('exhibit 2: client tree hidden behind the server view');
  await page.locator('#serverViewBtn').click();
  await expect(page.locator('#serverViewBtn')).toHaveAttribute('aria-pressed', 'false');

  // A named write, then a named read, so the status line carries a value.
  await page.locator('#blockIdInput').fill('5');
  await page.locator('#blockValueInput').fill('SECRET');
  await page.locator('#writeBlockBtn').click(HEAVY);
  await expect(page.locator('#treeStatus')).toContainText('WRITE(block 5', HEAVY);
  await scanAt('exhibit 2: block 5 written');

  await page.locator('#readBlockBtn').click(HEAVY);
  await expect(page.locator('#treeStatus')).toContainText('READ(block 5) = "SECRET"', HEAVY);
  await scanAt('exhibit 2: block 5 read back');

  // The input-validation branch: its own status line, reachable no other way.
  await page.locator('#blockIdInput').fill('99');
  await page.locator('#readBlockBtn').click();
  await expect(page.locator('#treeStatus')).toContainText('Invalid block ID');
  await scanAt('exhibit 2: block id rejected');
  await page.locator('#blockIdInput').fill('5');

  // Auto-run is exercised but deliberately NOT scanned: it mutates the trees,
  // the position map, the stash and the stats every 1200ms, so any scan of that
  // state races its own subject. It paints nothing the stepped state above does
  // not, apart from the button's own pressed label, which is asserted here.
  await page.locator('#autoBtn').click();
  await expect(page.locator('#autoBtn')).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('#autoBtn')).toHaveText('Stop Auto');
  await page.locator('#autoBtn').click();
  await expect(page.locator('#autoBtn')).toHaveAttribute('aria-pressed', 'false');
  await expect(page.locator('#autoBtn')).toHaveText('Auto-run');

  // ── Exhibit 3: the seven-step walkthrough ─────────────────────────────────
  await openTab(2);
  await expect(page.locator('#walkStatus')).toContainText('Initialize ORAM to begin');
  await expect(page.locator('#walkServerLogLines')).toHaveText('(no accesses yet)');
  // Every step is inactive here, which is its own rendering.
  await expect(page.locator('.step-item.active')).toHaveCount(0);
  await scanAt('exhibit 3: opened, no step reached');

  await page.locator('#walkInitBtn').click(HEAVY);
  await expect(page.locator('#walkStatus')).toContainText('Ready.', HEAVY);
  await scanAt('exhibit 3: walkthrough initialized');

  await page.locator('#walkReadBtn').click(HEAVY);
  await expect(page.locator('.step-item.active')).toHaveCount(1);
  await expect(page.locator('#walkStatus')).toContainText('Step 1/7');
  await scanAt('exhibit 3: READ walkthrough, step 1');

  // Steps 2..7. The last one runs the real access, so it gets the long timeout;
  // step 4 is the first state carrying both `.done` and `.active` items at once.
  for (const step of [2, 3, 4, 5, 6, 7] as const) {
    await page.locator('#walkNextBtn').click(HEAVY);
    if (step < 7) await expect(page.locator('#walkStatus')).toContainText(`Step ${step}/7`);
    else await expect(page.locator('#walkStatus')).toContainText('Complete!', HEAVY);
    await expect(page.locator('.step-item.done')).toHaveCount(step - 1);
    await scanAt(`exhibit 3: walkthrough step ${step}`);
  }
  await expect(page.locator('#walkNextBtn')).toBeDisabled();
  await expect(page.locator('#walkServerLogLines')).toContainText('[Step 7]');

  // The WRITE branch prints different step details and a different verdict.
  await page.locator('#walkWriteBtn').click(HEAVY);
  await expect(page.locator('#walkStatus')).toContainText('Step 1/7');
  await scanAt('exhibit 3: WRITE walkthrough, step 1');

  // ── Exhibit 4: adversary vs client ────────────────────────────────────────
  await openTab(3);
  await expect(page.locator('#advStatus')).toContainText('Initialize to begin');
  await expect(page.locator('#advServerLog')).toBeEmpty();
  await scanAt('exhibit 4: opened, no accesses');

  await page.locator('#advInitBtn').click(HEAVY);
  await expect(page.locator('#advStatus')).toContainText('Initialized.', HEAVY);
  await scanAt('exhibit 4: initialized');

  await page.locator('#advRunBtn').click(HEAVY);
  await expect(page.locator('#advStatus')).toContainText('Done.', HEAVY);
  await expect(page.locator('#advServerLog .access-row')).toHaveCount(20);
  await expect(page.locator('#advClientLog .access-row')).toHaveCount(20);
  await expect(page.locator('#advAnalysis')).toContainText('goodness-of-fit');
  await scanAt('exhibit 4: 20 accesses run, chi-square reported');

  await page.locator('#advClearBtn').click();
  await expect(page.locator('#advAnalysis')).toContainText('Log cleared.');
  await scanAt('exhibit 4: log cleared');

  // ── Exhibit 5: costs, and the caveats the other exhibits link into ────────
  await openTab(4);
  await expect(page.locator('table.costs tbody tr')).toHaveCount(7);
  await expect(page.locator('#caveats')).toBeVisible();
  await expect(page.locator('.crosslinks .crosslink')).toHaveCount(5);
  await scanAt('exhibit 5: costs and caveats');

  // ── The stale-vault refusal ───────────────────────────────────────────────
  // Exhibits 4 and 5 above re-provisioned the shared server, so exhibit 2's
  // client now holds a key that decrypts nothing. Its next access must refuse.
  await openTab(1);
  await page.locator('#stepBtn').click(HEAVY);
  await expect(page.locator('#treeStatus')).toContainText('Vault replaced', HEAVY);
  await expect(page.locator('#stepBtn')).toBeDisabled();
  await expect(page.locator('#evictionInvariant .ei-row')).toHaveCount(0);
  await scanAt('exhibit 2: vault replaced, exhibit parked');

  // And it recovers: Initialize is still live and rebuilds the tree in place.
  await page.locator('#initBtn').click(HEAVY);
  await expect(page.locator('#treeStatus')).toContainText('Initialized:', HEAVY);
  await expect(page.locator('#stepBtn')).toBeEnabled();
  await scanAt('exhibit 2: re-initialized after the replacement');

  // ── The cross-exhibit caveats link ────────────────────────────────────────
  await openTab(0);
  await page.locator('#ex0CaveatsLink').click();
  await expect(page.locator('#ex4')).toBeVisible();
  await expect(page.locator('#tab4')).toHaveAttribute('aria-selected', 'true');
  await scanAt('exhibit 5 reached through the caveats link');
}
