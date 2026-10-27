import { expect, test, type Locator, type Page } from '@playwright/test';

/**
 * Functional gate for the claims this page makes on screen.
 *
 * The a11y and border specs prove the page is reachable and legible; this one
 * proves it is telling the truth. Nothing here is asserted against a constant
 * the test picked: the ORAM parameters are read off the page, the χ² statistic
 * is recomputed from the page's own histogram, the block→leaf remap is chained
 * across successive accesses in the page's own logs, and the eviction
 * explanation is checked against the page's own position map.
 */

const READY = { timeout: 60_000 };

// ---------------------------------------------------------------- guards

function guardPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (msg) => {
    if (msg.type() === 'error') errors.push(`console.error: ${msg.text()}`);
  });
  return errors;
}

test.beforeEach(async ({ page }) => {
  (test.info() as unknown as { _pageErrors: string[] })._pageErrors = guardPageErrors(page);
});

test.afterEach(async () => {
  const errors = (test.info() as unknown as { _pageErrors?: string[] })._pageErrors ?? [];
  expect(errors, 'page must raise no uncaught exceptions or console errors').toEqual([]);
});

// ---------------------------------------------------------------- helpers

interface Params {
  N: number;
  Z: number;
  L: number;
  buckets: number;
  capacity: number;
}

/**
 * Read the ORAM parameters off the page and check the page's own arithmetic:
 * a complete binary tree of height L has 2^(L+1)-1 buckets, and Z slots each.
 */
async function readParams(page: Page): Promise<Params> {
  const text = await page.locator('#ex1 > p').first().innerText();
  const m =
    /N=(\d+) blocks · Z=(\d+) bucket size · tree height L=(\d+) \((\d+) levels\) · (\d+) total buckets · (\d+) block capacity/.exec(
      text.replace(/\s+/g, ' '),
    );
  expect(m, `unparseable parameter line: ${text}`).not.toBeNull();
  const p: Params = {
    N: Number(m![1]),
    Z: Number(m![2]),
    L: Number(m![3]),
    buckets: Number(m![5]),
    capacity: Number(m![6]),
  };
  expect(Number(m![4]), 'a height-L root-to-leaf tree must display L+1 levels').toBe(p.L + 1);
  expect(p.buckets, 'bucket count must be 2^(L+1) - 1').toBe((1 << (p.L + 1)) - 1);
  expect(p.capacity, 'capacity must be Z slots per bucket').toBe(p.Z * p.buckets);
  expect(p.N, 'N blocks must fit the leaf level').toBe(1 << p.L);
  return p;
}

/**
 * Bucket indices root-to-leaf on P(leaf), for a complete binary tree stored in
 * array form. Recomputed here so the test does not borrow the app's own routine.
 */
function pathBuckets(leaf: number, L: number): number[] {
  const ids: number[] = [];
  for (let level = 0; level <= L; level++) {
    ids.push((1 << level) - 1 + Math.floor(leaf / (1 << (L - level))));
  }
  return ids;
}

/** Deepest level at which a block assigned to `blockLeaf` may sit on P(pathLeaf). */
function deepestLegalLevel(blockLeaf: number, pathLeaf: number, L: number): number {
  let deepest = -1;
  for (let level = 0; level <= L; level++) {
    const shift = L - level;
    if (blockLeaf >> shift === pathLeaf >> shift) deepest = level;
  }
  return deepest;
}

async function initTree(page: Page): Promise<void> {
  await page.locator('#tab1').click();
  await page.locator('#initBtn').click();
  await expect(page.locator('#treeStatus')).toContainText('Initialized:', READY);
}

/** `server read+wrote path P(a); block re-randomised to leaf b` from a status line. */
function parseAccessStatus(status: string): { oldLeaf: number; newLeaf: number } {
  const m = /server read\+wrote path P\((\d+)\); block re-randomised to leaf (\d+)/.exec(status);
  expect(m, `unparseable access status: ${status}`).not.toBeNull();
  return { oldLeaf: Number(m![1]), newLeaf: Number(m![2]) };
}

/** The block → leaf table as the page currently renders it. */
async function positionMap(page: Page): Promise<Map<number, number>> {
  const rows = await page.locator('#positionMap .pm-row').all();
  const map = new Map<number, number>();
  for (const row of rows) {
    const block = Number(((await row.locator('th').innerText()) ?? '').replace(/^B/, ''));
    const cell = (await row.locator('td').innerText()).replace(/\s+/g, ' ');
    // The just-remapped row reads "leaf OLD → leaf NEW"; take the new leaf.
    const leaves = [...cell.matchAll(/leaf (\d+)/g)].map((x) => Number(x[1]));
    expect(leaves.length, `unparseable position-map cell: ${cell}`).toBeGreaterThan(0);
    map.set(block, leaves[leaves.length - 1]);
  }
  return map;
}

interface EvictionRow {
  block: number;
  bucket: number;
  blockLeaf: number;
}

async function evictionRows(page: Page): Promise<EvictionRow[]> {
  const rows = await page.locator('#evictionInvariant .ei-row').all();
  const out: EvictionRow[] = [];
  for (const row of rows) {
    const block = Number((await row.locator('.ei-block').innerText()).replace(/^B/, ''));
    const bucket = Number((await row.locator('.ei-bucket').innerText()).replace(/^B/, ''));
    const note = (await row.locator('.ei-note').innerText()).replace(/\s+/g, ' ');
    const m = /leaf (\d+)/.exec(note);
    expect(m, `eviction note names no leaf: ${note}`).not.toBeNull();
    out.push({ block, bucket, blockLeaf: Number(m![1]) });
  }
  return out;
}

/** Numeric block-ID labels drawn in a tree SVG (dummy `--` slots excluded). */
async function treeBlockIds(page: Page, containerId: string): Promise<number[]> {
  const labels = await page
    .locator(`#${containerId} text.block-id-label:not(.dummy)`)
    .allTextContents();
  return labels.map((t) => Number(t.trim()));
}

async function statNumber(page: Page, label: string): Promise<number> {
  const stats = await page.locator('#treeStats .stat').all();
  for (const s of stats) {
    const name = (await s.locator('.stat-label').innerText()).trim();
    if (name.toLowerCase() === label.toLowerCase()) {
      return Number((await s.locator('.stat-value').innerText()).trim());
    }
  }
  throw new Error(`no stat labelled ${label}`);
}

// ---------------------------------------------------------------- exhibit 0

test('the replay hides record identity but retains the visible timing cluster', async ({ page }) => {
  await page.goto('.');
  const p = await readParams(page);
  const blobsPerAccess = p.Z * (p.L + 1);

  await expect(page.locator('#replayStatus')).toHaveText('Not yet run.');
  await page.locator('#replayBtn').click();
  await expect(page.locator('#replayStatus')).toContainText('Done.', READY);

  const serverText = await page.locator('#replayServerLog').innerText();
  const clientText = await page.locator('#replayClientLog').innerText();

  const serverRows = [
    ...serverText.matchAll(/^(\S+ \d{2}:\d{2})\s+READ path\s+(\d+)\s+\(read\+write, (\d+) blobs\)$/gm),
  ];
  const clientRows = [
    ...clientText.matchAll(/^(\S+ \d{2}:\d{2})\s+READ block\s+(\d+)\s+\(record #(\d+)\)$/gm),
  ];
  expect(serverRows).toHaveLength(6);
  expect(clientRows).toHaveLength(6);

  for (let i = 0; i < 6; i++) {
    // Same six accesses, in the same order, on both sides of the screen.
    expect(serverRows[i][1], 'server and client rows must line up').toBe(clientRows[i][1]);
    // Every access moves one full path: Z·(L+1) blobs, as the costs table says.
    expect(Number(serverRows[i][3])).toBe(blobsPerAccess);
    const leaf = Number(serverRows[i][2]);
    expect(leaf).toBeGreaterThanOrEqual(0);
    expect(leaf).toBeLessThan(1 << p.L);
    // The client's block is the medical record folded into the toy vault.
    expect(Number(clientRows[i][2])).toBe(Number(clientRows[i][3]) % p.N);
  }

  // Three identical logical reads; the count of distinct paths the page reports
  // must be the count actually present in the log it just printed.
  const morning = serverRows.slice(0, 3).map((r) => Number(r[2]));
  const distinct = new Set(morning).size;
  expect(serverText).toContain(`(${distinct} distinct this run)`);
  expect(serverText).toContain('three-access timing cluster remains visible');
  expect(serverText).not.toContain('cluster is now indistinguishable');
  await expect(page.locator('#replayStatus')).toContainText(
    `produced ${distinct} distinct server paths this run`,
  );

  // The whole point: the log rows themselves name no block and no record.
  // (The commentary beneath them does, to explain what the rows no longer show.)
  for (const row of serverText.split('\n').slice(0, 6)) {
    expect(row.toLowerCase(), `adversary log row leaks a logical name: ${row}`).not.toContain(
      'block ',
    );
    expect(row.toLowerCase()).not.toContain('record');
  }
});

// ---------------------------------------------------------------- exhibit 1

test('a written block reads back, and each access reads the path the last one assigned', async ({
  page,
}) => {
  await page.goto('.');
  const p = await readParams(page);
  await initTree(page);

  await page.locator('#blockIdInput').fill('5');
  await page.locator('#blockValueInput').fill('SECRET');
  await page.locator('#writeBlockBtn').click();
  await expect(page.locator('#treeStatus')).toContainText('WRITE(block 5', READY);
  const wrote = parseAccessStatus(await page.locator('#treeStatus').innerText());

  await page.locator('#readBlockBtn').click();
  await expect(page.locator('#treeStatus')).toContainText('READ(block 5', READY);
  const readStatus = await page.locator('#treeStatus').innerText();

  // Round-trip: the value the page reports is the value it stored.
  expect(readStatus).toContain('READ(block 5) = "SECRET"');

  // The remap invariant, chained across two real accesses: the leaf the write
  // assigned is exactly the path the following read made the server serve.
  const read1 = parseAccessStatus(readStatus);
  expect(read1.oldLeaf, "the read must fetch the leaf the write assigned").toBe(wrote.newLeaf);
  expect(read1.newLeaf).toBeGreaterThanOrEqual(0);
  expect(read1.newLeaf).toBeLessThan(1 << p.L);

  // And once more, so the chain is not a coincidence of one hop.
  await page.locator('#readBlockBtn').click();
  await expect(page.locator('#treeStatus')).toContainText(`path P(${read1.newLeaf})`, READY);
  const read2 = parseAccessStatus(await page.locator('#treeStatus').innerText());
  expect(read2.oldLeaf).toBe(read1.newLeaf);

  // The position map is the same story told as a table.
  const map = await positionMap(page);
  expect(map.size, 'the map must hold every block').toBe(p.N);
  for (const [, leaf] of map) {
    expect(leaf).toBeGreaterThanOrEqual(0);
    expect(leaf).toBeLessThan(1 << p.L);
  }
  expect(map.get(5), 'block 5 must now point at the leaf the last access assigned').toBe(
    read2.newLeaf,
  );
  await expect(page.locator('#positionMap .pm-caption')).toContainText(
    `leaf ${read2.oldLeaf} → leaf ${read2.newLeaf}`,
  );
});

test('the server tree shows no block IDs and the client tree accounts for every slot', async ({
  page,
}) => {
  await page.goto('.');
  const p = await readParams(page);
  await initTree(page);
  await page.locator('#stepBtn').click();
  await expect(page.locator('#treeStatus')).toContainText('re-randomised', READY);

  // The server's headline claim: identical opaque blobs, no IDs anywhere.
  await expect(page.locator('#serverTree text.block-id-label')).toHaveCount(0);

  // The client's view covers exactly the highlighted path: (L+1) buckets of Z
  // slots, every slot either a real block ID or an explicit dummy.
  const slots = p.Z * (p.L + 1);
  await expect(page.locator('#clientTree text.block-id-label')).toHaveCount(slots);
  const real = await treeBlockIds(page, 'clientTree');
  const dummies = await page.locator('#clientTree text.block-id-label.dummy').count();
  expect(real.length + dummies, 'real + dummy slots must account for the whole path').toBe(slots);
  expect(new Set(real).size, 'no block may appear twice on one path').toBe(real.length);
  for (const b of real) {
    expect(b).toBeGreaterThanOrEqual(0);
    expect(b).toBeLessThan(p.N);
  }

  // Both trees are highlighted, and only the path is: (L+1) buckets of 2^(L+1)-1.
  await expect(page.locator('#serverTree rect.bucket-rect.on-path')).toHaveCount(p.L + 1);
  await expect(page.locator('#clientTree rect.bucket-rect.on-path')).toHaveCount(p.L + 1);
  await expect(page.locator('#serverTree rect.bucket-rect')).toHaveCount(p.buckets);

  // Toggling to server view must actually remove the IDs, not just relabel.
  await page.locator('#serverViewBtn').click();
  await expect(page.locator('#serverViewBtn')).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('#serverViewBtn')).toHaveText('Reveal client block IDs');
  await expect(page.locator('#clientTree text.block-id-label')).toHaveCount(0);

  await page.locator('#serverViewBtn').click();
  await expect(page.locator('#serverViewBtn')).toHaveAttribute('aria-pressed', 'false');
  await expect(page.locator('#clientTree text.block-id-label')).toHaveCount(slots);
  expect(await treeBlockIds(page, 'clientTree')).toEqual(real);
});

test('the eviction explanation is legal under the position map it is drawn from', async ({
  page,
}) => {
  await page.goto('.');
  const p = await readParams(page);
  await initTree(page);
  await page.locator('#stepBtn').click();
  await expect(page.locator('#treeStatus')).toContainText('re-randomised', READY);

  const { oldLeaf } = parseAccessStatus(await page.locator('#treeStatus').innerText());
  const onPath = pathBuckets(oldLeaf, p.L);
  const map = await positionMap(page);
  const rows = await evictionRows(page);

  expect(rows.length, 'the write-back must place at least one real block').toBeGreaterThan(0);
  expect(rows.length, 'no more real blocks than the path has slots').toBeLessThanOrEqual(
    p.Z * (p.L + 1),
  );
  expect(new Set(rows.map((r) => r.block)).size).toBe(rows.length);

  for (const row of rows) {
    // The bucket named must be on the path the status line says was written.
    const level = onPath.indexOf(row.bucket);
    expect(level, `B${row.bucket} is not on P(${oldLeaf})`).toBeGreaterThanOrEqual(0);
    // The leaf the note quotes must be the leaf the position map holds.
    expect(row.blockLeaf, `note for B${row.block} disagrees with the position map`).toBe(
      map.get(row.block),
    );
    // ...and the invariant the panel states: a block may rest only in buckets
    // its own path shares with the write-back path.
    expect(
      level,
      `B${row.block} (leaf ${row.blockLeaf}) may not legally sit at level ${level} of P(${oldLeaf})`,
    ).toBeLessThanOrEqual(deepestLegalLevel(row.blockLeaf, oldLeaf, p.L));
  }

  // The tree drawing and the prose explanation must describe the same placement.
  expect(
    (await treeBlockIds(page, 'clientTree')).sort((a, b) => a - b),
    'client tree and eviction list must agree on which blocks are on the path',
  ).toEqual(rows.map((r) => r.block).sort((a, b) => a - b));
});

test('an out-of-range block ID is refused by name and runs no access', async ({ page }) => {
  await page.goto('.');
  const p = await readParams(page);
  await initTree(page);
  await page.locator('#stepBtn').click();
  await expect(page.locator('#treeStatus')).toContainText('re-randomised', READY);

  const readsBefore = await statNumber(page, 'Server Reads');
  const writesBefore = await statNumber(page, 'Server Writes');
  const mapBefore = await positionMap(page);

  // '' is included deliberately: Number('') is 0, so an empty field must be
  // refused rather than silently reported as an access to block 0.
  for (const bad of [String(p.N), '-1', '2.5', '999', '']) {
    await page.locator('#blockIdInput').fill(bad);
    await page.locator('#readBlockBtn').click();
    await expect(
      page.locator('#treeStatus'),
      `input ${JSON.stringify(bad)} must be refused by name`,
    ).toHaveText(`Invalid block ID — enter an integer in [0, ${p.N - 1}].`);

    await page.locator('#writeBlockBtn').click();
    await expect(page.locator('#treeStatus')).toHaveText(
      `Invalid block ID — enter an integer in [0, ${p.N - 1}].`,
    );
  }

  // A refused access is a non-access: nothing reached the server, nothing moved.
  expect(await statNumber(page, 'Server Reads')).toBe(readsBefore);
  expect(await statNumber(page, 'Server Writes')).toBe(writesBefore);
  expect(await positionMap(page)).toEqual(mapBefore);

  // Character count is not byte count. Nine emoji occupy 36 UTF-8 bytes and
  // must fail before the ORAM access instead of being silently truncated.
  await page.locator('#blockIdInput').fill('0');
  await page.locator('#blockValueInput').fill('😀'.repeat(9));
  await page.locator('#writeBlockBtn').click();
  await expect(page.locator('#treeStatus')).toContainText('at most 32 UTF-8 bytes');
  expect(await statNumber(page, 'Server Reads')).toBe(readsBefore);
  expect(await statNumber(page, 'Server Writes')).toBe(writesBefore);
  expect(await positionMap(page)).toEqual(mapBefore);

  // A valid ID still works afterwards.
  await page.locator('#readBlockBtn').click();
  await expect(page.locator('#treeStatus')).toContainText('READ(block 0)', READY);
  expect(await statNumber(page, 'Server Reads')).toBeGreaterThan(readsBefore);
});

test('regression: re-initializing drops the previous vault\'s eviction explanation', async ({
  page,
}) => {
  // The panel names specific blocks, buckets and leaves derived from a position
  // map. Re-initializing throws that map away, so leaving the rows up would
  // explain a placement that no longer exists anywhere on the page.
  await page.goto('.');
  await initTree(page);
  await page.locator('#stepBtn').click();
  await expect(page.locator('#evictionInvariant .ei-row').first()).toBeVisible(READY);
  const stale = await page.locator('#evictionInvariant').innerText();

  await page.locator('#initBtn').click();
  await expect(page.locator('#treeStatus')).toContainText('Initialized:', READY);

  await expect(page.locator('#evictionInvariant .ei-row')).toHaveCount(0);
  await expect(page.locator('#evictionInvariant')).toContainText(
    'Run an access to see, block by block',
  );
  expect(await page.locator('#evictionInvariant').innerText()).not.toBe(stale);
  // The position map is reset to its own placeholder for the same reason.
  await expect(page.locator('#positionMap .pm-caption')).toContainText(
    'Run an access to watch a row re-randomise',
  );
});

test('regression: a replaced vault refuses to answer instead of answering wrong', async ({
  page,
}) => {
  // Every exhibit shares one server module, so initializing another exhibit
  // discards this one's tree. The leftover client keeps a valid key and a
  // plausible position map, so its next read decrypts nothing, comes back as 32
  // zero bytes, and used to be printed as `= "(empty)"` for a block the page
  // had just shown holding SECRET.
  await page.goto('.');
  await initTree(page);
  await page.locator('#blockIdInput').fill('5');
  await page.locator('#blockValueInput').fill('SECRET');
  await page.locator('#writeBlockBtn').click();
  await expect(page.locator('#treeStatus')).toContainText('WRITE(block 5', READY);
  await page.locator('#readBlockBtn').click();
  await expect(page.locator('#treeStatus')).toContainText('READ(block 5) = "SECRET"', READY);

  // Take the server away from under this exhibit.
  await page.locator('#tab3').click();
  await page.locator('#advInitBtn').click();
  await expect(page.locator('#advStatus')).toContainText('Initialized.', READY);
  await page.locator('#tab1').click();

  await page.locator('#readBlockBtn').click();
  const status = page.locator('#treeStatus');
  await expect(status).toContainText('Vault replaced', READY);
  await expect(status).toContainText('another exhibit initialized the shared server');
  await expect(status).toContainText('Press Initialize');
  // Crucially: no answer at all, right or wrong.
  await expect(status).not.toContainText('(empty)');
  await expect(status).not.toContainText('SECRET');

  for (const id of ['stepBtn', 'autoBtn', 'readBlockBtn', 'writeBlockBtn']) {
    await expect(page.locator(`#${id}`), `${id} must be parked`).toBeDisabled();
  }
  await expect(page.locator('#evictionInvariant .ei-row')).toHaveCount(0);

  // Re-initializing here restores a working vault.
  await page.locator('#initBtn').click();
  await expect(status).toContainText('Initialized:', READY);
  await expect(page.locator('#readBlockBtn')).toBeEnabled();
  await page.locator('#blockValueInput').fill('SECRET');
  await page.locator('#writeBlockBtn').click();
  await expect(status).toContainText('WRITE(block 5', READY);
  await page.locator('#readBlockBtn').click();
  await expect(status).toContainText('READ(block 5) = "SECRET"', READY);
});

// ---------------------------------------------------------------- exhibit 2

test('the walkthrough reads and writes one path and returns the stored value', async ({ page }) => {
  await page.goto('.');
  const p = await readParams(page);
  const blobs = p.Z * (p.L + 1);

  await page.locator('#tab2').click();
  await page.locator('#walkInitBtn').click();
  await expect(page.locator('#walkStatus')).toContainText('Ready.', READY);
  await expect(page.locator('#walkServerLogLines')).toHaveText('(no accesses yet)');

  await page.locator('#walkReadBtn').click();
  const oldLeafText = await page.locator('#stepDetail0').innerText();
  const oldLeaf = Number(/position\[5\] = leaf (\d+)/.exec(oldLeafText)![1]);

  for (let i = 0; i < 6; i++) await page.locator('#walkNextBtn').click();
  await expect(page.locator('#walkStatus')).toContainText('Complete!', READY);

  // Step 3 quotes the path it will read; the buckets must be that path.
  const step3 = await page.locator('#stepDetail2').innerText();
  const m3 = new RegExp(`Read path P\\(${oldLeaf}\\) → buckets \\[([\\d, ]+)\\]`).exec(step3);
  expect(m3, `step 3 does not name P(${oldLeaf}): ${step3}`).not.toBeNull();
  expect(m3![1].split(',').map((s) => Number(s.trim()))).toEqual(pathBuckets(oldLeaf, p.L));

  const log = await page.locator('#walkServerLogLines').innerText();

  // One full path read and one full path write, of the SAME path — the property
  // that makes a READ and a WRITE indistinguishable to the server.
  expect(log).toContain(`Server sees: READ path leafId=${oldLeaf}`);
  expect(log).toContain(`Server sees: WRITE path leafId=${oldLeaf}`);

  // The blob arithmetic the log prints must be Z·(L+1), consistently.
  const mBlobs = /\((\d+) buckets × (\d+) slots = (\d+) encrypted blobs\)/.exec(log);
  expect(mBlobs, `no blob arithmetic in log: ${log}`).not.toBeNull();
  expect(Number(mBlobs![1])).toBe(p.L + 1);
  expect(Number(mBlobs![2])).toBe(p.Z);
  expect(Number(mBlobs![3])).toBe(blobs);
  expect(Number(mBlobs![1]) * Number(mBlobs![2])).toBe(Number(mBlobs![3]));
  expect(log).toContain(`decrypt all ${blobs} blocks`);
  expect(log).toContain(`WRITE path leafId=${oldLeaf} (${blobs} freshly encrypted blobs)`);

  // Nothing the server is shown to see may name the block.
  for (const line of log.split('\n').filter((l) => l.includes('Server sees:'))) {
    expect(line, `server-visible line names the block: ${line}`).not.toMatch(/block\s*(ID\s*)?5/i);
  }
  expect(log).toContain('Server does NOT see: block ID 5');

  // The new leaf must be one number, reported identically in three places.
  const newLeaf = Number(
    /position\[5\] ← leaf (\d+) \(actual new mapping\)/.exec(
      await page.locator('#stepDetail1').innerText(),
    )![1],
  );
  expect(log).toContain(`New position[5] = leaf ${newLeaf}`);
  await expect(page.locator('#walkStatus')).toContainText(`map entry is now leaf ${newLeaf}`);
  await expect(page.locator('#walkStatus')).toContainText('wrote it to the old path');
  expect(newLeaf).toBeLessThan(1 << p.L);

  // The READ returns exactly what initialization wrote through the same ORAM.
  await expect(page.locator('#stepDetail6')).toHaveText('Returned: "HELLO, PATH ORAM!"');
  await expect(page.locator('#walkStatus')).toContainText('Block 5 = "HELLO, PATH ORAM!"');

  // Progress state: six steps done, the seventh active, and Next parked.
  await expect(page.locator('#walkSteps .step-item.done')).toHaveCount(6);
  await expect(page.locator('#walkSteps .step-item.active')).toHaveCount(1);
  await expect(page.locator('#walkSteps .step-item').nth(6)).toHaveClass(/active/);
  await expect(page.locator('#walkNextBtn')).toBeDisabled();
});

test('the walkthrough is inert before initialization and resets between runs', async ({ page }) => {
  await page.goto('.');
  await page.locator('#tab2').click();

  for (const id of ['walkReadBtn', 'walkWriteBtn', 'walkNextBtn']) {
    await expect(page.locator(`#${id}`)).toBeDisabled();
  }
  await expect(page.locator('#walkStatus')).toHaveText('Initialize ORAM to begin walkthrough.');
  await expect(page.locator('#walkSteps .step-item.active')).toHaveCount(0);
  await expect(page.locator('#walkSteps .step-item.done')).toHaveCount(0);

  await page.locator('#walkInitBtn').click();
  await expect(page.locator('#walkStatus')).toContainText('Ready.', READY);

  await page.locator('#walkWriteBtn').click();
  await expect(page.locator('#walkSteps .step-item.active')).toHaveCount(1);
  await expect(page.locator('#walkSteps .step-item').nth(0)).toHaveClass(/active/);
  for (let i = 0; i < 6; i++) await page.locator('#walkNextBtn').click();
  await expect(page.locator('#walkStatus')).toContainText('Block 5 written.', READY);
  await expect(page.locator('#stepDetail6')).toHaveText('Written successfully.');

  // Re-initializing wipes the trace rather than leaving the finished run on screen.
  await page.locator('#walkInitBtn').click();
  await expect(page.locator('#walkStatus')).toContainText('Ready.', READY);
  await expect(page.locator('#walkServerLogLines')).toHaveText('(no accesses yet)');
  await expect(page.locator('#walkSteps .step-item.done')).toHaveCount(0);
  await expect(page.locator('#walkSteps .step-item.active')).toHaveCount(0);
  await expect(page.locator('#walkNextBtn')).toBeDisabled();
});

// ---------------------------------------------------------------- exhibit 3

interface Histogram {
  counts: number[];
  expectedPerLeaf: number;
  chiSq: number;
  critical: number;
  verdict: string;
  total: number;
}

async function readHistogram(page: Page, numLeaves: number): Promise<Histogram> {
  // textContent, not innerText: the label is rendered uppercase by CSS.
  const label = (await page.locator('#advAnalysis .panel-label').textContent()) ?? '';
  const totalMatch = /(\d+) accesses/.exec(label);
  expect(totalMatch, `no access count in analysis label: ${label}`).not.toBeNull();
  const total = Number(totalMatch![1]);
  const text = await page.locator('#advAnalysis .scenario').innerText();

  const counts: number[] = [];
  for (let i = 0; i < numLeaves; i++) {
    const m = new RegExp(`^leaf\\s+${i}: ([█░]+) (\\d+)$`, 'm').exec(text);
    expect(m, `no histogram row for leaf ${i} in:\n${text}`).not.toBeNull();
    // Every bar is the same width, so the filled part is readable as a fraction.
    expect(m![1].length, `bar for leaf ${i} is the wrong width`).toBe(20);
    counts.push(Number(m![2]));
  }

  const exp = /Expected: ~([\d.]+) per leaf/.exec(text);
  const chi = /χ² goodness-of-fit vs\. uniform: ([\d.]+)\s+\(df=(\d+), critical=([\d.]+) at α=0\.05\)/.exec(
    text,
  );
  const ver = /Verdict: (.+)$/m.exec(text);
  expect(exp, `no expected line in:\n${text}`).not.toBeNull();
  expect(chi, `no χ² line in:\n${text}`).not.toBeNull();
  expect(ver, `no verdict in:\n${text}`).not.toBeNull();
  expect(Number(chi![2]), 'degrees of freedom must be numLeaves − 1').toBe(numLeaves - 1);

  // Bar lengths must be the counts they claim to draw.
  const maxCount = Math.max(...counts, 1);
  for (let i = 0; i < numLeaves; i++) {
    const filled = new RegExp(`^leaf\\s+${i}: (█*)`, 'm').exec(text)![1].length;
    expect(filled, `bar for leaf ${i} does not match its count`).toBe(
      Math.round((counts[i] / maxCount) * 20),
    );
  }

  return {
    counts,
    expectedPerLeaf: Number(exp![1]),
    chiSq: Number(chi![1]),
    critical: Number(chi![3]),
    verdict: ver![1].trim(),
    total,
  };
}

function chiSquare(counts: number[], expected: number): number {
  if (expected === 0) return 0;
  return counts.reduce((acc, c) => acc + (c - expected) ** 2 / expected, 0);
}

test('the adversary panel counts, χ² and verdict are all the same sample', async ({ page }) => {
  test.slow();
  await page.goto('.');
  const p = await readParams(page);
  const numLeaves = 1 << p.L;

  await page.locator('#tab3').click();
  await expect(page.locator('#advRunBtn')).toBeDisabled();
  await expect(page.locator('#advClearBtn')).toBeDisabled();
  await page.locator('#advInitBtn').click();
  await expect(page.locator('#advStatus')).toContainText('Initialized.', READY);

  await page.locator('#advRunBtn').click();
  await expect(page.locator('#advStatus')).toContainText('Done.', READY);

  let h = await readHistogram(page, numLeaves);
  expect(h.total).toBe(20);
  await expect(page.locator('#advServerLog .access-row')).toHaveCount(h.total);
  await expect(page.locator('#advClientLog .access-row')).toHaveCount(h.total);

  // The histogram must account for every access it claims to summarize.
  expect(
    h.counts.reduce((a, b) => a + b, 0),
    'per-leaf counts must sum to the accesses run',
  ).toBe(h.total);
  // Printed to one decimal, so compare against the same rounding of total/leaves.
  expect(h.expectedPerLeaf).toBe(Number((h.total / numLeaves).toFixed(1)));
  expect(h.chiSq, 'χ² must be the statistic of the histogram above it').toBeCloseTo(
    chiSquare(h.counts, h.total / numLeaves),
    1,
  );

  // With 20 accesses the χ² approximation is not valid, and the page says so —
  // naming both the condition and the sample size that would satisfy it.
  expect(h.expectedPerLeaf).toBeLessThan(5);
  expect(h.verdict).toContain('Inconclusive: need ≥5 expected/leaf');
  expect(h.verdict).toContain(`run ${5 * numLeaves}+ accesses total`);
  await expect(page.locator('#advStatus')).toContainText(h.verdict);

  // Run up to the threshold the page itself named; the verdict must change.
  for (let i = 0; i < 3; i++) {
    await page.locator('#advRunBtn').click();
    await expect(page.locator('#advStatus')).toContainText(`${20 * (i + 2)} total accesses`, READY);
  }

  h = await readHistogram(page, numLeaves);
  expect(h.total).toBe(5 * numLeaves);
  expect(h.counts.reduce((a, b) => a + b, 0)).toBe(h.total);
  expect(h.expectedPerLeaf).toBe(Number((h.total / numLeaves).toFixed(1)));
  expect(h.expectedPerLeaf, 'the χ² approximation is now valid').toBeGreaterThanOrEqual(5);
  const recomputed = chiSquare(h.counts, h.total / numLeaves);
  expect(h.chiSq).toBeCloseTo(recomputed, 1);
  expect(h.verdict, 'the sample is now large enough for a verdict').not.toContain('Inconclusive');

  // The verdict must be the one its own statistic supports.
  if (recomputed <= h.critical) {
    expect(h.verdict).toBe('This run is consistent with uniform paths (fail to reject H₀ at α=0.05).');
  } else {
    expect(h.verdict).toBe(
      'This run deviates from uniform at α=0.05 (expected for about 5% of uniform samples).',
    );
  }
});

test('the adversary log shows paths only, and each path is the leaf last assigned', async ({
  page,
}) => {
  await page.goto('.');
  const p = await readParams(page);

  await page.locator('#tab3').click();
  await page.locator('#advInitBtn').click();
  await expect(page.locator('#advStatus')).toContainText('Initialized.', READY);
  await page.locator('#advRunBtn').click();
  await expect(page.locator('#advStatus')).toContainText('Done.', READY);

  const serverRows = await page.locator('#advServerLog .access-row').all();
  const clientRows = await page.locator('#advClientLog .access-row').all();
  expect(serverRows.length).toBe(clientRows.length);

  const paths: number[] = [];
  const ops: Array<{ op: string; block: number; newLeaf: number }> = [];

  for (let i = 0; i < serverRows.length; i++) {
    expect(Number(await serverRows[i].locator('.acc-num').innerText())).toBe(i + 1);
    expect(Number(await clientRows[i].locator('.acc-num').innerText())).toBe(i + 1);

    // The adversary side must be a path index and nothing else.
    const seen = (await serverRows[i].locator('.acc-server').innerText()).trim();
    const sm = /^path (\d+) \(read\+write\)$/.exec(seen);
    expect(sm, `adversary row leaks more than a path: ${seen}`).not.toBeNull();
    paths.push(Number(sm![1]));

    const did = (await clientRows[i].innerText()).replace(/\s+/g, ' ').trim();
    const cm = /^(\d+) (READ|WRITE)\(block (\d+)\) → leaf (\d+)$/.exec(did);
    expect(cm, `unparseable client row: ${did}`).not.toBeNull();
    ops.push({ op: cm![2], block: Number(cm![3]), newLeaf: Number(cm![4]) });
    expect(ops[i].block).toBeLessThan(p.N);
    expect(paths[i]).toBeLessThan(1 << p.L);
  }

  // Chain the remap across the whole log: whenever a block is touched again,
  // the path the server was asked for is exactly the leaf the previous access
  // assigned it. This is what makes consecutive accesses unlinkable.
  const lastAssigned = new Map<number, number>();
  let chained = 0;
  for (let i = 0; i < ops.length; i++) {
    const prev = lastAssigned.get(ops[i].block);
    if (prev !== undefined) {
      expect(
        paths[i],
        `access ${i + 1} to block ${ops[i].block} read P(${paths[i]}), but its last access assigned leaf ${prev}`,
      ).toBe(prev);
      chained++;
    }
    lastAssigned.set(ops[i].block, ops[i].newLeaf);
  }
  expect(chained, 'the log must contain repeat accesses to chain').toBeGreaterThan(0);

  // Clearing must clear, not merely relabel.
  await page.locator('#advClearBtn').click();
  await expect(page.locator('#advServerLog .access-row')).toHaveCount(0);
  await expect(page.locator('#advClientLog .access-row')).toHaveCount(0);
  await expect(page.locator('#advAnalysis')).toHaveText('Log cleared.');

  await page.locator('#advRunBtn').click();
  await expect(page.locator('#advStatus')).toContainText('Done. 20 total accesses', READY);
  await expect(page.locator('#advServerLog .access-row')).toHaveCount(20);
});

// ---------------------------------------------------------------- exhibit 4

test('the costs table arithmetic matches the ORAM the demo actually runs', async ({ page }) => {
  await page.goto('.');
  const p = await readParams(page);
  const perAccess = p.Z * (p.L + 1);

  await page.locator('#tab4').click();
  const rows = page.locator('#ex4 table.costs tbody tr');

  // Column 0 = metric, column 1 = plain encrypted storage, column 2 = Path ORAM.
  expect((await rows.nth(0).locator('td').nth(1).innerText()).trim()).toBe('1 block');
  const reads = await rows.nth(0).locator('td').nth(2).innerText();
  expect(reads.replace(/\s+/g, ' ')).toBe(`Z·(L+1) = ${perAccess} blocks`);
  const writes = await rows.nth(1).locator('td').nth(2).innerText();
  expect(writes, 'reads and writes per access must be the same full path').toBe(reads);

  // Overhead is one path in plus one path out, relative to a single block.
  const overhead = await rows.nth(2).locator('td').nth(2).innerText();
  expect(overhead.replace(/\s+/g, ' ')).toBe(`~${2 * perAccess}× per access`);

  const storage = (await rows.nth(4).locator('td').nth(2).innerText()).replace(/\s+/g, ' ');
  expect(storage).toContain(`${p.buckets} buckets × ${p.Z} slots = ${p.capacity} slots`);
  expect(storage).toContain(`~${(p.capacity / p.N).toFixed(2)}N here`);

  // The caveat marker must lead to the caveats it promises.
  await expect(page.locator('#ex4 #caveats')).toBeVisible();
  await expect(page.locator('#ex4CaveatsLink')).toHaveAttribute('href', '#caveats');
});

test('scope copy distinguishes TEE leakage, Ring ORAM, and missing freshness', async ({ page }) => {
  await page.goto('.');
  await page.locator('#tab4').click();
  const costs = page.locator('#ex4');
  await expect(costs).toContainText('A TEE alone does not automatically hide its access pattern');
  await expect(costs).toContainText('Obladi');
  await expect(costs).toContainText('Ring ORAM rather than Path ORAM');
  await expect(costs).toContainText('no authenticated tree for path completeness or freshness');
  await expect(costs).toContainText('paper proves an exponential tail for Z=5');
  await expect(costs).toContainText('reports empirical support for Z=4');
  await expect(costs).not.toContainText('perfect access-pattern privacy');
});

test('server-view copy retains the transcript information the server really observes', async ({ page }) => {
  await page.goto('.');
  await page.locator('#tab3').click();
  const scope = page.locator('#ex3 .panel-server > p');
  await expect(scope).toContainText('encrypted path reads/writes and their size, order, and timing');
  await expect(scope).toContainText('receives no logical block ID or logical READ/WRITE label');
  await expect(scope).toContainText('does not prove that client timing hides the logical operation');
  await expect(scope).not.toContainText('Nothing else');
});

test('the caveats link from exhibit 1 crosses to the exhibit that holds them', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#ex0')).toBeVisible();
  await expect(page.locator('#ex4')).toBeHidden();

  await page.locator('#ex0CaveatsLink').click();
  await expect(page.locator('#ex4')).toBeVisible();
  await expect(page.locator('#ex0')).toBeHidden();
  await expect(page.locator('#tab4')).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator('#caveats')).toBeVisible();
  await expect(page.locator('[role="tabpanel"]:not([hidden])')).toHaveCount(1);
});

// ---------------------------------------------------------------- exhibit 5

test('the comparison table recomputes real Path and hierarchy traffic', async ({ page }) => {
  await page.goto('.');
  const p = await readParams(page);
  await page.locator('#tab5').click();
  await page.locator('#hierRunBtn').click();
  await expect(page.locator('#hierStatus')).toContainText(
    '8 workload operations measured and 16/16 blocks independently verified',
    READY,
  );

  const expectedOperations = [
    'READ block 3',
    'WRITE block 3',
    'READ block 3',
    'READ block 11',
    'WRITE block 11',
    'READ block 11',
    'READ block 0',
    'READ block 3',
  ];
  const expectedResults = ['(empty)', 'ALPHA', 'ALPHA', '(empty)', 'BETA', 'BETA', '(empty)', 'ALPHA'];
  const rows = page.locator('#hierComparisonBody tr');
  await expect(rows).toHaveCount(expectedOperations.length);

  const pathOneWay = p.Z * (p.L + 1);
  const fixedHierarchyOneWay = Array.from({ length: p.L + 1 }, (_, level) => 1 << level)
    .reduce((sum, slots) => sum + slots, 0);
  for (let index = 0; index < expectedOperations.length; index++) {
    const cells = rows.nth(index).locator('td');
    expect((await cells.nth(1).innerText()).trim()).toBe(expectedOperations[index]);
    expect((await cells.nth(2).innerText()).trim()).toBe(expectedResults[index]);

    const pathText = (await cells.nth(3).innerText()).replace(/\s+/g, ' ');
    const pathMatch = /(\d+) read \+ (\d+) write = (\d+)/.exec(pathText);
    expect(pathMatch, `unparseable Path traffic row ${index + 1}: ${pathText}`).not.toBeNull();
    expect(Number(pathMatch![1])).toBe(pathOneWay);
    expect(Number(pathMatch![2])).toBe(pathOneWay);
    expect(Number(pathMatch![3])).toBe(2 * pathOneWay);

    const lookup = Number((await cells.nth(5).innerText()).trim());
    expect(lookup).toBe(2 * fixedHierarchyOneWay);

    const accessNumber = index + 1;
    let carryLevel = 0;
    let quotient = accessNumber;
    while (quotient % 2 === 0) {
      carryLevel += 1;
      quotient /= 2;
    }
    const expectedLevels = Array.from({ length: carryLevel + 1 }, (_, level) => `L${level}`)
      .join(' → ');
    const expectedRebuildSlots =
      Array.from({ length: carryLevel }, (_, level) => 2 * (4 ** level))
        .reduce((sum, slots) => sum + slots, 0) + 4 ** carryLevel;
    const rebuildText = (await cells.nth(6).innerText()).replace(/\s+/g, ' ').trim();
    expect(rebuildText).toBe(`${expectedLevels} / ${expectedRebuildSlots}`);
    expect(Number((await cells.nth(7).innerText()).trim()))
      .toBe(2 * fixedHierarchyOneWay + expectedRebuildSlots);

    const found = /^L(\d+)$/.exec((await cells.nth(4).innerText()).trim());
    expect(found).not.toBeNull();
    expect(Number(found![1])).toBeGreaterThanOrEqual(0);
    expect(Number(found![1])).toBeLessThanOrEqual(p.L);
  }

  const summary = (await page.locator('#hierSummary').innerText()).replace(/\s+/g, ' ');
  expect(summary).toContain('16/16 blocks');
  expect(summary).toContain(`${p.capacity} server slots`);
  expect(summary).toContain('341 server slots');
  expect(summary).toContain('up to 16 transient rebuild blocks');
});

test('the skipped-probe control returns equal data but exposes the cache hit', async ({ page }) => {
  await page.goto('.');
  await page.locator('#tab5').click();
  await page.locator('#hierLeakBtn').click();
  await expect(page.locator('#hierLeakStatus')).toContainText(
    'fixed 31-slot and skipped 1-slot lookup traces',
    READY,
  );
  const cards = page.locator('#hierLeakResults .card');
  await expect(cards).toHaveCount(2);
  await expect(cards.nth(0)).toContainText('DEPTH-CONTROL');
  await expect(cards.nth(1)).toContainText('DEPTH-CONTROL');
  await expect(cards.nth(0)).toContainText('5 probes and read 31 lookup slots');
  await expect(cards.nth(1)).toContainText('stopped after 1 probe and 1 lookup slot');
  await expect(cards.nth(1)).toContainText('correct plaintext did not imply an oblivious access');
});

test('the hierarchy lesson keeps its finite adaptation and threat-model limits visible', async ({ page }) => {
  await page.goto('.');
  await page.locator('#tab5').click();
  const lesson = page.locator('#ex5');
  await expect(lesson).toContainText('about 21.31N server slots');
  await expect(lesson).toContainText('transient O(N) client memory');
  await expect(lesson).toContainText('not a performance benchmark');
  await expect(lesson).toContainText('not a transferred security proof');
  await expect(lesson).toContainText('does not reproduce Alibi\'s combined-stash attack or repair');
  await expect(lesson).toContainText('informational, not process isolation');
  await expect(lesson).toContainText('does not hide timing or termination');
  await expect(lesson.locator('a[href="https://web.cs.ucla.edu/~rafail/PUBLIC/248.pdf"]')).toHaveCount(1);
  await expect(lesson.locator('a[href="https://arxiv.org/abs/1007.1259"]')).toHaveCount(1);
  await expect(lesson.locator('a[href="https://doi.org/10.1145/233551.233553"]')).toHaveCount(1);
});

// ---------------------------------------------------- exhibit 7: multi-client
//
// Nothing below is asserted against a constant this spec chose. The rights
// table rendered by the page is read off the page and used to predict which
// attempts must be refused; the collusion table's candidate column is checked
// to contain its own "entry actually accessed" column, row by row; and the
// slot arithmetic in the server-view panel is recomputed from the page's own
// event signature.

const HEAVY = { timeout: 180_000 };

async function openMultiClient(page: Page): Promise<void> {
  await page.goto('.');
  await page.locator('#tab6').click();
  await expect(page.locator('#ex6')).toBeVisible();
}

/** The owner's matrix as the page renders it: entry index → right, per client. */
async function renderedRights(page: Page): Promise<Array<Map<number, string>>> {
  const rows = await page.locator('#ex6 table.costs').first().locator('tbody tr').all();
  const perClient: Array<Map<number, string>> = [new Map(), new Map(), new Map()];
  for (const row of rows) {
    const cells = await row.locator('td').allTextContents();
    const range = (cells[0] ?? '').replace(/–/g, '-');
    const [from, to] = range.split('-').map((part) => Number(part.trim()));
    for (let index = from as number; index <= (to as number); index++) {
      for (let client = 0; client < 3; client++) {
        perClient[client]?.set(index, (cells[2 + client] ?? '').trim());
      }
    }
  }
  return perClient;
}

test('every multi-client refusal is the one the rendered rights table predicts', async ({
  page,
}) => {
  const errors = guardPageErrors(page);
  await openMultiClient(page);
  const rights = await renderedRights(page);
  // The matrix really was rendered, for all 16 entries and all three clients.
  for (let client = 0; client < 3; client++) {
    expect(rights[client]?.size, `client ${client} rights`).toBe(16);
  }

  await page.locator('#mcBaselineBtn').click(HEAVY);
  await expect(page.locator('#mcBaselineStatus')).toContainText('released', HEAVY);

  const names = ['Clinician', 'Billing', 'Contractor'];
  const rows = await page.locator('#mcBaselineBody tr').all();
  expect(rows.length).toBeGreaterThanOrEqual(10);
  let refusals = 0;
  for (const row of rows) {
    const cells = (await row.locator('td').allTextContents()).map((cell) => cell.trim());
    const client = names.indexOf(cells[0] ?? '');
    expect(client, `unknown client ${cells[0]}`).toBeGreaterThanOrEqual(0);
    const operation = cells[1];
    const index = Number(cells[2]);
    const renderedRight = cells[3];
    const outcome = cells[4];

    // The right the row reports must be the right the matrix shows.
    expect(renderedRight, `row ${client}/${operation}/${index}`).toBe(
      rights[client]?.get(index),
    );

    // And the outcome must follow from it. A read needs at least `read`; a
    // write needs `read-write`. Anything else must be refused.
    const permitted =
      operation === 'read'
        ? renderedRight === 'read' || renderedRight === 'read-write'
        : renderedRight === 'read-write';
    expect(outcome, `row ${cells[0]} ${operation} ${index} right=${renderedRight}`).toBe(
      permitted ? 'released' : 'refused',
    );
    if (!permitted) {
      refusals += 1;
      // And the reason is a protocol failure, not a flag.
      expect(cells[5]).toMatch(/AccessDeniedError|EntryVerificationError|EnvelopeAuthError/);
    }
  }
  expect(refusals, 'the plan must actually exercise refusals').toBeGreaterThanOrEqual(4);
  expect(errors).toEqual([]);
});

test('the shared-key deployment exposes a clinician entry to the billing client', async ({
  page,
}) => {
  const errors = guardPageErrors(page);
  await openMultiClient(page);
  await page.locator('#mcNaiveBtn').click(HEAVY);
  await expect(page.locator('#mcNaiveStatus')).toContainText('Three outcomes computed', HEAVY);

  const panel = page.locator('#mcNaiveResults');
  const text = (await panel.textContent()) ?? '';
  // The exposed value is one of the clinician's notes, and the entry number in
  // the message is inside the clinician's band rather than billing's.
  const exposure = /entry (\d+) = “clinical-note-(\d+)”/.exec(text);
  expect(exposure, `no exposure reported in: ${text.slice(0, 400)}`).not.toBeNull();
  const entry = Number(exposure?.[1]);
  expect(Number(exposure?.[2])).toBe(entry);
  expect(entry).toBeGreaterThanOrEqual(0);
  expect(entry).toBeLessThanOrEqual(7);

  // A real remap may select the current leaf. The page either reports the
  // observed divergence and both different leaves, or the bounded 32-remap
  // miss without turning it into a lost-update claim.
  const leaves = /records entry \d+ at leaf (\d+) and billing still records leaf (\d+)/.exec(text);
  if (leaves) {
    expect(leaves[1]).not.toBe(leaves[2]);
    const attempts = /Given full but independent copies of the position map, (\d+) genuine write/.exec(
      text,
    );
    expect(Number(attempts?.[1])).toBeGreaterThanOrEqual(1);
    expect(Number(attempts?.[1])).toBeLessThanOrEqual(32);
  } else {
    expect(text).toContain('this bounded run tried 32 genuine writes');
    expect(text).toContain('did not diverge and this run makes no lost-update claim');
  }
  expect(errors).toEqual([]);
});

test('the collusion table’s candidate set always contains the entry it names', async ({ page }) => {
  const errors = guardPageErrors(page);
  await openMultiClient(page);
  await page.locator('#mcCollusionBtn').click(HEAVY);
  await expect(page.locator('#mcCollusionStatus')).toContainText('mean candidate set', HEAVY);

  const rows = await page.locator('#mcCollusionBody tr').all();
  expect(rows.length).toBe(8);
  let narrowed = 0;
  let totalCandidates = 0;
  for (const row of rows) {
    const cells = (await row.locator('td').allTextContents()).map((cell) => cell.trim());
    const candidates = (cells[2] ?? '')
      .replace(/\s*\(\d+ of 16\)\s*$/, '')
      .split(',')
      .map((part) => Number(part.trim()))
      .filter((value) => Number.isInteger(value));
    const actual = Number(cells[3]);
    // Parts sum to whole: the declared size matches the list it describes.
    const declared = /\((\d+) of 16\)/.exec(cells[2] ?? '');
    expect(Number(declared?.[1])).toBe(candidates.length);
    // The load-bearing claim: the true entry is always in the set.
    expect(candidates, `trial row: ${cells.join(' | ')}`).toContain(actual);
    expect(candidates.length).toBeLessThanOrEqual(16);
    totalCandidates += candidates.length;
    if (cells[4] === 'yes') {
      expect(candidates).toEqual([actual]);
      narrowed += 1;
    }
  }
  // The set is a handful, not sixteen.
  expect(totalCandidates / rows.length).toBeLessThanOrEqual(6);
  // And the summary's own count of unique identifications matches the table.
  const summary = (await page.locator('#mcCollusionStatus').textContent()) ?? '';
  const claimed = /narrowed to exactly one (\d+) times/.exec(summary);
  expect(Number(claimed?.[1])).toBe(narrowed);
  expect(errors).toEqual([]);
});

test('the collusion panel states the bound as evidence rather than as a proof', async ({ page }) => {
  await openMultiClient(page);
  await page.locator('#mcCollusionBtn').click(HEAVY);
  await expect(page.locator('#mcCollusionStatus')).toContainText('mean candidate set', HEAVY);
  const note = page.locator('#mcCollusionNote');
  await expect(note).toContainText('evidence consistent with');
  await expect(note).toContainText('not a proof of it');
  await expect(note).toContainText('o(n)');
  await expect(note).toContainText('implements neither');
});

test('every multi-client control behaves as the page says it expects', async ({ page }) => {
  const errors = guardPageErrors(page);
  await openMultiClient(page);
  await page.locator('#mcControlsBtn').click(HEAVY);
  await expect(page.locator('#mcControlsStatus')).toContainText('controls', HEAVY);

  const rows = await page.locator('#mcControlsBody tr').all();
  expect(rows.length).toBe(12);
  for (const row of rows) {
    const cells = (await row.locator('td').allTextContents()).map((cell) => cell.trim());
    expect(cells[3], `control "${cells[0]}" expected ${cells[1]} and observed ${cells[2]}`).toBe(
      'as expected',
    );
  }
  // And the status line agrees with the table rather than contradicting it.
  await expect(page.locator('#mcControlsStatus')).toContainText(
    `All ${rows.length} controls behaved as expected`,
  );

  // The named refusals really are the specified ones.
  const table = page.locator('#mcControlsTable');
  await expect(table).toContainText('EnvelopeAuthError');
  await expect(table).toContainText('EntryVerificationError');
  await expect(table).toContainText('StaleEntryError');
  await expect(table).toContainText('ConcurrencyRefusedError');
  await expect(table).toContainText('AccessDeniedError');
  expect(errors).toEqual([]);
});

test('the server view and the omniscient view are different panels with different content', async ({
  page,
}) => {
  await openMultiClient(page);
  await page.locator('#mcControlsBtn').click(HEAVY);
  await expect(page.locator('#mcControlsStatus')).toContainText('controls', HEAVY);

  const server = (await page.locator('#mcViews .panel-server').textContent()) ?? '';
  const teaching = (await page.locator('#mcViews .panel-client').textContent()) ?? '';

  // The server panel reports a uniform ORAM data shape, while exposing the
  // separate variable log catch-up rather than folding it into that claim.
  expect(server).toMatch(/path:read:\d+/);
  expect(server).toContain('No logical entry index');
  expect(server).toContain('full transcript is not fixed');
  expect(server).toContain('state/recency leakage');
  // Recompute the claimed per-access slot totals from the page's own
  // signature, read out of its own element so no neighbouring sentence can
  // bleed a digit into the last slot count.
  const signature = (await page.locator('#mcSignature').textContent()) ?? '';
  expect(signature).toMatch(/^(?:(?:log|state|path|stash):(?:read|write):\d+\|?)+$/);
  const events = signature.split('|').filter(Boolean);
  let reads = 0;
  let writes = 0;
  for (const event of events) {
    const [, direction, slots] = event.split(':');
    if (direction === 'read') reads += Number(slots);
    else writes += Number(slots);
  }
  const claimed = /(\d+) encrypted data slots in and (\d+) out every time/.exec(server);
  expect(claimed, 'no slot claim on the server panel').not.toBeNull();
  expect(Number(claimed?.[1])).toBe(reads);
  expect(Number(claimed?.[2])).toBe(writes);

  // The teaching panel carries exactly what the server panel must not.
  expect(teaching).toMatch(/(Clinician|Billing|Contractor) (read|write) entry \d+ via leaf \d+/);
  expect(server).not.toMatch(/(Clinician|Billing|Contractor) (read|write) entry \d+ via leaf/);
  expect(teaching).toContain('retracts nothing');
});

test('starting one multi-client scenario retires the others', async ({ page }) => {
  await openMultiClient(page);
  await page.locator('#mcBaselineBtn').click(HEAVY);
  await expect(page.locator('#mcBaselineStatus')).toContainText('released', HEAVY);
  const beforeRows = await page.locator('#mcBaselineBody tr').count();
  expect(beforeRows).toBeGreaterThanOrEqual(10);

  await page.locator('#mcControlsBtn').click(HEAVY);
  await expect(page.locator('#mcControlsStatus')).toContainText('controls', HEAVY);

  // The baseline's numbers are gone, and the panel says why rather than
  // leaving a stale table beside a different run's results.
  await expect(page.locator('#mcBaselineStatus')).toContainText('Retired');
  await expect(page.locator('#mcBaselineBody')).toContainText('Retired');
  await expect(page.locator('#mcBaselineBody tr')).toHaveCount(1);
  await expect(page.locator('#mcBaselineTable')).not.toContainText('AccessDeniedError');
});

test('the multi-client lesson keeps its actors, collusion model and non-claims visible', async ({
  page,
}) => {
  await openMultiClient(page);
  const lesson = page.locator('#ex6');
  // Actors and trust boundaries.
  await expect(lesson).toContainText('Data owner');
  await expect(lesson).toContainText('honest by assumption');
  await expect(lesson).toContainText('No coordinator and no key service');
  // Collusion, all three directions.
  await expect(lesson).toContainText('Client ↔ client');
  await expect(lesson).toContainText('Client ↔ server');
  await expect(lesson).toContainText('Server → client');
  // The properties, separated, including the ones not claimed.
  await expect(lesson).toContainText('Secrecy — claimed');
  await expect(lesson).toContainText('Tamper resistance — claimed');
  await expect(lesson).toContainText('Accountable integrity — claimed');
  await expect(lesson).toContainText('Integrity — NOT claimed');
  await expect(lesson).toContainText('Anonymity — NOT claimed');
  await expect(lesson).toContainText('Concurrency or linearizability — refused outright');
  await expect(lesson).toContainText('Freshness / rollback resistance');
  await expect(lesson).toContainText('A first-contact client cannot detect the same rollback');
  // Adaptations and the module boundary.
  await expect(lesson).toContainText('key-exposure-free');
  await expect(lesson).toContainText('oblivious gossiping protocol');
  await expect(lesson).toContainText('informational');
  await expect(lesson).toContainText('docs/multi-client-design.md');
  // Sources.
  await expect(lesson.locator('a[href="https://eprint.iacr.org/2015/224"]')).toHaveCount(1);
  await expect(lesson.locator('a[href="https://eprint.iacr.org/2017/329"]')).toHaveCount(1);
  await expect(lesson.locator('a[href="https://eprint.iacr.org/2020/1551"]')).toHaveCount(1);
  await expect(lesson.locator('a[href="https://eprint.iacr.org/2016/678"]')).toHaveCount(1);
  await expect(lesson.locator('a[href="https://arxiv.org/abs/1811.04366"]')).toHaveCount(1);
});
