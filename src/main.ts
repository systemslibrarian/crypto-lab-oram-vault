import {
  initializeORAM,
  read,
  write,
  getStashSize,
  getStashHighWater,
  type ORAMClient,
} from './client/oram-client.js';
import {
  getServerStats,
  getServerBuckets,
  getPathBucketIds,
} from './server/oram-server.js';

// ─── ORAM parameters ────────────────────────────────────────────────────────
const N = 16;
const Z = 4;
const L = Math.ceil(Math.log2(N)); // 4
const NUM_BUCKETS = (1 << (L + 1)) - 1; // 31

// ─── App state ───────────────────────────────────────────────────────────────
let client: ORAMClient | null = null;
let initializing = false;
let autoRunInterval: ReturnType<typeof setInterval> | null = null;

interface DisplayAccess {
  index: number;
  serverPaths: number[];
  clientOp: string;
  clientBlock: number;
}
const accessHistory: DisplayAccess[] = [];

// ─── Helpers ─────────────────────────────────────────────────────────────────
function $(id: string): HTMLElement {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Element #${id} not found`);
  return el;
}

function btn(id: string): HTMLButtonElement {
  return $(id) as HTMLButtonElement;
}

function setDisabled(id: string, disabled: boolean): void {
  const el = $(id) as HTMLButtonElement;
  el.disabled = disabled;
  el.setAttribute('aria-disabled', String(disabled));
}

function cryptoRandInt(max: number): number {
  const arr = new Uint32Array(1);
  crypto.getRandomValues(arr);
  return (arr[0] as number) % max;
}

function textToBytes(s: string): Uint8Array {
  const enc = new TextEncoder();
  const bytes = enc.encode(s);
  const padded = new Uint8Array(32);
  padded.set(bytes.slice(0, 32));
  return padded;
}

function bytesToText(b: Uint8Array): string {
  const dec = new TextDecoder();
  const text = dec.decode(b);
  return text.replace(/\0+$/, '') || '(empty)';
}

function stopAutoRun(): void {
  if (autoRunInterval) {
    clearInterval(autoRunInterval);
    autoRunInterval = null;
    btn('autoBtn').textContent = 'Auto-run';
    btn('autoBtn').setAttribute('aria-pressed', 'false');
  }
}

// ─── HTML scaffold ───────────────────────────────────────────────────────────
function buildShell(): void {
  const app = document.getElementById('app')!;
  app.innerHTML = `
<header role="banner">
  <h1><span class="accent">ORAM</span> Vault — <span class="accent2">Path ORAM</span> Demo</h1>
  <button class="theme-toggle" id="themeToggle" aria-label="Toggle light/dark theme">Toggle Theme</button>
</header>
<nav aria-label="Exhibit tabs">
  <div role="tablist" aria-label="Exhibits" id="tablist">
    <button class="nav-tab active" role="tab" aria-selected="true"  aria-controls="ex0" id="tab0" data-tab="0">1 · Access-Pattern Problem</button>
    <button class="nav-tab"        role="tab" aria-selected="false" aria-controls="ex1" id="tab1" data-tab="1">2 · Tree Visualization</button>
    <button class="nav-tab"        role="tab" aria-selected="false" aria-controls="ex2" id="tab2" data-tab="2">3 · Access Walkthrough</button>
    <button class="nav-tab"        role="tab" aria-selected="false" aria-controls="ex3" id="tab3" data-tab="3">4 · Adversary vs. Client</button>
    <button class="nav-tab"        role="tab" aria-selected="false" aria-controls="ex4" id="tab4" data-tab="4">5 · Costs &amp; When to Use</button>
  </div>
</nav>
<main id="main-content">
  ${exhibit0()}
  ${exhibit1()}
  ${exhibit2()}
  ${exhibit3()}
  ${exhibit4()}
</main>
<footer style="margin-top:3rem;padding:2rem 1rem;border-top:1px solid rgba(128,128,128,.25);text-align:center;font-size:.85rem;line-height:1.9;opacity:.85;font-family:ui-monospace,Menlo,Consolas,monospace">
  <div><strong>Related demos:</strong> <a href="https://systemslibrarian.github.io/crypto-lab-oblivious-shelf/" style="color:#35d6bb">oblivious-shelf</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-patron-shield/" style="color:#35d6bb">patron-shield</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-psi-gate/" style="color:#35d6bb">psi-gate</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-silent-tally/" style="color:#35d6bb">silent-tally</a></div>
  <div style="margin-top:.5rem"><a href="https://github.com/systemslibrarian/crypto-lab-oram-vault" style="color:#35d6bb">Source on GitHub</a> &middot; <a href="https://crypto-lab.systemslibrarian.dev/" style="color:#35d6bb">More crypto-lab demos</a></div>
  <div style="margin-top:.75rem;opacity:.75">&ldquo;So whether you eat or drink or whatever you do, do it all for the glory of God.&rdquo; &mdash; 1 Corinthians 10:31</div>
</footer>`;
}

// ─── Exhibit 0 ───────────────────────────────────────────────────────────────
function exhibit0(): string {
  return `
<section class="exhibit active" id="ex0" role="tabpanel" aria-labelledby="tab0" tabindex="0">
  <h2>Why Encryption Alone Isn't Enough</h2>
  <p>Encryption hides the <strong>contents</strong> of your data, but not the <strong>access pattern</strong>.</p>

  <div class="two-col">
    <div class="card panel-server">
      <div class="panel-label server" aria-hidden="true">What the Server Sees (Encrypted Storage)</div>
      <div class="scenario-wrap"><div class="scenario" id="serverAccessLog" aria-label="Server access log showing location reads">Monday    09:00  READ location 42 → [ciphertext A]
Tuesday   09:00  READ location 42 → [ciphertext A]
Wednesday 09:00  READ location 42 → [ciphertext A]
Friday    14:07  READ location  8 → [ciphertext B]
Friday    14:08  READ location 15 → [ciphertext C]
Friday    14:09  READ location 23 → [ciphertext D]</div></div>
    </div>
    <div class="card panel-client">
      <div class="panel-label client" aria-hidden="true">What the Server Infers (Without Decrypting)</div>
      <div class="scenario-wrap"><div class="scenario client-border" aria-label="What the server infers from access patterns">Location 42: accessed every morning at 9am
→ Likely daily medication or health routine

Friday afternoon spike across 3 locations:
→ Sudden frantic reading pattern
→ Probably just received a serious diagnosis

Access frequency → which records matter most
Time-of-day → behavioral schedule
Sudden access clusters → significant life events

The server never decrypted a single byte.
It still built a medical profile.</div></div>
    </div>
  </div>

  <h3>The Threat Model</h3>
  <p>Your cloud provider is <strong>honest-but-curious</strong>: it follows the protocol honestly but logs every access to learn as much as possible. Goldreich and Ostrovsky (1987) proved this can be defeated — with <em>logarithmic overhead</em>.</p>

  <h3>What Path ORAM Fixes</h3>
  <div class="scenario-wrap"><div class="scenario client-border" aria-label="What Path ORAM access patterns look like to the server">With Path ORAM, the server sees:

Access 1: read path  7, write path  7
Access 2: read path 14, write path 14
Access 3: read path  2, write path  2
Access 4: read path 11, write path 11
Access 5: read path  7, write path  7

Paths are uniformly random. No correlation.
Even accessing the same block 1000 times —
the server sees 1000 independent random paths.
Zero mutual information about your access pattern.</div></div>

  <p><strong>This is provable.</strong> The re-randomization of the position map on every access is the key insight. The Goldreich–Ostrovsky (1996) theorem gives the lower bound; Path ORAM achieves it with a concrete, simple construction.</p>
</section>`;
}

// ─── Exhibit 1 — Tree Visualization ─────────────────────────────────────────
function exhibit1(): string {
  return `
<section class="exhibit" id="ex1" role="tabpanel" aria-labelledby="tab1" tabindex="0" hidden>
  <h2>Path ORAM Tree Visualization</h2>
  <p>N=${N} blocks · Z=${Z} bucket size · L=${L} levels · ${NUM_BUCKETS} total buckets · ${Z * NUM_BUCKETS} block capacity</p>

  <div class="btn-row">
    <button class="btn primary" id="initBtn">Initialize ORAM (${N} blocks)</button>
    <button class="btn" id="stepBtn" disabled aria-disabled="true">Step Random Access</button>
    <button class="btn" id="autoBtn" disabled aria-disabled="true" aria-pressed="false">Auto-run</button>
    <button class="btn" id="serverViewBtn" disabled aria-disabled="true" aria-pressed="false">Toggle Server View</button>
  </div>

  <div class="input-row" aria-label="Read or write a specific block">
    <label for="blockIdInput">Block</label>
    <input type="number" id="blockIdInput" min="0" max="${N - 1}" value="5"
           inputmode="numeric" aria-label="Block ID (0 to ${N - 1})" />
    <label for="blockValueInput">Value</label>
    <input type="text" id="blockValueInput" maxlength="32" value="SECRET"
           aria-label="Value to write (up to 32 characters)" />
    <button class="btn accent" id="writeBlockBtn" disabled aria-disabled="true">Write</button>
    <button class="btn" id="readBlockBtn" disabled aria-disabled="true">Read</button>
  </div>

  <div role="status" aria-live="polite" class="status-bar" id="treeStatus">Click "Initialize ORAM" to begin.</div>

  <div class="stats-row" id="treeStats" aria-live="polite"></div>

  <div class="two-col">
    <div class="card panel-server">
      <div class="panel-label server" id="serverTreeLabel">Server View (untrusted cloud)</div>
      <p style="font-size:0.8rem">All blocks look identical — encrypted blobs only. No block IDs visible.</p>
      <div class="tree-container" id="serverTree" aria-labelledby="serverTreeLabel" role="img" aria-label="Binary tree showing server view with opaque encrypted blocks"></div>
    </div>
    <div class="card panel-client">
      <div class="panel-label client" id="clientTreeLabel">Client View (trusted)</div>
      <p style="font-size:0.8rem">Position map and stash visible. Real block IDs shown.</p>
      <div class="tree-container" id="clientTree" aria-labelledby="clientTreeLabel" role="img" aria-label="Binary tree showing client view with block IDs"></div>
    </div>
  </div>

  <h3>Client Stash</h3>
  <div class="card panel-client">
    <div class="panel-label client">Stash (client-local only, never sent to server)</div>
    <div class="stash-grid" id="stashDisplay" aria-live="polite" aria-label="Current stash contents"></div>
  </div>
</section>`;
}

// ─── Exhibit 2 — Access Walkthrough ─────────────────────────────────────────
function exhibit2(): string {
  return `
<section class="exhibit" id="ex2" role="tabpanel" aria-labelledby="tab2" tabindex="0" hidden>
  <h2>Access Walkthrough</h2>
  <p>Seven-step trace of a single READ or WRITE. Initialize first, then choose an operation.</p>

  <div class="btn-row">
    <button class="btn primary" id="walkInitBtn">Initialize ORAM</button>
    <button class="btn accent" id="walkReadBtn" disabled aria-disabled="true">READ block 5</button>
    <button class="btn" id="walkWriteBtn" disabled aria-disabled="true">WRITE block 5 = "HELLO, PATH ORAM!"</button>
    <button class="btn" id="walkNextBtn" disabled aria-disabled="true">Next Step ▶</button>
  </div>

  <div role="status" aria-live="polite" class="status-bar" id="walkStatus">Initialize ORAM to begin walkthrough.</div>

  <div class="two-col">
    <div>
      <h3>Steps</h3>
      <ol class="step-list" id="walkSteps" aria-label="ORAM access steps">
        <li class="step-item" data-step="0"><div class="step-num" aria-hidden="true">1</div><div class="step-body"><div class="step-title">Look up position map</div><div class="step-detail" id="stepDetail0">position[5] = ?</div></div></li>
        <li class="step-item" data-step="1"><div class="step-num" aria-hidden="true">2</div><div class="step-body"><div class="step-title">Remap to fresh leaf</div><div class="step-detail" id="stepDetail1">position[5] ← new random leaf</div></div></li>
        <li class="step-item" data-step="2"><div class="step-num" aria-hidden="true">3</div><div class="step-body"><div class="step-title">Read path P(x) from server</div><div class="step-detail" id="stepDetail2">Server receives: leafId (path index only)</div></div></li>
        <li class="step-item" data-step="3"><div class="step-num" aria-hidden="true">4</div><div class="step-body"><div class="step-title">Decrypt blocks → stash</div><div class="step-detail" id="stepDetail3">Client decrypts all blocks on path</div></div></li>
        <li class="step-item" data-step="4"><div class="step-num" aria-hidden="true">5</div><div class="step-body"><div class="step-title">Apply READ/WRITE</div><div class="step-detail" id="stepDetail4">Extract or update data in stash</div></div></li>
        <li class="step-item" data-step="5"><div class="step-num" aria-hidden="true">6</div><div class="step-body"><div class="step-title">Greedy eviction → write back</div><div class="step-detail" id="stepDetail5">Pack stash blocks back into path buckets</div></div></li>
        <li class="step-item" data-step="6"><div class="step-num" aria-hidden="true">7</div><div class="step-body"><div class="step-title">Return result</div><div class="step-detail" id="stepDetail6">Block data returned to user</div></div></li>
      </ol>
    </div>
    <div>
      <h3>Server Communication Log</h3>
      <div class="card panel-server" id="walkServerLog" aria-labelledby="walkServerLogLabel">
        <div class="panel-label server" id="walkServerLogLabel">What Server Sees</div>
        <div id="walkServerLogLines"
             role="log"
             aria-live="polite"
             aria-label="Server communication log"
             style="font-family:var(--mono);font-size:0.8rem;color:var(--server);min-height:10rem;white-space:pre-wrap;word-break:break-word;">(no accesses yet)</div>
      </div>
    </div>
  </div>
</section>`;
}

// ─── Exhibit 3 — Adversary vs. Client ────────────────────────────────────────
function exhibit3(): string {
  return `
<section class="exhibit" id="ex3" role="tabpanel" aria-labelledby="tab3" tabindex="0" hidden>
  <h2>Adversary's View vs. Client's View</h2>
  <p>Run many accesses and compare what the server observes against what actually happened.</p>

  <div class="btn-row">
    <button class="btn primary" id="advInitBtn">Initialize ORAM</button>
    <button class="btn accent" id="advRunBtn" disabled aria-disabled="true">Run 20 Random Accesses</button>
    <button class="btn" id="advClearBtn" disabled aria-disabled="true">Clear Log</button>
  </div>

  <div role="status" aria-live="polite" class="status-bar" id="advStatus">Initialize to begin.</div>

  <div class="two-col">
    <div class="card panel-server">
      <div class="panel-label server" id="advServerLabel">Adversary View (cloud server)</div>
      <p style="font-size:0.8rem">Server sees: path indices. Nothing else.</p>
      <div class="access-log" id="advServerLog" role="log" aria-labelledby="advServerLabel" aria-live="polite"></div>
    </div>
    <div class="card panel-client">
      <div class="panel-label client" id="advClientLabel">Actual Client Operations</div>
      <p style="font-size:0.8rem">Client perspective: actual block IDs and operations.</p>
      <div class="access-log" id="advClientLog" role="log" aria-labelledby="advClientLabel" aria-live="polite"></div>
    </div>
  </div>

  <h3>Statistical Analysis</h3>
  <div class="card" id="advAnalysis" aria-live="polite">
    <p style="color:var(--text2)">After running accesses, path distribution statistics will appear here.</p>
  </div>
</section>`;
}

// ─── Exhibit 4 — Costs ───────────────────────────────────────────────────────
function exhibit4(): string {
  return `
<section class="exhibit" id="ex4" role="tabpanel" aria-labelledby="tab4" tabindex="0" hidden>
  <h2>Costs and When ORAM Is Worth It</h2>
  <p>Path ORAM trades bandwidth and computation for perfect access-pattern privacy.</p>

  <div class="costs-wrap">
    <table class="costs">
      <thead>
        <tr>
          <th scope="col">Metric</th>
          <th scope="col">Plain Encrypted Storage</th>
          <th scope="col">Path ORAM</th>
        </tr>
      </thead>
      <tbody>
        <tr><td>Per-access reads</td><td>1 block</td><td>Z·(L+1) = ${Z*(L+1)} blocks</td></tr>
        <tr><td>Per-access writes</td><td>1 block</td><td>Z·(L+1) = ${Z*(L+1)} blocks</td></tr>
        <tr><td>Bandwidth overhead</td><td>1×</td><td>~${2*Z*(L+1)}× per access</td></tr>
        <tr><td>Client storage</td><td>O(1)</td><td>O(log N) stash + O(N) position map</td></tr>
        <tr><td>Server storage</td><td>O(N)</td><td>O(N log N) with bucket padding</td></tr>
        <tr><td>Access pattern leakage</td><td style="color:var(--server)">Full leakage</td><td style="color:var(--stash)">None (provably)</td></tr>
        <tr><td>Implementation complexity</td><td>Trivial</td><td>Moderate (16-line pseudocode)</td></tr>
      </tbody>
    </table>
  </div>

  <div class="two-col">
    <div class="card">
      <div class="panel-label" style="color:var(--stash)">✓ When to Use ORAM</div>
      <div class="scenario-wrap"><div class="scenario client-border" style="font-size:0.82rem" aria-label="When to use ORAM">✓ Adversary actively observing access patterns
✓ Access-pattern leakage is security-critical
✓ Latency-tolerant workloads (not real-time)
✓ Small-medium datasets (not billions of blocks)
✓ Healthcare records — pattern reveals diagnosis
✓ Intel SGX secure enclaves (Ascend, Maas FPGA)
✓ Privacy-preserving cloud database queries
✓ Secure cryptocurrency wallets
✓ Secure messaging with envelope privacy</div></div>
    </div>
    <div class="card">
      <div class="panel-label" style="color:var(--server)">✗ When NOT to Use ORAM</div>
      <div class="scenario-wrap"><div class="scenario" style="font-size:0.82rem" aria-label="When not to use ORAM">✗ Real-time / low-latency workloads
✗ Large databases (billions of blocks)
✗ High-throughput / bulk processing
✗ Access patterns already public
✗ When TEE (SGX, SEV-SNP) is available
  → No algorithmic overhead, hardware trust

Alternatives:
  PIR (Private Information Retrieval)
  → Lower client storage, higher server CPU
  → See crypto-lab-oblivious-shelf

  Differential Privacy
  → Statistical privacy, not cryptographic
  → See crypto-lab-patron-shield</div></div>
    </div>
  </div>

  <h3>Real-World Deployments</h3>
  <p>Path ORAM is used in: <strong>Intel SGX Ascend</strong>, <strong>Maas FPGA ORAMs</strong>, <strong>ZeroTrace</strong>, <strong>Obliviate</strong>, <strong>Obladi</strong> (oblivious OLTP databases). The 16-line pseudocode makes it the simplest practical ORAM construction.</p>

  <h3>Related Labs</h3>
  <nav aria-label="Related crypto labs">
    <div class="crosslinks">
      <a class="crosslink" href="../crypto-lab-blind-oracle/">crypto-lab-blind-oracle — FHE oblivious computation</a>
      <a class="crosslink" href="../crypto-lab-oblivious-shelf/">crypto-lab-oblivious-shelf — PIR (2-server)</a>
      <a class="crosslink" href="../crypto-lab-patron-shield/">crypto-lab-patron-shield — Differential privacy</a>
      <a class="crosslink" href="../crypto-lab-ot-gate/">crypto-lab-ot-gate — Oblivious transfer</a>
      <a class="crosslink" href="../crypto-lab-psi-gate/">crypto-lab-psi-gate — Private set intersection</a>
    </div>
  </nav>

  <h3>Security Caveats</h3>
  <div class="scenario-wrap"><div class="scenario" style="font-size:0.8rem" aria-label="Security caveats and limitations">⚠ Stash overflow: O(log N) whp, not zero. Real deployments use recursive ORAM + larger Z.
⚠ Timing attacks: browser operations are not constant-time. Production runs in constant-time hardware.
⚠ Position map is O(N): for large N, store position map in another ORAM (recursive construction).
⚠ Web Worker boundary is informational, not cryptographic (educational demo only).
⚠ Semi-honest security only: active adversary can corrupt server; Ring ORAM adds MACs/version counters.
⚠ Side-channels: cache timing, GC pauses can leak info. Out of scope for this demo.</div></div>
</section>`;
}

// ─── SVG Tree Renderer ────────────────────────────────────────────────────────
interface TreeRenderOpts {
  showBlockIds: boolean;
  highlightPath: number | null;
}

function renderTree(containerId: string, opts: TreeRenderOpts): void {
  const container = document.getElementById(containerId);
  if (!container) return;

  const buckets = getServerBuckets();
  const pathIds =
    opts.highlightPath !== null
      ? new Set(getPathBucketIds(opts.highlightPath))
      : new Set<number>();

  const LEVELS = L + 1;
  const BUCKET_W = 36;
  const BUCKET_H = 24;
  const SLOT_W = 7;
  const SLOT_H = 10;
  const SLOT_GAP = 1;
  const H_GAP = 8;
  const V_GAP = 28;
  const PAD = 12;

  const numLeaves = 1 << L;
  const leafLevelW = numLeaves * (BUCKET_W + H_GAP) - H_GAP;
  const svgW = leafLevelW + PAD * 2;
  const svgH = LEVELS * (BUCKET_H + V_GAP) + PAD * 2;

  let svgContent = '';

  for (let level = 0; level < LEVELS; level++) {
    const nodesAtLevel = 1 << level;
    const levelStartIdx = nodesAtLevel - 1;
    const levelW = nodesAtLevel * (BUCKET_W + H_GAP) - H_GAP;
    const levelXOffset = (svgW - levelW) / 2;
    const y = PAD + level * (BUCKET_H + V_GAP);

    for (let i = 0; i < nodesAtLevel; i++) {
      const bucketIdx = levelStartIdx + i;
      const x = levelXOffset + i * (BUCKET_W + H_GAP);
      const onPath = pathIds.has(bucketIdx);

      // Draw edge to parent
      if (level > 0) {
        const parentLevel = level - 1;
        const parentNodesAtLevel = 1 << parentLevel;
        const parentI = Math.floor(i / 2);
        const parentLevelW = parentNodesAtLevel * (BUCKET_W + H_GAP) - H_GAP;
        const parentXOffset = (svgW - parentLevelW) / 2;
        const px = parentXOffset + parentI * (BUCKET_W + H_GAP) + BUCKET_W / 2;
        const py = PAD + parentLevel * (BUCKET_H + V_GAP) + BUCKET_H;
        const cx = x + BUCKET_W / 2;
        const cy = y;
        svgContent += `<line x1="${px}" y1="${py}" x2="${cx}" y2="${cy}" stroke="${onPath ? 'var(--gold)' : 'var(--border)'}" stroke-width="${onPath ? 1.5 : 1}" opacity="0.6"/>`;
      }

      // Bucket rect
      svgContent += `<rect class="bucket-rect${onPath ? ' on-path' : ''}" x="${x}" y="${y}" width="${BUCKET_W}" height="${BUCKET_H}" rx="4" ry="4"/>`;

      // Block slots
      const bucket = buckets[bucketIdx];
      const blocks = bucket?.blocks ?? [];
      for (let s = 0; s < Z; s++) {
        const sx = x + 2 + s * (SLOT_W + SLOT_GAP);
        const sy = y + (BUCKET_H - SLOT_H) / 2;
        const hasBlock = s < blocks.length;
        let slotClass: string;

        if (hasBlock && opts.showBlockIds) {
          slotClass = 'block-slot block-real';
        } else if (hasBlock) {
          slotClass = 'block-slot block-dummy-server';
        } else {
          slotClass = 'block-slot block-dummy';
        }

        svgContent += `<rect class="${slotClass}" x="${sx}" y="${sy}" width="${SLOT_W}" height="${SLOT_H}" rx="1"/>`;
      }

      // Bucket label
      svgContent += `<text class="bucket-label" x="${x + BUCKET_W / 2}" y="${y + BUCKET_H + 9}" text-anchor="middle">B${bucketIdx}</text>`;
    }
  }

  container.innerHTML = `<div class="tree-svg-wrap"><svg class="oram-tree" viewBox="0 0 ${svgW} ${svgH}" xmlns="http://www.w3.org/2000/svg" aria-hidden="true" focusable="false">${svgContent}</svg></div>`;
}

function renderStash(containerId: string): void {
  if (!client) return;
  const el = document.getElementById(containerId);
  if (!el) return;
  if (client.stash.size === 0) {
    el.innerHTML = '<span style="color:var(--text2);font-size:0.8rem">(empty)</span>';
    return;
  }
  const items: string[] = [];
  for (const [bid, data] of client.stash) {
    const txt = bytesToText(data).substring(0, 12);
    items.push(`<div class="stash-block">B${bid}: ${txt}</div>`);
  }
  el.innerHTML = items.join('');
}

function updateTreeStats(containerId: string): void {
  if (!client) return;
  const stats = getServerStats();
  const el = document.getElementById(containerId);
  if (!el) return;
  const peak = getStashHighWater(client);
  // A generous, human-readable yardstick for the O(log N) stash guarantee.
  // Z·(L+1) is the size of one full path — if the stash never approaches it,
  // the bound is visibly holding.
  const bound = Z * (L + 1);
  const withinBound = peak <= bound;
  el.innerHTML = `
    <div class="stat"><span class="stat-label">Server Reads</span><span class="stat-value server-color">${stats.totalReads}</span></div>
    <div class="stat"><span class="stat-label">Server Writes</span><span class="stat-value server-color">${stats.totalWrites}</span></div>
    <div class="stat"><span class="stat-label">Stash Size</span><span class="stat-value stash-color">${getStashSize(client)}</span></div>
    <div class="stat"><span class="stat-label">Stash Peak</span><span class="stat-value ${withinBound ? 'stash-color' : 'server-color'}" title="Highest stash occupancy seen this session. Path ORAM keeps this O(log N) whp.">${peak} / ${bound} ${withinBound ? '✓' : '⚠'}</span></div>
    <div class="stat"><span class="stat-label">Tree Height L</span><span class="stat-value">${L}</span></div>
    <div class="stat"><span class="stat-label">Blocks N</span><span class="stat-value">${N}</span></div>
  `;
}

// ─── Exhibit 1 logic ─────────────────────────────────────────────────────────
let serverViewMode = false;
let lastAccessedLeaf: number | null = null;

async function initTree(): Promise<void> {
  if (initializing) return;
  initializing = true;
  stopAutoRun();
  setDisabled('initBtn', true);
  $('treeStatus').textContent = 'Initializing ORAM — please wait…';
  try {
    client = await initializeORAM(N, Z);
    $('treeStatus').textContent = `Initialized: ${N} blocks distributed across ${NUM_BUCKETS} buckets.`;
    setDisabled('stepBtn', false);
    setDisabled('autoBtn', false);
    setDisabled('serverViewBtn', false);
    setDisabled('readBlockBtn', false);
    setDisabled('writeBlockBtn', false);
    renderBothTrees(null);
    updateTreeStats('treeStats');
    renderStash('stashDisplay');
  } catch (e) {
    $('treeStatus').textContent = `Error: ${e}`;
  } finally {
    initializing = false;
    setDisabled('initBtn', false);
  }
}

function renderBothTrees(highlightLeaf: number | null): void {
  renderTree('serverTree', { showBlockIds: false, highlightPath: highlightLeaf });
  renderTree('clientTree', { showBlockIds: !serverViewMode, highlightPath: highlightLeaf });
}

async function stepRandomAccess(): Promise<void> {
  if (!client) return;
  const blockId = cryptoRandInt(N);
  $('treeStatus').textContent = `Accessing block ${blockId}…`;
  const oldLeaf = client.positionMap.get(blockId) ?? 0;
  await read(client, blockId);
  lastAccessedLeaf = oldLeaf;
  const newLeaf = client.positionMap.get(blockId) ?? 0;
  $('treeStatus').textContent = `READ(block ${blockId}): path P(${oldLeaf}) → remapped to leaf ${newLeaf}. Stash: ${getStashSize(client)}.`;
  renderBothTrees(oldLeaf);
  updateTreeStats('treeStats');
  renderStash('stashDisplay');
}

/** Validate the block-id input against [0, N). Returns null if invalid. */
function readBlockIdInput(): number | null {
  const raw = ($('blockIdInput') as HTMLInputElement).value.trim();
  const id = Number(raw);
  if (!Number.isInteger(id) || id < 0 || id >= N) return null;
  return id;
}

async function writeCustomBlock(): Promise<void> {
  if (!client) return;
  stopAutoRun();
  const blockId = readBlockIdInput();
  if (blockId === null) {
    $('treeStatus').textContent = `Invalid block ID — enter an integer in [0, ${N - 1}].`;
    return;
  }
  const value = ($('blockValueInput') as HTMLInputElement).value;
  const oldLeaf = client.positionMap.get(blockId) ?? 0;
  await write(client, blockId, textToBytes(value));
  const newLeaf = client.positionMap.get(blockId) ?? 0;
  $('treeStatus').textContent = `WRITE(block ${blockId} = "${value || '(empty)'}"): path P(${oldLeaf}) → remapped to leaf ${newLeaf}. Stash: ${getStashSize(client)}.`;
  renderBothTrees(oldLeaf);
  updateTreeStats('treeStats');
  renderStash('stashDisplay');
}

async function readCustomBlock(): Promise<void> {
  if (!client) return;
  stopAutoRun();
  const blockId = readBlockIdInput();
  if (blockId === null) {
    $('treeStatus').textContent = `Invalid block ID — enter an integer in [0, ${N - 1}].`;
    return;
  }
  const oldLeaf = client.positionMap.get(blockId) ?? 0;
  const data = await read(client, blockId);
  const newLeaf = client.positionMap.get(blockId) ?? 0;
  $('treeStatus').textContent = `READ(block ${blockId}) = "${bytesToText(data)}": path P(${oldLeaf}) → remapped to leaf ${newLeaf}. Stash: ${getStashSize(client)}.`;
  renderBothTrees(oldLeaf);
  updateTreeStats('treeStats');
  renderStash('stashDisplay');
}

// ─── Exhibit 2 walkthrough ───────────────────────────────────────────────────
let walkClient: ORAMClient | null = null;
let walkStep = -1;
let walkOp: 'read' | 'write' | null = null;
let walkOldLeaf = -1;

async function initWalk(): Promise<void> {
  $('walkStatus').textContent = 'Initializing…';
  try {
    walkClient = await initializeORAM(N, Z);
    const hello = textToBytes('HELLO, PATH ORAM!');
    await write(walkClient, 5, hello);
    $('walkStatus').textContent = 'Ready. Block 5 = "HELLO, PATH ORAM!". Pick READ or WRITE to start.';
    setDisabled('walkReadBtn', false);
    setDisabled('walkWriteBtn', false);
    setDisabled('walkNextBtn', true);
    walkStep = -1;
    resetWalkSteps();
    $('walkServerLogLines').textContent = '(no accesses yet)';
  } catch (e) {
    $('walkStatus').textContent = `Error: ${e}`;
  }
}

function resetWalkSteps(): void {
  document.querySelectorAll('.step-item').forEach((el) => {
    el.classList.remove('active', 'done');
  });
}

function activateStep(n: number): void {
  document.querySelectorAll('.step-item').forEach((el, i) => {
    el.classList.remove('active', 'done');
    if (i < n) el.classList.add('done');
    if (i === n) el.classList.add('active');
  });
}

async function startWalkThrough(op: 'read' | 'write'): Promise<void> {
  if (!walkClient) return;
  walkOp = op;
  walkStep = 0;
  setDisabled('walkNextBtn', false);

  walkOldLeaf = walkClient.positionMap.get(5) ?? 0;

  resetWalkSteps();
  activateStep(0);

  $('stepDetail0').textContent = `position[5] = leaf ${walkOldLeaf}`;
  $('stepDetail1').textContent = 'position[5] ← (will be assigned when access runs)';
  $('stepDetail2').textContent = `Will read path P(${walkOldLeaf}) — ${L+1} buckets: ${getPathBucketIds(walkOldLeaf).join(', ')}`;
  $('stepDetail3').textContent = 'Decrypting…';
  $('stepDetail4').textContent = op === 'read' ? 'READ: extract block 5 from stash' : 'WRITE: update block 5 in stash';
  $('stepDetail5').textContent = 'Greedy eviction: place stash blocks back into path buckets';
  $('stepDetail6').textContent = 'Waiting…';

  $('walkStatus').textContent = 'Step 1/7: Looking up position map for block 5.';
  appendWalkLog(`[Step 1] Client: position[5] = leaf ${walkOldLeaf} (private)`);
}

function appendWalkLog(line: string): void {
  const el = $('walkServerLogLines');
  if (el.textContent === '(no accesses yet)') el.textContent = '';
  el.textContent += line + '\n';
}

async function advanceWalkStep(): Promise<void> {
  if (!walkClient || walkOp === null) return;
  walkStep++;

  switch (walkStep) {
    case 1: {
      activateStep(1);
      $('stepDetail1').textContent = `position[5] ← uniform random leaf in [0, ${(1 << L) - 1}] (assigned during access)`;
      appendWalkLog(`[Step 2] Client: position[5] will be remapped to fresh uniform random leaf (private)`);
      $('walkStatus').textContent = 'Step 2/7: Position will be remapped before path is read.';
      break;
    }
    case 2: {
      const pathIds = getPathBucketIds(walkOldLeaf);
      activateStep(2);
      $('stepDetail2').textContent = `Read path P(${walkOldLeaf}) → buckets [${pathIds.join(', ')}]`;
      appendWalkLog(`[Step 3] Server sees: READ path leafId=${walkOldLeaf} (${L+1} buckets × ${Z} slots = ${(L+1)*Z} encrypted blobs)`);
      appendWalkLog(`         Server does NOT see: block ID 5, purpose of access`);
      $('walkStatus').textContent = `Step 3/7: Server transmits ${(L+1)*Z} encrypted blobs.`;
      break;
    }
    case 3: {
      activateStep(3);
      $('stepDetail3').textContent = `Decrypted ${(L+1)*Z} blobs. Real blocks added to stash.`;
      appendWalkLog(`[Step 4] Client: decrypt all ${(L+1)*Z} blocks. Real blocks → stash. Dummies discarded.`);
      $('walkStatus').textContent = 'Step 4/7: Decrypting path blocks, adding real blocks to stash.';
      break;
    }
    case 4: {
      activateStep(4);
      if (walkOp === 'read') {
        $('stepDetail4').textContent = 'READ: stash[5] = data to be returned';
      } else {
        $('stepDetail4').textContent = 'WRITE: stash[5] ← "HELLO, PATH ORAM!"';
      }
      appendWalkLog(`[Step 5] Client: ${walkOp.toUpperCase()} block 5 in stash (server never sees this)`);
      $('walkStatus').textContent = `Step 5/7: ${walkOp === 'read' ? 'Reading' : 'Writing'} block 5 in local stash.`;
      break;
    }
    case 5: {
      activateStep(5);
      $('stepDetail5').textContent = `Evicting stash → path P(${walkOldLeaf}): ${L+1} buckets with fresh nonces`;
      appendWalkLog(`[Step 6] Server sees: WRITE path leafId=${walkOldLeaf} (${(L+1)*Z} freshly encrypted blobs)`);
      appendWalkLog(`         Server cannot link blobs to pre-access blobs (fresh nonces)`);
      $('walkStatus').textContent = 'Step 6/7: Writing back path with greedy eviction and fresh encryption.';
      break;
    }
    case 6: {
      // Run the actual ORAM access now
      try {
        let resultData: Uint8Array;
        if (walkOp === 'read') {
          resultData = await read(walkClient, 5);
        } else {
          const hello = textToBytes('HELLO, PATH ORAM!');
          await write(walkClient, 5, hello);
          resultData = hello;
        }
        // Now we know the actual new leaf
        const actualNewLeaf = walkClient.positionMap.get(5) ?? -1;
        $('stepDetail1').textContent = `position[5] ← leaf ${actualNewLeaf} (actual new mapping)`;

        activateStep(6);
        const displayData = bytesToText(resultData);
        $('stepDetail6').textContent =
          walkOp === 'read' ? `Returned: "${displayData}"` : 'Written successfully.';
        appendWalkLog(`[Step 7] Client: return result to user. New position[5] = leaf ${actualNewLeaf}`);
        $('walkStatus').textContent = `Complete! ${walkOp === 'read' ? `Block 5 = "${displayData}"` : 'Block 5 written.'} Block 5 now lives on path to leaf ${actualNewLeaf}.`;
        setDisabled('walkNextBtn', true);
      } catch (e) {
        $('walkStatus').textContent = `Error: ${e}`;
      }
      break;
    }
    default:
      break;
  }
}

// ─── Exhibit 3 — Adversary ───────────────────────────────────────────────────
let advClient: ORAMClient | null = null;

async function initAdv(): Promise<void> {
  $('advStatus').textContent = 'Initializing…';
  try {
    advClient = await initializeORAM(N, Z);
    $('advStatus').textContent = 'Initialized. Click "Run 20 Random Accesses".';
    setDisabled('advRunBtn', false);
    setDisabled('advClearBtn', false);
    $('advServerLog').innerHTML = '';
    $('advClientLog').innerHTML = '';
    accessHistory.length = 0;
  } catch (e) {
    $('advStatus').textContent = `Error: ${e}`;
  }
}

async function runAdvAccesses(): Promise<void> {
  if (!advClient) return;
  setDisabled('advRunBtn', true);
  $('advStatus').textContent = 'Running 20 accesses…';

  for (let i = 0; i < 20; i++) {
    const blockId = cryptoRandInt(N);
    const oldLeaf = advClient.positionMap.get(blockId) ?? 0;
    const op = cryptoRandInt(2) === 0 ? 'read' : 'write';

    if (op === 'read') {
      await read(advClient, blockId);
    } else {
      const data = new Uint8Array(32);
      crypto.getRandomValues(data);
      await write(advClient, blockId, data);
    }

    const newLeaf = advClient.positionMap.get(blockId) ?? 0;
    accessHistory.push({
      index: accessHistory.length + 1,
      serverPaths: [oldLeaf],
      clientOp: op,
      clientBlock: blockId,
    });

    const serverLog = $('advServerLog');
    serverLog.innerHTML += `<div class="access-row"><span class="acc-num">${accessHistory.length}</span><span class="acc-server">path ${oldLeaf} (read+write)</span><span class="acc-client" style="display:none">hidden</span></div>`;
    const clientLog = $('advClientLog');
    clientLog.innerHTML += `<div class="access-row"><span class="acc-num">${accessHistory.length}</span><span class="acc-client">${op.toUpperCase()}(block ${blockId})</span><span style="color:var(--text2);font-size:0.75rem">→ leaf ${newLeaf}</span></div>`;

    serverLog.scrollTop = serverLog.scrollHeight;
    clientLog.scrollTop = clientLog.scrollHeight;
  }

  // Statistical analysis
  const pathCounts = new Map<number, number>();
  for (const acc of accessHistory) {
    const p = acc.serverPaths[0] ?? 0;
    pathCounts.set(p, (pathCounts.get(p) ?? 0) + 1);
  }
  const numLeaves = 1 << L;
  const maxCount = Math.max(...Array.from(pathCounts.values()), 1);
  const BAR_MAX = 20;
  const distStr = Array.from({ length: numLeaves }, (_, i) => {
    const c = pathCounts.get(i) ?? 0;
    const barLen = Math.round((c / maxCount) * BAR_MAX);
    return `leaf ${String(i).padStart(2)}: ${'█'.repeat(barLen)}${'░'.repeat(BAR_MAX - barLen)} ${c}`;
  }).join('\n');

  // Pearson chi-square goodness-of-fit against the uniform distribution.
  // df = numLeaves − 1 = 15; the χ² approximation needs expected ≥ 5 per cell.
  const expectedPerLeaf = accessHistory.length / numLeaves;
  let chiSq = 0;
  for (let i = 0; i < numLeaves; i++) {
    const o = pathCounts.get(i) ?? 0;
    chiSq += (o - expectedPerLeaf) ** 2 / expectedPerLeaf;
  }
  const CRIT_05 = 24.996; // χ² critical value, df=15, α=0.05
  const enoughData = expectedPerLeaf >= 5;
  const verdict = !enoughData
    ? `need ≥5 expected/leaf for a valid test — run ${Math.ceil(5 * numLeaves)}+ accesses total`
    : chiSq <= CRIT_05
      ? 'consistent with uniform — fail to reject H₀ at α=0.05 ✓'
      : 'this sample deviates (expected ~5% of the time under H₀) — keep running';

  $('advAnalysis').innerHTML = `
    <div class="panel-label server">Server Path Distribution — ${accessHistory.length} accesses</div>
    <div class="scenario-wrap"><div class="scenario" aria-label="Path access distribution statistics">${distStr}

Expected: ~${expectedPerLeaf.toFixed(1)} per leaf (uniform target)
χ² goodness-of-fit vs. uniform: ${chiSq.toFixed(2)}  (df=15, critical=${CRIT_05} at α=0.05)
Verdict: ${verdict}

Each bar shows relative frequency. With more accesses, bars converge.
The adversary sees a uniform stream — cannot detect repeated block access.</div></div>`;

  $('advStatus').textContent = `Done. ${accessHistory.length} total accesses. Distribution looks uniform.`;
  setDisabled('advRunBtn', false);
}

// ─── Tab Navigation (ARIA + keyboard) ────────────────────────────────────────
function setupTabs(): void {
  const tablist = document.getElementById('tablist')!;
  const tabs = Array.from(tablist.querySelectorAll<HTMLButtonElement>('[role="tab"]'));
  const panels = Array.from(document.querySelectorAll<HTMLElement>('[role="tabpanel"]'));

  function activateTab(idx: number): void {
    // Stop auto-run when leaving exhibit 1
    if (idx !== 1) stopAutoRun();

    tabs.forEach((t, i) => {
      const active = i === idx;
      t.classList.toggle('active', active);
      t.setAttribute('aria-selected', String(active));
      t.setAttribute('tabindex', active ? '0' : '-1');
    });
    panels.forEach((p, i) => {
      const active = i === idx;
      p.classList.toggle('active', active);
      if (active) {
        p.removeAttribute('hidden');
      } else {
        p.setAttribute('hidden', '');
      }
    });
  }

  tabs.forEach((tab, idx) => {
    tab.addEventListener('click', () => activateTab(idx));
    tab.addEventListener('keydown', (e: KeyboardEvent) => {
      let next = idx;
      if (e.key === 'ArrowRight') next = (idx + 1) % tabs.length;
      else if (e.key === 'ArrowLeft') next = (idx - 1 + tabs.length) % tabs.length;
      else if (e.key === 'Home') next = 0;
      else if (e.key === 'End') next = tabs.length - 1;
      else return;
      e.preventDefault();
      activateTab(next);
      tabs[next]?.focus();
    });
  });

  // Init tabindex on inactive tabs
  tabs.forEach((t, i) => t.setAttribute('tabindex', i === 0 ? '0' : '-1'));
}

// ─── Theme Toggle ────────────────────────────────────────────────────────────
function setupTheme(): void {
  $('themeToggle').addEventListener('click', () => {
    const html = document.documentElement;
    const current = html.getAttribute('data-theme') ?? 'dark';
    const next = current === 'dark' ? 'light' : 'dark';
    html.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
  });
}

// ─── Wire all buttons ─────────────────────────────────────────────────────────
function wireButtons(): void {
  // Exhibit 1
  $('initBtn').addEventListener('click', () => void initTree());
  $('stepBtn').addEventListener('click', () => void stepRandomAccess());
  $('autoBtn').addEventListener('click', () => {
    if (autoRunInterval) {
      stopAutoRun();
    } else {
      btn('autoBtn').textContent = 'Stop Auto';
      btn('autoBtn').setAttribute('aria-pressed', 'true');
      autoRunInterval = setInterval(() => void stepRandomAccess(), 1200);
    }
  });
  $('serverViewBtn').addEventListener('click', () => {
    serverViewMode = !serverViewMode;
    btn('serverViewBtn').textContent = serverViewMode ? 'Show Block IDs' : 'Toggle Server View';
    btn('serverViewBtn').setAttribute('aria-pressed', String(serverViewMode));
    renderBothTrees(lastAccessedLeaf);
  });
  $('writeBlockBtn').addEventListener('click', () => void writeCustomBlock());
  $('readBlockBtn').addEventListener('click', () => void readCustomBlock());

  // Exhibit 2
  $('walkInitBtn').addEventListener('click', () => void initWalk());
  $('walkReadBtn').addEventListener('click', () => void startWalkThrough('read'));
  $('walkWriteBtn').addEventListener('click', () => void startWalkThrough('write'));
  $('walkNextBtn').addEventListener('click', () => void advanceWalkStep());

  // Exhibit 3
  $('advInitBtn').addEventListener('click', () => void initAdv());
  $('advRunBtn').addEventListener('click', () => void runAdvAccesses());
  $('advClearBtn').addEventListener('click', () => {
    $('advServerLog').innerHTML = '';
    $('advClientLog').innerHTML = '';
    $('advAnalysis').innerHTML = '<p style="color:var(--text2)">Log cleared.</p>';
    accessHistory.length = 0;
  });
}

// ─── Entry Point ─────────────────────────────────────────────────────────────
buildShell();
setupTabs();
setupTheme();
wireButtons();
