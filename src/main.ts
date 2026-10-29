import {
  initializeORAM,
  read,
  write,
  getStashSize,
  getStashHighWater,
  reconstructPathPlacement,
  StaleVaultError,
  type ORAMClient,
} from './client/oram-client.js';
import {
  getServerStats,
  getServerBuckets,
  getPathBucketIds,
} from './server/oram-server.js';
import { analyzePathUniformity } from './analysis.js';
import { renderStashContents } from './ui/stash.js';
import {
  runORAMComparison,
  runSkippedProbeControl,
  type ORAMComparisonResult,
  type SkippedProbeControlResult,
} from './hierarchical/comparison.js';
import {
  CLIENT_LABELS,
  RIGHTS,
  runBaseline,
  runCollusion,
  runConcurrencyControl,
  runIntegrityExperiment,
  runNaiveSharing,
  runRevocationControl,
  runRollbackControl,
  runTamperControls,
  runTraceShape,
} from './multiclient/scenario.js';

// ─── ORAM parameters ────────────────────────────────────────────────────────
const N = 16;
const Z = 4;
const L = Math.ceil(Math.log2(N)); // 4
const NUM_BUCKETS = (1 << (L + 1)) - 1; // 31

// ─── App state ───────────────────────────────────────────────────────────────
let client: ORAMClient | null = null;
let initializing = false;
let treeAccessInFlight = false;
let autoRunInterval: ReturnType<typeof setInterval> | null = null;
let comparisonInFlight = false;
let skippedControlInFlight = false;

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
  if (!Number.isSafeInteger(max) || max < 1 || max > 0x100000000) {
    throw new RangeError('max must be an integer in [1, 2^32].');
  }
  const range = 0x100000000;
  const limit = Math.floor(range / max) * max;
  const sample = new Uint32Array(1);
  do {
    crypto.getRandomValues(sample);
  } while ((sample[0] as number) >= limit);
  return (sample[0] as number) % max;
}

function textToBytes(s: string): Uint8Array {
  const enc = new TextEncoder();
  const bytes = enc.encode(s);
  if (bytes.length > 32) {
    throw new RangeError('Block text must be at most 32 UTF-8 bytes.');
  }
  const padded = new Uint8Array(32);
  padded.set(bytes);
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
<nav aria-label="Exhibit tabs">
  <div role="tablist" aria-label="Exhibits" id="tablist">
    <button class="nav-tab active" role="tab" aria-selected="true"  aria-controls="ex0" id="tab0" data-tab="0">1 · Access-Pattern Problem</button>
    <button class="nav-tab"        role="tab" aria-selected="false" aria-controls="ex1" id="tab1" data-tab="1">2 · Tree Visualization</button>
    <button class="nav-tab"        role="tab" aria-selected="false" aria-controls="ex2" id="tab2" data-tab="2">3 · Access Walkthrough</button>
    <button class="nav-tab"        role="tab" aria-selected="false" aria-controls="ex3" id="tab3" data-tab="3">4 · Adversary vs. Client</button>
    <button class="nav-tab"        role="tab" aria-selected="false" aria-controls="ex4" id="tab4" data-tab="4">5 · Costs &amp; When to Use</button>
    <button class="nav-tab"        role="tab" aria-selected="false" aria-controls="ex5" id="tab5" data-tab="5">6 · Path vs. Hierarchy</button>
    <button class="nav-tab"        role="tab" aria-selected="false" aria-controls="ex6" id="tab6" data-tab="6">7 · Distrustful Clients</button>
  </div>
</nav>
<main id="main-content">
  <header class="cl-hero">
    <div class="cl-hero-main">
      <h1 class="cl-hero-title">ORAM Vault</h1>
      <p class="cl-hero-sub">Path ORAM · bounded hierarchical ORAM · access-pattern privacy</p>
      <p class="cl-hero-desc">Drive live reads and writes through a binary-tree ORAM, then compare its real traffic with a bounded executable hierarchy that probes every level and rebuilds on a public binary schedule.</p>
    </div>
    <aside class="cl-hero-why" aria-label="Why it matters">
      <span class="cl-hero-why-label">WHY IT MATTERS</span>
      <p class="cl-hero-why-text">Encryption hides file contents, but the sequence of locations you read still leaks behavior — routines, relationships, panic. In its stated semi-honest model, Path ORAM hides which logical block each storage access targets; access count and timing remain visible.</p>
    </aside>
  </header>
  ${exhibit0()}
  ${exhibit1()}
  ${exhibit2()}
  ${exhibit3()}
  ${exhibit4()}
  ${exhibit5()}
  ${exhibit6()}
</main>
<footer style="margin-top:3rem;padding:2rem 1rem;border-top:1px solid rgba(128,128,128,.25);text-align:center;font-size:.85rem;line-height:1.9;opacity:.85;font-family:ui-monospace,Menlo,Consolas,monospace">
  <div><strong>Related demos:</strong> <a class="footer-link" href="https://systemslibrarian.github.io/crypto-lab-oblivious-shelf/">oblivious-shelf</a> &middot; <a class="footer-link" href="https://systemslibrarian.github.io/crypto-lab-patron-shield/">patron-shield</a> &middot; <a class="footer-link" href="https://systemslibrarian.github.io/crypto-lab-psi-gate/">psi-gate</a> &middot; <a class="footer-link" href="https://systemslibrarian.github.io/crypto-lab-silent-tally/">silent-tally</a></div>
  <div style="margin-top:.5rem"><a class="footer-link" href="https://github.com/systemslibrarian/crypto-lab-oram-vault">Source on GitHub</a> &middot; <a class="footer-link" href="https://crypto-lab.systemslibrarian.dev/">More crypto-lab demos</a></div>
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
      <div class="scenario-wrap" role="group" tabindex="0" aria-label="Server access log showing location reads"><div class="scenario" id="serverAccessLog">Monday    09:00  READ location 42 → [ciphertext A]
Tuesday   09:00  READ location 42 → [ciphertext A]
Wednesday 09:00  READ location 42 → [ciphertext A]
Friday    14:07  READ location  8 → [ciphertext B]
Friday    14:08  READ location 15 → [ciphertext C]
Friday    14:09  READ location 23 → [ciphertext D]</div></div>
    </div>
    <div class="card panel-client">
      <div class="panel-label client" aria-hidden="true">What the Server Infers (Without Decrypting)</div>
      <div class="scenario-wrap" role="group" tabindex="0" aria-label="What the server infers from access patterns"><div class="scenario client-border">Location 42: accessed every morning at 9am
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
  <p>Your cloud provider is <strong>honest-but-curious</strong>: it follows the protocol but records every storage access. Goldreich and Ostrovsky introduced ORAM (1987/1996) and proved an Ω(log N) lower bound for statistically secure <em>balls-in-bins</em> ORAMs. Larsen and Nielsen (2018) later proved Ω(log N) for general online ORAMs, including computationally secure schemes. Path ORAM reads and rewrites one O(log N)-bucket path per data access before position-map recursion; OptORAMa (2020) supplied the first asymptotically optimal general ORAM construction.</p>

  <h3>What Path ORAM Fixes</h3>
  <div class="scenario-wrap" role="group" tabindex="0" aria-label="What Path ORAM access patterns look like to the server"><div class="scenario client-border">With Path ORAM, the server sees (illustrative):

Access 1: read path  7, write path  7
Access 2: read path 14, write path 14
Access 3: read path  2, write path  2
Access 4: read path 11, write path 11
Access 5: read path  7, write path  7

Paths are uniformly random. No correlation.
Even accessing the same block 1000 times —
the server sees 1000 independent random paths.
The *logical* access pattern is hidden: each
path is uniform and independent of which block
you touched.</div></div>

  <p><strong>What is proven — and what is not.</strong> In Path ORAM's model, each accessed leaf label is freshly uniform and independent of the logical address, while nonce-unique encryption makes rewritten block contents computationally unlinkable under the encryption scheme's nonce-respecting assumptions. That hides <em>which block</em> an access targets from a semi-honest storage server. It does <em>not</em> hide the number or timing of operations, make stash failure impossible, or supply freshness/completeness against a malicious server. <a class="footer-link" href="#caveats" id="ex0CaveatsLink">See the full security caveats →</a></p>

  <h3>Run the Same Attack Scenario Through ORAM</h3>
  <p>The log above is illustrative. Replay the <em>exact</em> Monday/Tuesday/Friday accesses from the attack — same logical blocks, in the same order — through a live Path ORAM and watch the server-visible paths collapse to independent random draws (real <code>crypto.getRandomValues</code>, no fixed values).</p>
  <div class="btn-row">
    <button class="btn primary" id="replayBtn">Replay medical scenario through ORAM</button>
  </div>
  <div role="status" aria-live="polite" class="status-bar" id="replayStatus">Not yet run.</div>
  <div class="two-col">
    <div class="card panel-server">
      <div class="panel-label server" id="replayServerLabel">What the Server Sees Now</div>
      <div class="scenario-wrap"><div class="scenario" id="replayServerLog" tabindex="0" role="region" aria-labelledby="replayServerLabel" aria-label="Server-visible paths after replaying the scenario through ORAM">Press "Replay" to run the six accesses.</div></div>
    </div>
    <div class="card panel-client">
      <div class="panel-label client" id="replayClientLabel">What the Client Actually Did</div>
      <div class="scenario-wrap"><div class="scenario client-border" id="replayClientLog" tabindex="0" role="region" aria-labelledby="replayClientLabel" aria-label="Actual client operations during the replay">Press "Replay" to run the six accesses.</div></div>
    </div>
  </div>
</section>`;
}

// ─── Exhibit 1 — Tree Visualization ─────────────────────────────────────────
function exhibit1(): string {
  return `
<section class="exhibit" id="ex1" role="tabpanel" aria-labelledby="tab1" tabindex="0" hidden>
  <h2>Path ORAM Tree Visualization</h2>
  <p>N=${N} blocks · Z=${Z} bucket size · tree height L=${L} (${L + 1} levels) · ${NUM_BUCKETS} total buckets · ${Z * NUM_BUCKETS} block capacity</p>

  <div class="btn-row">
    <button class="btn primary" id="initBtn">Initialize ORAM (${N} blocks)</button>
    <button class="btn" id="stepBtn" disabled aria-disabled="true">Step Random Access</button>
    <button class="btn" id="autoBtn" disabled aria-disabled="true" aria-pressed="false">Auto-run</button>
    <button class="btn" id="serverViewBtn" disabled aria-disabled="true" aria-pressed="false">Hide block IDs (server view)</button>
  </div>

  <div class="input-row" role="group" aria-label="Read or write a specific block">
    <label for="blockIdInput">Block</label>
    <input type="number" id="blockIdInput" min="0" max="${N - 1}" value="5"
           inputmode="numeric" aria-label="Block ID (0 to ${N - 1})" />
    <label for="blockValueInput">Value (≤32 UTF-8 bytes)</label>
    <input type="text" id="blockValueInput" maxlength="32" value="SECRET"
           aria-label="Value to write (up to 32 UTF-8 bytes)" />
    <button class="btn accent" id="writeBlockBtn" disabled aria-disabled="true">Write</button>
    <button class="btn" id="readBlockBtn" disabled aria-disabled="true">Read</button>
  </div>

  <div role="status" aria-live="polite" class="status-bar" id="treeStatus">Click "Initialize ORAM" to begin.</div>

  <div class="stats-row" id="treeStats" aria-live="polite"></div>

  <div class="two-col">
    <div class="card panel-server">
      <div class="panel-label server" id="serverTreeLabel">Server View (untrusted cloud)</div>
      <p style="font-size:0.8rem">All blocks look identical — encrypted blobs only. No block IDs visible.</p>
      <div class="tree-container" id="serverTree" role="group" tabindex="0" aria-labelledby="serverTreeLabel"></div>
    </div>
    <div class="card panel-client">
      <div class="panel-label client" id="clientTreeLabel">Client View (trusted)</div>
      <p style="font-size:0.8rem">On the highlighted path, real block IDs (<span class="lg lg-real">B5</span>) come from the client's retained record of its latest write-back, while the private position map establishes where each recorded block may legally sit. Off-path buckets it hasn't read stay opaque (<span class="lg lg-opaque"></span>) — the client can't cheaply know those either.</p>
      <div class="tree-container" id="clientTree" role="group" tabindex="0" aria-labelledby="clientTreeLabel"></div>
    </div>
  </div>

  <h3>Position Map · block → leaf (the indirection)</h3>
  <div class="card panel-client">
    <div class="panel-label client">Position Map (client-local only, never sent to server)</div>
    <div id="positionMap" aria-live="polite"><p class="pm-caption">Initialize ORAM to view the block → leaf map.</p></div>
  </div>

  <h3>Why Eviction Is Legal (the structural invariant)</h3>
  <div class="card panel-client">
    <p style="font-size:0.82rem;margin:0">A block assigned to leaf <em>x</em> may rest <strong>only</strong> in buckets shared by its own path and the write-back path — i.e. it can sink no deeper than the lowest common node of the two leaves. Greedy eviction pushes each stash block as deep as this rule allows.</p>
    <div id="evictionInvariant" aria-live="polite"><p class="pm-caption" style="margin-top:0.6rem">Run an access to see, block by block, why each on-path block landed where it did.</p></div>
  </div>

  <h3>Client Stash</h3>
  <div class="card panel-client">
    <div class="panel-label client">Stash (client-local only, never sent to server)</div>
    <div class="stash-grid" id="stashDisplay" role="group" aria-live="polite" aria-label="Current stash contents"></div>
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
      <div class="card panel-server" id="walkServerLog" role="group" aria-labelledby="walkServerLogLabel">
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
      <p style="font-size:0.8rem">The server API receives encrypted path reads/writes and their size, order, and timing; it receives no logical block ID or logical READ/WRITE label. This demo does not prove that client timing hides the logical operation.</p>
      <div class="access-log" id="advServerLog" role="log" tabindex="0" aria-labelledby="advServerLabel" aria-live="polite"></div>
    </div>
    <div class="card panel-client">
      <div class="panel-label client" id="advClientLabel">Actual Client Operations</div>
      <p style="font-size:0.8rem">Client perspective: actual block IDs and operations.</p>
      <div class="access-log" id="advClientLog" role="log" tabindex="0" aria-labelledby="advClientLabel" aria-live="polite"></div>
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
  <p>Path ORAM trades bandwidth, client state and computation for hiding logical block choices in its stated semi-honest-server model.</p>

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
        <tr><td>Client storage</td><td>O(1)</td><td>Finite stash (Z=4 evidence is empirical here) + O(N) position map</td></tr>
        <tr><td>Server storage</td><td>O(N)</td><td>O(N) &mdash; ${NUM_BUCKETS} buckets × ${Z} slots = ${NUM_BUCKETS * Z} slots (~${(NUM_BUCKETS * Z / N).toFixed(2)}N here)</td></tr>
        <tr><td>Access pattern leakage</td><td style="color:var(--server)">Full leakage</td><td style="color:var(--stash)">Logical pattern hidden<a href="#caveats" aria-label="See residual leakage caveats" class="caveat-mark" style="color:var(--text2)"></a></td></tr>
        <tr><td>Implementation complexity</td><td>Trivial</td><td>Moderate (16-line pseudocode)</td></tr>
      </tbody>
    </table>
  </div>
  <p style="font-size:0.78rem;margin-top:0.4rem"><span aria-hidden="true">*</span> Hidden under a <strong>semi-honest</strong> server: the server sees a uniform, independent path each access, but the <em>number and timing</em> of accesses and rare stash overflow are residual channels. See <a class="footer-link" href="#caveats" id="ex4CaveatsLink">Security Caveats</a> below.</p>

  <div class="two-col">
    <div class="card">
      <div class="panel-label" style="color:var(--stash)">✓ When to Use ORAM</div>
      <div class="scenario-wrap" role="group" tabindex="0" aria-label="When to use ORAM"><div class="scenario client-border" style="font-size:0.82rem">✓ Adversary actively observing access patterns
✓ Access-pattern leakage is security-critical
✓ Latency-tolerant workloads (not real-time)
✓ Small-medium datasets (not billions of blocks)
✓ Healthcare records — pattern reveals diagnosis
✓ Researching access-pattern protection around secure processors and enclaves
✓ Privacy-preserving cloud database queries
✓ Outsourced storage where the client can retain trusted ORAM state</div></div>
    </div>
    <div class="card">
      <div class="panel-label" style="color:var(--server)">✗ When NOT to Use ORAM</div>
      <div class="scenario-wrap" role="group" tabindex="0" aria-label="When not to use ORAM"><div class="scenario" style="font-size:0.82rem">✗ Real-time / low-latency workloads
✗ Large databases (billions of blocks)
✗ High-throughput / bulk processing
✗ Access patterns already public
✗ When the threat model explicitly permits storage-access leakage
  → A TEE alone does not automatically hide its access pattern

Alternatives:
  PIR (Private Information Retrieval)
  → Lower client storage, higher server CPU
  → See crypto-lab-oblivious-shelf

  Differential Privacy
  → Adds distributional noise; a different goal and guarantee
  → See crypto-lab-patron-shield</div></div>
    </div>
  </div>

  <h3>Research Systems and Prototypes</h3>
  <p><strong>Ascend</strong> and <strong>PHANTOM</strong> explored ORAM-backed secure processors; <strong>ZeroTrace</strong> evaluated both Path ORAM and Circuit ORAM on Intel SGX; and <strong>OBLIVIATE</strong> adapted ORAM to SGX file access. <strong>Obladi</strong> is related database work, but it builds on Ring ORAM rather than Path ORAM. These are research systems and prototypes, not evidence that this browser demo is production-ready.</p>

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

  <h3 id="caveats">Security Caveats</h3>
  <div class="scenario-wrap" role="group" tabindex="0" aria-label="Security caveats and limitations"><div class="scenario" style="font-size:0.8rem">⚠ Stash overflow: a finite stash can fail; probability depends on bucket size and stash capacity. The paper proves an exponential tail for Z=5 and reports empirical support for Z=4, used here. This toy run proves no production failure probability. Recursion handles the position map, not overflow.
⚠ Timing and termination remain visible. Padding, scheduling and constant-time client engineering are separate requirements this browser demo does not implement.
⚠ Position map is O(N): for large N, store position map in another ORAM (recursive construction).
⚠ Module separation is informational, not process isolation: client and server code run in the same page.
⚠ AES-GCM detects modified individual blobs, but this demo has no authenticated tree for path completeness or freshness. A malicious server can replay or drop valid data; Path ORAM §6.4 describes a Merkle-tree extension, while Onion ORAM describes a malicious-server construction.
⚠ Side-channels: cache timing, GC pauses can leak info. Out of scope for this demo.</div></div>
</section>`;
}

// ─── Exhibit 5 — Path vs. bounded hierarchy ─────────────────────────────────
function exhibit5(): string {
  return `
<section class="exhibit" id="ex5" role="tabpanel" aria-labelledby="tab5" tabindex="0" hidden>
  <h2>Path ORAM vs. a Bounded Hierarchical ORAM</h2>
  <p>Run one declared workload through <strong>both real implementations</strong>. Path ORAM reads and rewrites one root-to-leaf path. The hierarchy scans a one-block cache, probes one whole bucket in every hashed level, substitutes a unique dummy label after a hit, and reinserts through a binary-carry rebuild schedule.</p>

  <div class="two-col">
    <div class="card panel-client">
      <div class="panel-label client">Path ORAM in this lab</div>
      <p><strong>N=16, Z=4, five tree levels.</strong> Each logical access transfers 20 encrypted slots in and 20 out. The server holds 31 × 4 = 124 slots. Trusted state includes the AES key, a 16-entry position map and a finite stash; recursive position-map traffic is not implemented here.</p>
    </div>
    <div class="card panel-client">
      <div class="panel-label client">Bounded hierarchy in this lesson</div>
      <p><strong>N=16, server-held levels 1, 2, 4, 8 and 16.</strong> The one-slot top array is scanned in full; the four hashed levels use fresh secret HMAC-SHA-256 keys after every build. A level of capacity c has c buckets of c slots and each lookup selects one complete bucket, so the server holds 341 slots and a normal lookup transfers 31 slots in and 31 out before rebuild work.</p>
    </div>
  </div>

  <div class="card scope-card">
    <h3>Model boundary</h3>
    <p>This is a finite teaching adaptation of the generic hierarchy in Alibi §2.5/Fig. 2 and Goodrich–Mitzenmacher §5/Fig. 2. Deliberately oversized buckets make overflow impossible for this fixed instance, at the cost of about 21.31N server slots. Rebuilds decrypt an entire level into transient O(N) client memory. This is <strong>not</strong> the papers' asymptotically efficient oblivious hash table, not a performance benchmark, and not a transferred security proof. It implements no cuckoo stash or combined stash and therefore does not reproduce Alibi's combined-stash attack or repair.</p>
    <p>The storage observer receives only physical level/bucket coordinates, transfer sizes, ordering, and public rebuild phases. Logical block labels, real-versus-dummy probe kind, HMAC keys, plaintext and hit state stay in the trusted browser module. That module boundary is informational, not process isolation.</p>
  </div>

  <div class="btn-row">
    <button class="btn primary" id="hierRunBtn">Run same workload through both</button>
  </div>
  <div role="status" aria-live="polite" class="status-bar" id="hierStatus">Not yet run.</div>

  <div class="costs-wrap" tabindex="0" role="region" aria-label="Measured Path ORAM and hierarchical ORAM traffic">
    <table class="costs comparison-table" id="hierComparisonTable">
      <thead>
        <tr>
          <th scope="col">#</th>
          <th scope="col">Logical operation</th>
          <th scope="col">Value (write input / read result)</th>
          <th scope="col">Path slots</th>
          <th scope="col">Found level</th>
          <th scope="col">Hierarchy lookup</th>
          <th scope="col">Rebuild levels / slots</th>
          <th scope="col">Hierarchy total</th>
        </tr>
      </thead>
      <tbody id="hierComparisonBody">
        <tr><td colspan="8">Run the workload to compute current traffic from both server logs.</td></tr>
      </tbody>
    </table>
  </div>
  <div class="two-col" id="hierSummary" aria-live="polite">
    <div class="card"><div class="panel-label">Independent verification</div><p>Pending: after the eight displayed operations, the runner reads all 16 logical blocks from both constructions and compares them with a separate reference map.</p></div>
    <div class="card"><div class="panel-label">What traffic means</div><p>Path figures count encrypted slots in its actual bucket log. Hierarchy lookup and rebuild figures sum its physical server events. Initialization and the final verification sweep are excluded from the displayed workload rows.</p></div>
  </div>

  <h3>Negative control: stop probing after a hit</h3>
  <p>A tempting optimization is to stop after the target is found. Run the same repeated-block access under the fixed all-level schedule and that intentionally insecure policy. Both return the right plaintext; only one hides the hit depth from the number of lookup slots.</p>
  <div class="btn-row">
    <button class="btn accent" id="hierLeakBtn">Run skipped-probe control</button>
  </div>
  <div role="status" aria-live="polite" class="status-bar" id="hierLeakStatus">Not yet run.</div>
  <div class="two-col" id="hierLeakResults" aria-live="polite">
    <div class="card panel-client"><div class="panel-label client">Fixed all-level schedule</div><p>Pending.</p></div>
    <div class="card panel-server"><div class="panel-label server">Insecure skip-after-hit policy</div><p>Pending.</p></div>
  </div>

  <h3>Sources and retained assumptions</h3>
  <ul class="source-list">
    <li><a class="footer-link" href="https://web.cs.ucla.edu/~rafail/PUBLIC/248.pdf">Alibi, §2.5 and Figure 2</a>: generic cache lookup, real/dummy searches, deletion, reinsertion, rebuilds and fresh level keys; its later combined-cuckoo-stash flaw is outside this table.</li>
    <li><a class="footer-link" href="https://arxiv.org/abs/1007.1259">Goodrich and Mitzenmacher, §5 and Figure 2</a>: hierarchical query/rebuild schedule and the efficient hashing machinery this bounded table does not reproduce.</li>
    <li><a class="footer-link" href="https://doi.org/10.1145/233551.233553">Goldreich and Ostrovsky</a>: the historical hierarchical ORAM construction.</li>
  </ul>
  <p>The executable lesson assumes a semi-honest storage observer, a trusted client, HMAC-SHA-256 behaving as a pseudorandom function, nonce-respecting AES-GCM, fresh independent level keys, and a fixed operation count. It does not hide timing or termination, handle malicious omission/replay, recurse client state, establish asymptotic overhead, or claim production hardening.</p>
</section>`;
}

// ─── Exhibit 6 — Mutually distrustful clients sharing one ORAM ──────────────
function exhibit6(): string {
  const bands = RIGHTS.map(
    (band) =>
      `<tr><td>${band.from}&ndash;${band.to}</td><td>${band.label}</td>` +
      band.modes.map((mode) => `<td>${MODE_WORDS[mode]}</td>`).join('') +
      '</tr>',
  ).join('');
  return `
<section class="exhibit" id="ex6" role="tabpanel" aria-labelledby="tab6" tabindex="0" hidden>
  <h2>Mutually Distrustful Clients Sharing One ORAM</h2>
  <p>Everything before this tab has one client. One key, one position map, one stash, one trusted
  machine. This tab is about what changes when a clinician, a billing office and an outside
  contractor share a single encrypted store and <strong>do not trust each other</strong>.</p>
  <p>That is a different primitive with its own definition: a <strong>Multi-Client ORAM</strong>, a
  data owner, clients holding capabilities, an untrusted server, and an access-control matrix
  <code>ACM(i, idx)</code> over <em>no access</em>, <em>read</em> and <em>read-write</em> that
  <strong>only the owner ever sees</strong>.</p>

  <div class="two-col">
    <div class="card panel-client">
      <div class="panel-label client">Four actors, three trust boundaries</div>
      <ul>
        <li><strong>Data owner</strong> &mdash; honest by assumption. Holds <code>ACM</code>, the
        store key, every per-entry key, the capability signing key. Issues capabilities and rotates
        keys. It is the only party that knows the policy.</li>
        <li><strong>Clients</strong> &mdash; mutually distrustful and possibly malicious. Each holds
        only its own wrap key, its own signing key, the shared store key, and the write capabilities
        the owner issued to it.</li>
        <li><strong>Server</strong> &mdash; untrusted for confidentiality. Holds the encrypted tree,
        the shared leaf map, the shared stash and the signed upload log. Performs no access
        control, because it cannot.</li>
        <li><strong>No coordinator and no key service.</strong> Adding a trusted proxy would be a
        different construction; it is named in the sources below and deliberately not built.</li>
      </ul>
    </div>
    <div class="card panel-server">
      <div class="panel-label server">Collusion, stated in all three directions</div>
      <ul>
        <li><strong>Client &harr; client:</strong> assumed possible. Corrupted clients may pool
        capabilities. Nothing is claimed inside the union of their rights.</li>
        <li><strong>Client &harr; server:</strong> assumed <strong>not</strong> to happen. That is
        the assumption the attack below removes, and the point at which the published lower bound
        bites.</li>
        <li><strong>Server &rarr; client:</strong> the server may omit, replay or reorder. Integrity
        and global freshness are not claimed. Signatures, remembered log heads and local version
        watermarks detect only the bounded cases executed below.</li>
      </ul>
    </div>
  </div>

  <h3>The access-control matrix the owner holds</h3>
  <div class="costs-wrap" tabindex="0" role="region" aria-label="Access control matrix">
    <table class="costs">
      <thead>
        <tr><th scope="col">Entries</th><th scope="col">Band</th>
        ${CLIENT_LABELS.map((label) => `<th scope="col">${label}</th>`).join('')}</tr>
      </thead>
      <tbody>${bands}</tbody>
    </table>
  </div>
  <p class="pm-caption">This table is the omniscient teaching view. No client can see it, and the
  server cannot either &mdash; a capability carries only the entries that client may write.</p>

  <h3>1 &middot; The honest baseline</h3>
  <p>Every client tries what it may and what it may not. A denied read fails payload authentication;
  an ordinary denied write lacks an owner-issued write token. Neither is a disabled UI control:
  the runner calls the protocol directly. A malicious client can instead submit a mismatched token;
  that update lands and is rejected by honest readers during signature verification, as the integrity
  control below demonstrates.</p>
  <div class="btn-row">
    <button class="btn primary" id="mcBaselineBtn">Run honest baseline</button>
  </div>
  <div role="status" aria-live="polite" class="status-bar" id="mcBaselineStatus">Not yet run.</div>
  <div class="costs-wrap" tabindex="0" role="region" aria-label="Multi-client access attempts">
    <table class="costs" id="mcBaselineTable">
      <thead>
        <tr><th scope="col">Client</th><th scope="col">Operation</th><th scope="col">Entry</th>
        <th scope="col">Right</th><th scope="col">Outcome</th><th scope="col">Why</th></tr>
      </thead>
      <tbody id="mcBaselineBody">
        <tr><td colspan="6">Run the baseline to compute these from a live store.</td></tr>
      </tbody>
    </table>
  </div>

  <h3>2 &middot; What goes wrong if you just share the single-client ORAM</h3>
  <p>The tempting shortcut is to hand both clients the <em>existing</em> Path ORAM key and move its
  position map somewhere they can both reach. This runs that deployment against
  <strong>this lab&rsquo;s own unmodified Path ORAM</strong>. There is no attack code: every failure
  below is the shipped protocol doing exactly what it was written to do, in a setting it was not
  written for.</p>
  <div class="btn-row">
    <button class="btn accent" id="mcNaiveBtn">Run the shared-key deployment</button>
  </div>
  <div role="status" aria-live="polite" class="status-bar" id="mcNaiveStatus">Not yet run.</div>
  <div class="two-col" id="mcNaiveResults" aria-live="polite">
    <div class="card panel-server"><div class="panel-label server">Cross-client exposure</div><p>Pending.</p></div>
    <div class="card panel-server"><div class="panel-label server">Divergent state</div><p>Pending.</p></div>
  </div>

  <h3>3 &middot; Obliviousness, once one client talks to the server</h3>
  <p>The shared leaf map has to live on the server so that every client can use one tree, and it is
  encrypted under the store key <em>every registered client holds</em>. So a client can decrypt it.
  Pair that with the one thing the server genuinely observes &mdash; the leaf of each path access
  &mdash; and the pair narrows sixteen possible entries to a handful that always contains the right
  one.</p>
  <div class="btn-row">
    <button class="btn accent" id="mcCollusionBtn">Run the colluding-client attack</button>
  </div>
  <div role="status" aria-live="polite" class="status-bar" id="mcCollusionStatus">Not yet run.</div>
  <div class="costs-wrap" tabindex="0" role="region" aria-label="Colluding client observations">
    <table class="costs" id="mcCollusionTable">
      <thead>
        <tr><th scope="col">Trial</th><th scope="col">Leaf the server saw</th>
        <th scope="col">Candidates from the shared map</th><th scope="col">Entry actually accessed</th>
        <th scope="col">Narrowed to one?</th></tr>
      </thead>
      <tbody id="mcCollusionBody">
        <tr><td colspan="5">Run the attack to compute these from a live store.</td></tr>
      </tbody>
    </table>
  </div>
  <div class="card scope-card" id="mcCollusionNote" aria-live="polite">
    <p>Pending: the published bound this result sits against.</p>
  </div>

  <h3>4 &middot; The construction, inside its own stated model</h3>
  <p>Access control by per-client key wrapping and owner-signed write capabilities, a fixed ORAM
  data-access shape, a signed append-only path-upload log, client-local freshness watermarks, and a retained
  plaintext mirror to expose the integrity boundary. Every control below computes its outcome from
  live protocol state, including the properties this bounded adaptation deliberately does not have.</p>
  <div class="btn-row">
    <button class="btn primary" id="mcControlsBtn">Run every control</button>
  </div>
  <div role="status" aria-live="polite" class="status-bar" id="mcControlsStatus">Not yet run.</div>
  <div class="costs-wrap" tabindex="0" role="region" aria-label="Multi-client negative controls">
    <table class="costs" id="mcControlsTable">
      <thead>
        <tr><th scope="col">Control</th><th scope="col">Expected</th><th scope="col">Observed</th>
        <th scope="col">Verdict</th></tr>
      </thead>
      <tbody id="mcControlsBody">
        <tr><td colspan="4">Run the controls to compute these from live stores.</td></tr>
      </tbody>
    </table>
  </div>
  <div class="two-col" id="mcViews" aria-live="polite">
    <div class="card panel-server"><div class="panel-label server">What the server sees</div><p>Pending.</p></div>
    <div class="card panel-client"><div class="panel-label client">Omniscient teaching view</div><p>Pending.</p></div>
  </div>

  <div class="card scope-card">
    <h3>Which properties this exhibit claims, and which it does not</h3>
    <ul>
      <li><strong>Secrecy &mdash; claimed.</strong> A client with no read right cannot obtain the
      per-entry key, so AES-GCM refuses the payload.</li>
      <li><strong>Tamper resistance &mdash; claimed.</strong> Every client verifies the owner&rsquo;s
      capability signature and the writer&rsquo;s own signature on every entry it parses.</li>
      <li><strong>Accountable integrity &mdash; claimed.</strong> The signed upload log names the
      client whose upload broke an entry.</li>
      <li><strong>Integrity &mdash; NOT claimed.</strong> Preventing an unauthorised write requires
      the server to perform access control, and this server cannot: deciding the question means
      reading an entry index out of an envelope it cannot open. The full construction buys that
      check with zero-knowledge proofs; the accountable variant deliberately gives it up. So an
      unauthorised write <em>lands</em> and is then rejected by every honest reader.</li>
      <li><strong>Access-pattern privacy &mdash; claimed against the non-colluding server only.</strong>
      Not against a colluding client, and not improvable at this cost: a published lower bound says
      any multi-client ORAM touching <code>o(n)</code> addresses per access is insecure against
      malicious clients, and one path access here touches five buckets of thirty-one.</li>
      <li><strong>Freshness / rollback resistance &mdash; claimed only relative to local memory.</strong>
      An entry below a version this client has already seen is refused. A first-contact client cannot
      detect the same rollback even after validating the signed path-upload log, because that log does
      not publish per-entry version heads. Log truncation is likewise detectable only relative to a
      head the client already remembers. There is no global freshness claim.</li>
      <li><strong>Concurrency or linearizability &mdash; refused outright.</strong> The selected
      construction provides no concurrency control. Overlapping accesses are rejected rather than
      raced, and the control above shows what the interleaving costs when the refusal is lifted.</li>
      <li><strong>Anonymity &mdash; NOT claimed.</strong> Writers sign their own updates, so any
      client that can open an envelope learns who last wrote it.</li>
    </ul>
    <p>Teaching adaptations, each a real deviation: one key wrap per client instead of a
    short-ciphertext broadcast encryption scheme; writer signatures instead of a key-exposure-free
    chameleon hash; a plain signed log instead of an oblivious gossiping protocol; and a fixed
    sixteen-entry instance, from which no asymptotic claim follows. The module boundary between
    owner, clients and server is informational: they are modules in one browser page, and
    same-origin code can reach every key.</p>
  </div>

  <h3>Sources</h3>
  <ul class="source-list">
    <li>Chow and Lai, <em>Multi-client Oblivious RAM</em>, Encyclopedia of Cryptography, Security and
    Privacy, Springer, 2025, pp. 1592&ndash;1594 &mdash; the entry this lesson starts from. Its three
    citations are the three below.</li>
    <li><a class="footer-link" href="https://eprint.iacr.org/2015/224">Maffei, Malavolta, Reinert and
    Schr&ouml;der, <em>GORAM</em>, IACR ePrint 2015/224</a> &mdash; Definition 1, the properties, the
    attacker model, and the A-GORAM/S-GORAM construction shape this exhibit adapts.</li>
    <li><a class="footer-link" href="https://eprint.iacr.org/2017/329">Maffei, Malavolta, Reinert and
    Schr&ouml;der, <em>Maliciously Secure Multi-Client ORAM</em>, IACR ePrint 2017/329</a> &mdash; the
    refined definition, the <code>&Omega;(n)</code> lower bound, the signature-based tamper
    resistance used here, PIR-MCORAM, and the trusted-proxy alternative.</li>
    <li><a class="footer-link" href="https://eprint.iacr.org/2020/1551">Chow, Fech, Lai and Malavolta,
    <em>Multi-client Oblivious RAM with Poly-logarithmic Communication</em>, IACR ePrint 2020/1551</a>
    &mdash; the simulation-based definitions, and the integrity experiment run as a control above.</li>
    <li><a class="footer-link" href="https://eprint.iacr.org/2016/678">Backes, Herzberg, Kate and
    Pryvalov, <em>Anonymous RAM</em>, IACR ePrint 2016/678</a> &mdash; section 3.1, the source for why
    the shared-key deployment in part 2 fails.</li>
    <li><a class="footer-link" href="https://arxiv.org/abs/1811.04366">Chakraborti and Sion,
    <em>ConcurORAM</em>, arXiv:1811.04366</a> &mdash; concurrency for clients that share credentials,
    which is a different problem from this one.</li>
    <li>Bindschaedler, Naveed, Pan, Wang and Huang, <em>Practicing Oblivious Access on Cloud Storage:
    The Gap, the Fallacy, and the New Way Forward</em>, CCS 2015 &mdash; named as the paper that named
    the fallacy; its text was not consulted for this lesson.</li>
  </ul>
  <p>The full design record, including the constructions considered and rejected and what each
  adaptation costs, is in <code>docs/multi-client-design.md</code>.</p>
</section>`;
}

const MODE_WORDS: Record<string, string> = {
  none: 'no access',
  read: 'read',
  readwrite: 'read-write',
};

// ─── SVG Tree Renderer ────────────────────────────────────────────────────────
interface TreeRenderOpts {
  // 'server' = opaque encrypted blobs; 'client' = the client's own view, with
  // real block IDs retained from the most recent path write-back; the position
  // map separately determines whether each recorded placement is legal.
  view: 'server' | 'client';
  highlightPath: number | null;
  // Block whose journey we are narrating this access (pulsed on the new path).
  focusBlock?: number | null;
}

function renderTree(containerId: string, opts: TreeRenderOpts): void {
  const container = document.getElementById(containerId);
  if (!container) return;

  const buckets = getServerBuckets();
  const onPathLevel = new Map<number, number>(); // bucketId -> level on highlighted path
  if (opts.highlightPath !== null) {
    getPathBucketIds(opts.highlightPath).forEach((bid, lvl) => onPathLevel.set(bid, lvl));
  }

  // On the client view, replay the exact placement record retained from the
  // client's latest write-back. The position map alone determines eligibility,
  // not the exact physical bucket selected by prior stash/eviction history.
  let placement: number[][] | null = null; // level -> blockIds
  let eligible: Map<number, number> | null = null;
  if (opts.view === 'client' && client && opts.highlightPath !== null) {
    const r = reconstructPathPlacement(client, opts.highlightPath);
    placement = r.perLevel;
    eligible = r.eligibleLevel;
  }

  const LEVELS = L + 1;
  const BUCKET_W = 48;
  const BUCKET_H = 26;
  const SLOT_W = 9;
  const SLOT_H = 14;
  const SLOT_GAP = 1.5;
  const H_GAP = 10;
  const V_GAP = 30;
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
      const onPath = onPathLevel.has(bucketIdx);

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
      const pathLevel = onPathLevel.get(bucketIdx);
      const clientBids =
        opts.view === 'client' && placement && pathLevel !== undefined
          ? placement[pathLevel] ?? []
          : null;

      for (let s = 0; s < Z; s++) {
        const sx = x + 3 + s * (SLOT_W + SLOT_GAP);
        const sy = y + (BUCKET_H - SLOT_H) / 2;
        const hasBlock = s < blocks.length;

        if (opts.view === 'client' && clientBids !== null) {
          // Client, on-path: show the reconstructed real block ID or a gray dummy.
          const bid = clientBids[s];
          if (bid !== undefined) {
            const isFocus = opts.focusBlock !== undefined && opts.focusBlock === bid;
            svgContent += `<rect class="block-slot block-real${isFocus ? ' block-focus' : ''}" x="${sx}" y="${sy}" width="${SLOT_W}" height="${SLOT_H}" rx="1"/>`;
            svgContent += `<text class="block-id-label" x="${sx + SLOT_W / 2}" y="${sy + SLOT_H / 2 + 2.4}" text-anchor="middle">${bid}</text>`;
          } else {
            svgContent += `<rect class="block-slot block-dummy" x="${sx}" y="${sy}" width="${SLOT_W}" height="${SLOT_H}" rx="1"/>`;
            svgContent += `<text class="block-id-label dummy" x="${sx + SLOT_W / 2}" y="${sy + SLOT_H / 2 + 2.4}" text-anchor="middle">--</text>`;
          }
        } else if (opts.view === 'client') {
          // Client, off-path: honestly opaque — the client hasn't read these
          // buckets, so it can't cheaply know their contents either.
          svgContent += `<rect class="block-slot ${hasBlock ? 'block-offpath' : 'block-dummy'}" x="${sx}" y="${sy}" width="${SLOT_W}" height="${SLOT_H}" rx="1"/>`;
        } else {
          // Server view: every occupied slot is an identical opaque blob.
          svgContent += `<rect class="block-slot ${hasBlock ? 'block-dummy-server' : 'block-dummy'}" x="${sx}" y="${sy}" width="${SLOT_W}" height="${SLOT_H}" rx="1"/>`;
        }
      }

      // Bucket label
      svgContent += `<text class="bucket-label" x="${x + BUCKET_W / 2}" y="${y + BUCKET_H + 9}" text-anchor="middle">B${bucketIdx}</text>`;
    }
  }

  const label =
    opts.view === 'server'
      ? 'Binary tree, server view: every occupied slot is an identical encrypted blob with no visible block ID.'
      : 'Binary tree, client view: real block IDs retained from the latest write-back are shown on the highlighted path; the position map determines placement eligibility.';
  container.innerHTML = `<div class="tree-svg-wrap"><svg class="oram-tree" viewBox="0 0 ${svgW} ${svgH}" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="${label}" focusable="false">${svgContent}</svg></div>`;

  void eligible; // eligibility is surfaced via the position-map panel below
}

function renderStash(containerId: string): void {
  if (!client) return;
  const el = document.getElementById(containerId);
  if (!el) return;
  renderStashContents(el, client.stash, bytesToText);
}

function updateTreeStats(containerId: string): void {
  if (!client) return;
  const stats = getServerStats();
  const el = document.getElementById(containerId);
  if (!el) return;
  const peak = getStashHighWater(client);
  el.innerHTML = `
    <div class="stat"><span class="stat-label">Server Reads</span><span class="stat-value server-color">${stats.totalReads}</span></div>
    <div class="stat"><span class="stat-label">Server Writes</span><span class="stat-value server-color">${stats.totalWrites}</span></div>
    <div class="stat"><span class="stat-label">Stash Size</span><span class="stat-value stash-color">${getStashSize(client)}</span></div>
    <div class="stat"><span class="stat-label">Observed Stash Peak</span><span class="stat-value stash-color" title="Highest stash occupancy observed during live accesses; setup staging is excluded.">${peak}</span></div>
    <div class="stat"><span class="stat-label">Tree Height L</span><span class="stat-value">${L}</span></div>
    <div class="stat"><span class="stat-label">Blocks N</span><span class="stat-value">${N}</span></div>
  `;
}

// ─── Exhibit 1 logic ─────────────────────────────────────────────────────────
let serverViewMode = false;
let lastAccessedLeaf: number | null = null;
// Narration state for the position-map panel and block-journey animation.
interface RemapNarration {
  block: number;
  oldLeaf: number;
  newLeaf: number;
}
let lastRemap: RemapNarration | null = null;

/**
 * Live position-map panel: block → leaf for every block, with the just-accessed
 * row highlighted, its old leaf struck through, and the fresh random leaf shown.
 * This is the indirection the whole scheme rests on — visualized, not narrated.
 */
function renderPositionMap(focusBlock: number | null): void {
  const el = document.getElementById('positionMap');
  if (!el || !client) return;

  const rows: string[] = [];
  for (let b = 0; b < N; b++) {
    const leaf = client.positionMap.get(b) ?? 0;
    const isFocus = lastRemap !== null && lastRemap.block === b && focusBlock === b;
    if (isFocus) {
      rows.push(
        `<tr class="pm-row pm-focus"><th scope="row">B${b}</th>` +
          `<td><span class="pm-old">leaf ${lastRemap!.oldLeaf}</span> ` +
          `<span class="pm-arrow" aria-hidden="true">→</span> ` +
          `<span class="pm-new">leaf ${lastRemap!.newLeaf}</span>` +
          `<span class="visually-hidden"> remapped from leaf ${lastRemap!.oldLeaf} to leaf ${lastRemap!.newLeaf}</span></td></tr>`,
      );
    } else {
      rows.push(`<tr class="pm-row"><th scope="row">B${b}</th><td>leaf ${leaf}</td></tr>`);
    }
  }

  const caption =
    lastRemap !== null && focusBlock !== null
      ? `Block ${focusBlock} was just re-randomised in the map: leaf ${lastRemap.oldLeaf} → leaf ${lastRemap.newLeaf}. The server saw a read+write of path ${lastRemap.oldLeaf}; the block physically settled back on that path (at a bucket it shares with leaf ${lastRemap.newLeaf}). Its NEXT access will read path ${lastRemap.newLeaf} — an uncorrelated path — so the server can't link the two accesses to one logical block.`
      : 'block → leaf. The client keeps this map private; the server never sees it. Run an access to watch a row re-randomise.';

  el.innerHTML = `
    <p class="pm-caption">${caption}</p>
    <div class="pm-scroll" tabindex="0" role="region" aria-label="Position map: block to leaf assignments">
      <table class="pm-table">
        <thead><tr><th scope="col">Block</th><th scope="col">Assigned leaf</th></tr></thead>
        <tbody>${rows.join('')}</tbody>
      </table>
    </div>`;
}

async function initTree(): Promise<void> {
  if (initializing || treeAccessInFlight) return;
  initializing = true;
  stopAutoRun();
  setDisabled('initBtn', true);
  $('treeStatus').textContent = 'Initializing ORAM — please wait…';
  try {
    client = await initializeORAM(N, Z);
    // Replace the initialized zero blocks with recognizable teaching values via
    // genuine ORAM accesses. The initialization itself already placed every
    // logical block in the tree or stash; these writes only make the values
    // visible in the client-side walkthrough.
    $('treeStatus').textContent = 'Initializing ORAM and materializing blocks…';
    for (let b = 0; b < N; b++) {
      await write(client, b, textToBytes(`block-${b}`));
    }
    $('treeStatus').textContent = `Initialized: ${N} blocks written and distributed across ${NUM_BUCKETS} buckets. Step or read/write to watch remapping.`;
    lastRemap = null;
    lastAccessedLeaf = null;
    setDisabled('stepBtn', false);
    setDisabled('autoBtn', false);
    setDisabled('serverViewBtn', false);
    setDisabled('readBlockBtn', false);
    setDisabled('writeBlockBtn', false);
    lastRemap = null;
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

function renderBothTrees(highlightLeaf: number | null, focusBlock: number | null = null): void {
  renderTree('serverTree', { view: 'server', highlightPath: highlightLeaf });
  // serverViewMode collapses the client tree to the server's opaque view so the
  // learner can toggle the contrast on and off in place.
  renderTree('clientTree', {
    view: serverViewMode ? 'server' : 'client',
    highlightPath: highlightLeaf,
    focusBlock,
  });
  renderPositionMap(focusBlock);
  renderEvictionInvariant(highlightLeaf, focusBlock);
}

/**
 * Explain, per on-path bucket, why each real block is legally allowed there:
 * its assigned leaf shares exactly the buckets down to the lowest common node
 * with the write-back path, so that node is the deepest it can occupy.
 */
const EVICTION_PLACEHOLDER =
  '<p class="pm-caption" style="margin-top:0.6rem">Run an access to see, block by block, why each on-path block landed where it did.</p>';

function renderEvictionInvariant(highlightLeaf: number | null, focusBlock: number | null): void {
  const el = document.getElementById('evictionInvariant');
  if (!el) return;
  // No path highlighted means there is nothing to explain — after a re-init the
  // previous ORAM's placement is gone, and leaving those rows up would keep a
  // block→bucket explanation on screen for a position map that no longer exists.
  if (!client || highlightLeaf === null) {
    el.innerHTML = EVICTION_PLACEHOLDER;
    return;
  }

  const { perLevel } = reconstructPathPlacement(client, highlightLeaf);
  const pathBuckets = getPathBucketIds(highlightLeaf); // index = level, value = bucketId
  const lines: string[] = [];
  for (let level = perLevel.length - 1; level >= 0; level--) {
    const bucketId = pathBuckets[level];
    for (const bid of perLevel[level] ?? []) {
      const blockLeaf = client.positionMap.get(bid) ?? 0;
      const depthNote =
        level === L
          ? `shares this leaf (leaf ${blockLeaf}) with the path — can sink to the leaf bucket`
          : `leaf ${blockLeaf} and path-leaf ${highlightLeaf} first split below B${bucketId} — so it can go no deeper than B${bucketId}`;
      const focusCls = focusBlock === bid ? ' ei-focus' : '';
      lines.push(
        `<li class="ei-row${focusCls}"><span class="ei-block">B${bid}</span> → <span class="ei-bucket">B${bucketId}</span> <span class="ei-note">${depthNote}</span></li>`,
      );
    }
  }
  if (lines.length === 0) {
    el.innerHTML = `<p class="pm-caption" style="margin-top:0.6rem">This path currently holds only dummy blocks — nothing real to evict here.</p>`;
    return;
  }
  el.innerHTML = `<ul class="ei-list" aria-label="Eviction legality for each on-path block">${lines.join('')}</ul>`;
}

/**
 * Shared post-access rendering + the "watch the block move" narration.
 *
 * The honest Path ORAM motion: the client reads the OLD path P(oldLeaf), remaps
 * the block to newLeaf, then evicts along P(oldLeaf). The block therefore settles
 * back into P(oldLeaf) — at the deepest bucket shared by oldLeaf and newLeaf —
 * NOT onto the full new path yet. Its position-map entry now points to newLeaf,
 * so its *next* access will read an uncorrelated path. We show exactly that:
 * highlight the old path (where the block physically is), pulse the block's chip
 * in its real landing bucket, and re-randomise its row in the position map.
 */
function afterAccess(blockId: number, oldLeaf: number): void {
  if (!client) return;
  const newLeaf = client.positionMap.get(blockId) ?? 0;
  lastRemap = { block: blockId, oldLeaf, newLeaf };
  lastAccessedLeaf = oldLeaf;

  // Highlight P(oldLeaf) — the path the server just saw and where the block now
  // rests — and pulse the block's chip in its actual landing bucket.
  renderBothTrees(oldLeaf, blockId);
  updateTreeStats('treeStats');
  renderStash('stashDisplay');
}

/**
 * The Path-based exhibits share one server module, so pressing Initialize in
 * any of them (including the comparison) discards the tree the others were using. The leftover client keeps
 * a valid key and a plausible position map, so its next read used to come back
 * as 32 zero bytes and get printed as `= "(empty)"` — a confident wrong answer
 * for a block this exhibit had just shown holding data. `access()` now refuses
 * that access; this turns the refusal into a named on-screen state and parks the
 * exhibit until it is re-initialized.
 */
function reportVaultReplaced(statusId: string, disableIds: string[]): void {
  stopAutoRun();
  for (const id of disableIds) setDisabled(id, true);
  $(statusId).textContent =
    'Vault replaced — another exhibit initialized the shared server, so this exhibit\'s encrypted tree is gone. ' +
    'No result is shown because any result would be wrong: the old key decrypts nothing on the new tree. ' +
    'Press Initialize to provision a fresh vault here.';
}

const TREE_ACCESS_BTNS = ['stepBtn', 'autoBtn', 'readBlockBtn', 'writeBlockBtn'];

/** True if the error was a replaced vault, after reporting it in exhibit 1. */
function handleTreeAccessError(e: unknown): void {
  if (e instanceof StaleVaultError) {
    reportVaultReplaced('treeStatus', TREE_ACCESS_BTNS);
    renderEvictionInvariant(null, null);
    return;
  }
  $('treeStatus').textContent = `Error: ${e}`;
}

async function stepRandomAccess(): Promise<void> {
  if (!client || treeAccessInFlight) return;
  treeAccessInFlight = true;
  try {
    const activeClient = client;
    const blockId = cryptoRandInt(N);
    $('treeStatus').textContent = `Accessing block ${blockId}…`;
    const oldLeaf = activeClient.positionMap.get(blockId) ?? 0;
    await read(activeClient, blockId);
    if (client !== activeClient) throw new StaleVaultError();
    const newLeaf = activeClient.positionMap.get(blockId) ?? 0;
    $('treeStatus').textContent = `READ(block ${blockId}): server read+wrote path P(${oldLeaf}); block re-randomised to leaf ${newLeaf} (its next access reads that path). Stash: ${getStashSize(activeClient)}.`;
    afterAccess(blockId, oldLeaf);
  } catch (e) {
    handleTreeAccessError(e);
  } finally {
    treeAccessInFlight = false;
  }
}

/** Validate the block-id input against [0, N). Returns null if invalid. */
function readBlockIdInput(): number | null {
  const raw = ($('blockIdInput') as HTMLInputElement).value.trim();
  // Number('') is 0, so an empty field used to silently mean "block 0" and the
  // page would report an access the user never asked for.
  if (raw === '') return null;
  const id = Number(raw);
  if (!Number.isInteger(id) || id < 0 || id >= N) return null;
  return id;
}

async function writeCustomBlock(): Promise<void> {
  if (!client || treeAccessInFlight) return;
  stopAutoRun();
  const blockId = readBlockIdInput();
  if (blockId === null) {
    $('treeStatus').textContent = `Invalid block ID — enter an integer in [0, ${N - 1}].`;
    return;
  }
  const value = ($('blockValueInput') as HTMLInputElement).value;
  const activeClient = client;
  const oldLeaf = activeClient.positionMap.get(blockId) ?? 0;
  treeAccessInFlight = true;
  try {
    await write(activeClient, blockId, textToBytes(value));
    if (client !== activeClient) throw new StaleVaultError();
    const newLeaf = activeClient.positionMap.get(blockId) ?? 0;
    $('treeStatus').textContent = `WRITE(block ${blockId} = "${value || '(empty)'}"): server read+wrote path P(${oldLeaf}); block re-randomised to leaf ${newLeaf} (its next access reads that path). Stash: ${getStashSize(activeClient)}.`;
    afterAccess(blockId, oldLeaf);
  } catch (e) {
    handleTreeAccessError(e);
  } finally {
    treeAccessInFlight = false;
  }
}

async function readCustomBlock(): Promise<void> {
  if (!client || treeAccessInFlight) return;
  stopAutoRun();
  const blockId = readBlockIdInput();
  if (blockId === null) {
    $('treeStatus').textContent = `Invalid block ID — enter an integer in [0, ${N - 1}].`;
    return;
  }
  const activeClient = client;
  const oldLeaf = activeClient.positionMap.get(blockId) ?? 0;
  treeAccessInFlight = true;
  try {
    const data = await read(activeClient, blockId);
    if (client !== activeClient) throw new StaleVaultError();
    const newLeaf = activeClient.positionMap.get(blockId) ?? 0;
    $('treeStatus').textContent = `READ(block ${blockId}) = "${bytesToText(data)}": server read+wrote path P(${oldLeaf}); block re-randomised to leaf ${newLeaf} (its next access reads that path). Stash: ${getStashSize(activeClient)}.`;
    afterAccess(blockId, oldLeaf);
  } catch (e) {
    handleTreeAccessError(e);
  } finally {
    treeAccessInFlight = false;
  }
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
      appendWalkLog(`         Under nonce-respecting AES-GCM assumptions, the server cannot link individual rewritten plaintext blocks to their prior ciphertexts.`);
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
        $('walkStatus').textContent = `Complete! ${walkOp === 'read' ? `Block 5 = "${displayData}"` : 'Block 5 written.'} Its map entry is now leaf ${actualNewLeaf}; this access wrote it to the old path at a bucket shared with that new leaf.`;
        setDisabled('walkNextBtn', true);
      } catch (e) {
        if (e instanceof StaleVaultError) {
          reportVaultReplaced('walkStatus', ['walkReadBtn', 'walkWriteBtn', 'walkNextBtn']);
          $('stepDetail6').textContent = 'Aborted — the vault this walkthrough was reading is gone.';
        } else {
          $('walkStatus').textContent = `Error: ${e}`;
        }
      }
      break;
    }
    default:
      break;
  }
}

// ─── Exhibit 0 — Replay the medical scenario through ORAM ────────────────────
// The same logical accesses as the static attack log (three morning reads of the
// same record, then a Friday cluster), mapped into our N-block toy vault. Run
// through a REAL ORAM so the server-visible paths are genuine random draws.
const REPLAY_SCENARIO: Array<{ when: string; loc: number }> = [
  { when: 'Mon 09:00', loc: 42 },
  { when: 'Tue 09:00', loc: 42 },
  { when: 'Wed 09:00', loc: 42 },
  { when: 'Fri 14:07', loc: 8 },
  { when: 'Fri 14:08', loc: 15 },
  { when: 'Fri 14:09', loc: 23 },
];

async function replayScenario(): Promise<void> {
  setDisabled('replayBtn', true);
  $('replayStatus').textContent = 'Initializing a fresh ORAM and replaying six accesses…';
  try {
    const rc = await initializeORAM(N, Z);
    const serverLines: string[] = [];
    const clientLines: string[] = [];
    for (const step of REPLAY_SCENARIO) {
      const blockId = step.loc % N; // map the medical location into our toy vault
      const oldLeaf = rc.positionMap.get(blockId) ?? 0;
      await read(rc, blockId);
      const pad = (s: string | number, n: number): string => String(s).padStart(n);
      serverLines.push(`${step.when}  READ path ${pad(oldLeaf, 2)}  (read+write, ${(L + 1) * Z} blobs)`);
      clientLines.push(`${step.when}  READ block ${pad(blockId, 2)}  (record #${step.loc})`);
    }
    const morningDistinctPaths = new Set(
      serverLines.slice(0, 3).map((l) => l.replace(/.*READ path\s+(\d+).*/, '$1')),
    ).size;
    $('replayServerLog').textContent =
      serverLines.join('\n') +
      `\n\nThree identical morning reads of record #42 → independently sampled paths (${morningDistinctPaths} distinct this run).\n` +
      `The Friday paths do not reveal which records were read; the three-access timing cluster remains visible.`;
    $('replayClientLog').textContent =
      clientLines.join('\n') +
      `\n\nSame six logical accesses as the attack above —\nblock 10 read three times, then blocks 8, 15, 7.`;
    $('replayStatus').textContent =
      `Done. The repeated reads produced ${morningDistinctPaths} distinct server paths this run. Collisions are possible; each path is still an independent random draw.`;
  } catch (e) {
    $('replayStatus').textContent = `Error: ${e}`;
  } finally {
    setDisabled('replayBtn', false);
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

    try {
      if (op === 'read') {
        await read(advClient, blockId);
      } else {
        const data = new Uint8Array(32);
        crypto.getRandomValues(data);
        await write(advClient, blockId, data);
      }
    } catch (e) {
      if (e instanceof StaleVaultError) {
        reportVaultReplaced('advStatus', ['advRunBtn']);
      } else {
        $('advStatus').textContent = `Error: ${e}`;
        setDisabled('advRunBtn', false);
      }
      return;
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
  const analysis = analyzePathUniformity(pathCounts, numLeaves, accessHistory.length);
  const { expectedPerLeaf, chiSq, verdict, degreesOfFreedom, criticalValue } = analysis;

  $('advAnalysis').innerHTML = `
    <div class="panel-label server">Server Path Distribution — ${accessHistory.length} accesses</div>
    <div class="scenario-wrap" role="group" tabindex="0" aria-label="Path access distribution statistics"><div class="scenario">${distStr}

Expected: ~${expectedPerLeaf.toFixed(1)} per leaf (uniform target)
χ² goodness-of-fit vs. uniform: ${chiSq.toFixed(2)}  (df=${degreesOfFreedom}, critical=${criticalValue} at α=0.05)
Verdict: ${verdict}

Each bar shows relative frequency. With more accesses, bars converge.
Path ORAM predicts independent uniform paths; this test reports only what this sample supports.</div></div>`;

  $('advStatus').textContent = `Done. ${accessHistory.length} total accesses. ${verdict}`;
  setDisabled('advRunBtn', false);
}

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function renderORAMComparison(result: ORAMComparisonResult): void {
  $('hierComparisonBody').innerHTML = result.rows.map((row) => {
    const operation = `${row.operation.toUpperCase()} block ${row.blockId}`;
    const levels = row.hierarchyRebuildLevels.map((level) => `L${level}`).join(' → ');
    return `<tr>
      <td>${row.index}</td>
      <td>${operation}</td>
      <td><code>${escapeHtml(row.result)}</code></td>
      <td>${row.pathReadSlots} read + ${row.pathWriteSlots} write = ${row.pathTotalSlots}</td>
      <td>L${row.hierarchyFoundLevel}</td>
      <td>${row.hierarchyLookupSlots}</td>
      <td>${levels} / ${row.hierarchyRebuildSlots}</td>
      <td>${row.hierarchyTotalSlots}</td>
    </tr>`;
  }).join('');
  $('hierSummary').innerHTML = `
    <div class="card panel-client">
      <div class="panel-label client">Independent verification passed</div>
      <p><strong>${result.verificationBlocks}/${result.verificationBlocks} blocks</strong> matched a separate reference map after the displayed workload in both implementations. Every displayed row came from that run, not a hardcoded result table.</p>
    </div>
    <div class="card">
      <div class="panel-label">Measured state and storage</div>
      <p>Path: ${result.path.serverSlots} server slots; trusted state includes its AES key, ${result.path.clientPositionEntries} position entries and a finite stash; traffic is ${result.path.fixedRoundTripSlots} slots per access. Hierarchy: ${result.hierarchy.serverSlots} server slots; trusted state includes its AES key, ${result.hierarchy.hashKeys} hash keys, ${result.hierarchy.occupancyBits} occupancy bits, one counter and up to ${result.hierarchy.transientRebuildBlocks} transient rebuild blocks in this run.</p>
    </div>`;
}

async function runComparisonExhibit(): Promise<void> {
  if (comparisonInFlight) return;
  comparisonInFlight = true;
  setDisabled('hierRunBtn', true);
  $('hierStatus').textContent = 'Running both real constructions and clearing any earlier result…';
  $('hierComparisonBody').innerHTML = '<tr><td colspan="8">Current run in progress.</td></tr>';
  $('hierSummary').innerHTML = '<div class="card"><div class="panel-label">Verification in progress</div><p>No earlier verdict is retained while a fresh run is active.</p></div>';
  try {
    const result = await runORAMComparison();
    renderORAMComparison(result);
    $('hierStatus').textContent =
      `Done: ${result.rows.length} workload operations measured and ${result.verificationBlocks}/${result.verificationBlocks} blocks independently verified in both constructions.`;
  } catch (error) {
    $('hierComparisonBody').innerHTML = '<tr><td colspan="8">Run failed; no traffic verdict retained.</td></tr>';
    $('hierSummary').innerHTML = '<div class="card"><div class="panel-label">Verification refused</div><p>The run did not complete, so no result is claimed.</p></div>';
    $('hierStatus').textContent = `Error: ${error instanceof Error ? error.message : String(error)}`;
  } finally {
    comparisonInFlight = false;
    setDisabled('hierRunBtn', false);
  }
}

function renderSkippedProbeControl(result: SkippedProbeControlResult): void {
  $('hierLeakResults').innerHTML = `
    <div class="card panel-client">
      <div class="panel-label client">Fixed all-level schedule</div>
      <p>Returned <code>${escapeHtml(result.fixedResult)}</code> for block ${result.blockId}; found it at L${result.fixedFoundLevel}, but still issued ${result.fixedProbeCount} probes and read ${result.fixedLookupReadSlots} lookup slots. The count does not reveal that this run hit in the cache.</p>
    </div>
    <div class="card panel-server">
      <div class="panel-label server">Insecure skip-after-hit policy</div>
      <p>Returned the same <code>${escapeHtml(result.skippedResult)}</code>, but stopped after ${result.skippedProbeCount} probe and ${result.skippedLookupReadSlots} lookup slot. The storage observer learns the hit was at L${result.skippedFoundLevel}; correct plaintext did not imply an oblivious access.</p>
    </div>`;
}

async function runHierarchyLeakControl(): Promise<void> {
  if (skippedControlInFlight) return;
  skippedControlInFlight = true;
  setDisabled('hierLeakBtn', true);
  $('hierLeakStatus').textContent = 'Running fixed and intentionally insecure schedules…';
  $('hierLeakResults').innerHTML = '<div class="card"><div class="panel-label">Control in progress</div><p>No earlier verdict is retained while a fresh run is active.</p></div>';
  try {
    const result = await runSkippedProbeControl();
    renderSkippedProbeControl(result);
    $('hierLeakStatus').textContent =
      `Leak reproduced: equal plaintext, but fixed ${result.fixedLookupReadSlots}-slot and skipped ${result.skippedLookupReadSlots}-slot lookup traces.`;
  } catch (error) {
    $('hierLeakResults').innerHTML = '<div class="card"><div class="panel-label">Control refused</div><p>The run did not complete, so no leak verdict is claimed.</p></div>';
    $('hierLeakStatus').textContent = `Error: ${error instanceof Error ? error.message : String(error)}`;
  } finally {
    skippedControlInFlight = false;
    setDisabled('hierLeakBtn', false);
  }
}

// ─── Tab Navigation (ARIA + keyboard) ────────────────────────────────────────
// Module-level so a caveats link in one exhibit can jump to the caveats exhibit.
let activateTabExternal: ((idx: number) => void) | null = null;

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

  activateTabExternal = (idx: number): void => {
    activateTab(idx);
    tabs[idx]?.focus();
  };
}

// ─── Exhibit 6 logic ─────────────────────────────────────────────────────────
//
// Every figure rendered below is returned by one of the scenario runners in
// `src/multiclient/scenario.ts`, computed on the spot from a freshly
// provisioned store. Nothing is a stored expected answer, and starting one
// scenario retires the output of the others so no two panels can ever be
// showing results from different runs.

type McPanel = 'baseline' | 'naive' | 'collusion' | 'controls';

let mcInFlight = false;

function mcEsc(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

const MC_PANEL_IDS: Record<McPanel, { status: string; reset: () => void }> = {
  baseline: {
    status: 'mcBaselineStatus',
    reset: () => {
      $('mcBaselineBody').innerHTML =
        '<tr><td colspan="6">Retired: another scenario was run. Press the button above to recompute.</td></tr>';
    },
  },
  naive: {
    status: 'mcNaiveStatus',
    reset: () => {
      $('mcNaiveResults').innerHTML =
        '<div class="card panel-server"><div class="panel-label server">Cross-client exposure</div><p>Retired: another scenario was run.</p></div>' +
        '<div class="card panel-server"><div class="panel-label server">Divergent state</div><p>Retired: another scenario was run.</p></div>';
    },
  },
  collusion: {
    status: 'mcCollusionStatus',
    reset: () => {
      $('mcCollusionBody').innerHTML =
        '<tr><td colspan="5">Retired: another scenario was run. Press the button above to recompute.</td></tr>';
      $('mcCollusionNote').innerHTML = '<p>Retired: another scenario was run.</p>';
    },
  },
  controls: {
    status: 'mcControlsStatus',
    reset: () => {
      $('mcControlsBody').innerHTML =
        '<tr><td colspan="4">Retired: another scenario was run. Press the button above to recompute.</td></tr>';
      $('mcViews').innerHTML =
        '<div class="card panel-server"><div class="panel-label server">What the server sees</div><p>Retired: another scenario was run.</p></div>' +
        '<div class="card panel-client"><div class="panel-label client">Omniscient teaching view</div><p>Retired: another scenario was run.</p></div>';
    },
  },
};

const MC_BUTTONS = ['mcBaselineBtn', 'mcNaiveBtn', 'mcCollusionBtn', 'mcControlsBtn'];

/**
 * Clear every other panel before a run.
 *
 * A result sitting next to inputs that did not produce it is the one thing
 * this exhibit must never show, so the other panels are emptied rather than
 * greyed out, and each says why it is empty.
 */
function mcRetireOthers(keep: McPanel): void {
  for (const panel of Object.keys(MC_PANEL_IDS) as McPanel[]) {
    if (panel === keep) continue;
    MC_PANEL_IDS[panel].reset();
    $(MC_PANEL_IDS[panel].status).textContent =
      'Retired: a different scenario was run. Press this scenario’s button to recompute it.';
  }
}

async function mcRun(panel: McPanel, label: string, body: () => Promise<string>): Promise<void> {
  if (mcInFlight) return;
  mcInFlight = true;
  MC_BUTTONS.forEach((id) => setDisabled(id, true));
  mcRetireOthers(panel);
  MC_PANEL_IDS[panel].reset();
  $(MC_PANEL_IDS[panel].status).textContent = `Running ${label}…`;
  try {
    $(MC_PANEL_IDS[panel].status).textContent = await body();
  } catch (e) {
    const error = e as Error;
    $(MC_PANEL_IDS[panel].status).textContent = `${label} failed: ${error.name}: ${error.message}`;
  } finally {
    mcInFlight = false;
    MC_BUTTONS.forEach((id) => setDisabled(id, false));
  }
}

async function runMcBaseline(): Promise<void> {
  await mcRun('baseline', 'the honest baseline', async () => {
    const report = await runBaseline();
    $('mcBaselineBody').innerHTML = report.rows
      .map(
        (row) =>
          `<tr><td>${mcEsc(row.client)}</td><td>${row.operation}</td><td>${row.index}</td>` +
          `<td>${MODE_WORDS[row.mode] ?? row.mode}</td>` +
          `<td>${row.outcome === 'released' ? 'released' : 'refused'}</td>` +
          `<td>${mcEsc(row.detail)}</td></tr>`,
      )
      .join('');
    const released = report.rows.filter((row) => row.outcome === 'released').length;
    const refused = report.rows.length - released;
    const audit =
      report.referenceMismatches.length === 0
        ? 'every one of the 16 entries matches the retained plaintext mirror'
        : `${report.referenceMismatches.length} entr${report.referenceMismatches.length === 1 ? 'y' : 'ies'} disagree with the mirror`;
    return (
      `${report.rows.length} attempts: ${released} released, ${refused} refused. ` +
      `${report.traffic.readSlots} encrypted slots read and ${report.traffic.writeSlots} written; ${audit}.`
    );
  });
}

async function runMcNaive(): Promise<void> {
  await mcRun('naive', 'the shared-key deployment', async () => {
    const report = await runNaiveSharing();
    const exposed = report.exposure.foreignPlaintext
      .map(({ entry, value }) => `entry ${entry} = “${mcEsc(value)}”`)
      .join('; ');
    const divergence = report.lostUpdate.diverged
      ? `<p>Given full but independent copies of the position map, ${report.lostUpdate.remapAttempts} ` +
        `genuine write${report.lostUpdate.remapAttempts === 1 ? '' : 's'} made the copies disagree: ` +
        `the clinician records entry ${report.lostUpdate.entry} at leaf ` +
        `${report.lostUpdate.clinicianLeaf} and billing still records leaf ` +
        `${report.lostUpdate.billingLeaf}. ${mcEsc(report.lostUpdate.billingDetail)}</p>` +
        `<p>After billing works through its own entries the clinician reads back ` +
        `“${mcEsc(report.lostUpdate.clinicianObserved ?? '')}” where it wrote ` +
        `“${mcEsc(report.lostUpdate.expected)}” &mdash; ` +
        `${report.lostUpdate.clinicianLost ? 'its update is gone' : 'its update survived this run'}.</p>`
      : `<p>Given full but independent copies of the position map, this bounded run tried ` +
        `${report.lostUpdate.remapAttempts} genuine writes. Every remap returned entry ` +
        `${report.lostUpdate.entry} to leaf ${report.lostUpdate.clinicianLeaf}, so the copies did ` +
        `not diverge and this run makes no lost-update claim. ${mcEsc(report.lostUpdate.billingDetail)}</p>`;
    $('mcNaiveResults').innerHTML =
      '<div class="card panel-server"><div class="panel-label server">Cross-client exposure</div>' +
      `<p>The billing client performed an ordinary authorised read of its own entry ${report.exposure.accessed}. ` +
      'A Path ORAM read transfers the whole root-to-leaf path, and with one shared key the client ' +
      `decrypts all of it. It obtained the clinician’s plaintext: ${exposed || 'nothing on this run'}.</p>` +
      '<p>No attack code is involved. This is the shipped <code>decryptPath</code> doing what it ' +
      'was written to do, with the key the naive deployment handed over.</p></div>' +
      '<div class="card panel-server"><div class="panel-label server">Divergent state</div>' +
      `<p>Told only about its own entries, the second client trips the shipped integrity check on ` +
      `honest data: <code>${mcEsc(report.unusable.error)}</code> on entry ` +
      `${report.unusable.offendingEntry ?? 'n/a'}, which belongs to the other client, while reading ` +
      `its own entry ${report.unusable.accessed}.</p>` +
      divergence +
      '</div>';
    const divergentSummary = report.lostUpdate.diverged
      ? `the two position maps diverged on entry ${report.lostUpdate.entry} after ` +
        `${report.lostUpdate.remapAttempts} genuine remap${report.lostUpdate.remapAttempts === 1 ? '' : 's'}`
      : `the bounded ${report.lostUpdate.remapAttempts}-remap position-map experiment did not diverge`;
    return (
      `Three outcomes computed against this lab’s own Path ORAM: ` +
      `${report.exposure.foreignEntriesDecrypted.length} foreign entr${report.exposure.foreignEntriesDecrypted.length === 1 ? 'y' : 'ies'} ` +
      `decrypted, ${report.unusable.error} on honest data, and ${divergentSummary}.`
    );
  });
}

async function runMcCollusion(): Promise<void> {
  await mcRun('collusion', 'the colluding-client attack', async () => {
    const report = await runCollusion(8);
    $('mcCollusionBody').innerHTML = report.observations
      .map(
        (observation, index) =>
          `<tr><td>${index + 1}</td><td>${observation.leafObserved}</td>` +
          `<td>${observation.candidates.join(', ')} (${observation.candidates.length} of 16)</td>` +
          `<td>${observation.actualIndex}</td>` +
          `<td>${observation.uniquelyIdentified ? 'yes' : 'no'}</td></tr>`,
      )
      .join('');
    $('mcCollusionNote').innerHTML =
      `<p>${mcEsc(report.method)}</p>` +
      `<p>Across ${report.trials} trials the accessed entry was in the candidate set ` +
      `<strong>${report.actualInCandidates} of ${report.trials}</strong> times, with a mean candidate ` +
      `set of ${report.meanCandidates.toFixed(2)} out of 16. Guessing from that set succeeds about ` +
      `${(report.collusionRate * 100).toFixed(0)}% of the time against ` +
      `${(report.baselineRate * 100).toFixed(1)}% for a uniform guess over all sixteen.</p>` +
      '<p>This is <strong>evidence consistent with</strong> the published bound, not a proof of it. ' +
      'Theorem 1 of IACR ePrint 2017/329 states that a multi-client ORAM accessing on average ' +
      '<code>o(n)</code> physical addresses per operation is not secure against malicious clients. ' +
      'One path access here touches five buckets of thirty-one. Closing this gap means the ' +
      '<code>&Omega;(n)</code> constructions of that paper or its trusted proxy, and this lesson ' +
      'implements neither.</p>';
    return (
      `${report.trials} trials: the accessed entry was among the candidates ${report.actualInCandidates} ` +
      `times, mean candidate set ${report.meanCandidates.toFixed(2)} of 16, narrowed to exactly one ` +
      `${report.uniquelyIdentified} times.`
    );
  });
}

interface McControlRow {
  control: string;
  expected: string;
  observed: string;
  pass: boolean;
}

async function runMcControls(): Promise<void> {
  await mcRun('controls', 'every control', async () => {
    const tamper = await runTamperControls();
    const rollback = await runRollbackControl();
    const concurrency = await runConcurrencyControl();
    const revocation = await runRevocationControl();
    const integrity = await runIntegrityExperiment();
    const trace = await runTraceShape();

    const rows: McControlRow[] = [
      {
        control: 'Tampered ciphertext in a stored slot',
        expected: 'EnvelopeAuthError',
        observed: tamper.ciphertextTamper.error,
        pass: tamper.ciphertextTamper.error === 'EnvelopeAuthError',
      },
      {
        control: 'Unauthorised write, read back by an honest client',
        expected: 'lands, then EntryVerificationError',
        observed: `${tamper.unauthorisedWrite.landed ? 'landed' : 'blocked'}, then ${tamper.unauthorisedWrite.readerError}`,
        pass:
          tamper.unauthorisedWrite.landed &&
          tamper.unauthorisedWrite.readerError === 'EntryVerificationError',
      },
      {
        control: 'Accountability: who broke the entry',
        expected: `client ${CLIENT_LABELS[1]}`,
        observed:
          tamper.unauthorisedWrite.blamed === null
            ? 'nobody'
            : (CLIENT_LABELS[tamper.unauthorisedWrite.blamed] ?? String(tamper.unauthorisedWrite.blamed)),
        pass: tamper.unauthorisedWrite.blamed === 1,
      },
      {
        control: 'Same forged entry with verification switched off',
        expected: 'accepted, which is why the rejection above is verification',
        observed: tamper.withoutVerification.accepted
          ? `accepted “${tamper.withoutVerification.value ?? ''}”`
          : 'rejected',
        pass: tamper.withoutVerification.accepted,
      },
      {
        control: 'Store rolls the bytes back under genuine signatures',
        expected: 'StaleEntryError',
        observed: rollback.refusedError,
        pass: rollback.refusedError === 'StaleEntryError',
      },
      {
        control: 'Same rollback with the freshness check switched off',
        expected: 'the stale value comes back',
        observed:
          rollback.staleValue === null
            ? 'refused anyway'
            : `“${mcEsc(rollback.staleValue)}” at version ${rollback.staleVersion}`,
        pass: rollback.staleValue !== null && rollback.staleValue !== rollback.writtenValue,
      },
      {
        control: 'Same rollback, read by a client with no prior version watermark',
        expected: 'stale version 1 is accepted; there is no global freshness head',
        observed:
          rollback.firstContactValue === null
            ? 'refused'
            : `“${mcEsc(rollback.firstContactValue)}” at version ${rollback.firstContactVersion}`,
        pass:
          rollback.firstContactValue !== null &&
          rollback.firstContactValue !== rollback.writtenValue &&
          rollback.firstContactVersion === 1,
      },
      {
        control: 'Overlapping access',
        expected: 'ConcurrencyRefusedError',
        observed: concurrency.refusedError,
        pass: concurrency.refusedError === 'ConcurrencyRefusedError',
      },
      {
        control: 'Overlapping writes with the refusal lifted',
        expected: 'an update is lost or the access fails',
        observed: concurrency.unsafe.lostUpdate
          ? `entry 0 reads back “${mcEsc(concurrency.unsafe.observedAfter ?? 'nothing')}”`
          : (concurrency.unsafe.error ?? 'no damage on this run'),
        pass: concurrency.unsafe.lostUpdate || concurrency.unsafe.error !== null,
      },
      {
        control: 'Read after a downgrade and key rotation',
        expected: 'AccessDeniedError',
        observed: revocation.afterError,
        pass: revocation.afterError === 'AccessDeniedError',
      },
      {
        control: 'ePrint 2020/1551 Figure 3 integrity experiment',
        expected: 'the malformed update lands and the adversary wins; integrity is not claimed',
        observed: integrity.adversaryWins
          ? 'the adversary WON after the honest reader refused the malformed update'
          : `mirror “${mcEsc(integrity.mirrorValue)}” equals the authorised read`,
        pass:
          integrity.attackLanded &&
          integrity.adversaryWins &&
          integrity.readerHasReadAccess &&
          integrity.noCorruptedWriter,
      },
      {
        control: 'Server-visible data shape and direct-log synchronization',
        expected: 'one fixed data shape; variable log catch-up is exposed',
        observed:
          `${trace.perAccess.length} accesses, ${trace.uniformShape ? 'one' : 'multiple'} data ` +
          `shape(s), ${trace.fullShapeCount} full transcript shapes`,
        pass: trace.uniformShape && !trace.fullShapeUniform,
      },
    ];

    $('mcControlsBody').innerHTML = rows
      .map(
        (row) =>
          `<tr><td>${mcEsc(row.control)}</td><td>${mcEsc(row.expected)}</td>` +
          `<td>${row.observed}</td><td>${row.pass ? 'as expected' : 'UNEXPECTED'}</td></tr>`,
      )
      .join('');

    const first = trace.perAccess[0];
    const logReadCounts = trace.perAccess.map((row) => row.logRecordsRead);
    const minLogRead = Math.min(...logReadCounts);
    const maxLogRead = Math.max(...logReadCounts);
    $('mcViews').innerHTML =
      '<div class="card panel-server"><div class="panel-label server">What the server sees</div>' +
      `<p>One ORAM data access, excluding the separate log channel: <code id="mcSignature" style="word-break:break-word;overflow-wrap:anywhere;">${mcEsc(trace.shapeSignature)}</code></p>` +
      `<p>${trace.perAccess.length} accesses by three different clients, authorized reads and writes ` +
      `plus ${trace.perAccess.filter((row) => row.outcome === 'refused').length} authorization refusals, over ` +
      `different entries, produced ${trace.uniformShape ? 'exactly one' : 'more than one'} data-event ` +
      `shape, ${first?.readSlots ?? 0} encrypted data slots in and ${first?.writeSlots ?? 0} out every time. ` +
      `The leaf is the only field that varies in this compact shape summary, and it varied over ` +
      `${trace.distinctLeaves} values.</p>` +
      `<p>The full transcript is <strong>not</strong> fixed: direct log catch-up returned ` +
      `${minLogRead}&ndash;${maxLogRead} signed path records and exposed each requested starting ` +
      `sequence, producing ${trace.fullShapeCount} full transcript shapes. This is state/recency ` +
      `leakage from the non-oblivious synchronization adaptation, not ORAM traffic.</p>` +
      '<p>No logical entry index, no client identity and no version appears in any data event. The ' +
      'upload log is the one place a client identity is visible, because its records are ' +
      'client-signed &mdash; the anonymity this construction trades for accountability.</p></div>' +
      '<div class="card panel-client"><div class="panel-label client">Omniscient teaching view</div>' +
      `<p>The same accesses, with what the server cannot have: ` +
      trace.perAccess
        .map(
          (row) =>
            `${mcEsc(row.client)} ${row.operation} entry ${row.index} ` +
            `via leaf ${row.leaf} (${row.outcome})`,
        )
        .join('; ') +
      '.</p>' +
      `<p>Revocation, stated honestly: the contractor read “${mcEsc(revocation.beforeValue)}” from ` +
      `entry ${revocation.entry} before being downgraded. The owner rotated the entry key to version ` +
      `${revocation.rotatedVersion} for ${revocation.remainingReaders.length} remaining readers, and ` +
      `the contractor is now refused. It still holds what it already read; rotation stops future ` +
      'reads and retracts nothing.</p></div>';

    const failures = rows.filter((row) => !row.pass);
    return failures.length === 0
      ? `All ${rows.length} controls behaved as expected on this run.`
      : `${failures.length} of ${rows.length} controls did NOT behave as expected: ` +
        failures.map((row) => row.control).join('; ') + '.';
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
    // When ON, the client tree collapses to the server's opaque view so the
    // learner can flip the block-ID contrast on and off in place.
    btn('serverViewBtn').textContent = serverViewMode ? 'Reveal client block IDs' : 'Hide block IDs (server view)';
    btn('serverViewBtn').setAttribute('aria-pressed', String(serverViewMode));
    renderBothTrees(lastAccessedLeaf, lastRemap?.block ?? null);
  });
  $('writeBlockBtn').addEventListener('click', () => void writeCustomBlock());
  $('readBlockBtn').addEventListener('click', () => void readCustomBlock());

  // Exhibit 2
  $('walkInitBtn').addEventListener('click', () => void initWalk());
  $('walkReadBtn').addEventListener('click', () => void startWalkThrough('read'));
  $('walkWriteBtn').addEventListener('click', () => void startWalkThrough('write'));
  $('walkNextBtn').addEventListener('click', () => void advanceWalkStep());

  // Exhibit 0 replay
  $('replayBtn').addEventListener('click', () => void replayScenario());

  // Exhibit 0 → caveats live in exhibit 5 (zero-based panel 4); switch first.
  const ex0Caveats = document.getElementById('ex0CaveatsLink');
  if (ex0Caveats) {
    ex0Caveats.addEventListener('click', (e) => {
      e.preventDefault();
      activateTabExternal?.(4);
      document.getElementById('caveats')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  }

  // Exhibit 3
  $('advInitBtn').addEventListener('click', () => void initAdv());
  $('advRunBtn').addEventListener('click', () => void runAdvAccesses());
  $('advClearBtn').addEventListener('click', () => {
    $('advServerLog').innerHTML = '';
    $('advClientLog').innerHTML = '';
    $('advAnalysis').innerHTML = '<p style="color:var(--text2)">Log cleared.</p>';
    accessHistory.length = 0;
  });

  // Exhibit 6
  $('hierRunBtn').addEventListener('click', () => void runComparisonExhibit());
  $('hierLeakBtn').addEventListener('click', () => void runHierarchyLeakControl());

  // Exhibit 7 — mutually distrustful clients
  $('mcBaselineBtn').addEventListener('click', () => void runMcBaseline());
  $('mcNaiveBtn').addEventListener('click', () => void runMcNaive());
  $('mcCollusionBtn').addEventListener('click', () => void runMcCollusion());
  $('mcControlsBtn').addEventListener('click', () => void runMcControls());
}

// ─── Entry Point ─────────────────────────────────────────────────────────────
buildShell();
setupTabs();
wireButtons();
