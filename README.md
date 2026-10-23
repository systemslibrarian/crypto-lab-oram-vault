# crypto-lab-oram-vault

## What It Is

**Browser-based Path ORAM demo** implementing the protocol from Stefanov et al. "Path ORAM: An Extremely Simple Oblivious RAM Protocol" (CCS 2013, JACM 2018).

A fully interactive browser demo of Path ORAM — an Oblivious RAM construction that hides which logical block a client accesses from a storage server in the protocol's stated model. Encryption hides data contents; Path ORAM randomizes and rewrites a full tree path so physical storage locations do not reveal the logical address. Related ORAM research includes secure-processor prototypes, SGX memory/file systems, and oblivious databases, but those systems do not all use Path ORAM.

The demo separates client and server APIs: the server module stores fixed-size encrypted blobs and receives whole-path read/write requests, never logical block IDs, the position map, or stash contents. This is an explanatory module boundary inside one browser page, not process or cryptographic isolation. Blocks use AES-256-GCM through Web Crypto; a private per-key counter gives every encryption under that key a distinct 96-bit nonce, and random leaf assignments use `crypto.getRandomValues`.

**Parameters:** N=16 blocks, Z=4 bucket size, L=4 tree height, 32-byte blocks, 12-byte GCM nonces.

## When to Use It

- Understanding why encryption hides contents but not access patterns
- Comparing the restricted 1996 Goldreich–Ostrovsky lower bound with the general online Ω(log N) lower bound proved by Larsen–Nielsen (2018)
- Evaluating ORAM for healthcare record systems, SGX enclaves, cloud storage
- Visualizing how the Path ORAM tree + stash + position map work together
- Comparing ORAM cost vs. alternatives (PIR, TEE, differential privacy)
- Do NOT use for production — use a maintained library (PathORAM C++, Go equivalents); this is educational and runs in a browser.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-oram-vault](https://systemslibrarian.github.io/crypto-lab-oram-vault/)**

The demo presents five exhibits: the access-pattern attack and side-channel threat model — with a one-click replay that runs the same Monday/Tuesday/Friday logical accesses through a live ORAM, removing record identity from the path trace while leaving the timing burst visible; an interactive binary tree contrasting the server's encrypted view with the client's view; a step-by-step READ/WRITE trace; a side-by-side adversary/client log; and a costs/when-to-use panel. The tree includes a live block → leaf position map and an eviction-legality explanation. Privacy claims are scoped to logical-address hiding against a semi-honest storage server and link to the residual-leakage caveats.

## What Can Go Wrong

- **Finite-stash failure** remains possible. Its probability depends on bucket size and the provisioned stash capacity; recursion solves the position-map storage problem, not stash overflow.
- **Timing and termination leakage** remains. This browser code is not constant-time and does not schedule or pad application operations.
- **Position map is O(N).** For large N, the position map doesn't fit on the client. Recursive ORAM stores it in another ORAM instance.
- **The module boundary is informational, not isolation.** Client and server code share one page; a malicious same-origin script can inspect client state.
- **No path freshness/completeness proof.** AES-GCM now rejects malformed or modified individual blobs, and missing target blocks fail closed, but a malicious server can still replay or omit valid data. Path ORAM §6.4 describes a Merkle-tree extension for integrity with freshness; Onion ORAM describes a malicious-server construction. Ring ORAM is a different bandwidth-optimized construction, not a malicious-security layer for this demo.
- **Side-channels in the browser.** Cache timing, allocation and garbage collection can leak information. A deployment must separately engineer the client, scheduling, padding and hardware for its side-channel threat model.

## Real-World Usage

- Introduced by Stefanov, van Dijk, Shi, Fletcher, Ren, Yu, and Devadas at CCS 2013; extended JACM 2018.
- Ascend and PHANTOM are ORAM-backed secure-processor research prototypes; neither is Intel SGX.
- ZeroTrace evaluated Path ORAM and Circuit ORAM on Intel SGX, while OBLIVIATE adapted ORAM for SGX file access.
- Obladi is related oblivious-OLTP work but builds on Ring ORAM, not Path ORAM.
- Goldreich–Ostrovsky's 1996 Ω(log N) lower bound applied to statistically secure balls-in-bins ORAMs; Larsen–Nielsen proved the general online computational bound in 2018. OptORAMa supplied the first asymptotically optimal general ORAM in 2020.
- The 16-line pseudocode makes Path ORAM the simplest practical ORAM construction.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-oram-vault
cd crypto-lab-oram-vault
npm install
npm run dev
```

## Related Demos

- [crypto-lab-oblivious-shelf](https://systemslibrarian.github.io/crypto-lab-oblivious-shelf/) — 2-server IT-PIR hides a single query index instead of access patterns.
- [crypto-lab-patron-shield](https://systemslibrarian.github.io/crypto-lab-patron-shield/) — IT-PIR applied to library catalog privacy.
- [crypto-lab-psi-gate](https://systemslibrarian.github.io/crypto-lab-psi-gate/) — private set intersection for contact discovery.
- [crypto-lab-silent-tally](https://systemslibrarian.github.io/crypto-lab-silent-tally/) — Shamir-based MPC secure sum.

## Five Exhibits

1. **Why Encryption Alone Isn't Enough** — the access-pattern attack, side-channel threat model, what ORAM prevents, and a one-click replay showing independent random paths while the access-count/timing cluster remains visible
2. **Tree Visualization** — interactive binary tree showing server view (identical encrypted blobs) vs. client view (real block IDs reconstructed from the position map on the highlighted path); a live block → leaf position-map table that highlights and re-randomizes the accessed row; an eviction-legality explainer showing why each on-path block may rest only in buckets its assigned leaf shares with the write-back path; live path highlighting during accesses
3. **Access Walkthrough** — step-by-step trace of a single READ or WRITE: position-map lookup, re-randomization, path read, stash update, greedy eviction, write-back
4. **Adversary vs. Client** — side-by-side log of what the server observes (uniform random paths) vs. what the client actually did (specific block accesses)
5. **Costs and When to Use** — bandwidth overhead table, use-case guide, research-system distinctions, cross-links to related labs

## Protocol Implementation

Implements the core access shape of Algorithm 1 from the 2018 JACM paper, with added runtime validation, serialized client operations, authenticated-block failure handling, and generation checks for the demo's singleton server:

```
Access(op, a, data*):
  1. x ← position[a]
  2. position[a] ← uniform random leaf
  3. Read path P(x) from server
  4. Decrypt all blocks → add real blocks to stash
  5. if READ: data ← stash[a]
     if WRITE: stash[a] ← data*
  6. Greedy eviction: write back path P(x) with fresh-nonce encryption
  7. Return data
```

Every access reads AND writes a full path. The position map is re-randomized
before the old path is read and written back. Block re-encryption uses a private
per-key nonce prefix and monotonic counter, so the supported 2³² encryptions
under one key cannot reuse a GCM nonce.

## Testing

The protocol modules ship with a Vitest suite (`npm test`) that asserts both the
**correctness** and the **security properties** the demo claims — not just that the
code runs:

- **Encryption** — AES-256-GCM round-trips; a fresh 96-bit nonce per encryption (no
  reuse); dummy blocks are byte-shaped like real blocks yet decrypt to `null`;
  tampered ciphertext and wrong-key blocks are rejected by the GCM tag.
- **Correctness and boundaries** — every block is physically present exactly once
  after initialization; read-after-write, last-write-wins, a 200-step reference
  workload, serialized concurrent calls, copied return values, fixed-size server
  payloads, atomic path writes, and fail-closed missing/tampered blocks.
- **Obliviousness** — every access is exactly one full path read + one full path
  write; the server log holds only `{bucketId, operation, timestamp}` (never block
  ids); a READ and a WRITE produce the same API-operation and byte-length footprint; the accessed
  block is re-randomized to a fresh leaf each access; repeatedly hitting one block
  yields a near-uniform path distribution (χ² goodness-of-fit, df=15).
- **Bounded stash** — the high-water mark stays well within bound across a
  1000-access workload (the live demo surfaces this as the "Stash Peak" stat).
- **UI smoke** — `main.ts` boots under happy-dom with every wired control resolving,
  tab switching works, and a READ flows end-to-end and renders the tree.

```bash
npm run typecheck   # tsc --noEmit over src + tests
npm test            # vitest run (48 tests)
npm run test:workflow
npm run test:coverage
```

CI (`.github/workflows/deploy.yml`) runs clean-install, audit, type-check, unit,
workflow-policy and build gates on Node 22/24/26, then browser claim/accessibility
tests. Only the no-checkout deploy job receives Pages/OIDC authority.

## Stack

Vite · TypeScript strict · Vanilla CSS · Web Crypto API · Vitest · GitHub Pages

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
