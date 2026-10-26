# crypto-lab-oram-vault

## What It Is

**Browser-based ORAM lab** implementing Path ORAM from Stefanov et al. "Path ORAM: An Extremely Simple Oblivious RAM Protocol" (CCS 2013, JACM 2018) and a bounded hierarchical-ORAM teaching adaptation grounded in Alibi §2.5/Figure 2 and Goodrich–Mitzenmacher §5/Figure 2.

A fully interactive browser demo of Path ORAM — an Oblivious RAM construction that hides which logical block a client accesses from a storage server in the protocol's stated model. Encryption hides data contents; Path ORAM randomizes and rewrites a full tree path so physical storage locations do not reveal the logical address. Related ORAM research includes secure-processor prototypes, SGX memory/file systems, and oblivious databases, but those systems do not all use Path ORAM.

The demo separates client and server APIs: the server module stores fixed-size encrypted blobs and receives whole-path read/write requests, never logical block IDs, the position map, or stash contents. This is an explanatory module boundary inside one browser page, not process or cryptographic isolation. Blocks use AES-256-GCM through Web Crypto; within the demo's encryption module, a private per-key counter gives every supported block encryption a distinct 96-bit nonce, and random leaf assignments use `crypto.getRandomValues`.

The hierarchical extension executes the generic scan/probe/delete/reinsert/rebuild schedule with a one-block cache and levels of logical capacity 2, 4, 8 and 16. Each hashed level gets a fresh secret HMAC-SHA-256 placement key on rebuild; after a hit, later levels receive unique dummy labels. Its bucket table is deliberately overprovisioned so a level containing at most `c` real blocks has `c` buckets of `c` slots each. That eliminates data-dependent build failure for this fixed `N=16` lesson, but costs 341 server slots and transient `O(N)` client rebuild memory. It is not the papers' asymptotically efficient oblivious hash table or a transferred security proof. It has no cuckoo stash or combined stash, so it neither reproduces nor claims to repair the combined-stash vulnerability studied later in Alibi.

**Parameters:** both routes use N=16 logical blocks and 32-byte data. Path ORAM uses Z=4, L=4 and 124 encrypted server slots. The bounded hierarchy uses five levels (cache plus capacities 2/4/8/16), 341 encrypted server slots, four placement keys and fixed 31-slot reads plus 31-slot rewrites before scheduled rebuild traffic. Both use 12-byte AES-GCM nonces.

## When to Use It

- Understanding why encryption hides contents but not access patterns
- Comparing the restricted 1996 Goldreich–Ostrovsky lower bound with the general online Ω(log N) lower bound proved by Larsen–Nielsen (2018)
- Evaluating ORAM for healthcare record systems, SGX enclaves, cloud storage
- Visualizing how the Path ORAM tree + stash + position map work together
- Comparing Path ORAM's fixed per-access tree traffic with hierarchical lookup traffic and binary-carry rebuild spikes
- Comparing ORAM cost vs. alternatives (PIR, TEE, differential privacy)
- Do NOT use for production — use a maintained library (PathORAM C++, Go equivalents); this is educational and runs in a browser.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-oram-vault](https://systemslibrarian.github.io/crypto-lab-oram-vault/)**

The demo presents six exhibits: the access-pattern attack and side-channel threat model — with a one-click replay that runs the same Monday/Tuesday/Friday logical accesses through a live ORAM, removing record identity from the path trace while leaving the timing burst visible; an interactive binary tree contrasting the server's encrypted view with the client's view; a step-by-step READ/WRITE trace; a side-by-side adversary/client log; a costs/when-to-use panel; and an executable Path-versus-hierarchy comparison. The tree includes a live block → leaf position map and an eviction-legality explanation. The comparison sends the same eight-operation workload through both constructions, verifies all 16 final blocks against a separate reference map, displays traffic from the actual server logs, and runs a skipped-dummy-probe counterexample. Privacy claims are scoped to logical-address hiding against a semi-honest storage server and link to the residual-leakage caveats.

## What Can Go Wrong

- **Finite-stash failure** remains possible. Its probability depends on bucket size and the provisioned stash capacity; recursion solves the position-map storage problem, not stash overflow.
- **Timing and termination leakage** remains. This browser code is not constant-time and does not schedule or pad application operations.
- **Position map is O(N).** For large N, the position map doesn't fit on the client. Recursive ORAM stores it in another ORAM instance.
- **The bounded hierarchy trades away asymptotic efficiency.** Its 341 slots are about 21.31N, and a rebuild decrypts up to all 16 real blocks into trusted memory. The cited constructions require efficient oblivious hashing/sorting machinery that this table intentionally does not reproduce.
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

## Six Exhibits

1. **Why Encryption Alone Isn't Enough** — the access-pattern attack, side-channel threat model, what ORAM prevents, and a one-click replay showing independent random paths while the access-count/timing cluster remains visible
2. **Tree Visualization** — interactive binary tree showing server view (identical encrypted blobs) vs. client view (real block IDs from the client's retained record of its latest path write-back); a live block → leaf position-map table that highlights and re-randomizes the accessed row; an eviction-legality explainer that uses the position map to check why each recorded on-path block may rest only in buckets its assigned leaf shares with the write-back path; live path highlighting during accesses
3. **Access Walkthrough** — step-by-step trace of a single READ or WRITE: position-map lookup, re-randomization, path read, stash update, greedy eviction, write-back
4. **Adversary vs. Client** — side-by-side log of what the server observes (uniform random paths) vs. what the client actually did (specific block accesses)
5. **Costs and When to Use** — bandwidth overhead table, use-case guide, research-system distinctions, cross-links to related labs
6. **Path vs. Hierarchy** — one workload executed by both implementations; current-run output verification, fixed all-level probes, fresh HMAC-key rebuilds, measured binary-carry spikes, client/server-state comparison and an executable skipped-probe depth leak

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
before the old path is read and written back. Block re-encryption through the
demo module uses a private per-key nonce prefix and monotonic counter, so its
supported 2³² encryptions under one generated key cannot reuse a GCM nonce. The
same-origin-code limitation above still applies: this module rule is not misuse
resistance against code that can reach client state.

The bounded hierarchical route follows this finite schedule:

```
Access(op, a, data*):
  1. Scan the one-block cache for a
  2. For every hashed level i:
       probe HMAC(key_i, a) if not found
       otherwise probe HMAC(key_i, unique-dummy(access, i))
       read and freshly rewrite the complete selected bucket
  3. Remove the authenticated target; apply READ or WRITE
  4. Reinsert at level 0
  5. Carry through occupied levels; extract and clear each complete level
  6. Build the first empty level (or the bottom) under a fresh placement key
```

The storage observer's hierarchy API contains only `{phase, operation, level,
bucket, slotCount}`. The learner trace separately exposes probe kind, hit level
and logical id as an omniscient explanatory view; those fields are not passed to
the server. Rebuild timing follows the public access counter, and the client
refuses before its 32-bit dummy-label counter could wrap. The executable
`skip-after-hit` control returns the same plaintext but reads only one slot on a
cache hit instead of the fixed 31, demonstrating why correct output alone does
not establish obliviousness.

Primary construction sources:

- [Falk, Noble and Ostrovsky, *Alibi*, EUROCRYPT 2021, §2.5 and Figure 2](https://web.cs.ucla.edu/~rafail/PUBLIC/248.pdf)
- [Goodrich and Mitzenmacher, *Privacy-Preserving Access of Outsourced Data via Oblivious RAM Simulation*, arXiv:1007.1259v2 (2 May 2011), §5 and Figure 2](https://arxiv.org/abs/1007.1259)
- [Goldreich and Ostrovsky, *Software Protection and Simulation on Oblivious RAMs*, JACM 1996](https://doi.org/10.1145/233551.233553)

## Testing

The protocol modules ship with a Vitest suite (`npm test`) that asserts both the
**correctness** and the **security properties** the demo claims — not just that the
code runs:

- **Encryption** — AES-256-GCM round-trips; a fresh 96-bit nonce per module
  encryption call (no reuse); dummy blocks are byte-shaped like real blocks yet decrypt to `null`;
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
- **Observed stash occupancy** — the high-water mark stays within the explicit
  test ceiling across a 1000-access workload (the live demo surfaces this as the
  "Stash Peak" stat). This is empirical evidence for the configured `Z=4` toy,
  not the paper's proved exponential tail bound, which is established for `Z=5`.
- **Bounded hierarchy** — exact table geometry, an RFC 4231 HMAC vector, all-block
  recovery, reference-map workloads, serialization and input boundaries, every-level
  real/dummy probing, binary-carry rebuild cadence, event-derived traffic, and a
  server view with no logical labels or hit state.
- **Construction comparison and negative control** — the same workload executes in
  both implementations, every final block is checked against a separate map, Path
  and hierarchy traffic are derived from their event logs, and stopping after a
  cache hit is shown to leak one-slot versus 31-slot lookup depth while preserving
  the returned value.
- **UI smoke** — `main.ts` boots under happy-dom with every wired control resolving,
  tab switching works, a Path READ renders the tree, and the comparison and
  skipped-probe controls run end-to-end.

```bash
npm run typecheck   # tsc --noEmit over src + tests
npm test            # vitest run (69 tests)
npm run test:mutation # clean baseline, then all 12 hierarchy mutations caught
npm run test:workflow
npm run test:coverage
```

CI (`.github/workflows/deploy.yml`) runs clean-install, audit, type-check, unit,
workflow-policy and build gates on Node 22/24/26, then browser claim/accessibility
tests. Only the no-checkout deploy job receives Pages/OIDC authority, and both
artifact packaging and deployment require the `main` ref even on manual runs.

## Stack

Vite · TypeScript strict · Vanilla CSS · Web Crypto API · Vitest · GitHub Pages

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
