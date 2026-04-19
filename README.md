# crypto-lab-oram-vault

> "Whether therefore ye eat, or drink, or whatsoever ye do, do all to the glory of God."
> — 1 Corinthians 10:31

**Browser-based Path ORAM demo** implementing the protocol from Stefanov et al.
"Path ORAM: An Extremely Simple Oblivious RAM Protocol" (CCS 2013, JACM 2018).

## What It Is

A fully interactive browser demo of Path ORAM — the Oblivious RAM construction that hides *access patterns* from cloud storage providers. Encryption hides the contents of your data; ORAM hides which locations you access. Path ORAM is the protocol used in Intel SGX-based secure processors, FPGA secure designs, ZeroTrace, Obliviate, and privacy-preserving cloud database systems.

The demo uses a module-boundary-enforced client/server separation: the "server" module stores only encrypted blobs and responds to path read/write requests — it literally cannot see block IDs, the position map, or stash contents. All encryption uses AES-256-GCM via the Web Crypto API. Randomness exclusively via `crypto.getRandomValues` — never `Math.random()`.

**Parameters:** N=16 blocks, Z=4 bucket size, L=4 tree height, 32-byte blocks, 12-byte GCM nonces.

## Five Exhibits

1. **Why Encryption Alone Isn't Enough** — the access-pattern attack, side-channel threat model, what ORAM prevents
2. **Tree Visualization** — interactive binary tree showing server view (encrypted blobs) vs. client view (block IDs, position map), live path highlighting during accesses
3. **Access Walkthrough** — step-by-step trace of a single READ or WRITE: position-map lookup, re-randomization, path read, stash update, greedy eviction, write-back
4. **Adversary vs. Client** — side-by-side log of what the server observes (uniform random paths) vs. what the client actually did (specific block accesses)
5. **Costs and When to Use** — bandwidth overhead table, use-case guide, real-world deployments, cross-links to related labs

## When to Use It

- Understanding why encryption hides contents but not access patterns
- Teaching the Goldreich–Ostrovsky logarithmic overhead theorem (1987/1996)
- Evaluating ORAM for healthcare record systems, SGX enclaves, cloud storage
- Visualizing how the Path ORAM tree + stash + position map work together
- Comparing ORAM cost vs. alternatives (PIR, TEE, differential privacy)
- **Not for:** production use. Use a maintained library (PathORAM C++, Go equivalents). This is educational and runs in a browser.

## Live Demo

https://systemslibrarian.github.io/crypto-lab-oram-vault/

## Protocol Implementation

Implements Algorithm 1 from the 2018 JACM paper exactly:

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

Every access reads AND writes a full path. The position map update is
AFTER reading and BEFORE writing back. Block re-encryption uses fresh
nonces so the server cannot link pre-access to post-access ciphertexts.

## What Can Go Wrong

- **Stash overflow** is possible but rare. Path ORAM guarantees O(log N) stash with high probability, but the tail is not zero. Real deployments use recursive ORAM + larger Z to push overflow probability below 2⁻⁸⁰.
- **Timing attacks** through access latency. Browser operations are not constant-time. Production ORAMs pad all operations to constant time.
- **Position map is O(N).** For large N, the position map doesn't fit on the client. Recursive ORAM stores it in another ORAM instance.
- **Web Worker boundary is informational, not cryptographic.** A malicious client-side script could bypass it. In production, the server is a physically separate machine.
- **Semi-honest security only.** An actively malicious server can return wrong blocks, fork the tree, or drop writes. Malicious-secure ORAMs (Ring ORAM, MI-ORAM) add MACs and version counters.
- **Side-channels in the browser.** Cache timing, memory allocation patterns, garbage collection can leak information. Production ORAMs run in constant-time hardware.

## Real-World Usage

Introduced by Stefanov, van Dijk, Shi, Fletcher, Ren, Yu, and Devadas at CCS 2013; extended JACM 2018. Deployed in Intel SGX Ascend secure processors, Maas FPGA secure designs, ZeroTrace, Obliviate, Obladi (oblivious OLTP databases). Built on the Goldreich–Ostrovsky theorem (1987, 1996) proving logarithmic ORAM overhead. The 16-line pseudocode makes Path ORAM the simplest practical ORAM construction.

## Stack

Vite · TypeScript strict · Vanilla CSS · Web Crypto API · GitHub Pages
