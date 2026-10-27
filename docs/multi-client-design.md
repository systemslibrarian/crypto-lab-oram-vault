# L-R-13 — Mutually distrustful clients sharing an ORAM: design decision record

Written before implementation, against `origin/main` at
`0c7f89281784748a9c9d4fafb41d85ac1839a4c5` (the E-K-10 merge).

This record exists because the honest answer to "share an ORAM between two
clients who do not trust each other" is not an engineering tweak to the
existing Path ORAM. It is a different primitive with a different definition, a
different attacker model, and a published lower bound that rules out the
existing construction's access cost. Everything below is decided from the
primary literature rather than from the roadmap summary.

---

## 1. Sources actually read

The roadmap names the encyclopedia entry as the starting point. It was
resolved, and its three primary citations were obtained and read.

| # | Source | What was read |
|---|---|---|
| E | **Chow, Sherman S. M., and Russell W. F. Lai. "Multi-client Oblivious RAM." Encyclopedia of Cryptography, Security and Privacy, Springer Nature Switzerland, 2025, pp. 1592–1594.** DOI `10.1007/978-3-030-71522-9_1550`, ISBN 978-3-030-71522-9. | **Metadata and its complete reference list only.** The entry text is paywalled and was not obtained; no claim in this lesson rests on its prose. Its three references are [P1], [P2], [P3] below, and all three were read in full. |
| P1 | **Maffei, Malavolta, Reinert, Schröder. "Maliciously Secure Multi-Client ORAM."** ACNS 2017, pp. 645–664, DOI `10.1007/978-3-319-61204-1_32`. Full version: **IACR ePrint 2017/329**, 29 pp., received 2017-04-17. | §2.1 Definition 1 and the attacker model; §2.2 Theorem 1; §2.3 discussion; §3 PIR-MCORAM and §3.1–3.2; §4 hash-and-proof; §5 proxy-based realization; §6 Theorems 3–6; §8 conclusion. |
| P2 | **Chow, Fech, Lai, Malavolta. "Multi-client Oblivious RAM with Poly-logarithmic Communication."** ASIACRYPT 2020 Part II, pp. 160–190, DOI `10.1007/978-3-030-64834-3_6`. Full version: **IACR ePrint 2020/1551**, 30 pp. | Abstract; §2.1–2.3 technical overview; §5.1 Definition 15 (syntax); §5.2 Definition 16 and Fig. 3 (integrity); §5.3 obliviousness. |
| P3 | **Backes, Herzberg, Kate, Pryvalov. "Anonymous RAM."** ESORICS 2016 Part I, pp. 344–362, DOI `10.1007/978-3-319-45744-4_17`. Full version: **IACR ePrint 2016/678**. | Abstract; §1; §3.1 *Seemingly Natural but Flawed Approaches*; §3.2 `AnonRAM_lin`. |
| P4 | **Maffei, Malavolta, Reinert, Schröder. "GORAM — Group ORAM for Privacy and Access Control in Outsourced Personal Records."** **IACR ePrint 2015/224, 25 August 2015**, 78 pp. Conference version: IEEE S&P 2015. Journal version: *Journal of Computer Security* 27(1):1–47, 2019, DOI `10.3233/jcs-171030`. | §2.1 Definition 1; §2.2 properties; §2.3 attacker model; §3.1 prerequisites and Figure 1; §3.2 Algorithms 1–2; §4 A-GORAM, §4.1–4.2, Figure 2, Algorithm 9; §5 S-GORAM; §10 related work. P4 is [39] in P1 and [29] in P2 — the paper both of them build their definitions on. |
| P5 | **Chakraborti, Sion. "ConcurORAM: High-Throughput Stateless Parallel Multi-Client ORAM."** NDSS 2019. **arXiv:1811.04366v4, 13 December 2018.** | Abstract; §I including *Challenges and Key Insights*; §II related work; §III background. |

Obtained-but-not-implemented primitives, cited where they matter:
**Ateniese and de Medeiros, "On the Key Exposure Problem in Chameleon Hashes,"
SCN 2004, pp. 165–179** (P4 reference [22]) and **Gentry and Waters,
"Adaptive Security in Broadcast Encryption Systems (with Short Ciphertexts),"
EUROCRYPT 2009, pp. 171–188** (P4 reference [24]) were *not* obtained in full;
they are named only as the primitives this lesson substitutes for, and §7
states exactly what the substitution costs.

**How the PDFs were obtained, for reproducibility.** `eprint.iacr.org` serves
its abstract pages to this environment but returns HTTP 403 for every `.pdf`
path, so P1, P2, P3 and P4 were retrieved through the Internet Archive
(`https://web.archive.org/web/2024id_/https://eprint.iacr.org/<id>.pdf`) and
checked: page counts 29, 30, 29 and 78, with title and author lines matching
the Crossref metadata for the corresponding DOIs. P5 came directly from arXiv.

---

## 2. The definition this lesson implements

All three citations of the encyclopedia entry build on one definition, P4 §2.1
Definition 1, restated in P1 §2.1 Definition 1 and rephrased in P2 §5.1
Definition 15. Its parties and state:

- a **data owner** `O` who outsources a database `DB` of `n` entries;
- **clients** `C_1 … C_k`, each registered with a **capability** `cap_i`;
- an **untrusted server** `S` holding the encoded database;
- an **access-control matrix** `ACM(i, idx) ∈ {⊥, R, RW}` — no access,
  read-only, read-write — which P1 §2.1 states explicitly is
  *"only accessible to the data owner and not to any client."*

The protocol surface is `gen`, `addCl`, `addE`, `chMode`, `read`, `write`
(P4/P1), or `Setup`, `ChMod`, `Access` (P2, where read is signalled by an empty
message). `read` on an entry with `ACM(i, idx) = ⊥` returns `deny`; `write`
succeeds *iff* `ACM(i, idx) = RW`.

This is the primitive the roadmap item is about, and it is **not** the
primitive the lab currently implements. The existing Path ORAM is single-client
by construction: one key, one position map, one stash, one trusted client.

### The five properties, kept separate

Taken verbatim in substance from P4 §2.2 and P1 §2.1, with P2's refinements:

| Property | Statement | Source |
|---|---|---|
| **Secrecy** | only users with at least read permission on an entry can learn its content | P1 §2.1; P4 §2.2 |
| **Integrity** | only users with write permission on an entry can change its content — *"requires an honest-but-curious server to perform access control"*. **Not claimed by this lesson; see §5a.** | P1 §2.1 |
| **Tamper resistance** | only users with write permission can change content *"in a way that the updated entry is considered valid by honest clients"* — detectable a posteriori, *"can in principle be achieved even if the server is malicious"* | P1 §2.1 |
| **Accountable integrity** | clients cannot write entries they do not hold write permission on *without being detected* | P4 §2.2; P2 §5.2 calls it *"accountable integrity (defined in the single-server setting [29])"* |
| **Obliviousness against malicious clients** | the server *and an arbitrary subset of corrupted clients* learn nothing about honest clients' access patterns beyond what is trivially leaked by entries the corrupted clients can read | P1 §2.1 Definition 2 |
| **Anonymity** | the server *and the data owner* cannot determine who performed an operation among those allowed to perform it | P4 §2.2 |

P2's abstract states the upgrade over ORAM in one sentence: access patterns
*"must remain oblivious not only to the server but also to fellow clients.
This upgrade rules out many techniques for constructing ORAM."*

---

## 3. The published lower bound, and what it forbids

**P1 §2.2 Theorem 1.** *"Let `n` be the number of entries in the database and
`Θ` be a multi-client ORAM scheme. If `Θ` accesses on average `o(n)` physical
addresses for each read and write operation … `Θ` is not secure against
malicious clients."*

P1 §2.3 draws the consequence: any multi-client ORAM secure against malicious
clients *"must read and write a fixed constant fraction of the database on
every access."*

A Path ORAM access touches one root-to-leaf path — `O(log n)` buckets, which is
`o(n)`. **So the lab's existing access shape cannot be obliviousness-secure in
the malicious-client model, as a matter of a published theorem rather than of
implementation quality.** That is the single most important fact this lesson
has to teach, and it is why "share the existing ORAM" is not a repairable plan.

This record is careful about the direction of that claim. The lesson will
**state Theorem 1 as a property of the model and cite it**, and will separately
exhibit a concrete, measured distinguisher in the lab's own instance. The
distinguisher is *evidence consistent with* the theorem; the lab does not prove
the theorem and will not say it does.

---

## 4. The naive deployment that fails, and why it is the right failure to execute

The brief asks for an executable failure caused by naively sharing state
designed for a single-client ORAM, *derived from actual protocol state*. P3
§3.1 enumerates exactly these naive designs and why each fails:

1. *"maintain all the M·N cells in encrypted form on the server and … only
   access them via an anonymous channel … this approach fails … since the
   adversary can simply observe all memory accesses on the server and thereby
   determine how often the same cell `j` of a user is accessed."*
2. *"One may try to overcome this problem using a shared (M·N)-cell … ORAM …
   In this case, **all users will have to use the same private key** in the
   symmetric encryption scheme employed in the ORAM protocol … However, this
   allows Eve, an HbC user, to break privacy of honest users, **by observing
   the values in cells (allocated to honest users) which she downloaded and
   decrypted as a part of her legitimate ORAM requests.**"*
3. *"use a separate ORAM for the M cells of each user … the server can identify
   all accesses by the same user."*

Design (2) is reproducible in this lab **with no attack code at all**, because
it is a side effect of the shipped protocol. `src/client/oram-client.ts`
`decryptPath` decrypts every non-dummy block on the path it reads and merges
every real block into the caller's stash. Under one shared key:

- a second client's own *legitimate* access reads a full path containing the
  first client's blocks, decrypts them, and obtains their plaintext — P3's Eve,
  executed;
- with per-client position maps instead of a shared one, the same line throws
  `BlockUnavailableError` because the decrypted block is absent from *this*
  client's map — a crash that is itself the tell that the path carried another
  client's data;
- with one shared position map and no synchronisation, two interleaved
  accesses re-randomise the same entry's leaf and the later write-back drops
  the earlier update — a lost update, observable as a reference-model mismatch.

All three outcomes are computed from real protocol state. P5 §I states the
consistency half independently: deploying existing schemes for multiple clients
*"by sharing ORAM credentials and storing [state] that would normally be
maintained client-side … on the server to ensure state consistency"* forces
*"only one client … to access the … structures at any one time."*

P1's conclusion names the cited critique of this practice as
**Bindschaedler, Naveed, Pan, Wang, Huang, "Practicing Oblivious Access on
Cloud Storage: The Gap, the Fallacy, and the New Way Forward," CCS 2015,
pp. 837–849** (P1 reference [6]). It is cited in the exhibit as the paper that
named the fallacy; it was not read in full and nothing is attributed to its
text.

---

## 5. Construction selected

**Selected: the S-GORAM shape of P4 — that is, A-GORAM (P4 §4) with predicate
encryption replaced by broadcast encryption (P4 §5) — with the
tamper-resistance mechanism P1 §3 specifies for PIR-MCORAM, evaluated in the
GORAM attacker model (P4 §2.3).**

Why this one:

- It is a **named construction from a primary source**, not a blend invented
  here. P4 §5: *"If we stick to client-based read and write permissions …
  we can achieve a more efficient construction that scales to thousands of
  clients … we replace the predicate encryption scheme with a broadcast
  encryption scheme … `c_Key` is the broadcast encryption of `k_j`; `c_Auth` is
  the broadcast encryption of `csk`."* The lab's permission model is exactly
  client-based read/write, which is the regime S-GORAM is defined for.
- A-GORAM exists precisely to remove the unimplementable machinery: P4 §4
  states that with accountability *"zero-knowledge proofs are no longer
  necessary and, consequently, the outermost encryption can be implemented
  using symmetric, as opposed to asymmetric, cryptography."*
- It needs **no server-side authorization check**, which matters for
  obliviousness: a server that verified "may client `i` write entry `j`?" would
  learn `j`. A-GORAM moves the check to the clients and the owner.
- Its attacker model is the one this lab can honestly claim: P4 §2.3 — *"the
  data owner `O` is honest, the clients `C_1 … C_n` may be malicious, and the
  server `S` is assumed to be honest-but-curious … and not to collude with
  clients."* The existing lab already assumes a semi-honest server, so the only
  model change is malicious clients — which is the whole point of L-R-13.

### What gets built, with real computation

| Mechanism | Implementation | Faithful to |
|---|---|---|
| Owner key material and `ACM` | owner-held; `ACM` never leaves the owner | P1 §2.1, P4 Alg. 1–2 |
| **Read authorization (secrecy)** | per-entry data key `k_j`; the envelope carries **one wrap slot per registered client**, holding `k_j` wrapped under that client's key iff `ACM(i,j) ∈ {R, RW}` and an indistinguishable dummy wrap otherwise. AES-256-GCM. A client with no real wrap cannot decrypt — enforced by the cipher, not by a disabled control. | P4 §5 (broadcast encryption of `k_j`), trivial instantiation |
| **Write authorization (tamper resistance, *not* integrity)** | the owner issues, per `(client, entry)` with `RW`, an ECDSA P-256-signed **write capability**. A writer re-encrypts under `k_j`, bumps the entry version, and signs `(idx, version, ciphertext hash)` with its own key. Any client, and the owner, verify: capability signature valid under the owner's key, writer signature valid under that client's key, and the capability names that writer and that entry. **An unauthorised write lands on the store and is then rejected by every honest reader** — see §5a. | P1 §3: *"Tamper-resistance … is achieved by letting each client sign the modified entry so that others can check that this entry was produced by a client with write access."* Verification shape follows P4 Alg. 9 |
| **Entry verification on parse** | every parse of an entry runs the verification above; failure routes to `blame` | P4 §4.2 *Entry Verification* and *Blame* |
| **Accountable integrity** | append-only, client-signed upload **Log** on the server; `blame` walks it to the last consistent version of the entry and names the signer of the upload that broke it | P4 §4.1 *Structure of the log file*, §4.2 *Blame* |
| **Access-pattern protection** | the shared store is a Path ORAM tree over entry envelopes with the leaf map held **on the server**; every `Access` reads exactly one root-to-leaf path and writes exactly one back, with identical bucket and slot counts for read and write, every entry, and every client | P4 §3.1: layout *"follows the one proposed by Stefanov et al."*, with the stash *"stored and shared on the server like every other node"* |
| **State synchronisation and freshness** | per-entry monotonic version; an owner-signed **version head** over the whole store; a client refuses an envelope whose version is below the head's record for that entry (**stale-state refusal**) and refuses a replayed earlier envelope (**rollback refusal**) | P1 §3 requires *"an oblivious gossiping protocol … allows clients to find the most up-to-date entry"*; P1 footnote 1: *"Gossiping is necessary since we do not trust the server for consistency."* |
| **Reference-model verification** | a retained plaintext mirror `M'`, with the win condition of P2 Fig. 3 asserted as a test: adversary corrupts a client with read-but-not-write rights on `a*`, and an authorised reader's result must still equal `M'[a*]` | P2 §5.2 Definition 16 and Fig. 3, *"MCORAM's Integrity against Malicious Clients and Honest-but-Curious Server"* |

### 5a. Integrity is NOT claimed, and the reason is the construction's own

P1 §2.1 separates two properties that are easy to conflate:

> **Integrity:** only users with write permissions on an entry can change its
> content. … **Tamper Resistance:** only users with write permissions on an
> entry can change its content in a way that the updated entry is considered
> valid by honest clients. … The difference between integrity and
> tamper-resistance is that integrity prevents unauthorized changes and thus
> **requires an honest-but-curious server to perform access control**, while
> tamper resistance is a weaker property that allows clients to detect
> unauthorized changes a-posteriori and thus can in principle be achieved even
> if the server is malicious.

**This store performs no access control, and it cannot.** Deciding whether a
writer may change entry `j` requires knowing `j`, and `j` sits inside an
envelope the store cannot open. GORAM §3 buys a server-side check with
zero-knowledge proofs — the client proves it can decrypt `c_Auth^j` without
revealing which entry it is — and A-GORAM §4 deliberately abandons that: *"instead
of letting the server check the correctness of client operations, we develop a
technique that allows clients to detect a posteriori non-authorized changes on
the database and blame the misbehaving party"*, with the consequence that *"the
zero-knowledge proofs are no longer necessary."*

So the selected construction provides **tamper resistance and accountable
integrity, not integrity.** The observable consequence is tested rather than
hidden: a client that forges or steals a write capability **succeeds in
placing its envelope on the store**, and then

- every honest client's `verifyEntry` rejects that entry on sight, so the
  forged payload never becomes the entry's value for anyone, and
- `blame` walks the signed upload log and names the client whose upload broke
  it.

This is a strictly weaker guarantee than "the write is blocked", and the
exhibit says which one it is. Claiming integrity here would be transferring a
property the construction explicitly trades away.

---

## 6. Alternatives considered and rejected

| Construction | Source | Why not |
|---|---|---|
| **Full GORAM** | P4 §3 | Needs predicate encryption (Katz–Sahai–Waters, pairing-based) *and* Groth–Sahai zero-knowledge proofs of shuffle. No pairing or ZK dependency exists in this lab and adding one would not be a bounded extension. |
| **A-GORAM's chameleon-hash integrity** | P4 §4.2, Figure 2 | Requires a **key-exposure-free** chameleon hash (P4 reference [22], Ateniese–de Medeiros SCN 2004). The textbook discrete-log chameleon hash is *not* key-exposure free — one published collision reveals the trapdoor — so implementing that would silently destroy the integrity property it is there to provide. Replaced by P1 §3's signature-based tamper resistance. The cost is stated in §7. |
| **PIR-MCORAM** | P1 §3 | By P1 Theorem 1 it must touch `Ω(n)`; it needs PIR over `DB` and over every client stack, zero-knowledge integrity proofs, and an oblivious gossiping protocol. Not implementable at fidelity. Retained as the statement of what the stronger model costs: `O(√n)` amortized communication with `Ω(n)` server computation. |
| **TAO-MCORAM / TaoStore** | P1 §5; Sahin et al., S&P 2016 | A **trusted proxy** runs a single-client Path ORAM on behalf of clients, and P1 modifies TaoStore's sequencer *"so as to let it know the access control matrix and check for every client's read and write requests whether they are eligible."* Rejected as the primary route because it relocates all trust into a third party, and the roadmap item is about mutually distrustful clients. Retained as the named alternative and as the only route in these papers with full concurrency. P5 §I is explicit about the cost: *"The need for a trusted third-party … deviates from the standard ORAM model, where trust is only on the client(s) at most."* |
| **FHE / DPF MCORAM** | P2 §§2.2, 2.3, 6 | Fully homomorphic encryption with cross-key trial evaluation, or distributed point functions across `N` non-colluding servers. Not implementable in a browser teaching lab. |
| **AnonRAM** | P3 | Solves a *different* problem: anonymity of users over **per-user cells**, not differing rights over shared entries. Used here only as the primary source for the naive-sharing failure (§4) and for the anonymity/integrity tension. |
| **ConcurORAM** | P5 | Concurrency and throughput for clients that **share ORAM credentials** — mutually trusting, with no access control. P5 contains no access-control mechanism and does not cite GORAM. It answers the synchronisation half of the problem for a model this item is not about. Retained as the citation for the concurrency line of work. |

---

## 7. Teaching adaptations, and exactly what each costs

Each of these is a deviation from the selected construction. Each will be
stated on the page and in the README, not only here.

1. **Trivial broadcast encryption instead of Gentry–Waters.** `k_j` and the
   write capability are wrapped once per registered client. Ciphertext is
   linear in the number of clients — which is the regime P4 §5 itself names
   (*"linear in the number of clients"*) — but it is **not** Gentry–Waters, has
   no short ciphertexts, and carries no adaptive-security theorem. Dummy wrap
   slots keep the envelope a constant size so the *number* of authorised
   readers does not leak from its length; Gentry–Waters would give that for
   free.
2. **Client signatures instead of a key-exposure-free chameleon hash.**
   A-GORAM keeps the *owner's* signature valid across authorised writes by
   having the writer compute a chameleon collision, so the entry reveals
   nothing about who wrote it. This lesson instead has each writer sign its own
   update (P1 §3's mechanism). **Cost: anonymity.** Any client that can decrypt
   the envelope learns which client last wrote it. P4 §4.2's own Discussion
   already concedes this for the accountable variant — *"the
   accountable-integrity property, as presented in this section, sacrifices the
   anonymity property, since users have to sign the paths they upload"* — so
   the loss is inside the paper's own design space, but it is a loss and will
   be labelled as one. **Anonymity is therefore not claimed anywhere.**
3. **Non-oblivious version gossip.** P1 §3 requires an *oblivious* gossiping
   protocol so that finding the freshest version leaks nothing. This lesson
   implements a plain owner-signed version head that clients read directly.
   **Cost: the gossip channel itself is not oblivious**, so a server that
   watches which version records a client consults learns which entry it is
   about to touch. The exhibit will say this rather than hide it, and will
   point at P1 §3 for the construction that fixes it.
4. **Integrity in the honest-but-curious-server regime only.** P1 §2.1 is
   explicit that integrity *"can only be achieved by assuming an
   honest-but-curious server (while still allowing for client compromise)."*
   The lesson claims integrity only under that assumption, and claims
   tamper-resistance/accountable integrity separately as the property that
   survives a malicious server.
5. **No obliviousness against malicious clients.** Forbidden by P1 Theorem 1 at
   this access cost. The lesson claims obliviousness **only against the
   non-colluding honest-but-curious server of P4 §2.3**, demonstrates a
   distinguisher once a client colludes, and names Theorem 1 as the reason no
   amount of fixing inside this access shape would help.
6. **Fixed, small instance.** `n = 16` entries, two to three clients, 32-byte
   payloads, reusing the lab's existing parameters. No asymptotic claim is made
   from it.
7. **Revocation is out of the selected model.** P2 §5.1 states of `ChMod`:
   *"The basic model only allows granting additional rights."* P4 provides
   `chMode` with arbitrary vectors, but neither paper gives forward or backward
   secrecy for already-distributed keys: a client that has seen `k_j` keeps it.
   The lesson implements `chMode` **downgrade as key rotation** — the owner
   mints a fresh `k_j`, re-wraps for the remaining readers and re-signs — and
   states plainly that this stops *future* reads and does **not** retract what
   a revoked client has already learned.
8. **Concurrency is refused, explicitly, with the reason.** See §8.
9. **The module boundary is informational.** Unchanged from the existing lab:
   owner, clients and server are modules in one page, not processes. Same-origin
   code can reach every key. This is the lab's existing standing caveat and it
   applies with more force here, because there are now three distinct trust
   domains in one address space.

---

## 8. Assumptions the exhibit must state

**Actors and trust boundaries.** Four: the **owner** (honest by assumption —
P1 §2.1: *"The data owner is assumed to be trusted, since she is interested to
protect her data"*; holds `ACM`, all master key material, the signing key for
capabilities and the version head); **clients** (mutually distrustful, may be
malicious, each holds only its own capability); the **server** (untrusted for
confidentiality, honest-but-curious for the integrity claim, holds the
encrypted tree, the leaf map, the Log and the version head); and **no
coordinator or key service** — deliberately, since introducing one would be
TAO-MCORAM, which §6 rejects.

**Collusion, in three directions, as the selected model requires.**
- *client ↔ client*: assumed possible. Corrupted clients may pool capabilities.
  Secrecy and integrity are claimed only outside the union of their rights.
- *client ↔ server*: **assumed NOT to happen** — P4 §2.3, *"not to collude with
  clients."* This is the assumption the attack exhibit removes, and the point
  at which Theorem 1 bites.
- *server → client*: the server may lie to clients by omission, replay or
  reordering. Integrity is not claimed against this; tamper resistance,
  accountable integrity and the rollback refusal are.

**Freshness and rollback.** Only what the version head gives: an entry below
its recorded version is refused. A server that withholds the head entirely is
detectable by its absence, not by the protocol; this lesson does not implement
a signed timestamp or a monotonic counter service and claims no
freshness-against-withholding.

**Crash recovery.** A client that crashes mid-`Access` has read a path and not
written one back. The store is left consistent because path write-back is
atomic (the existing `serverWritePath` validates the whole payload before
mutating any bucket), but the *entry version* the client was about to bump is
not advanced, so the update is lost rather than half-applied. The exhibit shows
this as a lost update, not as corruption. P4 §4.2 notes the general
requirement — accountability *"is supposed to be paired with a data versioning
protocol in order to avoid data losses"* — and this lesson implements the
version counter but **no revert-to-last-safe-state recovery**.

**Concurrency: refused, and here is why.** P4 does not address concurrency at
all. P1 §3.2 permits concurrent reads and stack appends but not concurrent
flushes: *"This is no longer possible when a client flushes her personal stack
since the database is entirely updated, which might lead to inconsistent
results when reading from the database."* Full concurrency appears in these
papers only via the trusted proxy of P1 §5, or outside them in P5. In the
selected construction two concurrent `Access` operations on the shared tree
race on the leaf map and the path write-back, and the loser's update is
silently dropped. The lesson therefore **serialises every access and refuses
concurrent writes with a stated reason**, and exhibits the lost update that
appears when the serialisation is bypassed. Linearizability is not claimed.

---

## 9. What the exhibit shows, in order

Four states, each computed from the current run, each retired when any input
changes:

1. **Honest baseline.** Owner provisions 16 entries and three clients with
   different rights. Each client reads what it may, writes what it may, and is
   refused what it may not — the refusal arriving from a failed unwrap or a
   failed verification, not from a flag. Server transcript shows one path read
   and one path write per access, identical in shape.
2. **Naive sharing failure.** The same two clients over the *existing
   single-client Path ORAM* with one shared key, as P3 §3.1 design (2).
   Executed outcomes: cross-client plaintext exposure during a legitimate
   access; `BlockUnavailableError` from a divergent position map; a lost update
   from an unsynchronised shared map. No attack code — the shipped protocol
   does this.
3. **Collusion attack on obliviousness.** A corrupted client shares its own
   leaf knowledge with the server and distinguishes which of two entries an
   honest client touched, at a measured rate reported from the run. Named as
   evidence consistent with P1 Theorem 1, which is quoted, with the explicit
   statement that no `o(n)` scheme — including this one — can close it.
4. **Repaired case, inside the stated model.** Authorization, verification,
   version head and serialisation all engaged; the reference model agrees;
   every negative control fires. Accompanied by the explicit statement that the
   repair restores the properties of P4 §2.3's model and **does not** defeat
   state 3, because Theorem 1 forbids that at this cost.

**Negative controls** (each must fail, visibly, for a protocol reason):
read by a client with `⊥`; write by a client with `R`; write with a capability
issued to a different client; write with a capability for a different entry;
replay of a superseded envelope; an envelope whose ciphertext was tampered
with; an envelope whose writer signature was stripped; a stale version head; a
concurrent second write; and a read after `chMode` downgrade and key rotation.

**Omniscient teaching view vs. server view**, kept apart as the lab already
does for Path ORAM: the server view carries only physical coordinates,
transfer sizes, operation kind and ordering; the teaching view carries entry
indices, client identities, plaintext and verification outcomes, and is never
passed across the store API.

---

## 10. Files

New, in `src/multiclient/`: `store.ts` (untrusted shared store, Log, version
head, transcript), `owner.ts` (`ACM`, key material, capability issuance,
`chMode`), `client.ts` (`Access`, verification, gossip, `blame`), `naive.ts`
(the shared-key deployment, over the existing Path ORAM), `scenario.ts` (the
four states and the controls).

New tests: `tests/multiclient-authorization.test.ts`,
`tests/multiclient-integrity.test.ts` (including the P2 Fig. 3 experiment),
`tests/multiclient-trace.test.ts`, `tests/multiclient-naive.test.ts`.

Edited: `src/main.ts` (one new exhibit and tab), `src/style.css` only if a
reused class is genuinely missing, `vitest.config.ts` (coverage include),
`scripts/mutations.mjs` (new named mutations), `e2e/claims.spec.ts` and
`e2e/gate.ts` (new driven states), `README.md`.

**Nothing in `src/client/`, `src/server/` or `src/hierarchical/` changes.** The
multi-client store is a class with per-run state, following the
`HierarchicalServer` precedent, so the new exhibit cannot disturb the Path
ORAM singleton or any E-K-10 result.

**Mutations to add**, at minimum the five the brief requires: removed read
authorization (dummy wraps become real); removed write authorization
(capability signature unchecked); accepted stale state (version comparison
dropped); weakened trace check (read and write paths allowed to differ);
incorrect reference-state verification (the mirror compared against itself).

---

## 11. The claim this lesson will and will not make

It will claim: a faithful bounded implementation of the S-GORAM access-control
and accountability shape of P4, in P4 §2.3's attacker model, with real
cryptographic enforcement of read rights, real cryptographic *detection and
attribution* of unauthorised writes, a real synchronisation and freshness
mechanism, and an executable demonstration of why single-client ORAM state
cannot be shared.

It will **not** claim: integrity in P1 §2.1's sense (see §5a); obliviousness
against malicious clients; anonymity;
concurrency or linearizability; revocation of knowledge already released;
freshness against a server that withholds state; Gentry–Waters broadcast
encryption; a key-exposure-free chameleon hash; any theorem from P1, P2 or P4;
or that shared keys and one shared position map constitute multi-client ORAM —
which is the specific thing P3 §3.1 says *"does not work."*
