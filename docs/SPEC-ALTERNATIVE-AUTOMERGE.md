# Alternative: private data as a CRDT document (Automerge)

**Not adopted. Written for comparison against `SPEC.md`.**

Version: 0.1 (draft for evaluation)
Date: 2026-08-28
Status: alternative — evaluate against `SPEC.md` v2.1, do not implement

This document specifies the same wallet private data blob as `SPEC.md`, with
the event-sourced state layer replaced by a CRDT document. It is written in
the same normative register so the two can be read side by side; it is not a
proposal to adopt, and nothing implements it.

Sections 1–5 of `SPEC.md` — scope, transport, container model, cryptographic
processing — apply **unchanged**. Everything below replaces `SPEC.md` §6
onward.

---

## 1. What changes, in one paragraph

`SPEC.md` stores a base state `S` plus an ordered `events[]` log chained by
`parentHash`, and specifies by hand how two divergent histories reconcile.
This alternative stores a single Automerge document. Merge is a property of
the document type rather than a procedure clients implement, which removes
the merge strategies, the event chain, the fold horizon, and the entire
extension mechanism of `SPEC.md` §6.1 — namespaces, entry-key rules, the
registry and version-as-namespace.

## 2. Plaintext

The JWE plaintext MUST be an Automerge document in Automerge's own binary
save format, not JSON.

`SPEC.md` §3.3's tagged binary representation already carries this: the
backend accepts `{"$b64u": "<base64url>"}` and falls back to raw bytes, and
computes its ETag over bytes. **No backend change is required.**

### 2.1 Document schema

```
ROOT
  schemaVersion : u64            // 4
  credentials   : Map<CredentialId, Map>
  keypairs      : Map<Kid, Map>
  presentations : Map<PresentationId, Map>
  issuanceSessions : Map<SessionId, Map>
  settings      : Map<String, Scalar>
  <client-defined>: any Automerge type
```

Collections MUST be maps keyed by the entity's identifier, not lists.
Automerge merges concurrent list insertions by interleaving them; a map keyed
by identity gives the same convergence with an identity that survives
merging.

### 2.2 Client-defined state

There is no extension mechanism, because none is needed. A client MAY add
any key at ROOT or within any map. Automerge merges content a client does not
recognise, so:

- Clients MUST NOT delete keys they do not recognise.
- Clients MUST NOT be required to declare, register, or version
  client-defined keys.
- No namespace registry exists. Reverse-DNS naming is RECOMMENDED to avoid
  collision, and that is a convention, not a rule.

This is the substantive difference from `SPEC.md`. `SPEC.md` §6.1 exists
entirely because its merge is schema-aware and must be told how to reconcile
content it does not understand.

### 2.3 Identifiers

Every identifier used as a map key MUST be allocable without coordination —
derived from the material it names, or randomly generated with negligible
collision probability.

Identifiers MUST NOT be allocated from a shared counter. Two devices
allocating from the same counter while unsynchronised produce the same
identifier for different entities, which merges into one entry and silently
discards the other.

## 3. Change, merge and convergence

- A client MUST apply local modifications as Automerge changes.
- A client MUST merge a remote document by Automerge merge. Merge MUST NOT
  be conditional on a common ancestor being reachable.
- Merge is commutative, associative and idempotent. Two clients that have
  seen the same set of changes MUST hold identical state, regardless of the
  order in which they received them.

There is no `events[]`, no `lastEventHash`, no `parentHash`, and no merge
strategy per data type.

### 3.1 Ordering

Causality is carried by Automerge's actor identifiers and Lamport clocks.

Wall-clock timestamps MUST NOT be used to order changes. A device with an
incorrect clock would otherwise win or lose arbitrarily, and two devices with
equal timestamps would not converge.

`SPEC.md` §6.1.3 requires a `(timestampSeconds, eventId)` tiebreak precisely
because it orders on wall time. That requirement does not arise here.

### 3.2 No fold horizon

Clients MAY compact document history. Compaction MUST NOT remove the ability
to merge with a peer holding older changes.

`SPEC.md` §6.1.4 requires that a peer beyond the fold horizon be surfaced to
the user as an unresolvable divergence, because folding destroys the common
ancestor a linear history needs. Convergence here does not depend on a
reachable common ancestor, so that case does not exist and the rule is
unnecessary.

### 3.3 Concurrency against the backend

- Clients SHOULD use `X-Private-Data-If-Match` as in `SPEC.md` §8.
- On `412 Precondition Failed`, clients MUST re-fetch, merge the remote
  document, and retry. Merging always succeeds, so the reconcile step needs
  no user involvement and no recovery path.

## 4. What this does not solve, and makes worse

Stated normatively because it is the strongest argument against adopting
this document.

### 4.1 Single-use secrets

A CRDT reconciles everything, including state that should have conflicted.
Two devices that each spend a single-use `refresh_token` produce a document
that merges into a plausible, wrong state rather than reporting a conflict.

State whose consumption has an external side effect — one-time tokens,
issuer-side counters — MUST NOT rely on merge for correctness. Such state
requires an exclusive-ownership lease, and this document does not specify
one.

`SPEC.md` does not solve this either; it fails less quietly.

### 4.2 Auditability

An event log can be read, and how a state came about can be reconstructed
from it. An Automerge document's history is machine-readable but not
human-legible, and there is no equivalent of reading `events[]` to see what
happened.

### 4.3 Monotonic growth

Document history grows with every change. Compaction is available but is a
client decision with no coordination, so a fleet may hold documents compacted
to different points.

## 5. Cost, measured

Not normative. Recorded here because the comparison is otherwise conducted
on assertions.

| | brotli |
|---|---|
| Automerge wasm, bare-bones — 3 exported functions, `opt-level="z"`, LTO, `panic=abort`, stripped | **147 KB** |
| `SPEC.md`'s schema machinery, if deleted — `WalletStateSchema{,Common,Version1,2,3}.ts`, minified | **3.5 KB** |

Net **+143 KB** in a browser client. The 3.5 KB figure is not a rounding
error in the other direction: `WalletStateSchemaCommon.ts` minifies to zero
because it is types only, erased at build.

For scale, in the same wallet: `siros-wscd-manager` wasm is 94 KB brotli and
`zk-cred-bbs` wasm is 97 KB.

The bare-bones figure is a floor. A client needs the sync protocol, change
observation and richer read APIs; 200–300 KB brotli is the realistic range.

**"We delete the old merge code" is not an argument for this document.** If
it is adopted, it is adopted for §3 — merge that cannot crash on unknown
content, causality instead of wall time, and no fold horizon.

## 6. Comparison summary

| | `SPEC.md` v2.1 | This document |
|---|---|---|
| State | `S` fold cache + `events[]` chain | one Automerge document |
| Merge | hand-written strategy per event type | property of the document type |
| Unknown content | crashes the merge until tolerance lands | merges correctly, always |
| Extension mechanism | namespaces, registry, versions (§6.1) | none needed |
| Merge granularity | whole entry; finer resolution deliberately not offered | any, by construction |
| Ordering | wall clock + required tiebreak | Lamport clocks + actor ids |
| Fold horizon | destroys mergeability; user must resolve | no equivalent |
| Identifier discipline | MUST name an entity (§6.1.1) | MUST be uncoordinated (§2.3) |
| Single-use secrets | unsolved | unsolved, and quieter |
| Auditability | event log is readable | history is not human-legible |
| Browser cost | baseline | +143 KB brotli measured |
| Backend | no change | no change |

## 7. Relationship to `SPEC.md`

These are not mutually exclusive in time. `SPEC.md` §6.1 is what makes
staggered client adoption safe **today**; this document removes the need for
that machinery **eventually**. The migration question — a document cannot be
derived independently by two clients without duplicating, so conversion must
happen once and be distributed — is treated in `docs/ROLLOUT-PLAN.md` §5.
