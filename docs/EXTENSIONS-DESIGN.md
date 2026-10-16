# Private Data Extensions — design rationale

**Non-normative.** The normative rules are `SPEC.md` §6.1. Nothing in this
document constrains an implementation; where the two appear to disagree,
`SPEC.md` is correct.

Status: proposal, decisions settled 2026-08-28
Related: `wallet-frontend#183` (WSCA migration / private data split),
`wwWallet/wallet-frontend#751` (typed collections — §7)

This document holds everything that is not a rule: why `S.extensions` is
shaped as it is, the evidence behind each rule, the alternatives weighed,
what changed under review, and two corrections to claims made in other
documents. It exists so that `SPEC.md` can be read as a specification rather
than an argument.

---

## 1. Why this exists

Three kinds of native-SDK state need somewhere to live in the private data
blob:

- WSCD key metadata — how to address a key created on a roaming
  authenticator.
- OID4VCI renewal state — the `refresh_token` and the DPoP key it is bound
  to.
- Blind BBS holder state — the blinding factor, without which a BBS
  credential can never be presented again.

Each was heading for the same treatment: its own top-level field under `S`,
its own specification section, its own `wallet-frontend` reducer, and its
own note explaining that it is not yet normative and may be lost. That
pattern costs a cross-repo change per addition and had already accumulated a
standing data-loss warning. `wallet-frontend#183` §12.3 names resolving it
as the one remaining Phase 0 item.

This replaces the pattern rather than extending it a third time.

**Alignment with credential metadata (PR #3, `feat/credential-metadata`).**
All three kinds of state above are *defined by the client*, which is why they
live in `S.extensions`. A different kind of data exists: data that a
counterparty supplies for exactly one credential entry (for example a secret
an issuer delivers in its credential response). PR #3 gives that its own home,
an optional `metadata` member of the credential entry, and a general rule that
a rewriting reader preserves unknown members of `S` and of credential entries.
The two are complementary, not alternatives: counterparty-supplied data tied to
one entry belongs in the entry; client-defined state, and state spanning
several entities (such as a refresh token per `batchId`), belongs in a
namespace. The sections below record the situation *before* that change; where
a statement there is narrower than the combined specification, an alignment
note says so.

---

## 2. What was verified

Both claims below were checked by running `wallet-frontend`'s own schema
modules under vitest against commit `6cb68a35`, not by reading them. The
probe was removed afterwards.

### 2.1 Unknown `S` fields survive a fold — the existing documents are wrong

`wallet-frontend#183` §12.2 and the uncommitted draft of a
`privatedata-spec` §6.1 both state that `wallet-frontend`'s typed reducers
*silently drop* `S.wscdCredentials` on the next write.

On the normal path they do not. `foldState` starts from `container.S` — the
loaded base state, never a fresh one — and `walletStateReducer` spreads
`{...state}`, so unrecognised keys are carried through:

```
S.wscdCredentials = { fido2: "OPAQUE-STATE" }
foldState(container)          // with a known alter_settings event
// → {"fido2":"OPAQUE-STATE"}    survives
```

The `initialWalletStateContainer()` call that would discard them runs only
when migrating a V1 keystore, which predates the container entirely.

> **Alignment note.** This section examines `S.wscdCredentials`, a field that
> only a client defines. It does not show that *every* unknown per-entry
> datum needs an extension: a member inside a credential entry is carried by
> the event that creates the entry, so it is part of what a merge replays,
> not of the fold cache `S`. That reading follows from §2.3 and has not been
> separately run against `wallet-frontend`.

### 2.2 Unknown event types crash the merge

An event type `wallet-frontend` does not know does **not** pass through
harmlessly. `mergeDivergentHistoriesWithStrategies` buckets events with
`eventsByType[event.type][0].push(event)` against a literal map of the nine
known types. For anything else that lookup is `undefined`:

```
mergeEventHistories(historyWithUnknownEvent, otherHistory)
// → THREW: Cannot read properties of undefined (reading '1')
```

The subsequent `for (const type in mergeStrategies)` iterates only known
types, so even without the throw the events would be dropped from the merged
history. This fires on a `412` conflict — two devices, one account.

### 2.3 The real loss path is merge, not fold

`mergeEventHistories` sets `S: baseState` — the common ancestor's state —
and replays events on top. So **`S` is a fold cache and `events` are the
source of truth.** Anything written into `S` without a corresponding event
is not reconstructible after a merge.

That single sentence is the whole design constraint. It also explains why
the current fields look correct in testing and lose data in the field: the
fold path preserves them, and only a two-device conflict exposes the
problem.

### 2.4 Behaviour today

| Carrier | Load → fold → save | 412 conflict merge | Verdict |
|---|---|---|---|
| Unknown field on `S` | preserved | discarded | Silent loss, only on conflict |
| Unknown event type in `events[]` | preserved | throws | Hard failure, blocks sync |
| Known event type | preserved | merged | The only durable carrier |

Neither extension route works end to end. The one that does — a known event
type with a merge strategy — is what `S.extensions` generalises.

"The only durable carrier" in the table means the only one for state that is
not part of a credential entry. Unknown members of an entry written in the
entry's creation event are carried with that event (see the alignment note
in §2.1), which is what makes the `metadata` member of PR #3 viable without an
event type of its own.

### 2.5 A note on §6.1 and §6.2

At the time of writing, `origin/main` of this repository contained no
`wscdCredentials` text at all. The sections that `wallet-frontend#183` and
several native-SDK source comments cite as "privatedata-spec §6.1 / §6.2"
existed only as uncommitted local edits and were never published.

`SPEC.md` §6.2 now documents both legacy fields as deprecated, so that a
reader encountering them in a real container knows what they are, without
implying they were ever the recommended shape.

---

## 3. The design

One event type, one state field, one reducer, one merge strategy —
namespaces underneath.

```json
"extensions": {
  "org.siros.wscd": { "kid-a1b2": "<opaque>", "kid-c3d4": "<opaque>" },
  "org.siros.bbs":  { "1849302113": "<opaque>" }
}
```

```json
{
  "type": "set_extension",
  "namespace": "org.siros.bbs",
  "key": "1849302113",
  "value": "<opaque string>"
}
```

The reducer is total and generic: assign, or delete on a `null` value.
`wallet-frontend` never needs to know what a namespace means. The merge
strategy is last-write-wins on `(namespace, key)` ordered by
`(timestampSeconds, eventId)` — the same shape as the existing
`new_presentation` dedupe, so it slots into the current machinery rather
than sitting beside it.

### 3.0 One merge mode, after two rounds of review

The first draft made last-write-wins the only option. Review
([PR #1](https://github.com/sirosfoundation/privatedata-spec/pull/1))
pointed out that this permanently prevents resolution finer than whole-entry
replacement — two devices each adding a distinct item to a collection cannot
both survive — and that flattening extensions into a key-value store sits
oddly in a design whose whole argument is that `events` carry more than a
snapshot. That criticism is correct, and a second `events` mode was added in
response: the namespace defining its own event types and reduction, with
clients that did not support it required to retain, ignore, and never fold
those events.

**It has since been removed, and last-write-wins is again the only mode.**
Not because the criticism was wrong, but because the capability was being
paid for twice. See §9.

### 3.1 The decision that matters: keys name entities### 3.1 The decision that matters: keys name entities

`S.wscdCredentials.fido2` is one opaque blob for a whole plugin, and
last-write-wins on *that* is data loss: two devices each enrolling a
different authenticator produce two blobs, and one silently wins.

Keyed per `kid`, the two devices write disjoint keys and merge cleanly with
no special strategy. The same holds for BBS state keyed per credential and
refresh tokens keyed per `batchId`.

**Choosing keys so that last-write-wins is *correct* is what lets a single
generic strategy serve every future namespace.** This is why `SPEC.md`
§6.1.2 makes it a MUST rather than a recommendation.

---

## 4. Settled decisions

### 4.1 The registry belongs to this specification

A table in `SPEC.md` §6.1.6. Registration is a spec change: enough friction
that names get considered, little enough that it never blocks a release.

### 4.2 Bound the shape, because you cannot bound the size

A per-namespace byte budget was the original proposal and was wrong. It is
often impossible to say in advance how large a namespace becomes — it grows
with enrolled authenticators, issued credentials, renewable batches. Any
number picked up front is either uselessly generous or a ceiling someone
hits in production.

So §6.1.2 constrains *growth* instead: extension state MUST be proportional
to entities the user can enumerate and delete, and MUST NOT grow with event
count — in particular, no append-only history inside an entry value.
Last-write-wins already gives this, since only the newest value per key is
retained; the rule exists to stop it being defeated by packing a log into
the value.

That is checkable, unlike a byte budget. What remains is *accounting*:
per-namespace sizes surfaced at runtime, so a container approaching the
transport limit identifies which namespace is responsible.

### 4.2a Folding is order-independent

Review raised a determinism problem: under ignore-and-retain, a client
supporting only version 1 folds v1 events past the horizon while leaving v2
events unfolded, so the v1 events resolve first — and the folded outcome
depends on which client folded.

This does not arise. The result for a key is the value of the greatest
`(timestampSeconds, eventId)` among its events, so folding a prefix and
later applying the remainder reaches the same state as folding everything at
once. Partial support across a fleet does not make the folded state depend
on who folded it.

It would have arisen under the `events` mode described in §3.0, where the
reduction belongs to the namespace — one of several reasons that mode is no
longer specified (§9).

Review also exposed a genuine gap: the first draft ordered on
`timestampSeconds` alone, which is not deterministic on equal timestamps.
The `eventId` tiebreak is now REQUIRED.

### 4.2b What a version actually is

"A version is a new namespace" removes the cross-version fold interaction,
but taken literally it leaves nothing distinguishing `org.siros.bbs/v2` from
an unrelated namespace — while §6.1.5 originally kept migration rules that
only mean something if the two *are* related. That was inconsistent.

Working it through against real namespaces resolves it. A v2 of
`org.siros.bbs` would exist because what a BBS credential carries changed —
a pseudonym slot, say. At that point v2 state cannot be synthesised for a v1
credential: the blinding factor and committed messages come from an issuance
handshake that cannot be replayed. The credential would be re-issued. The
same holds for `org.siros.wscd`: new metadata fields cannot be invented for
a key already on an authenticator; it would be re-enrolled.

So migration is not under-specified, it is usually **impossible**, and the
real model is coexistence and drain:

- an entity's state lives under whichever version was current when the
  entity was created;
- new entities go to the newest supported version;
- old versions drain as their entities are deleted, which §6.1.4 already
  requires;
- nothing migrates, and no client deletes another version's state.

A version therefore differs from an unrelated namespace only by a lifecycle
expectation — same class of entity, predecessor is legacy-but-live — and not
by any format mechanism. That is also why no client support index is needed:
it answers "when can superseded state be retired", and nothing retires
superseded state.

### 4.3 A stale peer is a question for the user, not a merge

Tombstones must outlive the fold horizon, or a merge with a long-absent
device resurrects deleted entries. But retention alone does not solve the
general case: once a peer has been away longer than the horizon, its merge
base has been folded into `S` and is gone, so no correct merge exists for
*any* state — extensions included.

The resolution (§6.1.4) is a maximum time between folds. When a returning
wallet exceeds it, the histories are not silently reconciled; the user is
asked which wallet is authoritative.

This lands on a real code path. The horizon is already configurable at
`FOLD_EVENT_HISTORY_AFTER_SECONDS`, defaulting to 30 days. And
`mergeEventHistories` already detects the condition: with no common ancestor
it concatenates both histories, after which `validateEventHistoryContinuity`
throws `"Invalid event history chain"`. Today that surfaces as an opaque
failure with no way forward. Turning it into an explicit choice is a strict
improvement on what is there, independent of extensions entirely.

### 4.4 Tolerance ships on its own

The `wallet-frontend` tolerance work is not gated on any of this. It fixes a
live crash on two-device accounts and is worth landing whatever becomes of
the rest.

---

---

## 5. Work, by repository

| Repo | Change | Owner |
|---|---|---|
| `privatedata-spec` | Normative §6.1 and registry; legacy fields deprecated in §6.2; this design document; conformance vectors; conformance-runner fixes | this PR |
| `wallet-frontend` | `set_extension` event, generic reducer, LWW strategy, unknown-type tolerance, stale-peer resolution | separate session |
| `siros-sdk-kotlin` | `WalletExtensionStore`; migrate WSCD + refresh-token state; add BBS holder state | native SDK work |
| `siros-sdk-swift` | Same surface, mirrored | native SDK work |

### 5.1 Conformance vectors added here

The existing `metadata-preservation-001` fixture asserts only that *known*
fields survive decrypt and re-encrypt. Nothing covered unknown data, which
is why both defects in §2 went unnoticed. Six vectors close that:

| Vector | Asserts |
|---|---|
| `extensions-unknown-field-001` | An unrecognised top-level `S` field survives decrypt → re-encrypt |
| `extensions-unknown-event-001` | An unrecognised event type survives a merge, without raising |
| `extensions-concurrent-keys-001` | Two devices writing different keys in one namespace both survive — the case today's design loses |
| `extensions-tombstone-001` | A tombstone deletes, and is not resurrected by a peer at the fold horizon |
| `extensions-stale-peer-001` | A peer beyond the fold horizon is an unresolvable divergence, not a merge |
| `extensions-size-accounting-001` | Per-namespace size accounting is reported for a large container |
| `extensions-lww-fold-order-001` | Folding a prefix then the remainder converges with folding everything — what lets a client fold a namespace it does not understand |
| `extensions-lww-tiebreak-001` | Equal timestamps resolve by `eventId`, identically on every client |
| `extensions-unknown-namespace-retained-001` | An unrecognised namespace is ignored, preserved, and not an error |
| `extensions-version-coexistence-001` | Two versions of one namespace coexist; neither client deletes nor migrates the other's state |

### 5.2 Conformance runner

The runner could never have exercised the vectors added here, or the two
that already existed. Four defects, all pre-existing, all fixed in this PR:

1. `((COUNTER++))` returns the *old* value, so the first increment of a
   zero counter exits non-zero and `set -e` kills the script. This is why
   exactly one vector ever ran and no summary was ever printed.
2. The vector loop was a pipeline, so it ran in a subshell and every
   counter increment was discarded before `print_summary` read it. It now
   reads from a dedicated file descriptor, which also stops anything in the
   loop body consuming the vector stream.
3. `WALLET_FRONTEND_PATH` and `SIROS_SDK_SWIFT_PATH` were dereferenced but
   never assigned. Under `set -u` that aborts the run, and the caller's
   `2>/dev/null` made the error invisible.
4. A missing client harness returned the same code as a wrong answer, so
   "not installed" counted as a failure and, with `STOP_ON_FAIL` defaulting
   to 1, aborted everything. Unavailability now has its own return code and
   is reported as a skip.

A run where every client was skipped also reported "All tests passed ✓". It
now says plainly that nothing was exercised — a corpus that silently
verifies nothing is worse than one that fails.

---

## 6. Sequencing

Ordered and gated.

1. **Tolerance and vectors.** `wallet-frontend` stops crashing on unknown
   event types and carries them through merges; the null-merge-base case
   becomes a user-facing choice. No format change, no SDK change.
   *Gate: none — ships independently of `#183` entirely.*

2. **The extension namespace.** `set_extension`, the generic reducer and the
   LWW strategy land in `wallet-frontend`; §6.1 becomes normative. Nothing
   written to it yet.
   *Gate: step 1, so a client that predates the event type does not choke on
   it.*

3. **SDKs move across.** Both SDKs write through their extension store. BBS
   holder state goes straight there — it has no legacy form. WSCD state
   becomes per-`kid` entries, which is the fix for the two-device enrolment
   loss, not just a relocation.
   *Gate: step 2. Read-both, write-new for one release, then drop the legacy
   fields.*

4. **Fold into V4.** `S.extensions` carries into `#183`'s V4 state JWE
   unchanged. It is already on the side of the split that keeps the event
   log.
   *Gate: `#183` Phase 3.*

### 6.1 Interim behaviour for the SDKs

Until step 2 lands, an SDK that emits `set_extension` events would crash
`wallet-frontend`'s merge (§2.2). SDKs therefore adopt the `S.extensions`
*shape* first and defer event emission: writing to the state field alone is
no worse than the status quo — preserved on fold, lost on merge, exactly as
the legacy fields behave today — while unifying three ad-hoc fields into one
and fixing the per-entity key problem immediately.

---

## 7. Prior art: typed collections (`wwWallet/wallet-frontend#751`)

`wwWallet/wallet-frontend#751` ("Add support for JPT with Split-BBS, and JWT
key generation via ARKG") extends the same wallet state with two new kinds
of client data, using a different mechanism. That work was not adopted — the
ARKG approach it serves was superseded by the WSCD-manager design — but as a
schema-and-merge design it is the closest prior art to §6.1, and it is
better than §6.1 in ways worth being explicit about.

### 7.1 What it does

It introduces a new schema version carrying two **typed collections**:

```typescript
export type WalletStateV3 = SchemaV2.WalletState & {
  arkgSeeds: MaybeNamed<WebauthnSignArkgPublicSeed>[],
  splitBbsKeypairs: MaybeNamed<WebauthnSignSplitBbsKeypair>[],
}
```

with four typed events (`new_arkg_seed`, `delete_arkg_seed`,
`new_split_bbs_keypair`, `delete_split_bbs_keypair`), a reducer per
collection, and a merge strategy per event type. Each strategy is the same
shape:

```typescript
deduplicateBy(
  a.concat(b).filter(e => e.type === 'new_arkg_seed')
   .sort(compareBy(e => e.timestampSeconds)),
  e => toBase64Url(e.arkgSeed.credentialId),
)
```

### 7.2 Where it agrees, and what §6.1 takes from it

Three of its choices arrived independently at the same conclusions as
§6.1, which is the strongest available evidence that those rules are right:

- **Merge identity is a per-entity key.** Deduplication is by
  `credentialId` — one entry per authenticator credential, never one
  aggregate per subsystem. This is §6.1.1, reached from the other
  direction.
- **Deletion is an event, not an absence.** `delete_arkg_seed` participates
  in the merge exactly as the creation event does. These are §6.1.4's
  tombstones under another name.
- **Ordering before deduplication.** `sort(compareBy(timestampSeconds))`
  then `deduplicateBy(key)` is precisely §6.1.3's last-write-wins, and it
  is already proven code in the reference implementation. §6.1.3's merge
  rule is specified to match it rather than inventing a second formulation.

One further idea is worth borrowing: `MaybeNamed<T>` layers an optional
user-facing `name` on top of a cryptographic record, so a wallet can label
an authenticator without the record's owner having to model that. A
namespace MAY adopt the same convention within its own entry values.

### 7.3 Where the two differ

| | Typed collections (#751) | `S.extensions` (§6.1) |
|---|---|---|
| Type safety | Full — compile-time types, exhaustive reducers | None inside a value; the value is opaque |
| Cost of a new data kind | New event types, reducer, merge strategy, schema version, migration | One registry row |
| Who must change | The web wallet, for every addition | Nobody, once the mechanism exists |
| Cross-client carriage | Only clients that model the type can hold it | Any client can carry any namespace |
| Coordination | A new data kind needs a change in the web wallet | A new data kind needs a registry row |
| Merge correctness | A hand-written strategy per type | One generic strategy; correctness comes from §6.1.1 |
| Granularity | Any, per type | Whole entry — finer resolution is deliberately not offered (§9) |
| Discoverability | Excellent — the shape is in the type system | Weak — meaning lives with the namespace owner |

§6.1 also makes one class of merge error unrepresentable. #751 merges each
event type independently — `new_*` events are deduplicated against each
other by entity id, `delete_*` events likewise — and `deduplicateBy` retains
the *first* entry of an ascending-sorted list, so the earliest event per key
wins within its type. Consider one entity across a divergence:

| | |
|---|---|
| `t1` | device A creates entity `X` |
| `t2` | device A deletes `X` |
| `t3` | device B, diverged, creates `X` again |

The `new_*` bucket deduplicates to the `t1` creation and **discards the
`t3` re-creation**; the `delete_*` bucket keeps `t2`. The merged history is
then globally sorted and reduced, so `X` is created and then deleted, and
the later re-creation is lost.

Expressing deletion as a `null` value on the same `(namespace, key)` reduces
creation and deletion to one ordered sequence per key: `value@t1`,
`null@t2`, `value@t3` resolves to the `t3` value.

This is a property of the model rather than an unfixable defect in #751 —
deduplicating to the latest entry, or moving deletion into the value, would
correct it. The point is that the typed-collection shape admits the error
and the reference implementation contains it, while last-write-wins on a
single key cannot express it.

### 7.4 When to use which

They are complementary, not competing.

An earlier draft drew the line at whether the web wallet would *ever*
understand the data, and offered BBS holder state as the canonical
carry-only case. That was wrong, as review pointed out: once BBS is
implemented in the web wallet it will need to interpret and write holder
state to create commitments, store signatures and build presentations. The
same objection retires the other examples — `#183` puts the WSCD manager in
the browser, and the web wallet already implements OID4VCI. There may be no
*permanently* opaque case at all.

The distinction that survives is not *whether* a client understands the
data but *when*:

- **Use a typed collection** when the web wallet participates in the data
  today — renders it, lets the user name or delete it, or makes decisions
  from its contents. #751's ARKG seeds are exactly this: they appear in
  Settings and carry user-assigned names. Type safety and UI integration
  are worth a schema version there.
There is also a practical asymmetry behind that line. This organisation's
web wallet is a fork of `wwWallet/wallet-frontend`. Under the typed-collection
model, every new native-SDK data kind requires a new event type, reducer,
merge strategy and schema version *in the web wallet* — for state the web
wallet cannot use and has no reason to model. That is either permanent fork
divergence or an upstream change for someone else's data. An extension
namespace lets the web wallet carry the state faithfully while modelling
nothing.

- **Use an extension namespace** when clients need to hold the data before
  every client models it. Four clients on independent release cadences
  cannot adopt a schema version simultaneously. An extension lets a native
  SDK ship state that the web wallet carries faithfully without modelling,
  and lets the web wallet model it later — without a flag day, and without
  the intervening releases losing anything.

So the value is **decoupling when each client learns a data kind**, not
permanent opacity. A namespace is expected to graduate to a typed
collection once the web wallet genuinely owns the data; §6.1.5's
version-as-namespace rule is what makes that graduation expressible rather
than a breaking change.

That framing also sets the honest cost. For as long as a data kind lives in
an extension, no client but its owner can validate it, render it, or reject
a malformed value — the container carries bytes it cannot check. Typed
collections are strictly better once the wallet owns the data, which is why
graduation is the expected end state and not a courtesy.

---

## 8. Review record

The normative text in `SPEC.md` §6.1 is the result of one round of review on
[privatedata-spec#1](https://github.com/sirosfoundation/privatedata-spec/pull/1).
Four changes came out of it, recorded here because the reasoning is not
visible in the rules themselves.

### 8.1 Last-write-wins could not be the only mode

The first draft made LWW universal. Review pointed out that this permanently
prevents resolution finer than whole-entry replacement — two devices each
adding a distinct item to a collection cannot both survive — and that
flattening extensions into a key-value store sits oddly in a design whose
argument is that `events` carry more than a snapshot. Correct on both
counts. A second mode was added in response and has since been removed;
see §3.0 and §9.

### 8.2 Ordering on timestamp alone is not deterministic

Raised indirectly, while arguing about fold determinism across clients with
different support levels. The first draft ordered on `timestampSeconds`
only, which lets two clients disagree about identical input. `eventId` is
now a REQUIRED tiebreak, with a conformance vector.

The broader determinism concern does not apply to last-write-wins — folding
is order-independent (§4.2a). It would have applied to the `events` mode
added in response to §8.1 and since removed (§9).

### 8.3 A version is not meaningfully different from a new namespace

The first draft declared versions fully independent and then kept migration
rules that only mean something if they are related. Asked what actually
distinguishes `org.siros.bbs/v2` from an unrelated namespace, the honest
answer was: nothing. §4.2b records the resolution — migration is usually
impossible, so the model is coexistence and drain, and a version differs
only by a lifecycle expectation.

### 8.4 The carry-only framing was wrong

Review noted that the web wallet will need to interpret and write BBS holder
state once BBS is implemented there — and BBS was the example chosen to
illustrate permanently opaque data. §7.4 is rewritten around *when* each
client learns a data kind rather than whether it ever does.

---

## 9. `events` mode: considered, specified, removed

Between the first and second rounds of review, `SPEC.md` §6.1 carried a
second merge mode. A namespace could declare `events` instead of the default
last-write-wins, defining its own event types and reduction; clients without
support were required to retain those events, ignore them when folding, and
never fold them into `S`.

It is no longer specified. The reasoning, recorded because the capability was
asked for in review and the removal reverses that answer:

**It had no users.** Every namespace in the registry is entity-snapshot
state — one credential's holder state, one key's metadata, one batch's
refresh material. For all three, last-write-wins is *correct*, not a weaker
approximation. Nothing needed the finer granularity, so every rule in the
mode was unvalidated by any implementation. This repository already
demonstrated where that leads: §6.1 and §6.2 were cited by
`wallet-frontend#183` and by native-SDK source comments while existing only
as uncommitted local edits, never published.

**It was the most expensive thing in the specification.** Retain-and-ignore
obligations, per-namespace ordering rules, an explicit carve-out from the
growth rule, and the admission that `events` grows without bound for any
client that never gains support. Removing it took `SPEC.md` from six
subsections to five and deleted the only rule the document could not bound.

**The capability was being paid for twice.** Fine-grained convergent merge is
exactly what a CRDT provides by construction, and
[`SPEC-ALTERNATIVE-AUTOMERGE.md`](SPEC-ALTERNATIVE-AUTOMERGE.md) specifies
that alternative. Building a partial, hand-rolled version of it inside an
event log — one that only works for clients that already understand the
namespace — buys a fraction of the capability at most of the cost, and would
have to be maintained alongside whichever answer wins.

**What this concedes.** The review criticism stands: last-write-wins cannot
express two devices each adding a distinct item to a collection, and that is
a real limitation, not a theoretical one. The position is not that the
limitation is acceptable forever. It is that the general fix does not belong
in this layer, and that the first namespace to genuinely need it should make
the case then — by which time the alternative may have answered it.
