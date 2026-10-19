# SIROS Wallet Private Data Blob Specification (Normative)

Version: 2.1  
Date: 2026-08-28  
Status: Normative (reference implementation aligned)

## 1. Scope and Source of Truth

This document defines the normative format and processing rules for the wallet private data blob ("privateData"), which contains encrypted wallet state including credential key material and credentials.

The canonical source of truth is the web wallet implementation in `wallet-frontend`.

If any SDK behavior differs from this document, the `wallet-frontend` behavior is normative.

## 2. Normative Language

The terms MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted as in RFC 2119.

## 3. Blob Transport and Encoding

### 3.1 Stored backend field

`privateData` is stored as a serialized UTF-8 JSON container blob.

### 3.2 HTTP transport

- `POST /user/session/private-data` MUST receive the serialized container bytes.
- `GET /user/session/private-data` returns JSON with `privateData` encoded as tagged binary:

```json
{
  "privateData": { "$b64u": "<base64url(container-json-bytes)>" }
}
```

### 3.3 Tagged binary representation

Binary fields in JSON MUST be encoded as:

```json
{ "$b64u": "<base64url-no-padding>" }
```

This applies both to the top-level response payload wrapper and binary fields inside the container.

## 4. Container Model

The current normative output format is the asymmetric encapsulation container:

```json
{
  "mainKey": { ... },
  "prfKeys": [ ... ],
  "jwe": "<compact-jwe>"
}
```

### 4.1 Top-level fields

- `mainKey` MUST be present in newly written containers.
- `prfKeys` MUST be present (possibly empty).
- `jwe` MUST be present and MUST be a compact JWE string.

### 4.2 `mainKey`

`mainKey` defines how a content-encryption main AES key is decapsulated by PRF entries.

`mainKey.publicKey.importKey` MUST contain:

- `format`: `"raw"`
- `keyData`: tagged binary, uncompressed P-256 point (65 bytes)
- `algorithm.name`: `"ECDH"`
- `algorithm.namedCurve`: `"P-256"`

`mainKey.unwrapKey` MUST contain:

- `format`: `"raw"`
- `unwrapAlgo`: `"AES-KW"`
- `unwrappedKeyAlgo.name`: `"AES-GCM"`
- `unwrappedKeyAlgo.length`: `256`

### 4.3 `prfKeys[]`

Each PRF key entry corresponds to one WebAuthn credential.

Required fields:

- `credentialId` (tagged binary)
- `prfSalt` (32 bytes tagged binary)
- `hkdfSalt` (32 bytes tagged binary)
- `hkdfInfo` (tagged binary, normative value below)
- `keypair` (encapsulation keypair)
- `unwrapKey` (wrapped main key)

Optional fields:

- `transports`
- `algorithm` (if present, MUST be AES-GCM 256)

`keypair.publicKey.importKey` and `keypair.privateKey.unwrapKey` MUST encode ECDH P-256 keypair material as in the reference.

`unwrapKey.wrappedKey` MUST be AES-KW wrapped main key bytes.

## 5. Cryptographic Processing

## 5.1 PRF-derived key

Given WebAuthn PRF output (`prfOutput`), derive PRF wrapping key:

- HKDF hash: SHA-256
- IKM: PRF output
- salt: `hkdfSalt`
- info: `hkdfInfo`
- output length: 32 bytes

Normative default info string is UTF-8 `"eDiplomas PRF"`.

## 5.2 Main key decapsulation flow

1. Decrypt `keypair.privateKey.unwrapKey.wrappedKey` with PRF key using AES-GCM (`unwrapAlgo.iv`).
2. Import resulting ECDH private key (JWK).
3. ECDH with `mainKey.publicKey`.
4. Use derived secret as AES-KW key material (256-bit key).
5. Unwrap `prfKeys[i].unwrapKey.wrappedKey` to obtain main key.

## 5.3 Payload encryption

`jwe` MUST use:

- `alg`: `A256GCMKW`
- `enc`: `A256GCM`

The decrypted plaintext MUST be UTF-8 JSON WalletStateContainer (Section 6).

## 6. JWE Plaintext: WalletStateContainer

The plaintext JSON MUST follow the event-sourced wallet schema used by `wallet-frontend`:

```json
{
  "lastEventHash": "...",
  "events": [ ... ],
  "S": {
    "schemaVersion": 3,
    "credentials": [ ... ],
    "keypairs": [ ... ],
    "presentations": [ ... ],
    "settings": { "openidRefreshTokenMaxAgeInSeconds": "..." },
    "credentialIssuanceSessions": [ ... ]
  }
}
```

Normative requirements:

- `S.schemaVersion` MUST be `3` for newly written state.
- `events` and `lastEventHash` MUST be preserved as authored unless explicitly folded/merged by event logic.
- `S.keypairs[].keypair.privateKey` MUST contain JWK private key material for ES256 signing keys.
- `S.credentials[]` entries MUST preserve wallet metadata fields (`format`, `kid`, `instanceId`, `batchId`, `credentialIssuerIdentifier`, `credentialConfigurationId`).
- `S.settings.openidRefreshTokenMaxAgeInSeconds` MUST be preserved.
- `presentations` and `credentialIssuanceSessions` MUST be preserved.

### 6.1 `S.extensions`

Clients MAY carry state this specification does not define, under a single
namespaced field. `S.extensions` is an object keyed by **namespace**; each
namespace is an object keyed by **entry key**; each value is an opaque
string.

```json
"extensions": {
  "org.siros.wscd": { "kid-a1b2": "<opaque>", "kid-c3d4": "<opaque>" },
  "org.siros.bbs":  { "1849302113": "<opaque>" }
}
```

Namespaces are reverse-DNS strings, registered in §6.1.6. Registration is a
change to this document.

- Readers MUST NOT interpret a value in a namespace they do not own.
- In addition to any other preservation requirement of this specification, a
  reader that rewrites the container MUST preserve, with identical values,
  every namespace of `S.extensions` and every extension event that it does not
  recognise. An unrecognised namespace is not an error.

A reader that does not implement this section sees `S.extensions` as an
unknown member of `S` and handles it as it would any other unknown member.

*Non-normative guidance — extension namespace or entry member.* State that a
client defines for its own use (key handles, renewal material, the holder
state of a credential scheme) belongs in a namespace of `S.extensions`. Data
that a counterparty such as an issuer supplies for exactly one credential
entry, and that the wallet stores as received without interpreting it, is
carried in that entry, not in an extension: it then travels with the entry,
and deleting the entry deletes it. Where this specification defines a member
of the credential entry for such data, that member is used. State that spans
several entities, such as one refresh token shared by a batch of credentials,
is not tied to a single entry and belongs in an extension keyed by the entity
(`batchId`). Do not store the same datum in both places.

*Non-normative illustration:*

```typescript
type Extensions = Record<Namespace, Record<EntryKey, OpaqueValue>>;
type WalletStateV3 = { /* … */ extensions?: Extensions };
```

#### 6.1.1 Entry keys

An entry key MUST identify a single entity the wallet already tracks — a key
identifier, a credential identifier, a batch identifier. An entry key MUST
NOT name a subsystem, a plugin, or a category.

*Non-normative illustration — the rule exists because resolution is
per key:*

```typescript
// Conformant: two devices enrolling two authenticators write disjoint keys.
const ok: Extensions = {
  "org.siros.wscd": { "kid-a1b2": "…", "kid-c3d4": "…" },
};

// Non-conformant: one entry for the whole plugin. Concurrent writes collide
// on a single key, and last-write-wins discards one authenticator.
const notOk: Extensions = {
  "org.siros.wscd": { "fido2": "…" },
};
```

#### 6.1.2 Size

- A namespace's state size MUST be proportional to entities the user can
  enumerate and delete.
- A namespace MUST NOT grow its state with the number of events. An entry
  value MUST NOT accumulate an append-only history.
- Deleting the entity an entry key names MUST delete the entry.

*Non-normative:* data carried inside a credential entry disappears with the
entry. An extension entry that concerns a credential lives outside the entry
and is removed only by the tombstone of §6.1.3, which the client deleting the
credential has to write.

Implementations SHOULD report per-namespace sizes.

#### 6.1.3 Events, reduction and merge

Extension state MUST be written as events, of type `set_extension`:

```json
{
  "type": "set_extension",
  "schemaVersion": 3,
  "eventId": 1234,
  "parentHash": "…",
  "timestampSeconds": 1756400000,
  "namespace": "org.siros.bbs",
  "key": "1849302113",
  "value": "<opaque string>"
}
```

- Reduction MUST set `S.extensions[namespace][key]` to `value`.
- A `value` of `null` is a tombstone: reduction MUST delete the key.
- Merge resolution is last-write-wins per `(namespace, key)`, ordered by
  `timestampSeconds` and, where equal, by `eventId`. The tiebreak is
  REQUIRED.
- Tombstones MUST survive event-history folding for at least the maximum
  permitted time between folds (§6.1.4).

*Non-normative illustration — reduction, total over unknown namespaces:*

```typescript
function extensionsReducer(state: Extensions = {}, e: WalletSessionEvent): Extensions {
  if (e.type !== "set_extension") return state;
  const ns = { ...(state[e.namespace] ?? {}) };
  if (e.value === null) delete ns[e.key];
  else ns[e.key] = e.value;
  return { ...state, [e.namespace]: ns };
}
```

*Non-normative illustration — merge, with the required tiebreak:*

```typescript
const setExtensionStrategy: MergeStrategy = (_mbesv, a, b) =>
  deduplicateBy(
    a.concat(b)
      .filter(e => e.type === "set_extension")
      // Descending, so deduplicateBy (which keeps the first occurrence)
      // retains the newest event per key.
      .sort(compareBy(e => [-e.timestampSeconds, -e.eventId])),
    e => `${e.namespace}\u0000${e.key}`,
  );
```

*Non-normative deployment note:* a client that predates `set_extension` may
fail, rather than ignore, an event type it does not know when it merges
divergent histories (`docs/EXTENSIONS-DESIGN.md` §2.2). Writers therefore
introduce `set_extension` events only once the clients sharing the account
tolerate unknown event types; until then the `S.extensions` shape can be
written without events (`docs/EXTENSIONS-DESIGN.md` §6.1).

Folding is order-independent: for a given key the result is the value of the
greatest `(timestampSeconds, eventId)` among its events, whether a client
folds a prefix of the history or all of it. A client MAY therefore fold a
namespace it does not understand, and the folded state does not depend on
which client folded it.

#### 6.1.4 Peers beyond the fold horizon

A peer that has not synchronised within the fold horizon no longer shares a
reachable common ancestor, and no correct merge exists for any part of the
state.

- Implementations MUST NOT silently reconcile such histories.
- When no common ancestor is found, the implementation MUST surface the
  divergence and let the user choose which wallet is authoritative.
- Concatenating the two histories produces an invalid event chain and MUST
  NOT be treated as a merge result.

*Non-normative illustration:*

```typescript
const base = await findMergeBase(local, remote);
if (base === null) {
  // Not an error to report and not a merge to attempt: the user decides.
  throw new DivergedBeyondFoldHorizon({ local, remote });
}
return mergeFrom(base, local, remote);
```

#### 6.1.5 Versions and dependencies

A namespace identifier MAY carry a version suffix (`org.siros.bbs/v2`). A
versioned namespace is independent of its predecessor: its own registry
entry and its own state.

- Clients MUST NOT assume support for one version implies support for
  another.
- An entity's state lives under whichever version was current when the
  entity was created. New entities MUST be written to the newest version the
  creating client supports.
- Clients MUST NOT be required to migrate extension state between versions.
  A container MAY hold several versions indefinitely.
- A client MUST NOT delete state belonging to a version it does not support.
- Where a newer version's state is derivable from the older, that
  namespace's registration MAY specify a migration, which MUST be performed
  only by a client supporting both versions.

If a namespace's correct processing depends on another namespace — such that
reducing its events while ignoring the other's would produce wrong state —
its registration MUST declare that dependency, and a client supporting the
dependent namespace MUST also support the one it depends on.

#### 6.1.6 Namespace registry

| Namespace | Owner | Entry key | Value | Depends on |
|---|---|---|---|---|
| `org.siros.wscd` | WSCD plugins (native SDKs) | `kid` | Key metadata needed to address a key created on a roaming authenticator: credential handle, public key, plugin identity. Never private key material | — |
| `org.siros.bbs` | Blind BBS credentials (native SDKs) | credential id | Blinding factor, committed messages, bound key binding public keys, and the key handles needed to exercise the key binding private keys | `org.siros.wscd` |
| `org.siros.oid4vci.refresh` | OID4VCI renewal (native SDKs) | `batchId` | `refresh_token` and the DPoP key it is bound to | — |

### 6.2 Legacy top-level extension fields (deprecated)

Native SDKs released before §6.1 write two top-level fields under `S`:
`wscdCredentials`, keyed by WSCD plugin ID, and `credentialRefreshTokens`,
keyed by stringified `batchId`. Neither was described by a published version
of this document.

- Readers MAY accept both for migration.
- Writers MUST NOT emit them. The namespaces in §6.1.6 replace them.

A reader that does not migrate these fields handles them as unknown members
of `S`.

## 7. Legacy Compatibility Rules

`wallet-frontend` accepts legacy containers where PRF/password entries directly contain wrapped main keys (`mainKey` symmetric wrapping style) and may upgrade them to asymmetric encapsulation style.

Normative behavior:

- Readers MAY accept legacy formats.
- Writers SHOULD emit asymmetric format (`mainKey` + encapsulation keypair per entry).

## 8. Concurrency and Sync

Backend optimistic concurrency is part of privateData lifecycle:

- Clients SHOULD use `X-Private-Data-If-Match` with backend ETag (`X-Private-Data-ETag`).
- On `412 Precondition Failed`, clients SHOULD reconcile by re-fetching remote privateData and merging according to wallet event-history rules before retrying.

## 9. Reference Implementation Pointers

- `wallet-frontend/src/services/keystore.ts`
- `wallet-frontend/src/services/WalletStateSchemaVersion1.ts`
- `wallet-frontend/src/services/WalletStateSchemaVersion3.ts`
- `wallet-frontend/src/util.ts`

### 9.1 Design documents (non-normative)

Design rationale, the evidence behind the rules of Section 6.1, and a
comparison with the typed-collection approach of
`wwWallet/wallet-frontend#751` are in
[`docs/EXTENSIONS-DESIGN.md`](docs/EXTENSIONS-DESIGN.md).

An alternative in which the state layer is a CRDT document rather than an
event log — which would remove the need for §6.1 entirely — is specified for
comparison in
[`docs/SPEC-ALTERNATIVE-AUTOMERGE.md`](docs/SPEC-ALTERNATIVE-AUTOMERGE.md).
Sequencing for both is in [`docs/ROLLOUT-PLAN.md`](docs/ROLLOUT-PLAN.md).

All three documents are non-normative.

## 10. Changes

- 2.1 (2026-08-28): Section 6.1 (`S.extensions`: namespaced extension state, `set_extension` events, namespace registry) and Section 6.2 (deprecation of the legacy top-level fields `wscdCredentials` and `credentialRefreshTokens`) added. Additive; `S.schemaVersion` remains `3`.
