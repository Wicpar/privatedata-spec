# SIROS Wallet Private Data Blob Specification (Normative)

Version: 2.6  
Date: 2026-10-16  
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

## 5.4 Derived secrets

A client MAY derive secrets from `mainKey` for purposes outside the container
itself. All clients (TypeScript and native) MUST derive them identically, so
that the same secret is obtained on every passkey and every device of an
account.

Derivation:

- HKDF hash: SHA-256 (RFC 5869)
- IKM: the 32-byte `mainKey`, as unwrapped in Section 5.2 (never a PRF output:
  PRF outputs differ per passkey, `mainKey` does not)
- salt: empty (as RFC 5869: a string of 32 zero bytes)
- info: `label || context`, where `label` is the UTF-8 string
  `"<namespace>/v<n>"` and `context` is purpose-specific, with no separator
  between them
- output length: at most 32 bytes (a single HKDF block)

`<namespace>` identifies the purpose, in the same reverse-DNS style as the
`S.extensions` namespaces; the version `v<n>` is part of the label, so a
changed derivation is a new label and never silently replaces an old one.

Rules:

- A derived secret MUST NOT be stored, synchronised, exported or logged, and
  MUST NOT be returned outside the component that needs it. It is recomputed
  on use from an unlocked container. An API that offers derivation MUST NOT
  expose `mainKey`.
- `mainKey` is permanent. A client MUST NOT rotate or re-key `mainKey` (for
  example when a passkey is added or removed, or when the payload is
  re-encrypted); a new PRF entry wraps the existing `mainKey`. Should a new
  `mainKey` ever be created for an account that already has derived secrets
  in use, every secret derived from it changes, and any value that was
  computed from one (a commitment, say) no longer matches: such a re-key
  therefore breaks continuity of everything derived and MUST be treated as
  creating a new root.

### 5.4.1 Private seed

The holder's private seed for a credential type is:

    private_seed = HKDF-SHA256(mainKey, salt = empty, info = "org.siros.private_seed/v1" || credentialType)[:16]

`credentialType` is an opaque string supplied by the caller (for example a
document type or a `vct`), UTF-8 encoded and not interpreted. The seed is
therefore stable per credential type: it does not depend on a credential id,
a batch or an issuance. The commitment to it is `SHA-256(private_seed)`.

The label `org.siros.private_seed/v1` is a proposal and needs the
specification owner's decision.

Test vectors: `test-vectors/derived-secrets.json` (fixed roots; self-generated
with independent code, not yet cross-checked between clients). A client
conforming to this section MUST reproduce `seed_hex` and `psc_hex` for every
vector from `root_hex` and `credential_type`.
## 5A. Delivered secrets

A delivered secret is a secret value chosen and supplied by a counterparty such
as an issuer, for example by an issuer in an OpenID4VCI credential response (the
`nym_auth` credential's `secret_seed`). A secret that the wallet generates or
derives itself, for example `private_seed`, is out of scope of this section and
is covered in Section 5.4.

### 5A.0 Parties

The rules of this section name the party that enforces them. The party that
performs the OpenID4VCI request and receives the response is the "OpenID4VCI
client": the wallet itself, or a component acting for the wallet, for example an
engine. The party that merges display metadata is the "metadata merger". The
wallet that holds the encrypted container is the "secret store". One process MAY
fill several of these roles. When they are different processes:

- the OpenID4VCI client enforces the request for `credential_response_encryption`,
  the refusal of a plain response, the refusal of a deferred response that
  carries a seed (Section 5A.2), and the `notification_id` rule;
- the metadata merger enforces stripping (Section 5A.3); a party that receives
  the unstripped `credential_metadata` object MUST strip the seed itself before
  passing the object on to any display-metadata consumer;
- the seed is handed only to the secret store.

Below, "the wallet or its OpenID4VCI client" means the OpenID4VCI client role
in this sense.

### 5A.1 Wire shape

A delivered `secret_seed` is carried in the response-level `credential_metadata`
object of the OpenID4VCI 1.1 Credential Response and Deferred Credential
Response (openid/OpenID4VCI#721, merged into the 1.1 working draft on
2026-06-11). OpenID4VCI 1.1 is a working draft and may still change; the member
name `org.siros.secret_seed` is defined by this specification, not by
OpenID4VCI. It is a collision-resistant member name, as the OpenID4VCI
extension rule requires, and its value is an object:

```json
{
  "credentials": [ { "credential": "..." } ],
  "notification_id": "3fwe98js",
  "credential_metadata": {
    "org.siros.secret_seed": {
      "<namespace>": "00112233445566778899aabbccddeeff"
    }
  }
}
```

- There is ONE `credential_metadata` object per response. It applies to every
  credential in that response; credentials of one batch share one subject and
  one seed. It is not repeated per credential.
- The value of `org.siros.secret_seed` is an object that maps a namespace to a
  seed. A namespace is a non-empty string of at most 64 UTF-8 bytes and is not `namespaces` (reserved for the advertisement of Section 5A.4). The object
  has at least one and at most 8 members. A seed is a JSON string of exactly 32
  lowercase hexadecimal characters (`[0-9a-f]`), the 16-byte seed. Uppercase or
  mixed-case hexadecimal, a different length, a non-string value, or an empty or
  over-sized object is malformed.
- A response MUST NOT carry a delivered secret in any other form. If present,
  `credential_metadata` MUST be a JSON object; an array or any other type is
  malformed and the issuance fails.
- Wallets MUST ignore members of `credential_metadata` that they do not
  understand, and relays and proxies MUST preserve them verbatim. A wallet that
  stores them does so under Section 6 (below).

### 5A.2 Rules

- A response that carries `org.siros.secret_seed` MUST be a JWE-encrypted
  response. The wallet or its OpenID4VCI client MUST refuse a plain
  (unencrypted) response that carries the member: the issuance fails and
  nothing from the response is stored.
- Seed delivery over a Deferred Credential Response is not supported in this
  version. A Deferred Credential Response that carries `org.siros.secret_seed`,
  whether plain or encrypted, MUST be refused by the wallet or its OpenID4VCI
  client, and the issuance fails. (Note, non-normative: a later version may
  define delivery over an encrypted deferred response.)
- The response MUST carry a `notification_id`. The wallet or its OpenID4VCI
  client MUST treat a response that carries a seed but no `notification_id` as
  a failed issuance.
- A malformed `org.siros.secret_seed` member (Section 5A.1) is a failed
  issuance.
- The wallet MUST verify the commitment (below) before storing the seed. A
  mismatch is a failed issuance: the seed MUST NOT be stored or used and the
  wallet MUST NOT accept the credentials of the response.
- A delivered secret MAY be stored in the `metadata` member of the credential
  entry it belongs to (Section 6). The wallet stores, in each credential entry
  of the response, one `metadata` entry whose `type` is the member name
  (`org.siros.secret_seed`) and whose `value` is the member's object exactly as
  received. Other `credential_metadata` members that the wallet chooses to keep
  are stored in the same way, in the order received. See the example in Section 6.
- It is protected exactly like all other container contents: it exists in
  plaintext only inside the encrypted container (Section 5.3) and the unlocked
  wallet.
- It MUST NOT be logged, displayed, or exported in clear, and MUST NOT be sent
  to the backend other than inside the encrypted container.
- It MUST be deleted together with the credential entry it belongs to.
- If the credential makes a commitment to the secret, the wallet MUST verify the
  commitment against the issuer-signed credential before storing the secret and
  again before each use, and MUST treat a mismatch as a failed issuance (the
  secret MUST NOT be stored or used). For `nym_auth` the commitment is
  `SHA256(secret_seed) == ssc`, where `ssc` is the claim of the issuer-signed
  credential and `secret_seed` is the 16-byte value decoded from the lowercase
  hexadecimal string of the namespace that the credential type designates. A
  credential type with no designated namespace present in the object fails
  verification. Seeds of other namespaces are stored as received and are
  verified only if a commitment for them exists.

### 5A.3 Separation from display metadata

In the OpenID4VCI 1.1 draft (openid/OpenID4VCI main bde23b72, "Credential
Metadata") the response-level `credential_metadata` is the same object as the
`credential_metadata` of the public issuer metadata. It is display-centric, and
a value in the Credential Response is preferred over, and overwrites, the
existing value. Extension members are to be collision-resistant names holding
an object. `org.siros.secret_seed` is such a member, at the top level of
`credential_metadata`; it is not nested in a `display` entry. Because the object
is shared with display data, the following apply:

- STRIP BEFORE MERGE. The wallet or its OpenID4VCI client (the metadata merger of Section 5A.0) MUST remove `org.siros.secret_seed` from the
  `credential_metadata` object before any merge into display metadata,
  rendering, caching or logging. The seed goes only to the secret store
  (`S.credentials[].metadata`, Section 6). The remainder of the object (the
  stripped result) is then treated as ordinary display metadata. A relay MUST
  NOT treat the member as display data.
- NEVER PUBLIC. In issuer metadata the member MAY appear only as the
  advertisement of Section 5A.4, a list of namespace names, and never with a
  seed. A Credential Response whose `org.siros.secret_seed` value has the
  advertisement form (a `namespaces` member), and an issuer metadata entry
  whose `org.siros.secret_seed` carries hexadecimal seed values, are malformed.
  An issuer metadata entry that is malformed is treated as if the configuration
  were not offered.

Example. Issuer metadata holds, for the configuration,
`{"display":[{"name":"Nym","locale":"en"}],"org.siros.secret_seed":{"namespaces":["org.siros.nym_auth"]}}`.
The response carries
`{"display":[{"name":"Nym v2","locale":"en"}],"org.siros.secret_seed":{"org.siros.nym_auth":"00112233445566778899aabbccddeeff"}}`.
The metadata merger strips the member, giving `{"display":[{"name":"Nym v2","locale":"en"}]}`,
and merges that over the issuer metadata (members of the response overwrite
members of the same name). The merged display metadata is
`{"display":[{"name":"Nym v2","locale":"en"}],"org.siros.secret_seed":{"namespaces":["org.siros.nym_auth"]}}`
(the public advertisement stays; the seed is absent). The seed is stored only as the `metadata` entry
`{"type":"org.siros.secret_seed","value":{"org.siros.nym_auth":"00112233445566778899aabbccddeeff"}}`.

### 5A.4 Advertisement without the value

Issuer metadata for a credential configuration that delivers a seed carries, in
that configuration's `credential_metadata`:

```json
"credential_metadata": {
  "org.siros.secret_seed": { "namespaces": ["org.siros.nym_auth"] }
}
```

`namespaces` is an array of 1 to 8 distinct namespace names (Section 5A.1 rules
for a name). Only names appear, never values. The wallet or its OpenID4VCI
client, when it sees the advertisement, MUST request
`credential_response_encryption` for that issuance, because OpenID4VCI encrypts
the response only when asked, and MUST refuse a plain response. (The refusal of a plain response that carries a seed holds
regardless of the advertisement.)

Note (non-normative). Alternative considered: a separate top-level response
parameter (for example `org.siros.secret_seed` beside `credentials`), which
would keep the secret out of the shared display object and make stripping
unnecessary. It was not chosen because the decision is to use the response-level
`credential_metadata` object of OpenID4VCI#721, and because relays are required
to preserve unknown members of that object but not necessarily of the response.

### 5A.5 Limits and extension

The limits of this section (1 to 8 namespaces, a namespace of 1 to 64 UTF-8
bytes, a seed of 32 lowercase hexadecimal characters = 16 bytes, and the
reserved name `namespaces`) are the limits of this version of the
specification. An implementation MUST NOT hard-code them in a way that prevents
extension: they SHOULD be named constants or configuration. A later version may
raise them or add seed lengths. Until a version defines otherwise, a value
outside these limits is malformed (Section 5A.1). No negotiation parameter is
defined in this version; a later version that raises a limit or adds a seed
length introduces its own member name, so wallets of this version, which ignore
unknown members of `credential_metadata`, are not affected.

### 5A.6 Designation of the commitment namespace (PROPOSAL, awaiting decision)

Section 5A.2 verifies the seed of "the namespace that the credential type
designates". Proposed mechanism, in order of authority:

1. The issuer's per-configuration advertisement (Section 5A.4) lists the
   namespace(s). If it lists exactly one namespace, that namespace is the
   commitment namespace of the configuration.
2. The credential type's rulebook names the namespace in which its commitment
   claim (for `nym_auth`, `ssc`) is verified. The rulebook is the source of
   truth; the advertisement MUST NOT contradict it, and a wallet that knows the
   rulebook's namespace uses it, treating a different advertised namespace as a
   failed issuance.
3. A wallet MAY hold a table from credential type to namespace, generated from
   the rulebooks. It is a cache of item 2, not an independent source.

If no namespace can be determined, or the determined namespace is absent from
the response object, verification fails (Section 5A.2).

Test vectors: `delivered-secret-commitment-001`, `delivered-secret-wire-001`,
`delivered-secret-malformed-001`, `delivered-secret-refusal-001`,
`delivered-secret-strip-001` and `delivered-secret-advertise-001` in
`test-vectors/vectors.jsonl`.

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
- A reader that rewrites the container MUST preserve, with an identical value,
  every member of an `S.credentials[]` entry that it does not understand, and
  every member of `S` that it does not understand, and likewise every member of
  a `metadata` entry (below). Preservation applies to the JSON value, not only
  to the wallet metadata fields named above. An implementation that cannot
  preserve such a member MUST refuse to rewrite the container rather than drop
  the member.

`S.credentials[]` entries MAY carry the member `metadata`:

```json
{
  "id": "cred-001",
  "format": "dc+sd-jwt",
  "metadata": [
    { "type": "org.siros.secret_seed", "value": { "NS": "00112233445566778899aabbccddeeff" } }
  ]
}
```

- `metadata` is OPTIONAL. If present it MUST be an array of objects, each with a
  `type` member that is a non-empty string and a `value` member that is any
  JSON value.
- Entries MUST be stored exactly as received from the party that supplied them
  (for credentials obtained by OpenID4VCI, each member of the issuer's
  response-level `credential_metadata` becomes one entry whose `type` is the
  member name and whose `value` is the member value; see Section 5A.2). The container does not interpret an entry. The
  order of entries MUST be preserved, and several entries MAY have the same
  `type`; the consumer of a `type` defines its meaning.
- A writer MUST NOT emit `metadata` when there is nothing to store: it MUST NOT
  emit `null` or an empty array. A reader MUST accept an absent member and an
  empty array, and treat both as no metadata.
- `metadata` holds data tied to one credential entry, for example secrets
  delivered by the issuer (Section 5A) or tokens that give the holder control
  over revocation of that credential. It MUST NOT hold display metadata, which
  is re-fetched from the issuer, and MUST NOT hold secrets that the wallet
  generates or derives itself. The member name is unrelated to display metadata
  that implementations keep elsewhere.
- Adding `metadata` is additive; `S.schemaVersion` remains `3`.

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
- 2.2 (2026-10-16): Section 5A (delivered secrets) added; Section 6 gains the optional `S.credentials[].metadata` member and the rule that unknown credential-entry and `S` members MUST be preserved. Additive; `S.schemaVersion` remains `3`.
- 2.3 (2026-10-16): Section 5.4 (derived secrets, including the `private_seed` derivation of Section 5.4.1) added. Additive; `S.schemaVersion` remains `3`.
- 2.4 (2026-10-19): Section 5A rewritten: delivered `secret_seed` uses the OpenID4VCI 1.1 response-level `credential_metadata` object (openid/OpenID4VCI#721, working draft) with the member `org.siros.secret_seed`. Wire shape, JWE-only, `notification_id` and malformed-input rules added. Section 5A also gains the strip-before-merge, never-public and advertisement rules (5A.3, 5A.4). Storage in `S.credentials[].metadata` is unchanged in form; `S.schemaVersion` remains `3`.
- 2.5 (2026-10-19): Section 5A gains 5A.0 (which party enforces which rule when the OpenID4VCI client, the metadata merger and the secret store are different processes), the statement that seed delivery over a Deferred Credential Response is not supported, and 5A.5 (the limits are those of this version and MUST NOT be hard-coded in a way that prevents extension). Minor bump, as for 2.2 to 2.4, because it adds normative text without changing any wire shape or the container; `S.schemaVersion` remains `3`.
- 2.6 (PROPOSAL, unmerged): Section 5A.6, designation of the commitment namespace.
