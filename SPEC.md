# SIROS Wallet Private Data Blob Specification (Normative)

Version: 2.0  
Date: 2026-06-22  
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
