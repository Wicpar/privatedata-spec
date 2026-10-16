# SIROS Wallet Private Data Blob Specification (Normative)

Version: 2.2  
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

## 5A. Delivered secrets

A delivered secret is a secret value chosen and supplied by a counterparty such
as an issuer, for example by an issuer in an OpenID4VCI credential response (the
`nym_auth` credential's `secret_seed`, delivered as an entry of
`credential_metadata`). A secret that the wallet generates or derives itself, for
example `private_seed`, is out of scope of this section and is covered elsewhere.

Rules:

- A delivered secret MAY be stored, in the `metadata` member of the credential
  entry it belongs to (Section 6).
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
  credential and `secret_seed` is the 16-byte value carried as lowercase
  hexadecimal.

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
    { "type": "org.siros.NS.secret_seed", "value": "00112233445566778899aabbccddeeff" }
  ]
}
```

- `metadata` is OPTIONAL. If present it MUST be an array of objects, each with a
  `type` member that is a non-empty string and a `value` member that is any
  JSON value.
- Entries MUST be stored exactly as received from the party that supplied them
  (for credentials obtained by OpenID4VCI, the issuer's `credential_metadata`
  from the credential response). The container does not interpret an entry. The
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

## 10. Changes

- 2.2 (2026-10-16): Section 5A (delivered secrets) added; Section 6 gains the optional `S.credentials[].metadata` member and the rule that unknown credential-entry and `S` members MUST be preserved. Additive; `S.schemaVersion` remains `3`. The version number is provisional until reconciled with 2.1 (`S.extensions`).
