# Normative Serialization Requirements

This document specifies exact serialization rules to ensure cross-client byte-for-byte compatibility.

## Table of Contents

1. JSON Serialization
2. Binary Field Encoding
3. JWE Compact Serialization
4. WalletStateContainer Ordering
5. Numeric Precision
6. Common Pitfalls

## 1. JSON Serialization

### 1.1 Whitespace

- **MUST** serialize JSON with no extra whitespace (compact form)
- **MUST NOT** include spaces after `:` or `,`
- **MUST NOT** include newlines or indentation
- **MUST NOT** include trailing commas

**Correct:**
```json
{"mainKey":{"publicKey":{"importKey":{"keyData":{"$b64u":"..."}}}}}
```

**Incorrect:**
```json
{
  "mainKey": {
    "publicKey": {
      "importKey": {
        "keyData": { "$b64u": "..." }
      }
    }
  }
}
```

### 1.2 Object Key Ordering

For containers and repeated schemas, use this canonical order:

**Top-level EncryptedContainer:**
```
1. mainKey
2. prfKeys
3. jwe
```

**mainKey:**
```
1. publicKey
2. unwrapKey
```

**publicKey (ECDH import):**
```
1. format
2. keyData
3. algorithm
```

**algorithm (for ECDH):**
```
1. name
2. namedCurve
```

**PRF entry:**
```
1. credentialId
2. prfSalt
3. hkdfSalt
4. hkdfInfo
5. keypair
6. unwrapKey
7. transports (if present)
8. algorithm (if present)
```

**WalletStateContainer:**
```
1. lastEventHash
2. events
3. S
```

**S (state object):**
```
1. schemaVersion
2. credentials
3. keypairs
4. presentations
5. settings
6. credentialIssuanceSessions
```

### 1.3 NULL and Missing Fields

- **MUST** omit fields with `null` values (do not serialize `"field": null`)
- **MUST** omit optional fields if not present
- **MUST** include empty arrays `[]` if the array is logically defined even if empty
- **MUST** include empty objects `{}` if the object is logically defined

**Correct:**
```json
{"events":[],"presentations":[],"settings":{"openidRefreshTokenMaxAgeInSeconds":"0"}}
```

**Incorrect:**
```json
{"events":null,"presentations":[],"settings":{"openidRefreshTokenMaxAgeInSeconds":"0","ignored":null}}
```

## 2. Binary Field Encoding

### 2.1 Tagged Binary Format

All binary data MUST be encoded as:

```json
{ "$b64u": "<base64url-string>" }
```

This applies to:
- `mainKey.publicKey.importKey.keyData`
- `prfKeys[].credentialId`
- `prfKeys[].hkdfSalt`
- `prfKeys[].prfSalt`
- `prfKeys[].hkdfInfo` (if binary)
- `prfKeys[].keypair.publicKey.importKey.keyData`
- `prfKeys[].keypair.privateKey.unwrapKey.wrappedKey`
- `prfKeys[].unwrapKey.wrappedKey`

### 2.2 Base64url Encoding

- **MUST** use RFC 4648 base64url (URL-safe alphabet: `A-Z`, `a-z`, `0-9`, `-`, `_`)
- **MUST NOT** include padding (`=` characters)
- **MUST** produce consistent output from the same input

**Correct:**
```
base64url("hello") = "aGVsbG8"
```

**Incorrect:**
```
base64url("hello") = "aGVsbG8=" (with padding)
base64("hello") = "aGVsbG8=" (standard base64, different alphabet)
```

### 2.3 Binary Field Length Validation

After decoding base64url, verify expected lengths:

- `keyData` (P-256 uncompressed point): 65 bytes
- `credentialId`: variable, typically 32-64 bytes
- `hkdfSalt`: 32 bytes
- `prfSalt`: 32 bytes
- `wrappedKey` (AES-KW output): variable, typically 40-100 bytes

## 3. JWE Compact Serialization

### 3.1 Format

JWE MUST use compact serialization:

```
BASE64URL(UTF8(JWE Protected Header)) || '.' ||
BASE64URL(JWE Encrypted Key) || '.' ||
BASE64URL(JWE IV) || '.' ||
BASE64URL(JWE Ciphertext) || '.' ||
BASE64URL(JWE Authentication Tag)
```

This produces exactly 5 dot-separated parts.

### 3.2 JWE Header (Protected)

The JWE Protected Header MUST be UTF-8 JSON with:

```json
{
  "alg": "A256GCMKW",
  "enc": "A256GCM"
}
```

Optionally include:
```json
{
  "kid": "<key-id>"
}
```

Header key order (canonical):
1. alg
2. enc
3. kid (if present)

**Must encode as:**
```
BASE64URL(UTF8('{"alg":"A256GCMKW","enc":"A256GCM"}'))
```

### 3.3 Verification

Validate structure before processing:

```
parts = jwe.split('.')
if parts.length != 5:
  ERROR "Invalid JWE: expected 5 parts, got" parts.length
for part in parts:
  if not isValidBase64Url(part):
    ERROR "Invalid JWE part: not base64url"
```

## 4. WalletStateContainer Ordering

### 4.1 Credentials Array

Preserve insertion order from original state:
- Do NOT sort by `credentialId`
- Do NOT sort by issuance date
- Maintain order as authored

Example:
```json
{
  "credentials": [
    {"credentialId": 3, "format": "dc+sd-jwt", "data": "..."},
    {"credentialId": 1, "format": "dc+sd-jwt", "data": "..."},
    {"credentialId": 2, "format": "dc+sd-jwt", "data": "..."}
  ]
}
```

After round-trip, order MUST be identical.

### 4.2 Events Array

Same as credentials: preserve insertion order.

Events MUST include:
- Original event sequence
- All metadata fields from each event
- Timestamps in original format

## 5. Numeric Precision

### 5.1 String vs Number

Use strings for:
- Timestamps in ISO 8601 format: `"2026-06-23T10:00:00Z"`
- Configuration values: `"openidRefreshTokenMaxAgeInSeconds": "0"`
- Semantic numbers that don't require arithmetic

Use numbers for:
- Array indices (JSON arrays only)
- Lengths (rarely needed in wallet state)

**Correct:**
```json
{
  "expiresAt": "2028-06-23T00:00:00Z",
  "openidRefreshTokenMaxAgeInSeconds": "0",
  "credentials": [...]
}
```

**Incorrect:**
```json
{
  "expiresAt": 1687513200,
  "openidRefreshTokenMaxAgeInSeconds": 0,
  "credentials": {...}
}
```

### 5.2 Floating Point

Avoid floating-point numbers. If required:
- Use IEEE 754 double precision
- Document exact bit representation in test vectors
- Include sufficient precision for cryptographic operations

## 6. Common Pitfalls

### 6.1 Base64url Padding Mismatch

**Problem:** Some libraries add padding, others don't.

**Solution:** Always strip padding before serializing:

```python
def base64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

def base64url_decode(s):
    # Add padding back as needed
    missing_padding = len(s) % 4
    if missing_padding:
        s += '=' * (4 - missing_padding)
    return base64.urlsafe_b64decode(s)
```

### 6.2 Field Ordering in Maps

**Problem:** JSON doesn't guarantee key order; implementations may reorder.

**Solution:** Serialize to string with canonical key order BEFORE computing hashes:

```typescript
// DON'T do this
const hash = sha256(JSON.stringify(object));

// DO this
const canonical = JSON.stringify(sortKeys(object));
const hash = sha256(canonical);

function sortKeys(obj) {
  const order = ['mainKey', 'prfKeys', 'jwe'];
  return Object.keys(obj)
    .sort((a, b) => order.indexOf(a) - order.indexOf(b))
    .reduce((result, key) => {
      result[key] = obj[key];
      return result;
    }, {});
}
```

### 6.3 Event Mutation

**Problem:** Events are immutable; re-serializing after parsing can lose precision.

**Solution:** Preserve original serialized bytes:

```typescript
// Store original bytes from remote
const originalBytes = base64url_decode(remoteState.events_b64u);

// Parse for use
const events = JSON.parse(utf8_decode(originalBytes));

// On re-encryption, use original bytes
container.events = originalBytes;
```

### 6.4 JWE Encryption Determinism

**Problem:** Some JWE libraries use random IVs, breaking determinism.

**Solution:** Use derived IV from inputs or fixed test vectors:

```typescript
const iv = hkdf.derive(prfOutput, 'iv-derivation', 12); // 12 bytes for GCM
const encrypted = await aesGcm.encrypt(plaintext, iv);
```

### 6.5 Timestamp Precision

**Problem:** Timestamps with different precision cause mismatches.

**Solution:** Use full ISO 8601 UTC format consistently:

```javascript
// Correct
"2026-06-23T10:00:00.123Z"
"2026-06-23T10:00:00Z"

// Incorrect (missing timezone)
"2026-06-23T10:00:00"
"2026-06-23 10:00:00"
```

### 6.6 Empty vs Null Arrays

**Problem:** Empty array `[]` vs `null` vs omitted field.

**Solution:** Use canonical form:

```json
// Correct: include empty array if field is defined
{"presentations": []}

// Incorrect: null or omitted when field is part of schema
{"presentations": null}
{}
```

## Validation Checklist

Before considering a serialization valid:

- [ ] JSON has no whitespace except inside strings
- [ ] All binary fields are in `{"$b64u": "..."}` format
- [ ] No base64url padding (`=` characters)
- [ ] Object key order matches canonical order
- [ ] JWE has exactly 5 dot-separated parts
- [ ] No `null` values in output (fields either present or omitted)
- [ ] Timestamps in full ISO 8601 UTC format
- [ ] Numeric values as strings where semantically appropriate
- [ ] Array order preserved from input
- [ ] All required fields present according to schema version

## Testing Serialization Compliance

Use these utilities:

```bash
# Check JSON compactness
python3 -c "import json, sys; obj = json.load(sys.stdin); compact = json.dumps(obj, separators=(',', ':'), sort_keys=False); print(compact)" < input.json

# Verify no padding in base64url fields
grep -o '\$b64u":"[^"]*=' input.json && echo "ERROR: Padding found" || echo "OK: No padding"

# Validate JWE format
echo "eyJ...UQ...." | awk -F. '{print NF}' | grep -q '^5$' && echo "OK: 5 parts" || echo "ERROR: Wrong part count"
```

## References

- RFC 7159: JavaScript Object Notation
- RFC 4648: The Base16, Base32, and Base64 Data Encodings
- RFC 7516: JSON Web Encryption (JWE)
- RFC 8174: Ambiguity of Uppercase vs Lowercase in RFC 2119
