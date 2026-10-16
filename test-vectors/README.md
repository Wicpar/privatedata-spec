# Test Vectors for Private Data Encryption

This directory contains canonical test vectors for validating SIROS wallet private data encryption implementations.

## Test Vector Format

Each line in `vectors.jsonl` is a complete JSON object describing one test case:

```json
{
  "id": "unique-test-identifier",
  "description": "Human-readable description",
  "version": "3",
  "sections": ["4", "5", "6"],
  "tags": ["single-passkey", "basic"],
  "inputs": {
    "credentialId": "<base64url-encoded-credential-id>",
    "credentialIdBytes": 64,
    "prfOutput": "<base64url-encoded-prf-output>",
    "prfOutputBytes": 32,
    "hkdfSalt": "<base64url-encoded-hkdf-salt>",
    "hkdfSaltBytes": 32,
    "hkdfInfo": "eDiplomas PRF",
    "plaintextState": {
      "lastEventHash": "sha256-hash-of-previous-event",
      "events": [{"type": "...", ...}],
      "S": {
        "schemaVersion": 3,
        "credentials": [...],
        "keypairs": [...],
        "presentations": [...],
        "settings": {"openidRefreshTokenMaxAgeInSeconds": "3600"},
        "credentialIssuanceSessions": [...]
      }
    }
  },
  "expected": {
    "containerJsonBytes": "<serialized-container-as-json-string>",
    "containerHash": "sha256-hash-of-container-json-bytes",
    "jweCompact": "eyJ...eye...",
    "decryptedPayload": {...}
  },
  "validations": {
    "encryptMatch": "byte-for-byte match of serialized container JSON",
    "decryptMatch": "parsed state must match plaintextState",
    "roundTrip": "decrypt -> re-encrypt -> compare bytes",
    "metadata": ["credentials[].format", "credentials[].kid", "keypairs[].did"],
    "statePreservation": ["events", "lastEventHash", "presentations", "credentialIssuanceSessions"]
  }
}
```

## Categories

### Basic Vectors (fixtures/)

- **single-credential-v3.json**: One passkey, simple metadata
- **multi-passkey-v3.json**: Multiple credentials, tests PRF entry selection
- **metadata-preservation.json**: All credential/keypair metadata fields present
- **legacy-v1-symmetric.json**: Old symmetric mainKey format (read-only test)

### Edge Cases (edge-cases/)

- **max-size-container.json**: Large credential set, near practical limits
- **unicode-credentials.json**: Non-ASCII characters in credential names/issuers
- **empty-presentations.json**: No presentations or issuance sessions
- **minimal-state.json**: Minimal required fields only
- **missing-optional-fields.json**: Test optional field handling

## Running Tests Manually

### Decrypt a Test Vector

```bash
# Extract plaintext from vector
cat vectors.jsonl | jq '.[] | select(.id == "single-credential-v3-001") | .expected.containerJsonBytes'

# Run your decrypt implementation
your-client decrypt <container-file>

# Validate against expected state
diff <(your-client decrypt <container-file>) \
     <(cat vectors.jsonl | jq '.[] | select(.id == "single-credential-v3-001") | .inputs.plaintextState')
```

### Encrypt and Verify

```bash
# Get plaintext state
cat vectors.jsonl | jq '.[] | select(.id == "single-credential-v3-001") | .inputs.plaintextState' > plaintext.json

# Get PRF inputs
cat vectors.jsonl | jq '.[] | select(.id == "single-credential-v3-001") | .inputs | {credentialId, prfOutput, hkdfSalt, hkdfInfo}' > prf-inputs.json

# Run encryption
your-client encrypt plaintext.json prf-inputs.json > encrypted.json

# Verify container hash
sha256sum encrypted.json | awk '{print $1}' | \
  diff <(cat) <(cat vectors.jsonl | jq -r '.[] | select(.id == "single-credential-v3-001") | .expected.containerHash')
```

## Normative Test Requirements

Every implementation MUST pass these validations for every vector:

1. **Encryption Determinism**: Encrypting the same plaintext + PRF inputs MUST produce byte-for-byte identical output
2. **Decryption Fidelity**: Decrypting the expected container MUST parse to the plaintext state
3. **Round-trip**: Decrypt → parse → re-encrypt MUST produce identical container bytes
4. **Metadata Preservation**: All credential/keypair fields in plaintext MUST appear in encrypted state
5. **Event Preservation**: `events[]` and `lastEventHash` MUST be identical after round-trip
6. **Field Completeness**: `presentations`, `credentialIssuanceSessions` MUST be preserved (not empty if present)

## Vector Maintenance

When adding new test vectors:

1. Create a descriptive JSON object with all required fields
2. Add it to `vectors.jsonl` (one object per line)
3. Document the test case in appropriate `fixtures/` or `edge-cases/` subdirectory
4. Run all clients against it: `conformance-runner.sh --vector <id>`
5. Verify all pass before committing

## Implementation-Specific Notes

### TypeScript/JavaScript (wallet-frontend)

The reference implementation is `wallet-frontend`. Generate vectors by:

```bash
cd wallet-frontend
npm run conformance:generate-vectors > privatedata-spec/test-vectors/vectors-reference.jsonl
npm run conformance:validate -- --vectors privatedata-spec/test-vectors/vectors.jsonl
```

### Kotlin (siros-sdk-kotlin)

Generate and validate:

```bash
cd siros-sdk-kotlin
./gradlew generateConformanceVectors --output ../privatedata-spec/test-vectors/vectors-kotlin.jsonl
./gradlew validateConformance --vectors ../privatedata-spec/test-vectors/vectors.jsonl
```

### Swift (siros-sdk-swift)

Generate and validate:

```bash
cd siros-sdk-swift
swift run ConformanceGenerator > ../privatedata-spec/test-vectors/vectors-swift.jsonl
swift run ConformanceValidator --vectors ../privatedata-spec/test-vectors/vectors.jsonl
```

All outputs must be identical (bitwise) for shared test cases.
