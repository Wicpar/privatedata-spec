# SIROS Private Data Specification and Conformance

Normative specification and conformance artifacts for SIROS wallet private data compatibility across TypeScript/JavaScript, Kotlin, and Swift clients.

## Contents

- `SPEC.md`: Normative private data format and processing rules
- `docs/SERIALIZATION.md`: Canonical encoding and serialization requirements
- `docs/INTEGRATION.md`: SDK integration guidance for conformance
- `docs/TROUBLESHOOTING.md`: Common interop and implementation pitfalls
- `test-vectors/vectors.jsonl`: Canonical vector index
- `test-vectors/fixtures/`: Core vectors (single credential, multi-passkey, metadata, legacy)
- `test-vectors/edge-cases/`: Edge-case vectors (unicode, empty arrays, large state)
- `conformance/conformance-runner.sh`: Cross-client conformance runner
- `conformance/README.md`: Runner usage and CI integration

## Quick Start

1. Read `SPEC.md` for normative behavior.
2. Review `test-vectors/vectors.jsonl` and fixture files.
3. Run conformance checks:

```bash
cd conformance
./conformance-runner.sh --help
./conformance-runner.sh
```

## Goals

- Keep all clients interoperable at the private data level
- Prevent metadata and event history loss during round-trips
- Validate credential-bound PRF entry selection in multi-passkey containers
- Catch regressions before release via repeatable conformance runs

## Source of Truth

Behavior is aligned with `wallet-frontend` as reference implementation.

## License

See `LICENSE`.

### 3. Run Conformance Tests

```bash
# Run all tests against all three clients
./conformance/conformance-runner.sh

# Run tests for specific client
./conformance/conformance-runner.sh --client swift
./conformance/conformance-runner.sh --client kotlin
./conformance/conformance-runner.sh --client ts

# Run specific test vector
./conformance/conformance-runner.sh --vector single-credential-v3-001
```

### 4. Integrate with Your SDK

See [INTEGRATION.md](docs/INTEGRATION.md) for language-specific setup:

- **TypeScript**: Add conformance target to `package.json`
- **Kotlin**: Add conformance task to `build.gradle`
- **Swift**: Add conformance scheme to `Package.swift`

Each SDK must expose two entry points:
- `<client> encrypt <plaintext-json-file>` → outputs encrypted container
- `<client> decrypt <container-json-file>` → outputs decrypted WalletStateContainer

## Normative Requirements

### For All Implementations

- **MUST** implement JWE with `alg=A256GCMKW, enc=A256GCM`
- **MUST** derive HKDF-SHA-256 with normative info string `"eDiplomas PRF"`
- **MUST** preserve full WalletStateContainer (events, lastEventHash, presentations, credentialIssuanceSessions)
- **MUST** preserve credential metadata (`credentialId`, `data`, `format`, `kid`, `instanceId`, `batchId`; SPEC Section 6.0)
- **MUST** preserve keypair DID (not recompute)
- **MUST** use "0" as default for `openidRefreshTokenMaxAgeInSeconds`
- **MUST** support optimistic concurrency via ETag headers

### Test Coverage

All implementations MUST pass:
- ✅ Encrypt canonical vector → byte-for-byte match
- ✅ Decrypt canonical vector → schema match
- ✅ Round-trip: decrypt → re-encrypt → byte comparison
- ✅ Multi-passkey container handling (credential-bound PRF selection)
- ✅ Metadata field preservation
- ✅ Event history preservation
- ✅ Legacy format acceptance (read-only)
- ✅ Edge case handling (unicode, large containers, empty fields)

## CI/CD Integration

Each client repository SHOULD implement conformance gating:

```yaml
# .github/workflows/conformance.yml
conformance:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v3
      with:
        repository: sirosfoundation/privatedata-spec
        path: spec
    - name: Run conformance tests
      run: |
        spec/conformance/conformance-runner.sh --client ${{ matrix.client }}
```

Conformance tests are **gating**: PRs that break compatibility cannot merge.

## Reference Implementation

`wallet-frontend` is the source of truth for all behavior:
- Encryption logic: `src/services/keystore.ts`
- State schema: `src/services/WalletStateSchemaVersion3.ts`
- Serialization: `src/util.ts`

## Support

For issues or questions:
1. Check [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for common problems
2. Review [SERIALIZATION.md](docs/SERIALIZATION.md) for normative encoding details
3. Open an issue with reference to the test vector and client version

## License

This specification and test suite are part of the SIROS project.
See LICENSE file for details.
