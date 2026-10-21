# Conformance Testing Guide

This directory contains the conformance test runner and integration guides for ensuring all three SIROS wallet implementations remain compatible.

## Quick Start

```bash
# Make runner executable
chmod +x conformance-runner.sh

# Run all tests for all clients
./conformance-runner.sh

# Run tests for specific client
./conformance-runner.sh --client swift
./conformance-runner.sh --client kotlin
./conformance-runner.sh --client ts

# Run specific test vector
./conformance-runner.sh --vector single-credential-v3-001

# Verbose output with failure continuation
./conformance-runner.sh --verbose --continue-on-fail
```

## Required Client Integration

Each SDK must implement two executable targets:

### TypeScript/JavaScript (wallet-frontend)

Add to `package.json`:

```json
{
  "scripts": {
    "conformance:encrypt": "node --require=./conformance/encrypt.js",
    "conformance:decrypt": "node --require=./conformance/decrypt.js"
  }
}
```

Create `src/conformance/encrypt.ts`:

```typescript
import { args } from 'process';
import * as fs from 'fs';
import { KeystoreService } from '../services/keystore';

async function main() {
  const plaintextFile = args[2];
  const prfInputsFile = args[3];
  
  const plaintext = JSON.parse(fs.readFileSync(plaintextFile, 'utf-8'));
  const prfInputs = JSON.parse(fs.readFileSync(prfInputsFile, 'utf-8'));
  
  const keystore = new KeystoreService();
  const container = await keystore.encrypt(plaintext, {
    credentialId: prfInputs.credentialId,
    prfOutput: prfInputs.prfOutput,
    hkdfSalt: prfInputs.hkdfSalt,
    hkdfInfo: prfInputs.hkdfInfo
  });
  
  console.log(JSON.stringify(container, null, 2));
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
```

Create `src/conformance/decrypt.ts`:

```typescript
import { args } from 'process';
import * as fs from 'fs';
import { KeystoreService } from '../services/keystore';

async function main() {
  const containerFile = args[2];
  const container = JSON.parse(fs.readFileSync(containerFile, 'utf-8'));
  
  // Container must include credentialId to select PRF entry
  const keystore = new KeystoreService();
  const plaintext = await keystore.decrypt(container);
  
  console.log(JSON.stringify(plaintext, null, 2));
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
```

### Kotlin (siros-sdk-kotlin)

Add to `build.gradle`:

```gradle
task conformanceEncrypt {
  doLast {
    def plaintextFile = project.findProperty('plaintext') ?: ''
    def prfInputsFile = project.findProperty('prf-inputs') ?: ''
    
    def plaintext = new groovy.json.JsonSlurper().parse(new File(plaintextFile))
    def prfInputs = new groovy.json.JsonSlurper().parse(new File(prfInputsFile))
    
    def keystore = new JweKeystore()
    def container = keystore.lock(plaintext, prfInputs)
    
    println(new groovy.json.JsonOutput().toJson(container))
  }
}

task conformanceDecrypt {
  doLast {
    def containerFile = project.findProperty('input') ?: ''
    def container = new groovy.json.JsonSlurper().parse(new File(containerFile))
    
    def keystore = new JweKeystore()
    def plaintext = keystore.unlock(container)
    
    println(new groovy.json.JsonOutput().toJson(plaintext))
  }
}
```

Create `src/test/kotlin/org/sirosfoundation/sdk/keystore/ConformanceTest.kt`:

```kotlin
class ConformanceTest {
  @Test
  fun encryptDecryptRoundTrip() {
    val keystore = JweKeystore()
    
    // Load test vector
    val testVector = loadTestVector("single-credential-v3-001")
    
    // Encrypt
    val encrypted = keystore.lock(testVector.plaintext, testVector.prfInputs)
    
    // Decrypt
    val decrypted = keystore.unlock(encrypted)
    
    // Verify
    assertEquals(testVector.plaintext, decrypted)
  }
}
```

### Swift (siros-sdk-swift)

Add to `Package.swift`:

```swift
.executable(
  name: "ConformanceEncrypt",
  targets: ["ConformanceEncrypt"]
),
.executable(
  name: "ConformanceDecrypt",
  targets: ["ConformanceDecrypt"]
)
```

Create `Sources/ConformanceEncrypt/main.swift`:

```swift
import Foundation
import SirosKeystore

let plaintextFile = CommandLine.arguments[1]
let prfInputsFile = CommandLine.arguments[2]

let plaintextData = try Data(contentsOf: URL(fileURLWithPath: plaintextFile))
let prfInputsData = try Data(contentsOf: URL(fileURLWithPath: prfInputsFile))

let plaintext = try JSONDecoder().decode(WalletStateContainer.self, from: plaintextData)
let prfInputs = try JSONDecoder().decode(PRFInputs.self, from: prfInputsData)

let keystore = JweKeystore()
let container = try keystore.lock(plaintext: plaintext, prfInputs: prfInputs)

let output = try JSONEncoder().encode(container)
print(String(data: output, encoding: .utf8) ?? "")
```

Create `Sources/ConformanceDecrypt/main.swift`:

```swift
import Foundation
import SirosKeystore

let containerFile = CommandLine.arguments[1]
let containerData = try Data(contentsOf: URL(fileURLWithPath: containerFile))

let container = try JSONDecoder().decode(EncryptedContainer.self, from: containerData)

let keystore = JweKeystore()
let plaintext = try keystore.unlock(container: container)

let output = try JSONEncoder().encode(plaintext)
print(String(data: output, encoding: .utf8) ?? "")
```

## Environment Variables

Set these in your CI environment:

```bash
# Path to wallet-frontend repo
export WALLET_FRONTEND_PATH="/path/to/wallet-frontend"

# Path to siros-sdk-kotlin repo
export SIROS_SDK_KOTLIN_PATH="/path/to/siros-sdk-kotlin"

# Path to siros-sdk-swift repo
export SIROS_SDK_SWIFT_PATH="/path/to/siros-sdk-swift"
```

## CI/CD Integration

### GitHub Actions

Add to `.github/workflows/conformance.yml`:

```yaml
name: Conformance Tests

on:
  pull_request:
    paths:
      - 'src/**/*.ts'
      - 'src/**/*.swift'
      - 'src/**/*.kt'

jobs:
  conformance:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        client: [ts, kotlin, swift]
    
    steps:
      - uses: actions/checkout@v3
      - uses: actions/checkout@v3
        with:
          repository: sirosfoundation/privatedata-spec
          path: spec
      
      - name: Setup client environment
        run: |
          case ${{ matrix.client }} in
            ts)
              npm install
              ;;
            kotlin)
              echo "SIROS_SDK_KOTLIN_PATH=$PWD" >> $GITHUB_ENV
              ;;
            swift)
              echo "SIROS_SDK_SWIFT_PATH=$PWD" >> $GITHUB_ENV
              ;;
          esac
      
      - name: Run conformance tests
        run: |
          cd spec
          ./conformance/conformance-runner.sh --client ${{ matrix.client }} --verbose
      
      - name: Upload results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: conformance-results-${{ matrix.client }}
          path: conformance-results/
```

## Test Vector Analysis

Each test vector validates:

1. **Encryption Determinism**: Same inputs → same output bytes
2. **Decryption Fidelity**: Decrypted state matches input plaintext
3. **Round-trip**: Decrypt → re-encrypt → byte-for-byte match
4. **Metadata Preservation**: All credential/keypair fields present
5. **Event History**: events[] and lastEventHash unchanged
6. **PRF Selection**: Multi-passkey unlock uses credentialId matching

## Debugging Failed Tests

### Common Issues

#### "Encryption produced different bytes"
- Check JSON serialization: no extra whitespace
- Verify ECDH keypair generation is deterministic
- Ensure base64url encoding has no padding

#### "Decryption failed"
- Verify JWE compact format: 5 dot-separated parts
- Check AES-KW unwrapping parameters
- Ensure ECDH private key is correctly imported

#### "Metadata missing"
- Verify WalletStateContainer schema version (must be 3 or 4)
- Check credential field mapping
- Ensure keypair DID is preserved (not recomputed)

#### "PRF selection wrong"
- Verify unlock() finds PRF entry by credentialId match
- Check hkdfSalt and hkdfInfo are read from correct entry
- Ensure multi-passkey containers are handled correctly

### Enable Verbose Logging

```bash
./conformance-runner.sh --verbose --client kotlin
```

This will output:
- Input/output samples for each test
- Serialization details
- PRF key derivation steps
- Cryptographic operation results

## Manual Test Execution

### Encrypt only

```bash
# Get plaintext state from test vector
jq '.inputs.plaintextState' test-vectors/vectors.jsonl > plaintext.json

# Get PRF inputs
jq '.inputs | {credentialId, prfOutput, hkdfSalt, hkdfInfo}' test-vectors/vectors.jsonl > prf.json

# Encrypt with specific client
your-client encrypt plaintext.json prf.json > encrypted.json
```

### Decrypt only

```bash
# Decrypt and pretty-print
your-client decrypt encrypted.json | jq .
```

### Compare across clients

```bash
# Encrypt with TS
ts-client encrypt plaintext.json prf.json > ts-output.json

# Encrypt with Kotlin
kotlin-client encrypt plaintext.json prf.json > kotlin-output.json

# Compare
diff <(jq -S . ts-output.json) <(jq -S . kotlin-output.json)
```

## Adding New Test Vectors

1. Create vector file in `test-vectors/fixtures/` or `test-vectors/edge-cases/`
2. Add entry to `test-vectors/vectors.jsonl` (one line, complete JSON object)
3. Run against all three clients:
   ```bash
   ./conformance-runner.sh --vector new-test-id
   ```
4. All clients must pass before committing
5. Document the test case purpose in the vector's `description` and `purpose` fields

## Test Vector Maintenance

Check that test vectors still validate with current implementations:

```bash
# Run all vectors against all clients
./conformance-runner.sh

# Archive old results
mkdir -p results/$(date +%Y-%m-%d-%H%M%S)
cp conformance-results/* results/$(date +%Y-%m-%d-%H%M%S)/

# Compare with previous run
diff results/2026-06-23-100000/ results/2026-06-23-120000/
```

## Performance Benchmarking

Conformance tests also serve as performance baselines:

```bash
# Time conformance tests
time ./conformance-runner.sh --client ts

# Parse timing from output
./conformance-runner.sh --client kotlin --verbose | grep "Encryption took:"
```

Track performance regressions in PRs.
