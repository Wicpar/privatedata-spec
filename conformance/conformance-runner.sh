#!/bin/bash
#
# SIROS Private Data Conformance Test Runner
#
# Validates all three SDK implementations (TypeScript, Kotlin, Swift) against
# canonical test vectors to ensure cross-client compatibility.
#
# Usage:
#   ./conformance-runner.sh                    # Run all clients, all vectors
#   ./conformance-runner.sh --client swift     # Run only Swift
#   ./conformance-runner.sh --vector single-credential-v3-001
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
TEST_VECTORS_DIR="$REPO_ROOT/test-vectors"

# Configuration
CLIENT="${CLIENT:-all}"
VECTOR="${VECTOR:-}"
VERBOSE="${VERBOSE:-0}"
STOP_ON_FAIL="${STOP_ON_FAIL:-1}"

# State tracking
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $*"
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $*"
}

log_skip() {
    echo -e "${YELLOW}[SKIP]${NC} $*"
}

log_verbose() {
    if [[ $VERBOSE -eq 1 ]]; then
        echo -e "${BLUE}[VERBOSE]${NC} $*"
    fi
}

# Display help
show_help() {
    cat << 'EOF'
SIROS Private Data Conformance Test Runner

Usage: conformance-runner.sh [OPTIONS]

Options:
    --client CLIENT        Run tests for specific client: ts, kotlin, swift, or all (default: all)
    --vector ID            Run tests for specific test vector ID (default: all)
    --verbose              Enable verbose output
    --stop-on-fail         Stop on first failure (default: 1)
    --continue-on-fail     Continue testing on failure
    --help                 Show this help message

Environment Variables:
    CLIENT                 Override --client option
    VECTOR                 Override --vector option
    VERBOSE                Set to 1 for verbose output
    WALLET_FRONTEND_PATH   Path to wallet-frontend repo (for TS client)
    SIROS_SDK_KOTLIN_PATH  Path to siros-sdk-kotlin repo (for Kotlin client)
    SIROS_SDK_SWIFT_PATH   Path to siros-sdk-swift repo (for Swift client)

Examples:
    # Run all tests for all clients
    ./conformance-runner.sh

    # Run Swift tests only
    ./conformance-runner.sh --client swift

    # Run specific test vector on all clients
    ./conformance-runner.sh --vector single-credential-v3-001

    # Verbose output, continue on fail
    ./conformance-runner.sh --verbose --continue-on-fail

EOF
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --client)
            CLIENT="$2"
            shift 2
            ;;
        --vector)
            VECTOR="$2"
            shift 2
            ;;
        --verbose)
            VERBOSE=1
            shift
            ;;
        --stop-on-fail)
            STOP_ON_FAIL=1
            shift
            ;;
        --continue-on-fail)
            STOP_ON_FAIL=0
            shift
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Validate CLIENT option
if [[ ! "$CLIENT" =~ ^(all|ts|typescript|kotlin|swift)$ ]]; then
    log_fail "Invalid client: $CLIENT"
    show_help
    exit 1
fi

# Normalize client names
declare -a CLIENTS
if [[ "$CLIENT" == "all" ]]; then
    CLIENTS=("ts" "kotlin" "swift")
else
    if [[ "$CLIENT" == "typescript" ]]; then
        CLIENT="ts"
    fi
    CLIENTS=("$CLIENT")
fi

# Check for test vectors file
if [[ ! -f "$TEST_VECTORS_DIR/vectors.jsonl" ]]; then
    log_fail "Test vectors file not found: $TEST_VECTORS_DIR/vectors.jsonl"
    exit 1
fi

# Load test vectors
load_test_vectors() {
    if [[ -z "$VECTOR" ]]; then
        cat "$TEST_VECTORS_DIR/vectors.jsonl"
    else
        cat "$TEST_VECTORS_DIR/vectors.jsonl" | grep "\"id\": \"$VECTOR\""
    fi
}

# Check client availability
check_client() {
    local client=$1
    case $client in
        ts)
            if command -v node &> /dev/null && npm --version &> /dev/null; then
                log_info "✓ Node.js/npm available for TypeScript client"
                return 0
            else
                log_skip "Node.js/npm not available"
                return 1
            fi
            ;;
        kotlin)
            if command -v gradle &> /dev/null || [[ -x "$(command -v ./gradlew)" ]]; then
                log_info "✓ Gradle available for Kotlin client"
                return 0
            else
                log_skip "Gradle not available"
                return 1
            fi
            ;;
        swift)
            if command -v swift &> /dev/null; then
                log_info "✓ Swift available for Swift client"
                return 0
            else
                log_skip "Swift not available"
                return 1
            fi
            ;;
    esac
    return 1
}

# Encrypt test via client
encrypt_test() {
    local client=$1
    local test_id=$2
    local plaintext_file=$3
    local prf_inputs_file=$4
    
    log_info "[$client] Encrypting test vector $test_id..."
    
    case $client in
        ts)
            # wallet-frontend expects: npm run conformance:encrypt -- --plaintext FILE --prf-inputs FILE
            # Output: encrypted container JSON to stdout
            if [[ -x "$WALLET_FRONTEND_PATH/node_modules/.bin/conformance-encrypt" ]]; then
                "$WALLET_FRONTEND_PATH/node_modules/.bin/conformance-encrypt" \
                    --plaintext "$plaintext_file" \
                    --prf-inputs "$prf_inputs_file"
            else
                log_skip "conformance:encrypt not available for TS client"
                return 1
            fi
            ;;
        kotlin)
            # siros-sdk-kotlin expects: ./gradlew conformanceEncrypt --input=FILE --output=FILE
            # Output: encrypted container JSON
            if command -v gradle &> /dev/null; then
                gradle conformanceEncrypt \
                    --plaintext="$plaintext_file" \
                    --prf-inputs="$prf_inputs_file" \
                    --output="-"
            else
                log_skip "conformanceEncrypt not available for Kotlin client"
                return 1
            fi
            ;;
        swift)
            # siros-sdk-swift expects: swift run ConformanceEncrypt PLAINTEXT PRF_INPUTS
            # Output: encrypted container JSON to stdout
            if [[ -x "$SIROS_SDK_SWIFT_PATH/.build/debug/ConformanceEncrypt" ]]; then
                "$SIROS_SDK_SWIFT_PATH/.build/debug/ConformanceEncrypt" \
                    "$plaintext_file" "$prf_inputs_file"
            else
                log_skip "ConformanceEncrypt not available for Swift client"
                return 1
            fi
            ;;
    esac
    return $?
}

# Decrypt test via client
decrypt_test() {
    local client=$1
    local test_id=$2
    local container_file=$3
    
    log_info "[$client] Decrypting test vector $test_id..."
    
    case $client in
        ts)
            # npm run conformance:decrypt -- --container FILE
            if [[ -x "$WALLET_FRONTEND_PATH/node_modules/.bin/conformance-decrypt" ]]; then
                "$WALLET_FRONTEND_PATH/node_modules/.bin/conformance-decrypt" \
                    --container "$container_file"
            else
                log_skip "conformance:decrypt not available for TS client"
                return 1
            fi
            ;;
        kotlin)
            # ./gradlew conformanceDecrypt --input=FILE
            if command -v gradle &> /dev/null; then
                gradle conformanceDecrypt --input="$container_file" --output="-"
            else
                log_skip "conformanceDecrypt not available for Kotlin client"
                return 1
            fi
            ;;
        swift)
            # swift run ConformanceDecrypt CONTAINER
            if [[ -x "$SIROS_SDK_SWIFT_PATH/.build/debug/ConformanceDecrypt" ]]; then
                "$SIROS_SDK_SWIFT_PATH/.build/debug/ConformanceDecrypt" "$container_file"
            else
                log_skip "ConformanceDecrypt not available for Swift client"
                return 1
            fi
            ;;
    esac
    return $?
}

# Validate metadata preservation
validate_metadata() {
    local client=$1
    local test_id=$2
    local decrypted_state=$3
    
    log_verbose "[$client] Validating metadata preservation for $test_id..."
    
    # Check required credential fields
    local required_fields=("format" "kid" "instanceId" "batchId" "credentialIssuerIdentifier")
    for field in "${required_fields[@]}"; do
        if echo "$decrypted_state" | jq -e ".S.credentials[0].${field}" > /dev/null 2>&1; then
            log_verbose "  ✓ credential.$field present"
        else
            log_fail "  ✗ credential.$field missing"
            return 1
        fi
    done
    
    # Check keypair DID
    if echo "$decrypted_state" | jq -e ".S.keypairs[0].did" > /dev/null 2>&1; then
        log_verbose "  ✓ keypair.did present"
    else
        log_fail "  ✗ keypair.did missing"
        return 1
    fi
    
    # Check event preservation
    if echo "$decrypted_state" | jq -e ".events | length > 0" > /dev/null 2>&1; then
        log_verbose "  ✓ events array preserved"
    else
        log_fail "  ✗ events array missing or empty"
        return 1
    fi
    
    # Check settings default
    local settings=$(echo "$decrypted_state" | jq -r '.S.settings.openidRefreshTokenMaxAgeInSeconds // "null"')
    if [[ "$settings" == "0" ]] || [[ "$settings" == "null" ]]; then
        log_verbose "  ✓ settings.openidRefreshTokenMaxAgeInSeconds correct"
    else
        log_fail "  ✗ settings.openidRefreshTokenMaxAgeInSeconds incorrect (got: $settings)"
        return 1
    fi
    
    return 0
}

# Main test execution
run_tests() {
    log_info "========================================"
    log_info "SIROS Private Data Conformance Tests"
    log_info "========================================"
    log_info "Clients: ${CLIENTS[*]}"
    if [[ -n "$VECTOR" ]]; then
        log_info "Vectors: $VECTOR (specific)"
    else
        log_info "Vectors: all"
    fi
    log_info ""
    
    # For each test vector
    load_test_vectors | while IFS= read -r vector_line; do
        local test_id=$(echo "$vector_line" | jq -r '.id')
        local description=$(echo "$vector_line" | jq -r '.description')
        
        log_info "─────────────────────────────────────"
        log_info "Test: $test_id"
        log_info "Description: $description"
        log_info ""
        
        # For each client
        for client in "${CLIENTS[@]}"; do
            ((TOTAL_TESTS++))
            
            # Check if client is available
            if ! check_client "$client"; then
                ((SKIPPED_TESTS++))
                continue
            fi
            
            # Extract test data
            local plaintext=$(echo "$vector_line" | jq '.inputs.plaintextState')
            local prf_inputs=$(echo "$vector_line" | jq '.inputs | {credentialId, prfOutput, hkdfSalt, hkdfInfo}')
            
            # Create temp files
            local tmp_dir=$(mktemp -d)
            local plaintext_file="$tmp_dir/plaintext.json"
            local prf_inputs_file="$tmp_dir/prf_inputs.json"
            local encrypted_file="$tmp_dir/encrypted.json"
            local decrypted_file="$tmp_dir/decrypted.json"
            
            echo "$plaintext" > "$plaintext_file"
            echo "$prf_inputs" > "$prf_inputs_file"
            
            # Test encryption
            if encrypt_test "$client" "$test_id" "$plaintext_file" "$prf_inputs_file" > "$encrypted_file" 2>/dev/null; then
                log_pass "  [$client] Encryption successful"
                ((PASSED_TESTS++))
            else
                log_fail "  [$client] Encryption failed"
                ((FAILED_TESTS++))
                rm -rf "$tmp_dir"
                if [[ $STOP_ON_FAIL -eq 1 ]]; then
                    exit 1
                fi
                continue
            fi
            
            # Test decryption
            if decrypt_test "$client" "$test_id" "$encrypted_file" > "$decrypted_file" 2>/dev/null; then
                log_pass "  [$client] Decryption successful"
                ((PASSED_TESTS++))
            else
                log_fail "  [$client] Decryption failed"
                ((FAILED_TESTS++))
                rm -rf "$tmp_dir"
                if [[ $STOP_ON_FAIL -eq 1 ]]; then
                    exit 1
                fi
                continue
            fi
            
            # Validate metadata
            if validate_metadata "$client" "$test_id" "$(cat "$decrypted_file")"; then
                log_pass "  [$client] Metadata validation passed"
                ((PASSED_TESTS++))
            else
                log_fail "  [$client] Metadata validation failed"
                ((FAILED_TESTS++))
                if [[ $STOP_ON_FAIL -eq 1 ]]; then
                    rm -rf "$tmp_dir"
                    exit 1
                fi
            fi
            
            # Cleanup
            rm -rf "$tmp_dir"
        done
        
        log_info ""
    done
}

# Summary
print_summary() {
    log_info "========================================"
    log_info "Test Summary"
    log_info "========================================"
    log_info "Total Tests:   $TOTAL_TESTS"
    log_pass "Passed Tests:  $PASSED_TESTS"
    if [[ $FAILED_TESTS -gt 0 ]]; then
        log_fail "Failed Tests:  $FAILED_TESTS"
    fi
    if [[ $SKIPPED_TESTS -gt 0 ]]; then
        log_skip "Skipped Tests: $SKIPPED_TESTS"
    fi
    log_info ""
    
    if [[ $FAILED_TESTS -eq 0 ]] && [[ $TOTAL_TESTS -gt 0 ]]; then
        log_pass "All tests passed! ✓"
        return 0
    else
        log_fail "Some tests failed. ✗"
        return 1
    fi
}

# Main execution
run_tests
print_summary
