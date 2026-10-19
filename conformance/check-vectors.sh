#!/bin/bash
#
# Offline self-check of test-vectors/vectors.jsonl: needs only jq and sha256sum,
# no client SDK. Verifies that every vector with expected.plaintextStateSha256 /
# roundTripStateSha256 hashes consistently (compact JSON, key order as written),
# that credential `metadata` obeys SPEC.md Section 6 in the expected states, and
# that the delivered-secret commitment vector (Section 5A) holds.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../test-vectors"
fail=0; n=0
while IFS= read -r line; do
    id=$(jq -r .id <<<"$line")
    if jq -e '.expected.plaintextStateSha256' <<<"$line" >/dev/null 2>&1; then
        n=$((n+1))
        for pair in "inputs.plaintextState:plaintextStateSha256" "expected.roundTripState:roundTripStateSha256"; do
            path=${pair%%:*}; hashf=${pair##*:}
            got=$(jq -c ".${path}" <<<"$line" | tr -d '\n' | sha256sum | cut -d' ' -f1)
            want=$(jq -r ".expected.${hashf}" <<<"$line")
            if [[ "$got" != "$want" ]]; then echo "FAIL $id: $hashf $got != $want"; fail=1; fi
        done
        if ! jq -e 'all(.expected.roundTripState.S.credentials[]?;
              (has("metadata")|not) or (.metadata|type=="array" and length>0 and
               all(.[]; type=="object" and has("value") and (.type|type=="string" and length>0))))' <<<"$line" >/dev/null; then
            echo "FAIL $id: expected state has null/empty/ill-formed metadata"; fail=1
        fi
        echo "ok   $id"
    fi
    if [[ "$id" == "delivered-secret-commitment-001" ]]; then
        n=$((n+1))
        seed=$(jq -r .inputs.secret_seed_hex <<<"$line")
        calc=$(printf '%s' "$seed" | xxd -r -p | sha256sum | cut -d' ' -f1)
        m=$(jq -r '.inputs.cases[] | select(.name=="match") | .ssc_hex' <<<"$line")
        x=$(jq -r '.inputs.cases[] | select(.name=="mismatch") | .ssc_hex' <<<"$line")
        if [[ "$calc" == "$m" && "$calc" != "$x" ]]; then echo "ok   $id"; else echo "FAIL $id"; fail=1; fi
    fi
done < vectors.jsonl
echo "checked $n vectors, fail=$fail"
exit $fail
