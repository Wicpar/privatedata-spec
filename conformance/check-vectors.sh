#!/bin/bash
#
# Offline self-check of test-vectors/vectors.jsonl: needs only jq and sha256sum,
# no client SDK. Verifies that every vector with expected.plaintextStateSha256 /
# roundTripStateSha256 hashes consistently (compact JSON, key order as written),
# that credential `metadata` obeys SPEC.md Section 6 in the expected states, and
# that the delivered-secret commitment vector and the wire-shape / malformed /
# refusal vectors (Section 5A) hold: each case's response is evaluated against the
# Section 5A rules and must give the vector's expected outcome and stored metadata.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../test-vectors"
fail=0; n=0

# Section 5A.1 shape of org.siros.secret_seed: object of 1..8 members, namespace a
# non-empty string of <= 64 bytes, seed exactly 32 lowercase hex characters.
SEED_SHAPE='(.credential_metadata["org.siros.secret_seed"]) as $m
  | ($m|type=="object") and (($m|length) as $l | $l>=1 and $l<=8)
    and all($m|to_entries[]; (.key|type=="string" and length>0 and (utf8bytelength<=64))
      and (.value|type=="string" and test("^[0-9a-f]{32}$")))'

# evaluate_case <case-json>: prints "accept <stored-metadata-json>" or "refuse".
evaluate_case() {
    local c=$1 ns seed ssc calc
    local has; has=$(jq -r '.response.credential_metadata|has("org.siros.secret_seed")' <<<"$c" 2>/dev/null || echo false)
    if [[ "$has" == true ]]; then
        jq -e '.jweEncrypted == true' <<<"$c" >/dev/null || { echo refuse; return; }
        jq -e '.response.notification_id|type=="string" and length>0' <<<"$c" >/dev/null || { echo refuse; return; }
        jq -e ".response|$SEED_SHAPE" <<<"$c" >/dev/null || { echo refuse; return; }
    fi
    ns=$(jq -r .commitmentNamespace <<<"$c"); ssc=$(jq -r .sscHex <<<"$c")
    seed=$(jq -r --arg ns "$ns" '.response.credential_metadata["org.siros.secret_seed"][$ns] // empty' <<<"$c")
    [[ -n "$seed" ]] || { echo refuse; return; }
    calc=$(printf '%s' "$seed" | xxd -r -p | sha256sum | cut -d' ' -f1)
    [[ "$calc" == "$ssc" ]] || { echo refuse; return; }
    echo "accept $(jq -c '[.response.credential_metadata|to_entries[]|{type:.key,value:.value}]' <<<"$c")"
}
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
    if [[ "$id" == delivered-secret-wire-001 || "$id" == delivered-secret-malformed-001 || "$id" == delivered-secret-refusal-001 ]]; then
        n=$((n+1)); ok=1
        ncases=$(jq '.inputs.cases|length' <<<"$line")
        [[ "$ncases" -gt 0 ]] || { echo "FAIL $id: no cases"; ok=0; }
        for ((k=0;k<ncases;k++)); do
            c=$(jq -c ".inputs.cases[$k]" <<<"$line")
            want=$(jq -r .expected.outcome <<<"$c")
            got=$(evaluate_case "$c"); gotout=${got%% *}
            if [[ "$gotout" != "$want" ]]; then echo "FAIL $id[$k] $(jq -r .name <<<"$c"): got $gotout want $want"; ok=0; continue; fi
            if [[ "$want" == accept ]]; then
                stored=${got#accept }; wantst=$(jq -c .expected.storedMetadataPerCredential <<<"$c")
                [[ "$stored" == "$wantst" ]] || { echo "FAIL $id[$k]: stored $stored != $wantst"; ok=0; }
            fi
        done
        # the vectors must keep covering both outcomes where they claim to
        case "$id" in
            *wire*) jq -e '[.inputs.cases[].expected.outcome]|all(.=="accept")' <<<"$line" >/dev/null || { echo "FAIL $id: non-accept case"; ok=0; } ;;
            *) jq -e '[.inputs.cases[].expected.outcome]|all(.=="refuse")' <<<"$line" >/dev/null || { echo "FAIL $id: non-refuse case"; ok=0; } ;;
        esac
        if [[ $ok == 1 ]]; then echo "ok   $id ($ncases cases)"; else fail=1; fi
    fi
done < vectors.jsonl
echo "checked $n vectors, fail=$fail"
exit $fail
