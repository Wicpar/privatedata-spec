#!/bin/bash
#
# Offline self-check of test-vectors/vectors.jsonl: needs only jq and sha256sum,
# no client SDK. Verifies that every vector with expected.plaintextStateSha256 /
# roundTripStateSha256 hashes consistently (compact JSON, key order as written),
# that credential `metadata` obeys SPEC.md Section 6 in the expected states, and
# that derived-secrets.json (Section 5.4.1) is reproduced from the roots with openssl,
# that the delivered-secret commitment vector and the wire-shape / malformed /
# refusal vectors (Section 5A) hold: each case's response is evaluated against the
# Section 5A rules and must give the vector's expected outcome and stored metadata,
# and that the version 3 to 4 migration vectors change only S.schemaVersion.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../test-vectors"
fail=0; n=0

# SPEC.md Section 6.0: S.credentials[] entry shape (as wallet-frontend stores it).
ENTRY_SHAPE='(has("id")|not) and (.credentialId|type=="number" and .==floor and .>=0)
  and (.data|type=="string") and (.format|type=="string") and (.kid|type=="string")
  and (.instanceId|type=="number" and .==floor and .>=0) and (.batchId|type=="number" and .==floor and .>=0)
  and (.credentialIssuerIdentifier|type=="string") and (.credentialConfigurationId|type=="string")'
check_entries() { # check_entries <label> <json-array-of-entries>
    jq -e "length>0 and all(.[]; $ENTRY_SHAPE)" <<<"$2" >/dev/null || { echo "FAIL $1: credential entry violates SPEC Section 6.0"; fail=1; return 1; }
}

# Section 5A.1 shape of org.siros.secret_seed: object of 1..8 members, namespace a
# non-empty string of <= 64 bytes, seed exactly 32 lowercase hex characters.
SEED_SHAPE='(.credential_metadata["org.siros.secret_seed"]) as $m
  | ($m|type=="object") and (($m|length) as $l | $l>=1 and $l<=8)
    and all($m|to_entries[]; (.key|type=="string" and length>0 and (utf8bytelength<=64) and .!="namespaces")
      and (.value|type=="string" and test("^[0-9a-f]{32}$")))'

# Section 5A.4: valid advertisement is {namespaces: [1..8 distinct names]} only.
ADV_SHAPE='(.issuerCredentialMetadata["org.siros.secret_seed"]) as $m
  | ($m|type=="object") and ($m|keys==["namespaces"]) and ($m.namespaces|type=="array")
    and (($m.namespaces|length) as $l | $l>=1 and $l<=8) and ($m.namespaces|length==(unique|length))
    and all($m.namespaces[]; type=="string" and length>0 and utf8bytelength<=64 and .!="namespaces"
      and (test("^[0-9a-f]{32}$")|not))'

# SPEC.md Section 6: the event types a version 4 reader implements (wallet-frontend's
# nine, WalletStateSchemaVersion1.ts, plus set_extension) and the versions it knows.
EVENT_TYPES='["new_credential","delete_credential","new_keypair","delete_keypair","new_presentation","delete_presentation","alter_settings","save_credential_issuance_session","delete_credential_issuance_session","set_extension"]'
# event_ok: true when the event has an integer schemaVersion 1..4 and a known type
# (a reader accepts set_extension at schemaVersion 3 or 4, never 1 or 2; a writer emits 4).
EVENT_OK='def event_ok: (.schemaVersion|type=="number" and .==floor and .>=1 and .<=4)
  and (.type as $t | '"$EVENT_TYPES"' | index($t) != null) and (.type!="set_extension" or .schemaVersion>=3);'

# dupfree: folds .events over .S the way wallet-frontend's reducers do and is true when no
# new_credential / new_keypair / new_presentation event creates an id that already exists.
FOLD_DUPFREE='def dupfree: . as $st | reduce ($st.events // [])[] as $e
  ({c:[$st.S.credentials[]?.credentialId], k:[$st.S.keypairs[]? | select(type=="object") | .kid], p:[$st.S.presentations[]?.presentationId], bad:false};
   if   $e.type=="new_credential"    then (if (.c|index($e.credentialId))   then .bad=true else .c+=[$e.credentialId] end)
   elif $e.type=="delete_credential" then .c-=[$e.credentialId]
   elif $e.type=="new_keypair"       then (if (.k|index($e.kid))            then .bad=true else .k+=[$e.kid] end)
   elif $e.type=="delete_keypair"    then .k-=[$e.kid]
   elif $e.type=="new_presentation"  then (if (.p|index($e.presentationId)) then .bad=true else .p+=[$e.presentationId] end)
   elif $e.type=="delete_presentation" then .p-=[$e.presentationId]
   else . end) | .bad|not;'

# evaluate_adv <case-json>: prints valid-advertisement | no-advertisement | malformed.
evaluate_adv() {
    local c=$1
    jq -e '.issuerCredentialMetadata|has("org.siros.secret_seed")' <<<"$c" >/dev/null || { echo no-advertisement; return; }
    if jq -e "$ADV_SHAPE" <<<"$c" >/dev/null; then echo valid-advertisement; else echo malformed; fi
}

# evaluate_strip <case-json>: prints "<stripped>|<merged>" (compact JSON); the seed
# member is removed from the response object before the member-wise merge.
evaluate_strip() {
    jq -c '(.responseCredentialMetadata|del(.["org.siros.secret_seed"])) as $s
      | "\($s)|\(.issuerCredentialMetadata + $s)"' -r <<<"$1"
}

# evaluate_case <case-json>: prints "accept <stored-metadata-json>" or "refuse".
evaluate_case() {
    local c=$1 ns seed ssc calc
    jq -e '.response|(has("credential_metadata")|not) or (.credential_metadata|type=="object")' <<<"$c" >/dev/null || { echo refuse; return; }
    local has; has=$(jq -r '.response.credential_metadata|has("org.siros.secret_seed")' <<<"$c" 2>/dev/null || echo false)
    if [[ "$has" == true ]]; then
        jq -e '.jweEncrypted == true' <<<"$c" >/dev/null || { echo refuse; return; }
        jq -e '(.responseType // "credential") != "deferred"' <<<"$c" >/dev/null || { echo refuse; return; }
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
    for src in .inputs.plaintextState.S.credentials .expected.roundTripState.S.credentials; do
        ents=$(jq -c "$src // empty" <<<"$line")
        if [[ -n "$ents" && "$ents" != "[]" ]]; then check_entries "$id $src" "$ents" && echo "ok   $id entries ($src)"; fi
    done
    if [[ "$id" == delivered-secret-commitment-001 ]]; then
        check_entries "$id credentialAfterAccept" "$(jq -c '[.expected.credentialAfterAccept]' <<<"$line")" && echo "ok   $id entry"
    fi
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
    # Section 6: an accepted vector (anything that is not a refusal vector) carries only real,
    # versioned events of the implemented types, in EVERY event carrier it has: the state
    # events, the round-trip events, and the merge histories / event lists of the extension
    # vectors. Unversioned or unknown events are refused (refusal vectors below).
    case "$id" in
        schema-version-unknown-state-001|schema-version-unknown-event-version-001|schema-version-unknown-event-type-001|schema-version-event-missing-version-001|extensions-unknown-event-001) refusal=1 ;;
        *) refusal=0 ;;
    esac
    if [[ $refusal == 0 ]]; then
        jq -e "$EVENT_OK [.inputs.plaintextState.events?, .inputs.events?, .inputs.historyA?, .inputs.historyB?, .expected.roundTripState.events?]
            | map(select(. != null)) | add // [] | all(.[]; event_ok)" <<<"$line" >/dev/null || { echo "FAIL $id: an event is unversioned, of an unknown type, or a set_extension below schemaVersion 3"; fail=1; }
        jq -e '.inputs.plaintextState.S.schemaVersion // 4 | IN(1,2,3,4)' <<<"$line" >/dev/null || { echo "FAIL $id: S.schemaVersion not implemented"; fail=1; }
    fi
    # Folding the events over S with wallet-frontend's reducers (WalletStateSchemaVersion1.ts:
    # new_* append, delete_* filter) must not create an identifier that already exists.
    for path in .inputs.plaintextState .expected.roundTripState; do
        jq -e "$FOLD_DUPFREE [${path} | select(. != null) | dupfree] | all" <<<"$line" >/dev/null || { echo "FAIL $id: $path creates an event entity that S already holds (folding would duplicate it)"; fail=1; }
    done
    case "$id" in
        schema-version-unknown-state-001|schema-version-unknown-event-version-001|schema-version-unknown-event-type-001|schema-version-event-missing-version-001|extensions-unknown-event-001)
            n=$((n+1))
            if jq -e "$EVENT_OK ([.inputs.plaintextState.events?, .inputs.historyA?, .inputs.historyB?] | map(select(. != null)) | add // []) as \$ev
                | ((.inputs.plaintextState.S.schemaVersion // 4) | IN(1,2,3,4) | not) or any(\$ev[]; event_ok|not)" <<<"$line" >/dev/null; then echo "ok   $id (refused input)"; else echo "FAIL $id: input is not refusable"; fail=1; fi
            case "$id" in
                *unknown-event-version*) jq -e '.inputs.plaintextState.events|any(.[]; (.schemaVersion|type=="number" and .>4))' <<<"$line" >/dev/null || { echo "FAIL $id: no event with a too-new schemaVersion"; fail=1; } ;;
                *missing-version*) jq -e '.inputs.plaintextState.events|any(.[]; has("schemaVersion")|not)' <<<"$line" >/dev/null || { echo "FAIL $id: every event has a schemaVersion"; fail=1; } ;;
                extensions-unknown-event-001) jq -e '([.inputs.historyA[],.inputs.historyB[]]|any(.type as $t | '"$EVENT_TYPES"'|index($t)|not))' <<<"$line" >/dev/null || { echo "FAIL $id: no unknown event type in the histories"; fail=1; } ;;
            esac ;;
        schema-version-event-types-001)
            jq -e "$EVENT_TYPES as \$t | ([.inputs.plaintextState.events[].type]|unique) == (\$t|sort)" <<<"$line" >/dev/null || { echo "FAIL $id: not every event type is covered"; fail=1; } ;;
        keypair-unknown-entry-001)
            jq -e '.inputs.plaintextState==.expected.roundTripState and (.inputs.plaintextState.S.keypairs|length)>=3' <<<"$line" >/dev/null || { echo "FAIL $id: keypair entries not preserved verbatim"; fail=1; } ;;
    esac
    if [[ "$id" == schema-version-migrate-v3-001 || "$id" == schema-version-v3-legacy-members-001 || "$id" == single-credential-v3-001 || "$id" == multi-passkey-v3-001 ]]; then
        n=$((n+1))
        if jq -e '.inputs.plaintextState.S.schemaVersion==3 and (.inputs.plaintextState|.S.schemaVersion=4)==.expected.roundTripState' <<<"$line" >/dev/null; then
            echo "ok   $id"
        else
            echo "FAIL $id: migration changes more than S.schemaVersion"; fail=1
        fi
    fi
    if [[ "$id" == "delivered-secret-commitment-001" ]]; then
        n=$((n+1))
        seed=$(jq -r .inputs.secret_seed_hex <<<"$line")
        calc=$(printf '%s' "$seed" | xxd -r -p | sha256sum | cut -d' ' -f1)
        m=$(jq -r '.inputs.cases[] | select(.name=="match") | .ssc_hex' <<<"$line")
        x=$(jq -r '.inputs.cases[] | select(.name=="mismatch") | .ssc_hex' <<<"$line")
        if [[ "$calc" == "$m" && "$calc" != "$x" ]]; then echo "ok   $id"; else echo "FAIL $id"; fail=1; fi
    fi
    if [[ "$id" == delivered-secret-strip-001 ]]; then
        n=$((n+1)); ok=1
        ncases=$(jq '.inputs.cases|length' <<<"$line")
        [[ "$ncases" -gt 0 ]] || { echo "FAIL $id: no cases"; ok=0; }
        for ((k=0;k<ncases;k++)); do
            c=$(jq -c ".inputs.cases[$k]" <<<"$line"); nm=$(jq -r .name <<<"$c")
            got=$(evaluate_strip "$c"); gs=${got%%|*}; gm=${got#*|}
            [[ "$gs" == "$(jq -c .expected.strippedResponse <<<"$c")" ]] || { echo "FAIL $id[$k] $nm: stripped $gs"; ok=0; }
            [[ "$gm" == "$(jq -c .expected.mergedDisplayMetadata <<<"$c")" ]] || { echo "FAIL $id[$k] $nm: merged $gm"; ok=0; }
            # the seed hex must be absent from the stripped and merged display metadata
            while IFS= read -r hex; do
                if [[ "$gs$gm" == *"$hex"* ]]; then echo "FAIL $id[$k] $nm: seed leaked into display metadata"; ok=0; fi
            done < <(jq -r '.responseCredentialMetadata["org.siros.secret_seed"]//{}|.[]' <<<"$c")
            # the stored entry is the seed member verbatim
            [[ "$(jq -c '[.responseCredentialMetadata["org.siros.secret_seed"]|select(.)|{type:"org.siros.secret_seed",value:.}]' <<<"$c")" == "$(jq -c .expected.storedMetadata <<<"$c")" ]] || { echo "FAIL $id[$k] $nm: stored metadata"; ok=0; }
        done
        if [[ $ok == 1 ]]; then echo "ok   $id ($ncases cases)"; else fail=1; fi
    fi
    if [[ "$id" == delivered-secret-advertise-001 ]]; then
        n=$((n+1)); ok=1
        ncases=$(jq '.inputs.cases|length' <<<"$line")
        [[ "$ncases" -gt 0 ]] || { echo "FAIL $id: no cases"; ok=0; }
        for ((k=0;k<ncases;k++)); do
            c=$(jq -c ".inputs.cases[$k]" <<<"$line")
            want=$(jq -r .expected.outcome <<<"$c"); got=$(evaluate_adv "$c")
            [[ "$got" == "$want" ]] || { echo "FAIL $id[$k] $(jq -r .name <<<"$c"): got $got want $want"; ok=0; }
            if [[ "$want" == valid-advertisement ]]; then
                jq -e '.expected.walletMustRequestCredentialResponseEncryption and .expected.walletMustRefusePlainResponse' <<<"$c" >/dev/null || { echo "FAIL $id[$k]: encryption obligations missing"; ok=0; }
            fi
        done
        if [[ $ok == 1 ]]; then echo "ok   $id ($ncases cases)"; else fail=1; fi
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
# Fixtures that carry a plaintextState (same entry shape).
for f in fixtures/*.json edge-cases/*.json; do
    ents=$(jq -c '(.inputs.plaintextState.S.credentials // .sample.credentials) // empty | select(length>0 and (.[0]|type=="object"))' "$f")
    [[ -n "$ents" ]] || continue
    if [[ "$f" == edge-cases/unknown-credential-members.json ]]; then
        jq -e 'all(.[]; (has("id")|not) and (.credentialId|type=="number") and (.data|type=="string"))' <<<"$ents" >/dev/null || { echo "FAIL $f: entry shape"; fail=1; continue; }
    else
        check_entries "$f" "$ents" || continue
    fi
    echo "ok   $f"
done

# SPEC.md Section 5.4.1: private_seed = HKDF-SHA256(mainKey, salt = empty,
# info = label || lp(type) || lp(issuer))[:16]. One HKDF block, computed with
# openssl HMAC (messages go through stdin, so a 65535-byte field is no problem).
PS_LABEL_HEX=$(printf '%s' "org.siros.private_seed/v2" | xxd -p | tr -d '\n')
field_hex() { # field_hex <json> <name>: UTF-8 bytes of .name, or of .name_fill 'a's
    local fill; fill=$(jq -r ".${2}_fill // empty" <<<"$1")
    if [[ -n "$fill" ]]; then head -c "$fill" /dev/zero | tr '\0' a | xxd -p | tr -d '\n'
    else jq -j ".${2} // \"\"" <<<"$1" | xxd -p | tr -d '\n'; fi
}
lp_hex() { # lp_hex <hex>: 2-byte big-endian length || bytes; fails if length is 0 or > 65535
    local n=$(( ${#1} / 2 ))
    (( n >= 1 && n <= 65535 )) || return 1
    printf '%04x%s' "$n" "$1"
}
hmac_hex() { # hmac_hex <key-hex> : HMAC-SHA256 of stdin
    openssl dgst -sha256 -mac HMAC -macopt "hexkey:$1" -binary | xxd -p -c 64 | tr -d '\n'
}
derive_seed() { # derive_seed <vector-json>: prints "seed_hex psc_hex", or fails (refused)
    local v=$1 root th ih info prk seed
    root=$(jq -r .root_hex <<<"$v")
    th=$(lp_hex "$(field_hex "$v" credential_type)") || return 1
    ih=$(lp_hex "$(field_hex "$v" issuer)") || return 1
    info="${PS_LABEL_HEX}${th}${ih}01"
    prk=$(printf '%s' "$root" | xxd -r -p | hmac_hex "$(printf '0%.0s' {1..64})")
    seed=$(printf '%s' "$info" | xxd -r -p | hmac_hex "$prk" | cut -c1-32)
    echo "$seed $(printf '%s' "$seed" | xxd -r -p | sha256sum | cut -d' ' -f1)"
}
ds=derived-secrets.json
if [[ -f "$ds" ]]; then
    n=$((n+1)); ok=1; declare -A got_seed
    [[ "$(jq -r .label "$ds")" == "org.siros.private_seed/v2" ]] || { echo "FAIL derived-secrets: label"; ok=0; }
    nv=$(jq '.vectors|length' "$ds"); [[ "$nv" -gt 0 ]] || { echo "FAIL derived-secrets: no vectors"; ok=0; }
    for ((k=0;k<nv;k++)); do
        v=$(jq -c ".vectors[$k]" "$ds"); nm=$(jq -r .name <<<"$v")
        if r=$(derive_seed "$v"); then
            got_seed["$nm"]=${r% *}
            [[ "$r" == "$(jq -r '"\(.seed_hex) \(.psc_hex)"' <<<"$v")" ]] || { echo "FAIL derived-secrets[$k] $nm: got $r"; ok=0; }
        else echo "FAIL derived-secrets[$k] $nm: refused"; ok=0; fi
    done
    nr=$(jq '.refused|length' "$ds"); [[ "$nr" -gt 0 ]] || { echo "FAIL derived-secrets: no refusal vectors"; ok=0; }
    for ((k=0;k<nr;k++)); do
        v=$(jq -c ".refused[$k]" "$ds")
        if derive_seed "$v" >/dev/null; then echo "FAIL derived-secrets refused[$k] $(jq -r .name <<<"$v"): not refused"; ok=0; fi
    done
    nd=$(jq '.must_differ|length' "$ds"); [[ "$nd" -gt 0 ]] || { echo "FAIL derived-secrets: no must_differ pairs"; ok=0; }
    for ((k=0;k<nd;k++)); do
        a=$(jq -r ".must_differ[$k][0]" "$ds"); b=$(jq -r ".must_differ[$k][1]" "$ds")
        if [[ -z "${got_seed[$a]:-}" || -z "${got_seed[$b]:-}" || "${got_seed[$a]}" == "${got_seed[$b]}" ]]; then echo "FAIL derived-secrets must_differ[$k]: '$a' vs '$b'"; ok=0; fi
    done
    if [[ $ok == 1 ]]; then echo "ok   derived-secrets ($nv vectors, $nr refused, $nd distinct pairs)"; else fail=1; fi
fi
echo "checked $n vectors, fail=$fail"
exit $fail
