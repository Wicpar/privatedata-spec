# Rollout

**Moved.** The plan that used to live here is now
[`siros-wscd-manager` `docs/wallet-frontend-migration.md`](https://github.com/sirosfoundation/siros-wscd-manager/blob/main/docs/wallet-frontend-migration.md),
which is the single source of truth for both the rollout of this
specification and the `wallet-frontend` WASM migration it gates.

Two plans covering overlapping work is how the previous three drifted apart,
so this file is a pointer rather than a summary that could drift again.

## What this repository owes that plan

Its Stage 0. Until these land, §6.1 is a rule no client outside this
organisation is on the hook for, and the SDKs are writing into a container
shape that has no published definition:

1. Merge [#1](https://github.com/sirosfoundation/privatedata-spec/pull/1) —
   `SPEC.md` v2.1 §6.1 `S.extensions` and §6.2's deprecations.
2. Register the namespaces the plan uses in §6.1.6: `org.siros.wscd`,
   `org.siros.oid4vci.refresh`, `org.siros.bbs`.
3. Add a conformance vector per namespace — including the one the mechanism
   exists for: a container carrying a namespace the implementation does not
   know, round-tripped twice.

## Why it is urgent rather than merely pending

`org.siros.bbs` is written by `siros-sdk-kotlin` today and holds a blind BBS
credential's secret prover blind. It cannot be reconstructed. A client that
drops it does not degrade the credential, it makes it permanently
unpresentable — and the failure lands on whichever client touches the
container last, not on the one that caused it.

## Relation to credential metadata (PR #3)

`org.siros.oid4vci.refresh` stays an extension: a refresh token is shared by a
batch of credentials, so it is keyed by `batchId` and is not data of one
credential entry. Data that an issuer supplies for exactly one credential
entry, and that the wallet stores uninterpreted, goes in that entry's
`metadata` member instead (SPEC.md v2.2, PR #3), not in a namespace; such data
needs neither a registry entry nor `set_extension` events, and is deleted with
the entry. Neither change gates the other.

## Related

- `SPEC.md` §6.1 — the normative mechanism
- `docs/EXTENSIONS-DESIGN.md` — why it is shaped this way
- `docs/SPEC-ALTERNATIVE-AUTOMERGE.md` — the alternative, not adopted; bears
  on the migration plan's decision D2
