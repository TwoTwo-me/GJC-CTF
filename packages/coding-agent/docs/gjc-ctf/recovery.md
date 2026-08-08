# Recovery, fencing, and corruption

`gjc-ctf` treats the manifest and canonical event stream as authoritative bytes. Recovery is replay of validated durable records; it is not an invitation to edit JSON until a check passes.

## Durable registration transaction

A challenge registration transaction is written below the competition state root:

```text
.gjc-ctf/
└── competition/
    ├── event-head.json
    ├── registration-journal.jsonl
    ├── registration/<transaction-id>.json
    ├── events/<event-id>.json
    └── checkpoints/<revision>-<event-id>.json
```

Writes use a temporary file, `fsync`, rename, and directory sync. A registration records the old manifest revision/digest, the next revision/digest, the descriptor digest, the event digest, and the phase (`prepared`, `committed`, or `aborted`). The transaction and event are retained so a later writer can classify state without guessing.

The registration lock serializes writers. The event head must agree with the manifest revision and predecessor digest. The manifest advances exactly one revision at a time. A transaction is idempotent on `challengeId` plus `descriptorDigest`; a different descriptor under an existing id is a conflict.

## Replay classification

On a subsequent registration, durable transactions are examined in creation order:

| Durable state | Recovery action |
| --- | --- |
| Prepared transaction, old manifest, event absent | Write the validated event/checkpoint, then apply the manifest and commit. |
| Prepared transaction, old manifest, event present | Complete the manifest and commit. |
| Prepared transaction, new manifest, event absent | Complete the event/checkpoint and commit. |
| Prepared transaction, new manifest, event present | Commit as a no-op after all digests validate. |
| Committed transaction, matching new manifest and event | Commit as a no-op and ensure its event/checkpoint exist. |
| Aborted transaction, missing descriptor, stale head, or any digest/revision disagreement | Refuse with `registration_repair_required` (or the more specific integrity/conflict error). |

Recovery never accepts a transaction whose IDs, descriptor digest, event digest, or manifest digest do not agree. A prepared transaction behind a newer manifest is not silently rebased.

The public CLI has no repair or recovery command. `resume` is not a recovery substitute: it is an unimplemented solver orchestration command. Recovery currently occurs as part of a validated registration API call; do not claim that running `resume` repaired state.

## Canonical events and projections

The canonical event log is append-only and hash chained. Each event has a contiguous revision, a predecessor revision, and a predecessor digest. Invalid JSON, an empty line, a partial final line, a non-contiguous revision, or a hash-chain mismatch raises an integrity error. Reads deliberately do not truncate a partial tail or repair the log.

A derived projection can be rebuilt from the beginning or refreshed with only the next canonical suffix. It becomes `rebuilding` while rebuilding, `current` when caught up, `lagging` when canonical state is ahead, and `integrity_error` after a failed read/reduce. Projection metadata is safe to expose, but projection data is not. The dashboard returns an enveloped 503 for unavailable, rebuilding, or integrity-error projection state.

## Run leases and fencing

Run ownership is a separate, fenced lease lane per competition/challenge. A lease has a run id, owner id, process identity, expiry, and positive fencing token (default duration: 30 seconds; callers may select a positive duration no longer than 24 hours).

- Acquisition of an occupied lane requires an explicit `takeoverOf` run id and the existing lease must be expired.
- A takeover increments the fencing token and records the predecessor run.
- Renew and state-transition operations require the run id, owner id, and expected fencing token, and reject expired leases.
- `assertFence` rejects missing, expired, or stale tokens with retryable `stale_run_fence`.
- A stale worker must not write after a takeover. It must stop and reacquire through the owner protocol.

Lease JSON is schema validated when read. Invalid JSON or invalid owner records are integrity failures, not an invitation to reuse a token.

## Corruption and operator response

Typical refusals include `manifest_missing`, `unmarked_directory`, `invalid_manifest`, `manifest_digest_mismatch`, `digest_mismatch`, `revision_conflict`, `registration_repair_required`, `integrity_error`, and `idempotency_conflict`. Retryability is explicit on typed errors; do not infer it from a message.

When state is corrupt:

1. Stop writers and preserve the complete competition directory, including journals, event files, checkpoints, and lease files.
2. Capture the error code, affected path (from local logs), manifest revision/digest, and event-head digest without modifying bytes.
3. Compare against a trusted backup or an independently verified source of truth.
4. Restore or repair through an owning recovery procedure that revalidates every digest and revision; there is no generic CLI repair command.
5. Re-run a read-only status/dashboard inspection only after the restored bytes validate.

Do not delete a journal entry, truncate an event tail, overwrite a conflicting transaction, hand-edit a digest, or reuse a stale fencing token. Those actions destroy the evidence needed to distinguish a crash from tampering.
## Operator recovery checklist

Recovery preserves evidence; it does not make an unavailable solve runnable. On a refusal or restart, inspect the durable competition event head and transaction/checkpoint records, replay only through the validated APIs, and verify digests and fencing before treating state as current. A corrupt, stale, or missing record is an integrity failure and must remain unavailable until repaired by the owning integration. Do not delete event history, rewrite a manifest or lock, or retry against a different ancestor to bypass a refusal.

The available recovery surface is the existing `init`, `status`, and dashboard inspection flow. `resume` validates a recorded run but is currently unavailable because durable solver resume is not configured. Preserve the original run identity and failure evidence; recovery must not convert a blocked run, stale claim, or missing oracle into a pass.
