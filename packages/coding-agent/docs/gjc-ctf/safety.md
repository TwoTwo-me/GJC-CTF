# Safety, calibration, and clean rooms

Safety is a precondition, not a score. `gjc-ctf` validates a declared policy and trusted runtime facts before allowing a local execution class. Missing facts are not interpreted as safe defaults.

## Immutable safety maxima

A `SafetyMaximaV1` policy is identified by `policyId` and `policyDigest`. It fixes upper bounds for wall time, CPU cores, memory, PIDs, output bytes, file descriptors, and temporary bytes. It also fixes:

- `networkMode: "off"`;
- `capabilities: "none"`;
- `devices: "none"`;
- `hostMounts: "none"`; and
- `credentials: "none"`.

The policy digest covers the maxima. A malformed policy or digest mismatch is `unsafe_sandbox`/`digest_mismatch`, not a request to choose a weaker fallback.

## Calibration is narrower than the maxima

An `OperationalLimitsV1` record is measured calibration, not permission to raise the safety ceiling. It contains a calibration id, measurement time, evidence digest, selected purpose (`fixture` or `benchmark`), each operational limit, and the referenced safety policy id/digest. Validation requires:

1. every operational value is positive and its digest is correct;
2. every value is less than or equal to the corresponding immutable maximum;
3. the calibration id and safety-policy reference agree; and
4. benchmark scoring uses `selectedFor: "benchmark"` limits (`validateScoredLimits`).

A challenge descriptor must carry `limits`, `calibrationId`, and `safetyPolicyDigest`. An uncalibrated or cross-policy record is refused; it is never silently promoted to a benchmark limit. The maxima remain the ceiling even when a calibration measured a smaller value.

## Local preflight

The local execution preflight requires complete runtime probe facts, including rootless status, user namespace, network mode, capabilities, devices, host mounts, credentials, seccomp digest, and (for rootless execution) a pinned image digest.

- `fixture/static` and `static` are validation-only classes. Requesting execution for a static fixture is rejected.
- `verified-local/rootless-podman-network-off` requires calibrated operational limits and a rootless runtime using `keep-id`, network off, no capabilities/devices/host mounts/credentials, and a matching pinned image digest.
- Unknown Podman/runtime facts, a missing image digest, or a mismatch are refusals (`unsafe_sandbox` or `uncalibrated_limits`), never direct host execution.
- `external-untrusted/proxmox-deferred` is a contract class for later work; the current local preflight does not execute it.

Use the non-throwing policy inspection form when building an integration, but treat `{ allowed: false }` as a hard stop. A successful preflight proves policy facts only; it does not prove a solve.
When a preflight request supplies a registered descriptor (and optionally its manifest), validation binds challenge id, source revision/hash, canonical backend digest, oracle id, visible allowlist, safety-policy digest, calibration/limits digest, image digest when pinned, and execution class to that descriptor. Any mismatch is a typed refusal; an unbound legacy request does not manufacture descriptor evidence.

## Clean-room policy

A clean-room policy is challenge-scoped and must include:

- a `challengeId` and root digest;
- distinct relative `visibleArtifacts` and `writableArtifacts` lists;
- `network: "off"`;
- `credentials: "none"`; and
- `preserveProvenance: true`.

Absolute POSIX paths, Windows drive paths (including drive-relative forms), UNC or rooted-backslash paths, empty paths, NUL bytes, and `..` traversal are rejected. Visible and writable sets may not overlap or contain duplicates. The policy validator checks metadata only; it does not inspect the filesystem.

The [clean-room example](../../examples/gjc-ctf/clean-room/policy.json) is intentionally policy-shaped, with an all-zero placeholder root digest. Replace that digest with the digest of the authorized challenge root and record real artifact provenance before use; the fixture is not evidence of a runnable challenge.

An artifact policy separately binds an allowlist to per-artifact digests and a provenance digest. `assertArtifactAllowed` rejects a path not on the allowlist or a digest that differs from the authorized value. A path that merely exists on disk is not automatically visible or trusted.

## Trusted oracle boundary

An oracle result is trusted only after all of these checks pass:

- the oracle registry and registry digest validate;
- every Ed25519 key fingerprint matches its public key and active status;
- the oracle entry is signed by a trusted signer and authorizes the challenge;
- the result validates against the expected run/challenge/nonce/candidate/input identity; and
- the result signature verifies with the registered public key.

There is no inferred success path. A missing, unsigned, unauthorized, stale, or unverifiable oracle result is `oracle_integrity_error`/missing evidence and cannot become a pass by interpretation.

## Safe operational rule

Keep safety maxima, calibration evidence, clean-room provenance, runtime preflight, and oracle evidence in the manifest/lock lineage. Do not hand-edit a descriptor to bypass a refusal, broaden an allowlist, turn on networking, mount credentials, or replace a missing probe with a guessed value.
## Operator security boundary

Challenge content is data, not authority. Do not execute install, setup, download, shell, or package-manager instructions copied from a challenge, archive, README, issue, or untrusted manifest. The `bootstrap` command accepts only its compiled source-bundled allowlist, requires an explicit profile for apply mode, invokes exact argv without a shell, checks installer status, and re-verifies binaries. It never reads package names or commands from challenge content. Do not let challenge-controlled values broaden a visible-artifact allowlist, enable networking, mount credentials, or replace missing runtime facts.
