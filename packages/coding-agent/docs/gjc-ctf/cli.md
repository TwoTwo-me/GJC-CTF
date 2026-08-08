# `gjc-ctf` CLI

The CLI name is consistently `gjc-ctf`. In a source checkout, invoke the Bun entry point directly:

```sh
bun packages/coding-agent/bin/gjc-ctf.js --help
bun packages/coding-agent/bin/gjc-ctf.js --version
```

`--help`, `-h`, and `help` print help. `--version` and `-v` print `gjc-ctf/<GJC version>`.

## Command surface

The parser recognizes these commands:

| Command | Implemented behavior |
| --- | --- |
| `init [DIR] [--json]` | Creates or verifies a competition workspace. `DIR` defaults to the current directory. |
| `status [CHALLENGE_ID] --json` | Discovers the nearest workspace and prints manifest identity and challenge descriptors. When a challenge id is supplied, the result is scoped to that challenge and rejects unknown ids.
| `dashboard [--port PORT]` | Starts the loopback, read-only dashboard. `PORT` may be `0` for an OS-selected port. |
| `bootstrap [--category CATEGORY...] [--apply] [--json]` | Audits reviewed tool profiles. `--apply` requires an explicit category, invokes one exact package-manager argv, and re-verifies installed binaries. |
| `challenge add ...` | Requires the basic registration flags plus `--descriptor-json PATH` containing validated limits, calibration, safety, backend, and artifact-allowlist metadata; missing or malformed metadata is a usage refusal. Registration still requires a skill-bearing manifest. |
| `solve CHALLENGE_ID... [--concurrency N] [--budget-ms N] [--backend ID]` | Schedules bounded parallel candidate runs when an owning integration supplies a registered backend and authority. The stock CLI supplies neither and records unavailable evidence instead of a solved claim. |
| `stats inspect --input PATH [--json]` | Validates and renders one explicit active v2 LA CTF diagnostic observation. It is read-only, candidate-free, unscored, and cannot generate, seal, compare, or promote evidence. JSON is the fixed `gjc-ctf-stats-inspection-1` public projection, not the observation document. |
| `resume ...` | **Unavailable.** The command validates its run id and reads its durable owner record, then refuses because durable solver resume is not configured. |

Unknown commands and malformed command forms are usage errors (exit code 2). Workspace errors are printed as `gjc-ctf: ...`; retryable workspace errors use exit code 75, and non-retryable workspace errors use exit code 1. A refusal is not success.

## Inspect version statistics

```sh
gjc-ctf stats inspect --input artifacts/ctf/lactf-version-observation-v2.json
gjc-ctf stats inspect --input artifacts/ctf/lactf-version-observation-v2.json --json
```

The command requires exactly one input path and validates the complete document before writing output. It accepts only `gjc-ctf-version-observation-2` with an active machine-registered digest, valid invalidation lineage, unique version IDs, zero independently verified solves, unavailable comparison, and unscored Tier 2-locked status. Active and revoked digest lists are release-scoped offline authority embedded in this build: they authorize this build's accepted observation lineage, not a network lookup or a general trust registry. `hardStop` is an evidence cutoff for the recorded campaign, not an expiry time for that release authority. Success JSON has exactly `schemaVersion`, `versionsInspected`, `independentlyVerifiedSolveCount`, `status`, `comparisonStatus`, `comparable`, `tier2Authorized`, and `limitationsRecorded`; it excludes evidence references, digests, reasons, and other free-form observation fields. Invalid JSON, extra fields, generic self-sealed statistics, revoked observations, digest mismatches, or malformed stats grammar return exit code 2 with a constant sanitized message and no raw input.

## Initialize twice

A new path is created recursively; an existing path must be an empty directory unless it already contains a valid `gjc-ctf.manifest.json` and state tree. `init` writes:

- `gjc-ctf.manifest.json` at the competition root; and
- `.gjc-ctf/competition/event-head.json` for the canonical head.

Registration transaction, event, checkpoint, and journal files are created lazily beneath `.gjc-ctf/competition/` when the first challenge is registered.

```sh
bun packages/coding-agent/bin/gjc-ctf.js init ./competition --json
bun packages/coding-agent/bin/gjc-ctf.js init ./competition --json
```

The first response has `created: true` and `noOp: false`. The second verifies the manifest and state and returns `created: false` and `noOp: true`. It does not rotate the competition ID or rewrite a valid manifest. A non-empty directory without the marker is refused (`unmarked_directory`). A malformed or inconsistent existing marker is refused; `init` is not a repair command.

The CLI initializer currently has no option for the effective CTF skill identity. The TypeScript initializer accepts a skill reference, but that API is not a shell command. A manifest created by plain CLI `init` therefore cannot satisfy registration's required skill field until an owning orchestrator installs that identity. The skill loader's canonical optional workspace override is exactly `<competition-root>/.gjc-ctf/skills/overrides/ctf/SKILL.md` (or a validated JSON skill artifact at that path); when it is absent, the loader may check the rooted legacy path `<competition-root>/skills/ctf/SKILL.md`. It never reads from a global skills directory.

## Nearest discovery

Commands that need a workspace call nearest-ancestor discovery. Starting at the current directory (or its containing directory if the start path is a file), discovery checks each parent for `gjc-ctf.manifest.json` and stops at the filesystem root. It validates the manifest and state directory before returning. There is no `--root` or `--competition` override on `status` or `challenge add`.

```sh
mkdir -p ./competition/challenges/example
(
  cd ./competition/challenges/example
  bun ../../../packages/coding-agent/bin/gjc-ctf.js status --json
)
```

The relative path in this example assumes the command is run from the repository root. If no marker is found, the command returns `manifest_missing`; if the marker is stale or the state root is absent, it returns a typed integrity/revision error instead of selecting another ancestor.

## Challenge registration metadata

The command syntax printed by help is:
```text
gjc-ctf challenge add --id ID --category CATEGORY --path PATH --trust-level LEVEL --execution-class CLASS --source-revision REV --source-sha SHA --oracle-id ID --descriptor-json PATH
```

The implementation passes these values through a validated `ChallengeDescriptor`. The descriptor contract requires all of the following fields (digests are 64 lowercase hexadecimal characters):

| Field | Meaning and constraints |
| --- | --- |
| `id` | Stable challenge identity and registration idempotency key. |
| `category` | Non-empty category label. |
| `sourcePath` | Relative path below the competition root; POSIX absolute, Windows drive/UNC/rooted-backslash paths, and `..` segments are rejected. |
| `sourceRevision` | Non-empty source revision. |
| `sourceSha256` | Digest of the exact challenge source. |
| `trustLevel` | `fixture`, `verified-local`, or `external-untrusted`. |
| `executionClass` | `static`, `rootless-podman-network-off`, or `proxmox-deferred`. |
| `visibleArtifactAllowlist` | Explicit relative paths visible to the solver. |
| `backend` | Non-empty backend kind/version and tool-version map; a rootless backend also needs a pinned image digest. |
| `networkMode` | Always `off`; another value is invalid. |
| `limits` | Calibrated operational limits, including calibration id, evidence digest, selected purpose, and a safety-policy reference. |
| `safetyPolicyDigest` | Digest of immutable safety maxima. |
| `calibrationId` | Must equal `limits.calibrationId`. |
| `oracleId` | Registered trusted-oracle identity. |
| `registeredAt` | Timestamp added by the TypeScript descriptor helper. |
| `descriptorDigest` | Digest over the descriptor, excluding this digest field. |
At registration and workspace preflight, source and visible artifact paths are realpath-checked beneath the competition root. Missing leaves are allowed, but symlink escapes (including dangling links) are refused.

The CLI now accepts strict metadata through `--descriptor-json PATH`. That JSON must contain `limits`, `safetyPolicyDigest`, `calibrationId`, `backend`, and `visibleArtifactAllowlist`; the limits calibration and safety digests must agree, and optional `oracleId` must match the required `--oracle-id` flag. No backend, oracle, solver, skill, limits, calibration, safety, or allowlist defaults are invented. Plain CLI initialization still leaves out `skill`, so registration correctly refuses until an owning integration supplies a skill-bearing manifest. A complete registration requires the effective skill, safety maxima, calibrated limits, trusted oracle, backend, and their digests.

When a complete descriptor is submitted through that API, registration is a digest-checked transaction. Repeating the same challenge id and descriptor is an idempotent no-op; reusing the id with a different descriptor is an `idempotency_conflict`. See [Recovery](recovery.md).

## Dashboard command

```sh
bun packages/coding-agent/bin/gjc-ctf.js dashboard --port 0
```

The command prints a JSON object containing `schemaVersion: "ctf-cli-1"`, a `url` such as `http://127.0.0.1:<port>`, the selected `port`, and `readOnly: true`. It binds IPv4 `127.0.0.1` explicitly. The listener cannot be configured to a wildcard or external host.

The HTTP policy requires `http:`, a loopback hostname (`127.0.0.1` or `localhost`), the listener's exact port, a matching `Host`, and (when present) an `Origin` with the same loopback origin. Only `GET` is accepted; other methods receive 405 with `Allow: GET`. Rejections are enveloped JSON errors and do not expose a mutation route.

Read routes are under `/api/ctf/v1/` (competition, challenge status/graph, run, run events, run metrics, and health). Unknown routes are rejected. The CLI-created reader verifies the canonical event log and graph projection; absent or invalid state remains an explicit unavailable/integrity response and never invents competition data.
## Bootstrap and operator workflow

Dry-run is the default and does not install anything:

```sh
bun packages/coding-agent/bin/gjc-ctf.js bootstrap --category essential --category reverse --json
```

Apply mode is explicit:

```sh
bun packages/coding-agent/bin/gjc-ctf.js bootstrap --category pwn --category runtime --apply --json
```

Profiles are `essential`, `crypto`, `forensics`, `network`, `pwn`, `reverse`, `runtime`, and `web`; the reviewed reverse profile includes `objdump` and Z3. The implementation detects `apt`, `dnf`, `pacman`, `brew`, or `winget` only in fixed operator-trusted absolute roots. Every probe, package-manager invocation, and optional `sudo -n` elevation binds the executable's canonical real path and SHA-256 digest, revalidates that identity immediately before execution, uses an absolute argv with an empty child `PATH`, and runs from a non-challenge working directory. Empty, relative, current, competition, and challenge-controlled executable roots are rejected. It batches only reviewed package names for system package managers; emits one exact `winget install --exact --id ... --disable-interactivity` command per reviewed Windows package; rejects shell interpolation and any manifest differing from the source-bundled allowlist; checks every installer exit code; and re-probes every installed tool. Missing privilege or executable identity fails rather than prompting, searching ambient `PATH`, or falling back. Apply without an explicit category, or a selected tool without install authority, is refused.

Programmatic operators can pass the audited `BootstrapResult` to `closeSolverRouteCapabilities`. A closed `SolverCapabilityClosureV1` binds the reviewed challenge route, derived category plan, builtin bootstrap manifest, platform, ordered tool versions, executable paths and digests, probe argv digests, and reviewed install-command digests. Missing, extra, drifted, or non-absolute evidence returns an open result. This closure is preflight evidence only: it does not schedule a run or confer candidate, oracle, solve, tier, or scoring authority.

Use `init` to create or verify a workspace, then use `status --json` from the competition root or a nested challenge directory. Corpus acquisition is an operator/API prerequisite: use only the pinned source, retain exact file hashes, and never expose archive flags or solve scripts to a solver. The bounded scheduler accepts multiple challenge IDs and a concurrency/budget, but the stock CLI has no default backend, permission authority, or trusted oracle. A non-zero unavailable result is the expected fail-closed behavior. Programmatic operators may compose the production `AgentSession` adapter, local candidate backend, and durable campaign controller described in the operator README; that does not add implicit CLI authority or convert candidates into solves.

The deterministic repeat runner and blinded skill optimizer are programmatic harness surfaces, not shortcuts around benchmark authority. Five-repeat fixture output remains non-scored. Production optimizer promotion requires a digest-sealed round, one signed training selection, and one independently signed redacted holdout gate from the store-owned Ed25519 registry; legacy aggregate reports remain diagnostic compatibility evidence only. Never treat task state, candidate output, archive metadata, process exit, or dashboard data as a flag or benchmark pass.
