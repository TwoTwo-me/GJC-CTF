# CTF harness operator guide

GJC includes a local-first CTF evaluation harness for reproducible solver development. It is not a claim that every challenge is solved. Candidate generation, local checker observations, independently verified solves, and scored benchmark results are separate states; missing authority always fails closed.

## Pinned corpus and trust boundary

The bundled LA CTF corpus metadata pins `https://github.com/uclaacm/lactf-archive` at commit `3379d4a7b36680764a34e7dc817cc3c94c244764` and identifies six challenges:

| Tier | Challenge ID | Category | Local route |
|---|---|---|---|
| 1 | `lactf-2026-misc-endians` | misc | offline checker |
| 1 | `lactf-2026-rev-ooo` | reverse | offline checker |
| 1 | `lactf-2026-rev-flag-finder` | reverse | offline checker |
| 2 | `lactf-2026-crypto-not-so-lazy-trigrams` | crypto | offline checker |
| 2 | `lactf-2026-pwn-tic-tac-no` | pwn | confined process service |
| 2 | `lactf-2026-web-single-trust` | web | browser session, disabled until a reviewed fixture driver supplies opaque run authority |

Tier 2 is not promoted merely because a candidate exists or a local checker accepts it. Promotion requires independently signed, verified evidence for every eligible active-tier challenge under the same pinned manifest, corpus, calibration, runtime, and oracle authority.

Never use archive flags, official solutions, hidden files, challenge metadata secrets, or candidate plaintext as benchmark evidence. Do not contact competition endpoints without explicit authorization. The current archive metadata has no permission record, trusted independent oracle registry, benchmark calibration, or signed runtime authority, so scored results remain unavailable.

## Command-line workflow

Run from the repository root:

```sh
# Inspect tool availability. This does not install anything.
bun packages/coding-agent/bin/gjc-ctf.js bootstrap \
  --category essential --category reverse --json

# Explicitly install only reviewed profiles, then verify their versions.
bun packages/coding-agent/bin/gjc-ctf.js bootstrap \
  --category essential --category reverse --apply --json

# Create an isolated workspace and inspect its fail-closed state.
bun packages/coding-agent/bin/gjc-ctf.js init ./competition --json
bun packages/coding-agent/bin/gjc-ctf.js status --json

# Serve the local evidence dashboard. Port 0 selects an available loopback port.
bun packages/coding-agent/bin/gjc-ctf.js dashboard --port 0
```

After a release build:

```sh
bun --cwd=packages/coding-agent run build
packages/coding-agent/dist/gjc-ctf --help
packages/coding-agent/dist/gjc-ctf bootstrap --category essential --category reverse --json
```

Bootstrap uses a source-bundled allowlist with exact executable roots, probe argv, minimum versions, and reviewed install argv. It never installs an arbitrary model-requested package. Missing or mismatched tools remain unavailable.

## Solver pipeline

The programmatic path is intentionally explicit:

1. Validate the pinned manifest, corpus source, materialization provenance, visible-file allowlist, and per-file SHA-256 mapping.
2. Select exactly one reviewed solver route and its immutable attempt limits.
3. Close the tool capability set against the reviewed bootstrap manifest.
4. Materialize only allowlisted public files through no-follow, inode-stable reads.
5. Run a bounded analyzer or isolated agent session with network and credentials disabled unless the exact route has a reviewed local adapter.
6. Retain candidate, refusal, exhaustion, timeout, crash, and artifact evidence without retaining candidate plaintext in benchmark records.
7. Submit candidates only to a separately trusted oracle. A local checker observation is diagnostic evidence, not independent benchmark truth.
8. Compute metrics and tier state only from signed evidence bound to the same manifest, lock, calibration, implementation identity, and runtime lineage.

`createProductionGjcLocalSolverSessionFactory`, `createLocalCtfSolverBackend`, and `runCtfCampaign` are the main composition surfaces. Interactive providers are opt-in and route-bound; none is implicitly trusted by the stock CLI.

Every reviewed route pins the exact model identity `openai-codex/gpt-5.6-sol`. An unavailable model or missing provider credential blocks the attempt; the harness never substitutes another provider under the same route digest. Changing this identity creates new route-registry and version evidence rather than rewriting historical statistics.

### Pwn diagnostics

The Tic-Tac-No route exposes canonical base64 process I/O and a bounded in-memory ELF64/x86-64 inspector. ELF inspection reports headers, mitigations, and a capped set of printable strings; brace-shaped candidate material and flag-like file references are redacted before the model sees them. It does not execute the binary, recover a flag, verify a candidate, or count as a solve.

The rootless Podman provider is an opt-in composition surface. It requires the exact pinned image to exist locally and uses `--pull=never`; absence fails closed rather than pulling or falling back to host execution. The provider must remain rootless, local-only, network-disabled, digest-bound, resource-bounded, and container-identity-aware.

Install the reviewed image explicitly before enabling the provider; this is an operator action, not a solver fallback:

```sh
podman --remote=false pull \
  docker.io/library/debian@sha256:b5ace515e78743215a1b101a6f17e59ed74b17132139ca3af3c37e605205e973
podman --remote=false image exists \
  docker.io/library/debian@sha256:b5ace515e78743215a1b101a6f17e59ed74b17132139ca3af3c37e605205e973
```

The provider still launches with `--pull=never`. It validates a canonical non-root home before consulting the rootless local image store and gives fixed control operations a two-second bound; it never searches another store or falls back to host execution.

### Web diagnostics

The web route remains disabled unless a trusted driver supplies a one-shot opaque authority bound to the exact run and canonical `http://127.0.0.1:<port>` origin. `localhost`, alternate IP forms, credentials, external networking, downloads, raw CDP, service workers, and filesystem disclosure are not accepted substitutes.

## Evidence and version statistics

Repository evidence lives under `artifacts/ctf/`:

- `ctf-harness-v3-evidence.json`: source, focused verification, build hashes, compiled smoke, security exclusions, and current authority status.
- `lactf-version-observation-v2.json`: immutable per-version diagnostic comparison.
- `lactf-expanded-v2-invalidation.json`: revocation record for an earlier campaign whose crypto allowlist exposed an unnecessary plaintext source.
- `lactf-tier1-local-evidence-v1.json`: non-scored local-checker observations with candidate digests only.
- `pwn-provider-live-smoke-v1.json`: candidate-free live proof that the pinned visible Tic-Tac-No ELF opened through the exact rootless, network-off, pull-never provider and emitted bounded output.
- `fresh-endians-model-v3.json`: a fresh-secret, candidate-plaintext-free Endians fixture solved by the exact reviewed model and verified by the independent synthetic oracle; it proves the model route, not a corpus solve.
- `pinned-ooo-model-v3.json`: candidate-plaintext-free proof that the exact reviewed model produced a candidate accepted by the reviewed local OOO checker; independent oracle authority is still absent, so it is not a scored or tier-promoting solve.
- `ctf-dashboard-v3.png`: captured dashboard evidence.

Version statistics distinguish known values from unavailable values. Solve rate, pass@k, latency, runtime, tokens, tool calls, cost, confidence, and holdout statistics are unavailable until two versions share complete independent authority over the same denominator. Do not convert diagnostic counts into scored metrics.

## Verification

Use focused checks first:

```sh
bun test packages/coding-agent/test/ctf benchmarks/gjc-ctf \
  packages/coding-agent/test/release-build-args.test.ts
bun --cwd=packages/coding-agent run check:types
bun --cwd=packages/coding-agent run build
```

A repository-wide or package typecheck can fail because of unrelated work. Record the exact diagnostics; never suppress them or claim the check passed. A final evidence receipt must name the command, pass/fail status, test and assertion counts, build artifact sizes and SHA-256 digests, and compiled smoke results.

## Troubleshooting

- `status: unavailable` is a safety result, not a synthetic failure or solve. Inspect the sanitized reason and the missing authority list.
- `projection_revision_unavailable` or a dashboard integrity error means canonical events and the derived projection are not bound to the same verified revision. Rebuild the projection from canonical evidence; do not patch dashboard JSON by hand.
- A missing reviewed tool profile requires an explicit bootstrap category. Arbitrary installation commands are rejected.
- A missing pinned container image keeps the process route unavailable. Do not change the digest, enable pulls, or execute the challenge directly on the host.
- An analyzer candidate or local checker pass never unlocks a tier. Only independently signed verified evidence does.
