---
name: ctf
version: 1.1.0
description: Evidence-first CTF challenge solving with GJC
source: "CTF-owned generated skill; not a canonical GJC workflow default"
---

# CTF Solve

Use this skill only inside a marked CTF competition workspace. The competition manifest, benchmark lock, effective skill identity, model activation, and challenge provenance are authoritative; do not replace them with ad-hoc files or a second team runtime.

## Solve loop

1. Discover and validate the competition workspace and manifest.
2. Confirm the effective skill ID, version, content digest, loader/build digests, and any workspace-override digest match the manifest. Refuse stale or mismatched identities.
3. Activate an authenticated model through the existing GJC profile merge/resolve path. Record the effective selector and whether fallback or escalation occurred; unknown cost stays unknown.
4. Use the existing GJC team CLI/API adapter. Claim work, acknowledge startup, and keep the claim lease alive. Do not report completion without persisted completion evidence and a monitor receipt.
5. Respect challenge provenance, sandbox/network policy, operational limits, oracle evidence, and benchmark locks. Never read or emit credentials, hidden flags, or unrelated challenge data.
6. Submit only a validated solve. Report outcome, evidence digests, model telemetry, and unresolved limitations; a timeout, failed oracle, stale claim, missing evidence, or integrity error is not a solve.
7. Resolve the challenge's reviewed solver route before using a general model session. Run only the route's allowlisted analyzers over digest-bound visible files; an analyzer refusal is retained evidence, not permission to inspect excluded files.
8. Treat analyzer output as candidate material only. Preserve failed, refused, cancelled, timeout, and unknown outcomes, and use them to refine reviewed analyzers or skill candidates without changing the corpus, oracle, or holdout authority.
9. Expand to a harder tier only from a signed report that independently verifies every eligible active-tier challenge. Local ephemeral signatures, archive flags, official solutions, and candidate-only observations never authorize promotion.

Fail closed on missing manifests, absent effective model activation, stale claims, invalid provenance, digest/identity mismatches, and incomplete monitor evidence. The CTF skill is replaceable and competition-owned; it is intentionally not installed or registered as a canonical GJC workflow default.
