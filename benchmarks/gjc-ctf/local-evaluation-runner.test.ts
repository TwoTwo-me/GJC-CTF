import { describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { canonicalDigest, sha256Hex } from "../../packages/coding-agent/src/ctf/contracts/digest";
import { evaluationPreflightDigest, evaluationSpecDigest } from "../../packages/coding-agent/src/ctf/contracts/evaluation";
import { challengeDescriptorDigest } from "../../packages/coding-agent/src/ctf/contracts/manifest";
import { LACTF_2026_CORPUS_SOURCE, corpusContentDigest } from "../../packages/coding-agent/src/ctf/corpus";
import type {
	TrustedOracleExecutor,
} from "../../packages/coding-agent/src/ctf/runtime/evaluation";
import type { AnchoredOracleAuthority } from "../../packages/coding-agent/src/ctf/runtime/oracle";
import { runLocalEvaluation, type LocalEvaluationRunnerRequest } from "./local-evaluation-runner";


const digest = (value: string) => sha256Hex(value);

async function fixture(): Promise<{ request: LocalEvaluationRunnerRequest; root: string }> {
	const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-local-evaluation-"));
	const challengeRoot = path.join(root, "checkout", "2026/misc/endians");
	await fs.mkdir(path.join(challengeRoot, ".checker"), { recursive: true });
	const publicBytes = "approved public challenge";
	await fs.writeFile(path.join(challengeRoot, "chall.txt"), publicBytes);
	await fs.writeFile(path.join(challengeRoot, "flag.txt"), "canary-private-data");
	await fs.writeFile(path.join(challengeRoot, "solve.py"), "private solve script");
	await fs.writeFile(path.join(challengeRoot, "challenge.yml"), "private challenge metadata");
	await fs.writeFile(path.join(challengeRoot, ".checker", "secret"), "private checker material");
	const source = LACTF_2026_CORPUS_SOURCE;
	const corpus = {
		source,
		provenance: {
			repositoryUrl: source.repositoryUrl,
			sourceCommit: source.sourceCommit,
			challengePath: source.challengePath,
			files: [{ relativePath: "chall.txt", sha256: digest(publicBytes) }],
		},
		permissionEvidence: { reference: "approved-local-fixture", grantedBy: "test", grantedAt: "2026-01-01T00:00:00Z" },
	} as const;
	const corpusDigest = corpusContentDigest(corpus.provenance);
	const descriptorUnsigned = {
		id: source.challengeId,
		category: "misc",
		sourcePath: source.challengePath,
		sourceRevision: source.sourceCommit,
		sourceSha256: corpusDigest,
		trustLevel: "verified-local" as const,
		executionClass: "rootless-podman-network-off" as const,
		visibleArtifactAllowlist: ["chall.txt"],
		backend: { kind: "test", version: "1", imageDigest: digest("image"), toolVersions: {} },
		networkMode: "off" as const,
		limits: { calibrationId: "calibration", limitsDigest: digest("limits"), wallMs: 1, cpuCores: 1, memoryBytes: 1, pids: 1, outputBytes: 1, fileDescriptors: 1, tmpBytes: 1, safetyPolicyDigest: digest("safety") },
		safetyPolicyDigest: digest("safety"),
		calibrationId: "calibration",
		oracleId: "oracle",
		backendDigest: digest("backend"),
		registeredAt: "2026-01-01T00:00:00Z",
	};
	const descriptor = { ...descriptorUnsigned, descriptorDigest: challengeDescriptorDigest(descriptorUnsigned) };
	const adapter = { adapterId: "checker", kind: "offline-checker" as const, roles: ["checker"] as ["checker"], checkerRef: "checker", checkerDigest: digest("checker"), workingDirectory: "work", arguments: [] };
	const specUnsigned = { schemaVersion: "ctf-evaluation-spec-1" as const, evaluationId: "evaluation", challengeId: source.challengeId, descriptorDigest: descriptor.descriptorDigest, secretPolicy: "not-feasible" as const, candidate: { encoding: "utf8" as const, maxBytes: 1024 }, adapters: [adapter] };
	const spec = { ...specUnsigned, specDigest: evaluationSpecDigest(specUnsigned) };
	const component = { adapterId: "checker", preflight: { schemaVersion: "ctf-sandbox-preflight-1" as const, executionClass: "verified-local/rootless-podman-network-off" as const, rootless: true, userNamespace: "keep-id" as const, networkMode: "off" as const, capabilities: "none" as const, devices: "none" as const, hostMounts: "none" as const, credentials: "none" as const, seccompDigest: digest("seccomp"), passed: true, reason: "ready" } };
	const preflightUnsigned = { schemaVersion: "ctf-evaluation-preflight-1" as const, components: [component], passed: true };
	const preflight = { ...preflightUnsigned, preflightDigest: evaluationPreflightDigest(preflightUnsigned) };
	const lineage = {
		schemaVersion: "ctf-evaluation-lineage-1" as const,
		runId: "run",
		challengeId: source.challengeId,
		descriptorDigest: descriptor.descriptorDigest,
		specDigest: spec.specDigest,
		corpusDigest,
		sourceDigest: canonicalDigest(source),
		visiblePolicyDigest: canonicalDigest(source.visibleFiles),
		toolDigest: digest("tool"), backendDigest: digest("backend"), runtimeDigest: digest("runtime"), safetyDigest: digest("safety"), limitsDigest: digest("limits"), calibrationDigest: digest("calibration"),
		preflightDigest: preflight.preflightDigest,
		inputDigest: digest("input"),
	};
	return {
		root,
		request: {
			corpus,
			checkoutRoot: path.join(root, "checkout"),
			destinationRoot: path.join(root, "materialized"),
			descriptor,
			spec,
			preflight,
			lineage,
			adapters: [{
				adapterId: "checker",
				roles: ["checker"],
				start() {
					return {
						result: Promise.resolve({ capability: { kind: "checker" as const, adapterId: "checker", available: true as const }, async destroy() {} }),
						async terminate() {},
						quiesced: Promise.resolve(),
					};
				},
			}],
			async createCandidateCollector(materialized) {
				expect(await fs.readdir(materialized.root)).toEqual(["chall.txt"]);
				expect(await fs.readFile(path.join(materialized.root, "chall.txt"), "utf8")).toBe(publicBytes);
				return () => ({
					result: Promise.resolve({ encoding: "utf8" as const, value: "candidate" }),
					async terminate() {},
					quiesced: Promise.resolve(),
				});
			},
		},
	};
}

describe("verified local evaluation runner", () => {
	test("rejects a caller-created directory that is not the exact pinned Git checkout", async () => {
		const { request, root } = await fixture();
		try {
			const result = await runLocalEvaluation(request);
			expect(result.status).toBe("unavailable");
			if (result.status === "unavailable") {
				expect(result.sanitizedReason).not.toContain("canary-private-data");
				expect(result.sanitizedReason).not.toContain("flag.txt");
			}
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test("fails closed for permission, lineage, source, symlink, and destination integrity failures", async () => {
		const { request, root } = await fixture();
		try {
			const missingPermission = await runLocalEvaluation({ ...request, corpus: { ...request.corpus, permissionEvidence: undefined } });
			expect(missingPermission.status).toBe("unavailable");
			const invalidPermission = await runLocalEvaluation({ ...request, corpus: { ...request.corpus, permissionEvidence: { reference: "", grantedBy: "test", grantedAt: "invalid" } } });
			expect(invalidPermission.status).toBe("unavailable");
			const wrongCorpus = await runLocalEvaluation({ ...request, corpus: { ...request.corpus, provenance: { ...request.corpus.provenance, files: [{ relativePath: "chall.txt", sha256: digest("wrong") }] } } });
			expect(wrongCorpus.status).toBe("unavailable");
			const wrongSpec = await runLocalEvaluation({ ...request, spec: { ...(request.spec as Record<string, unknown>), specDigest: digest("wrong") } });
			expect(wrongSpec.status).toBe("unavailable");
			const wrongLineage = await runLocalEvaluation({ ...request, lineage: { ...request.lineage, corpusDigest: digest("wrong") } });
			expect(wrongLineage.status).toBe("unavailable");
			await fs.writeFile(path.join(request.checkoutRoot, "2026/misc/endians/chall.txt"), "changed");
			const changedSource = await runLocalEvaluation({ ...request, destinationRoot: path.join(root, "changed") });
			expect(changedSource.status).toBe("unavailable");
			await fs.rm(path.join(request.checkoutRoot, "2026/misc/endians/chall.txt"));
			await fs.symlink(path.join(request.checkoutRoot, "2026/misc/endians/flag.txt"), path.join(request.checkoutRoot, "2026/misc/endians/chall.txt"));
			const symlink = await runLocalEvaluation({ ...request, destinationRoot: path.join(root, "symlink") });
			expect(symlink.status).toBe("unavailable");
			await fs.rm(path.join(request.checkoutRoot, "2026/misc/endians/chall.txt"));
			await fs.writeFile(path.join(request.checkoutRoot, "2026/misc/endians/chall.txt"), "approved public challenge");
			await fs.mkdir(path.join(root, "collision"));
			const collision = await runLocalEvaluation({ ...request, destinationRoot: path.join(root, "collision") });
			expect(collision.status).toBe("unavailable");
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test("does not invoke the anchored authority or owned executor for an untrusted checkout", async () => {
		const { request, root } = await fixture();
		let executions = 0;
		const executor: TrustedOracleExecutor = {
			execute({ identity }) {
				executions += 1;
				return {
					result: Promise.resolve({ registry: {}, result: { identity } }),
					async terminate() {},
					quiesced: Promise.resolve(),
				};
			},
		};
		const oracleAuthority = {
			verify(_registry: unknown, _result: unknown, identity: Record<string, unknown>) {
				return {
					verified: true as const,
					result: {
						schemaVersion: "ctf-oracle-result-2" as const,
						oracleId: "oracle",
						identity,
						verdict: "pass" as const,
						verifierVersion: "test",
						outputDigest: digest("oracle-output"),
						sanitizedSummary: "pass" as const,
						signature: "test-signature",
					},
					oracleRegistryDigest: digest("registry"),
					registrySignerFingerprint: digest("registry-signer"),
					resultSignerFingerprint: digest("result-signer"),
				};
			},
		} as unknown as AnchoredOracleAuthority;
		try {
			const result = await runLocalEvaluation({
				...request,
				receiptAuthority: { competitionId: "competition", fencingToken: 1 },
				oracleAuthority,
				trustedOracleExecutor: executor,
			});
			expect(result.status).toBe("unavailable");
			expect(executions).toBe(0);
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});
});
