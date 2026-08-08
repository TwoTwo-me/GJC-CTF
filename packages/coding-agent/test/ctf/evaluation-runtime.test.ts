import { describe, expect, it } from "bun:test";
import { generateKeyPairSync, sign } from "node:crypto";
import { canonicalJson, type Digest, sha256Hex } from "../../src/ctf/contracts/digest";
import {
	type EvaluationPreflightV1,
	type EvaluationSpecV1,
	evaluationPreflightDigest,
	evaluationSpecDigest,
} from "../../src/ctf/contracts/evaluation";
import { oracleRegistryDigest } from "../../src/ctf/contracts/oracle";
import { assertBrowserSessionTarget, createOfflineCheckerAdapter } from "../../src/ctf/runtime/adapters";
import {
	type CandidateCollector,
	deliverSecretLease,
	type EvaluationLineageInput,
	type EvaluationRuntimeAdapter,
	evaluateLocalCandidate,
	type LocalEvaluationRequest,
	type SecretSink,
	type TrustedOracleExecutor,
} from "../../src/ctf/runtime/evaluation";
import { createAnchoredOracleAuthority } from "../../src/ctf/runtime/oracle";

type EvaluationSpecInput = Omit<EvaluationSpecV1, "specDigest">;
type EvaluationPreflightInput = Omit<EvaluationPreflightV1, "preflightDigest">;

const DIGEST = "a".repeat(64) as Digest;
function spec(maxBytes = 1024): EvaluationSpecV1 {
	const unsigned: EvaluationSpecInput = {
		schemaVersion: "ctf-evaluation-spec-1",
		evaluationId: "evaluation-1",
		challengeId: "challenge-1",
		descriptorDigest: DIGEST,
		secretPolicy: "supported",
		candidate: { encoding: "utf8", maxBytes },
		adapters: [
			{
				kind: "offline-checker",
				adapterId: "checker-1",
				roles: ["checker"],
				checkerRef: "checker/verify",
				checkerDigest: DIGEST,
				workingDirectory: "work",
				arguments: [],
			},
		],
	};
	return { ...unsigned, specDigest: evaluationSpecDigest(unsigned) };
}
function preflight(): EvaluationPreflightV1 {
	const sandbox = {
		schemaVersion: "ctf-sandbox-preflight-1" as const,
		executionClass: "fixture/static" as const,
		rootless: true,
		userNamespace: "keep-id" as const,
		networkMode: "off" as const,
		capabilities: "none" as const,
		devices: "none" as const,
		hostMounts: "none" as const,
		credentials: "none" as const,
		seccompDigest: DIGEST,
		passed: true,
		reason: "ok",
	};
	const unsigned: EvaluationPreflightInput = {
		schemaVersion: "ctf-evaluation-preflight-1",
		components: [{ adapterId: "checker-1", preflight: sandbox }],
		passed: true,
	};
	return { ...unsigned, preflightDigest: evaluationPreflightDigest(unsigned) };
}
function adapter(destroy: () => Promise<void>, commitments?: string[]): EvaluationRuntimeAdapter {
	return {
		adapterId: "checker-1",
		roles: ["checker"],
		async start(context) {
			commitments?.push(context.instanceCommitmentDigest);
			expect(context.nonce.startsWith("nonce-")).toBe(true);
			expect(context.secretLease).toBeDefined();
			expect(JSON.stringify(context.secretLease)).toBe("{}");
			return { capability: { kind: "checker", adapterId: "checker-1", available: true }, destroy };
		},
	};
}
function request(runtime: EvaluationRuntimeAdapter, candidate = "flag"): LocalEvaluationRequest {
	const value = spec();
	const checked = preflight();
	const collectCandidate: CandidateCollector = async context => {
		expect(JSON.stringify(context)).not.toContain("secretLease");
		expect(context.capabilities).toEqual([{ kind: "checker", adapterId: "checker-1", available: true }]);
		return { encoding: "utf8", value: candidate };
	};
	return {
		spec: value,
		preflight: checked,
		lineage: {
			schemaVersion: "ctf-evaluation-lineage-1",
			runId: "run-1",
			challengeId: "challenge-1",
			descriptorDigest: DIGEST,
			specDigest: value.specDigest,
			corpusDigest: DIGEST,
			sourceDigest: DIGEST,
			visiblePolicyDigest: DIGEST,
			toolDigest: DIGEST,
			backendDigest: DIGEST,
			runtimeDigest: DIGEST,
			safetyDigest: DIGEST,
			limitsDigest: DIGEST,
			calibrationDigest: DIGEST,
			preflightDigest: checked.preflightDigest,
			inputDigest: DIGEST,
		} satisfies EvaluationLineageInput,
		adapters: [runtime],
		collectCandidate,
	};
}
describe("local evaluation lifecycle", () => {
	it("is candidate-only, keeps leases opaque, and destroys sessions", async () => {
		let destroyed = 0;
		const result = await evaluateLocalCandidate(
			request(
				adapter(async () => {
					destroyed++;
				}),
			),
		);
		expect(result.kind).toBe("candidate");
		expect(destroyed).toBe(1);
	});
	it("does not return a candidate when session destruction fails", async () => {
		let destroyed = 0;
		const result = await evaluateLocalCandidate(
			request(
				adapter(async () => {
					destroyed++;
					throw new Error("secret flag /tmp/evaluation");
				}),
			),
		);
		expect(result).toMatchObject({ kind: "unavailable", sanitizedReason: "evaluation cleanup failed" });
		expect(destroyed).toBe(1);
		expect(JSON.stringify(result)).not.toContain("secret flag");
		expect(JSON.stringify(result)).not.toContain("/tmp/evaluation");
	});
	it("fails closed when cancellation arrives during cleanup", async () => {
		const controller = new AbortController();
		let destroyed = 0;
		const result = await evaluateLocalCandidate({
			...request(
				adapter(async () => {
					destroyed++;
					controller.abort();
				}),
			),
			signal: controller.signal,
		});
		expect(result).toMatchObject({ kind: "unavailable", sanitizedReason: "evaluation cancelled" });
		expect(destroyed).toBe(1);
	});
	it("creates distinct commitments for independent runs", async () => {
		const commitments: string[] = [];
		await evaluateLocalCandidate(request(adapter(async () => {}, commitments)));
		await evaluateLocalCandidate(request(adapter(async () => {}, commitments)));
		expect(commitments[0]).not.toBe(commitments[1]);
	});
	it("tears down on solver failure and cancellation", async () => {
		let destroyed = 0;
		const failed = {
			...request(
				adapter(async () => {
					destroyed++;
				}),
			),
			collectCandidate: async () => {
				throw new Error("sensitive-marker-collector");
			},
		};
		const failedResult = await evaluateLocalCandidate(failed);
		expect(failedResult).toMatchObject({ kind: "unavailable", sanitizedReason: "candidate collection failed" });
		expect(JSON.stringify(failedResult)).not.toContain("sensitive-marker");
		const controller = new AbortController();
		const cancelled = {
			...request(
				adapter(async () => {
					destroyed++;
				}),
			),
			collectCandidate: async () => {
				controller.abort();
				return { encoding: "utf8" as const, value: "flag" };
			},
			signal: controller.signal,
		};
		const cancellationResult = await evaluateLocalCandidate(cancelled);
		expect(cancellationResult).toMatchObject({ kind: "unavailable", sanitizedReason: "evaluation cancelled" });
		expect(destroyed).toBe(2);
	});
	it("rejects encoding and size violations", async () => {
		expect(
			(
				await evaluateLocalCandidate(
					request(
						adapter(async () => {}),
						"x".repeat(1025),
					),
				)
			).kind,
		).toBe("unavailable");
		const bad = {
			...request(adapter(async () => {})),
			collectCandidate: async () => ({ encoding: "base64" as const, value: "Zm9v" }),
		};
		expect((await evaluateLocalCandidate(bad)).kind).toBe("unavailable");
	});
	it("revokes directly delivered sinks during normal teardown", async () => {
		let revoked = 0;
		const sink: SecretSink = {
			role: "checker",
			async writeOnce() {},
			async revoke() {
				revoked++;
			},
		};
		const runtime: EvaluationRuntimeAdapter = {
			adapterId: "checker-1",
			roles: ["checker"],
			async start(context) {
				if (context.secretLease === undefined) throw new Error("missing lease");
				await deliverSecretLease(context.secretLease, "checker", sink);
				return {
					capability: { kind: "checker", adapterId: "checker-1", available: true },
					async destroy() {},
				};
			},
		};
		expect((await evaluateLocalCandidate(request(runtime))).kind).toBe("candidate");
		expect(revoked).toBe(1);
	});
	it("revokes a partially delivered sink and redacts its failure", async () => {
		let revoked = 0;
		const sink: SecretSink = {
			role: "checker",
			async writeOnce() {
				throw new Error("sensitive-marker-candidate");
			},
			async revoke() {
				revoked++;
				throw new Error("sensitive-marker-revocation");
			},
		};
		const runtime: EvaluationRuntimeAdapter = {
			adapterId: "checker-1",
			roles: ["checker"],
			async start(context) {
				if (context.secretLease === undefined) throw new Error("missing lease");
				await deliverSecretLease(context.secretLease, "checker", sink);
				throw new Error("unreachable");
			},
		};
		const result = await evaluateLocalCandidate(request(runtime));
		expect(result).toMatchObject({ kind: "unavailable", sanitizedReason: "evaluation cleanup failed" });
		expect(revoked).toBeGreaterThanOrEqual(1);
		expect(JSON.stringify(result)).not.toContain("sensitive-marker");
	});
	it("delivers exactly once, zeroes the temporary copy, and revokes the sink", async () => {
		let observed: Uint8Array | undefined;
		let revoked = 0;
		const sink: SecretSink = {
			role: "checker",
			async writeOnce(bytes) {
				observed = bytes;
			},
			async revoke() {
				revoked++;
			},
		};
		const adapterSpec = spec().adapters[0];
		if (adapterSpec?.kind !== "offline-checker") throw new Error("fixture must provide an offline checker");
		const runtime = createOfflineCheckerAdapter(adapterSpec, {
			async createSecretSink() {
				return sink;
			},
			async prepare() {
				return { async destroy() {} };
			},
		});
		expect((await evaluateLocalCandidate(request(runtime))).kind).toBe("candidate");
		expect([...(observed ?? [])]).toEqual(Array(32).fill(0));
		expect(revoked).toBe(1);
	});
	it("reports failed startup cleanup without exposing sink data", async () => {
		let revoked = 0;
		const adapterSpec = spec().adapters[0];
		if (adapterSpec?.kind !== "offline-checker") throw new Error("fixture must provide an offline checker");
		const runtime = createOfflineCheckerAdapter(adapterSpec, {
			async createSecretSink() {
				return {
					role: "checker",
					async writeOnce() {},
					async revoke() {
						revoked++;
						throw new Error("secret flag /tmp/sink");
					},
				};
			},
			async prepare() {
				throw new Error("driver startup failed");
			},
		});
		const result = await evaluateLocalCandidate(request(runtime));
		expect(result.kind).toBe("unavailable");
		if (result.kind !== "unavailable") throw new Error("expected unavailable result");
		expect(result.sanitizedReason).toBe("evaluation cleanup failed");
		expect(revoked).toBe(1);
		expect(JSON.stringify(result)).not.toContain("secret flag");
		expect(JSON.stringify(result)).not.toContain("/tmp/sink");
	});
	it("rejects wrong-role and replay lease delivery", async () => {
		let wrongRole = false;
		let replay = false;
		const sink: SecretSink = { role: "checker", async writeOnce() {}, async revoke() {} };
		const runtime: EvaluationRuntimeAdapter = {
			adapterId: "checker-1",
			roles: ["checker"],
			async start(context) {
				if (context.secretLease === undefined) throw new Error("missing lease");
				try {
					await deliverSecretLease(context.secretLease, "service", sink);
				} catch {
					wrongRole = true;
				}
				await deliverSecretLease(context.secretLease, "checker", sink);
				try {
					await deliverSecretLease(context.secretLease, "checker", sink);
				} catch {
					replay = true;
				}
				return {
					capability: { kind: "checker", adapterId: "checker-1", available: true },
					async destroy() {
						await sink.revoke();
					},
				};
			},
		};
		expect((await evaluateLocalCandidate(request(runtime))).kind).toBe("candidate");
		expect(wrongRole).toBe(true);
		expect(replay).toBe(true);
	});
	it("creates durable unscored evidence only from fresh externally anchored V2 receipts", async () => {
		const registryPrincipal = generateKeyPairSync("ed25519");
		const resultPrincipal = generateKeyPairSync("ed25519");
		const key = (keyId: string, publicKey: typeof registryPrincipal.publicKey) => {
			const publicKeyText = publicKey.export({ format: "der", type: "spki" }).toString("base64");
			return {
				keyId,
				algorithm: "ed25519" as const,
				publicKey: publicKeyText,
				fingerprint: sha256Hex(publicKeyText),
				active: true,
			};
		};
		const registryKey = key("registry-signer", registryPrincipal.publicKey);
		const resultKey = key("result-signer", resultPrincipal.publicKey);
		const unsignedEntry = {
			schemaVersion: "ctf-oracle-entry-1" as const,
			oracleId: "oracle-v2",
			protocolVersion: "v2",
			executableRef: "oracle/v2",
			imageDigest: DIGEST,
			artifactDigest: DIGEST,
			allowedChallengeIds: ["challenge-1"],
			publicKeyId: resultKey.keyId,
			signerKeyId: registryKey.keyId,
			outputSchemaVersion: "ctf-oracle-result-2",
		};
		const entry = {
			...unsignedEntry,
			signature: sign(null, Buffer.from(canonicalJson(unsignedEntry)), registryPrincipal.privateKey).toString(
				"base64",
			),
		};
		const registry = {
			schemaVersion: "ctf-oracle-registry-1" as const,
			entries: [entry],
			registryDigest: oracleRegistryDigest({ schemaVersion: "ctf-oracle-registry-1", entries: [entry] }),
		};
		const authority = createAnchoredOracleAuthority(
			{
				registrySignerFingerprint: registryKey.fingerprint,
				resultSignerFingerprint: resultKey.fingerprint,
			},
			registry.registryDigest,
		);
		const identities: Array<Record<string, unknown>> = [];
		const executor: TrustedOracleExecutor = {
			async execute({ identity, candidate }) {
				identities.push({ ...identity });
				expect(new TextDecoder().decode(candidate)).toBe("synthetic-candidate");
				const unsigned = {
					schemaVersion: "ctf-oracle-result-2" as const,
					oracleId: entry.oracleId,
					identity,
					verdict: "pass" as const,
					verifierVersion: "v2",
					outputDigest: DIGEST,
					sanitizedSummary: "pass" as const,
				};
				return {
					registry: { registry, keys: [registryKey, resultKey] },
					result: {
						...unsigned,
						signature: sign(null, Buffer.from(canonicalJson(unsigned)), resultPrincipal.privateKey).toString(
							"base64",
						),
					},
				};
			},
		};
		const evidenceRequest = (evaluationId = "evaluation-1") => {
			const base = request(
				adapter(async () => {}),
				"synthetic-candidate",
			);
			const evaluationSpec = { ...base.spec, evaluationId };
			const specDigest = evaluationSpecDigest(evaluationSpec);
			return {
				...base,
				spec: { ...evaluationSpec, specDigest },
				lineage: { ...base.lineage, specDigest },
				receiptAuthority: { competitionId: "competition-1", fencingToken: 7 },
				oracleAuthority: authority,
				trustedOracleExecutor: executor,
			};
		};
		const passed = await evaluateLocalCandidate(evidenceRequest());
		expect(passed.schemaVersion).toBe("ctf-verified-evaluation-evidence-1");
		expect(passed).toMatchObject({
			evaluationId: "evaluation-1",
			competitionId: "competition-1",
			runId: "run-1",
			challengeId: "challenge-1",
			fencingToken: 7,
			oracleResult: { verdict: "pass", identity: identities[0] },
		});
		expect(JSON.stringify(passed)).not.toContain("synthetic-candidate");
		expect(identities).toHaveLength(1);
		const failedExecutor: TrustedOracleExecutor = {
			async execute({ identity }) {
				const unsigned = {
					schemaVersion: "ctf-oracle-result-2" as const,
					oracleId: entry.oracleId,
					identity,
					verdict: "fail" as const,
					verifierVersion: "v2",
					outputDigest: DIGEST,
					sanitizedSummary: "fail" as const,
				};
				return {
					registry: { registry, keys: [registryKey, resultKey] },
					result: {
						...unsigned,
						signature: sign(null, Buffer.from(canonicalJson(unsigned)), resultPrincipal.privateKey).toString(
							"base64",
						),
					},
				};
			},
		};
		const failed = await evaluateLocalCandidate({ ...evidenceRequest(), trustedOracleExecutor: failedExecutor });
		expect(failed).toMatchObject({
			schemaVersion: "ctf-verified-evaluation-evidence-1",
			oracleResult: { verdict: "fail" },
		});
		const otherEvaluation = await evaluateLocalCandidate(evidenceRequest("evaluation-2"));
		expect(otherEvaluation.schemaVersion).toBe("ctf-verified-evaluation-evidence-1");
		expect(identities[0]?.instanceCommitmentDigest).not.toBe(identities[1]?.instanceCommitmentDigest);

		const wrongCommitment: TrustedOracleExecutor = {
			async execute({ identity }) {
				const unsigned = {
					schemaVersion: "ctf-oracle-result-2" as const,
					oracleId: entry.oracleId,
					identity: { ...identity, instanceCommitmentDigest: DIGEST },
					verdict: "pass" as const,
					verifierVersion: "v2",
					outputDigest: DIGEST,
					sanitizedSummary: "pass" as const,
				};
				return {
					registry: { registry, keys: [registryKey, resultKey] },
					result: {
						...unsigned,
						signature: sign(null, Buffer.from(canonicalJson(unsigned)), resultPrincipal.privateKey).toString(
							"base64",
						),
					},
				};
			},
		};
		expect(
			(await evaluateLocalCandidate({ ...evidenceRequest(), trustedOracleExecutor: wrongCommitment })).kind,
		).toBe("unavailable");
		let replay: Parameters<TrustedOracleExecutor["execute"]>[0]["identity"] | undefined;
		const replayExecutor: TrustedOracleExecutor = {
			async execute({ identity }) {
				const replayIdentity = replay ?? identity;
				replay = replayIdentity;
				const unsigned = {
					schemaVersion: "ctf-oracle-result-2" as const,
					oracleId: entry.oracleId,
					identity: replayIdentity,
					verdict: "pass" as const,
					verifierVersion: "v2",
					outputDigest: DIGEST,
					sanitizedSummary: "pass" as const,
				};
				return {
					registry: { registry, keys: [registryKey, resultKey] },
					result: {
						...unsigned,
						signature: sign(null, Buffer.from(canonicalJson(unsigned)), resultPrincipal.privateKey).toString(
							"base64",
						),
					},
				};
			},
		};
		await evaluateLocalCandidate({ ...evidenceRequest(), trustedOracleExecutor: replayExecutor });
		expect(
			(
				await evaluateLocalCandidate({
					...evidenceRequest(),
					lineage: { ...request(adapter(async () => {})).lineage, runId: "run-2" },
					trustedOracleExecutor: replayExecutor,
				})
			).kind,
		).toBe("unavailable");

		const legacy = {
			...request(
				adapter(async () => {}),
				"synthetic-candidate",
			),
			trustedOracle: { registry, keys: [registryKey, resultKey] },
			requestOracle: async () => ({}),
		} as LocalEvaluationRequest;
		expect((await evaluateLocalCandidate(legacy)).kind).toBe("candidate");

		const revocationFailure = await evaluateLocalCandidate({
			...evidenceRequest(),
			adapters: [
				{
					adapterId: "checker-1",
					roles: ["checker"],
					async start(context) {
						if (context.secretLease === undefined) throw new Error("missing lease");
						await deliverSecretLease(context.secretLease, "checker", {
							role: "checker",
							async writeOnce() {},
							async revoke() {
								throw new Error("synthetic revocation failure");
							},
						});
						return {
							capability: { kind: "checker", adapterId: "checker-1", available: true },
							async destroy() {},
						};
					},
				},
			],
		});
		expect(revocationFailure.kind).toBe("unavailable");
		const cleanupFailure = await evaluateLocalCandidate({
			...evidenceRequest(),
			adapters: [
				adapter(async () => {
					throw new Error("synthetic cleanup failure");
				}),
			],
		});
		expect(cleanupFailure.kind).toBe("unavailable");
		const controller = new AbortController();
		const cancelled = await evaluateLocalCandidate({
			...evidenceRequest(),
			collectCandidate: async () => {
				controller.abort();
				return { encoding: "utf8", value: "synthetic-candidate" };
			},
			signal: controller.signal,
		});
		expect(cancelled.kind).toBe("unavailable");
	});
});
describe("browser adapter", () => {
	it("rejects external/file/download/CDP-shaped targets", () => {
		const target = assertBrowserSessionTarget({ origin: "http://127.0.0.1:3000", entryPath: "index.html" });
		expect(target.downloads).toBe(false);
		expect(target.rawCdp).toBe(false);
		expect(() => assertBrowserSessionTarget({ origin: "https://example.test", entryPath: "x" })).toThrow();
		expect(() => assertBrowserSessionTarget({ origin: "file:///tmp/x", entryPath: "x" })).toThrow();
		expect(() => assertBrowserSessionTarget({ origin: "http://localhost:3000", entryPath: "../download" })).toThrow();
	});
});
