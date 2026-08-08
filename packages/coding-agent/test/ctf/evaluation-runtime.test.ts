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
	type TrustedOracleCallback,
} from "../../src/ctf/runtime/evaluation";
import { verifyTrustedOracleResult } from "../../src/ctf/runtime/oracle";

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
	it("preserves signed verdicts and rejects unsigned/mismatched oracle output", async () => {
		const { privateKey, publicKey } = generateKeyPairSync("ed25519");
		const publicKeyText = publicKey.export({ format: "der", type: "spki" }).toString("base64");
		const key = {
			keyId: "key-1",
			algorithm: "ed25519" as const,
			publicKey: publicKeyText,
			fingerprint: sha256Hex(publicKeyText),
			active: true,
		};
		const unsignedEntry = {
			schemaVersion: "ctf-oracle-entry-1" as const,
			oracleId: "oracle-1",
			protocolVersion: "v1",
			executableRef: "oracle/1",
			imageDigest: DIGEST,
			artifactDigest: DIGEST,
			allowedChallengeIds: ["challenge-1"],
			publicKeyId: "key-1",
			signerKeyId: "key-1",
			outputSchemaVersion: "ctf-oracle-result-1",
		};
		const entry = {
			...unsignedEntry,
			signature: sign(null, Buffer.from(canonicalJson(unsignedEntry)), privateKey).toString("base64"),
		};
		const registry = {
			schemaVersion: "ctf-oracle-registry-1" as const,
			entries: [entry],
			registryDigest: oracleRegistryDigest({ schemaVersion: "ctf-oracle-registry-1", entries: [entry] }),
		};
		for (const verdict of ["pass", "fail"] as const) {
			const requestOracle: TrustedOracleCallback = async identity => {
				const unsigned = {
					schemaVersion: "ctf-oracle-result-1" as const,
					oracleId: "oracle-1",
					...identity,
					verdict,
					verifierVersion: "v1",
					outputDigest: DIGEST,
					sanitizedSummary: verdict,
				};
				return {
					...unsigned,
					signature: sign(null, Buffer.from(canonicalJson(unsigned)), privateKey).toString("base64"),
				};
			};
			const base = request(adapter(async () => {}));
			const evaluation = {
				...base,
				trustedOracle: { registry, keys: [key] },
				requestOracle,
			};
			const result = await evaluateLocalCandidate(evaluation);
			expect(result.kind).toBe("verified");
			if (result.kind === "verified") expect(result.verdict).toBe(verdict);
			const adapterSpec = spec().adapters[0];
			if (adapterSpec?.kind !== "offline-checker") throw new Error("fixture must provide an offline checker");
			const teardownRuntime = createOfflineCheckerAdapter(adapterSpec, {
				async createSecretSink() {
					return {
						role: "checker",
						async writeOnce() {},
						async revoke() {
							throw new Error("secret flag /tmp/sink");
						},
					};
				},
				async prepare() {
					return { async destroy() {} };
				},
			});
			const teardownResult = await evaluateLocalCandidate({ ...evaluation, adapters: [teardownRuntime] });
			expect(teardownResult.kind).toBe("unavailable");
			expect(JSON.stringify(teardownResult)).not.toContain("secret flag");
			expect(JSON.stringify(teardownResult)).not.toContain("/tmp/sink");
		}
		const unsigned = {
			...request(adapter(async () => {})),
			trustedOracle: { registry, keys: [key] },
			requestOracle: async () => ({}),
		};
		expect((await evaluateLocalCandidate(unsigned)).kind).toBe("unavailable");
		const mismatchedEntryUnsigned = { ...unsignedEntry, outputSchemaVersion: "ctf-oracle-result-2" };
		const mismatchedEntry = {
			...mismatchedEntryUnsigned,
			signature: sign(null, Buffer.from(canonicalJson(mismatchedEntryUnsigned)), privateKey).toString("base64"),
		};
		const mismatchedRegistry = {
			schemaVersion: "ctf-oracle-registry-1" as const,
			entries: [mismatchedEntry],
			registryDigest: oracleRegistryDigest({
				schemaVersion: "ctf-oracle-registry-1",
				entries: [mismatchedEntry],
			}),
		};
		const identity = {
			runId: "run-1",
			challengeId: "challenge-1",
			nonce: "nonce-1",
			candidateDigest: DIGEST,
			inputDigest: DIGEST,
		};
		const unsignedValidResult = {
			schemaVersion: "ctf-oracle-result-1" as const,
			oracleId: "oracle-1",
			...identity,
			verdict: "pass" as const,
			verifierVersion: "v1",
			outputDigest: DIGEST,
			sanitizedSummary: "pass",
		};
		const validResult = {
			...unsignedValidResult,
			signature: sign(null, Buffer.from(canonicalJson(unsignedValidResult)), privateKey).toString("base64"),
		};
		let rejection: unknown;
		try {
			verifyTrustedOracleResult({ registry: mismatchedRegistry, keys: [key] }, validResult, identity);
		} catch (error) {
			rejection = error;
		}
		expect(rejection).toMatchObject({ code: "oracle_integrity_error" });
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
