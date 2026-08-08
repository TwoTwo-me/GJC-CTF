import { describe, expect, it } from "bun:test";
import { generateKeyPairSync, sign } from "node:crypto";
import {
	type BenchmarkOracleProofContext,
	benchmarkEligibleDenominator,
	createBenchmarkLock,
	LACTF_2026_CORPUS_SOURCE,
	LACTF_2026_CORPUS_SOURCES,
	preflightBenchmark,
	verifyBenchmarkOracleTransitionProof,
} from "../../../../benchmarks/gjc-ctf/manifest";
import {
	evaluateBenchmarkReport,
	evaluateBenchmarkResult,
	type MetricFixture,
	type MetricRunRecord,
	metricFixtureDigest,
	summarizeMetricRuns,
} from "../../../../benchmarks/gjc-ctf/metrics";
import { runDeterministicFixtureBenchmark } from "../../../../benchmarks/gjc-ctf/repeat-runner";
import {
	type BenchmarkCorpusEntry,
	type BenchmarkManifestV1,
	benchmarkLockDigest,
	benchmarkManifestDigest,
	benchmarkRepeatSeed,
	benchmarkSeedSchedule,
	validateBenchmarkManifest,
} from "../../src/ctf/contracts/benchmark";
import { assertDigest, canonicalDigest, canonicalJson, type Digest, sha256Hex } from "../../src/ctf/contracts/digest";
import { CtfError } from "../../src/ctf/contracts/errors";
import {
	type OracleTransitionProof,
	oracleEvidenceDigest,
	oracleTransitionDigest,
} from "../../src/ctf/contracts/event";
import {
	type MetricsReportV1,
	metricsFingerprint,
	repeatSeed,
	validateMetricsReport,
} from "../../src/ctf/contracts/metrics";
import { oracleEntryDigest, oracleRegistryDigest, oracleResultDigest } from "../../src/ctf/contracts/oracle";
import { operationalLimitsDigest, safetyPolicyDigest } from "../../src/ctf/contracts/sandbox";
import { oracleTransitionSignaturePayload } from "../../src/ctf/graph/ontology";
import { benchmarkCalibrationDigest } from "../../src/ctf/runtime/policy";

const DIGEST = sha256Hex("benchmark-contract");
function requireDigest(value: string, label: string): Digest {
	assertDigest(value, label);
	return value;
}

const SEEDS = benchmarkSeedSchedule("benchmark-1", ["challenge-1"])["challenge-1"];

function expectCtfCode(action: () => unknown, code: CtfError["code"]): void {
	let caught: unknown;
	try {
		action();
	} catch (error) {
		caught = error;
	}
	expect(caught).toBeInstanceOf(CtfError);
	expect((caught as CtfError).code).toBe(code);
}

function makeManifest(
	overrides: Partial<BenchmarkCorpusEntry> = {},
	objective: BenchmarkManifestV1["objective"] = "competition-solve-first",
): BenchmarkManifestV1 {
	const corpusEntry: BenchmarkCorpusEntry = {
		challengeId: "challenge-1",
		category: "category-1",
		sourceRef: "upstream:challenge-1",
		sourceRevision: "revision-1",
		sourceSha256: DIGEST,
		permissionRef: "permission:challenge-1",
		artifactDigests: [DIGEST],
		executionClass: "fixture/static",
		backendDigest: DIGEST,
		solverVisibleAllowlist: ["answer.txt"],
		oracleId: "oracle-1",
		oracleDigest: DIGEST,
		...overrides,
	};
	const seedSchedule = benchmarkSeedSchedule("benchmark-1", [corpusEntry.challengeId]);
	const unsigned = {
		schemaVersion: "ctf-benchmark-1" as const,
		benchmarkId: "benchmark-1",
		createdAt: "2026-01-01T00:00:00.000Z",
		sourceCommit: "commit-1",
		corpus: [corpusEntry],
		holdoutChallengeIds: [],
		eligibilityPolicyVersion: "eligibility-1",
		objective,
		budget: { wallMs: 1_000, inputTokens: 0, outputTokens: 0, toolCalls: 0, costCents: 0 },
		repeatCount: 5 as const,
		seedSchedule,
		seeds: seedSchedule[corpusEntry.challengeId],
		modelPolicyId: "model-policy-1",
		modelConfigDigest: DIGEST,
		skill: {
			effectiveId: "skill-1",
			effectiveVersion: "1.0.0",
			contentDigest: DIGEST,
			loaderDigest: DIGEST,
			buildDigest: DIGEST,
			workspaceOverrideDigest: null,
		},
		backendPolicyDigest: DIGEST,
		oracleRegistryDigest: DIGEST,
		safetyPolicyDigest: DIGEST,
		calibrationId: "calibration-1",
		operationalLimitsDigest: DIGEST,
		reportRoot: "report-root-1",
	};
	return { ...unsigned, manifestDigest: benchmarkManifestDigest(unsigned) };
}

function trustedOracle(challengeId: string) {
	const { privateKey, publicKey } = generateKeyPairSync("ed25519");
	const publicKeyText = publicKey.export({ format: "der", type: "spki" }).toString("base64");
	const key = {
		keyId: "oracle-key-1",
		algorithm: "ed25519" as const,
		publicKey: publicKeyText,
		fingerprint: sha256Hex(publicKeyText),
		active: true,
	};
	const unsignedEntry = {
		schemaVersion: "ctf-oracle-entry-1" as const,
		oracleId: "oracle-1",
		protocolVersion: "oracle-1",
		executableRef: "oracle:v1",
		imageDigest: DIGEST,
		artifactDigest: DIGEST,
		allowedChallengeIds: [challengeId],
		publicKeyId: key.keyId,
		signerKeyId: key.keyId,
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
	return { trustedRegistry: { registry, keys: [key] }, entry, privateKey };
}
function signedBenchmarkProof(
	authority: "preflight" | "oracle",
	context: BenchmarkOracleProofContext,
	trusted: ReturnType<typeof trustedOracle>,
	evidenceRefs: readonly Digest[],
): OracleTransitionProof {
	const resultDigest = evidenceRefs[1] ?? DIGEST;
	const unsigned = {
		schemaVersion: "ctf-oracle-transition-proof-1" as const,
		authority,
		registryDigest: trusted.trustedRegistry.registry.registryDigest,
		oracleEntryDigest: oracleEntryDigest(trusted.entry),
		...(authority === "preflight"
			? { preflightReportDigest: evidenceRefs[0] ?? DIGEST }
			: { oracleResultDigest: resultDigest }),
		transitionDigest: oracleTransitionDigest({
			eventType: context.eventType === "node" ? "node_transition" : "edge_transition",
			before: context.before,
			after: context.after,
		}),
		evidenceDigest: oracleEvidenceDigest(evidenceRefs),
		signerKeyId: trusted.entry.publicKeyId,
		signatureAlgorithm: "ed25519" as const,
		signature: "unsigned",
	};
	const signature = sign(
		null,
		Buffer.from(
			canonicalJson(
				oracleTransitionSignaturePayload({
					eventType: context.eventType === "node" ? "node_transition" : "edge_transition",
					challengeId: context.challengeId,
					proof: unsigned,
				}),
			),
		),
		trusted.privateKey,
	).toString("base64");
	return { ...unsigned, signature };
}

function benchmarkCalibration() {
	const unsigned = {
		schemaVersion: "ctf-benchmark-calibration-1" as const,
		calibrationId: "calibration-1",
		operationalLimitsDigest: DIGEST,
		selectedFor: "benchmark" as const,
		eligibleDenominator: 1,
		thresholds: { passAt1: 1 },
	};
	return { ...unsigned, calibrationDigest: benchmarkCalibrationDigest(unsigned) };
}

function metricRun(overrides: Partial<MetricRunRecord> = {}): MetricRunRecord {
	return {
		runId: "run-1",
		challengeId: "challenge-1",
		repeatIndex: 0,
		seed: `sha256:${"b".repeat(64)}`,
		validatedSolve: false,
		outcome: "fail",
		wallTimeMs: 100,
		firstValidTimeMs: 90,
		manualInterventionCount: 0,
		inputTokens: 0,
		outputTokens: 0,
		cacheTokens: 0,
		toolCalls: 0,
		cost: { status: "known", cents: 1, source: "meter" },
		codeCommit: "commit-1",
		benchmarkLockDigest: DIGEST,
		effectiveSkillDigest: DIGEST,
		modelFingerprint: DIGEST,
		backendFingerprint: DIGEST,
		calibrationDigest: benchmarkCalibration().calibrationDigest,
		category: "category-1",
		...overrides,
	};
}
function metricReport(overrides: Partial<Omit<MetricsReportV1, "fingerprint">> = {}): MetricsReportV1 {
	const calibration = benchmarkCalibration();
	const unsigned = {
		metricsSchemaVersion: "ctf-metrics-1" as const,
		benchmarkId: "benchmark-1",
		benchmarkLockDigest: DIGEST,
		calibrationDigest: calibration.calibrationDigest,
		eligibleChallengeIds: ["challenge-1"],
		createdAt: "2026-01-01T00:00:00.000Z",
		repeatCount: 5 as const,
		seedSchedule: benchmarkSeedSchedule("benchmark-1", ["challenge-1"]),
		seeds: SEEDS,
		runs: [metricRun({ seed: SEEDS[0], calibrationDigest: calibration.calibrationDigest })],
		passAt1: 0,
		passAt3: 0,
		categoryAggregates: [{ category: "category-1", numerator: 0, denominator: 1, excludedCount: 0, unknownCount: 0 }],
		p50WallTimeMs: 100,
		p95WallTimeMs: 100,
		manualInterventionCount: 0,
		unknownCount: 0,
		...overrides,
	};
	return { ...unsigned, fingerprint: metricsFingerprint(unsigned) };
}
type ScoredMetricFixture = Readonly<{
	input: {
		manifest: BenchmarkManifestV1;
		lock: ReturnType<typeof createBenchmarkLock>;
		calibration: ReturnType<typeof benchmarkCalibration>;
		eligibleDenominator: number;
		eligibleChallengeIds: readonly string[];
		effectiveSkill: BenchmarkManifestV1["skill"];
		operationalLimits: Record<string, unknown>;
		safetyMaxima: Record<string, unknown>;
		oracle: Record<string, unknown>;
	};
	run: MetricRunRecord;
	context: BenchmarkOracleProofContext;
	trusted: ReturnType<typeof trustedOracle>;
}>;

function scoredMetricFixture(): ScoredMetricFixture {
	const trusted = trustedOracle("challenge-1");
	const oracleDigest = oracleEntryDigest(trusted.entry);
	const safetyBase = {
		schemaVersion: "ctf-safety-maxima-1" as const,
		policyId: "safety-policy-1",
		wallMsMax: 10_000,
		cpuCoresMax: 2,
		memoryBytesMax: 4_096,
		pidsMax: 16,
		outputBytesMax: 4_096,
		fileDescriptorsMax: 64,
		tmpBytesMax: 4_096,
		networkMode: "off" as const,
		capabilities: "none" as const,
		devices: "none" as const,
		hostMounts: "none" as const,
		credentials: "none" as const,
	};
	const safety = { ...safetyBase, policyDigest: safetyPolicyDigest(safetyBase) };
	const limitsBase = {
		schemaVersion: "ctf-operational-limits-1" as const,
		calibrationId: "calibration-1",
		measuredAt: "2026-01-01T00:00:00.000Z",
		evidenceDigest: DIGEST,
		wallMs: 1_000,
		cpuCores: 1,
		memoryBytes: 1_024,
		pids: 1,
		outputBytes: 1_024,
		fileDescriptors: 16,
		tmpBytes: 1_024,
		safetyPolicyId: safety.policyId,
		safetyPolicyDigest: safety.policyDigest,
		selectedFor: "benchmark" as const,
	};
	const limits = { ...limitsBase, limitsDigest: operationalLimitsDigest(limitsBase) };
	const skill = {
		effectiveId: "skill-1",
		effectiveVersion: "1.0.0",
		contentDigest: DIGEST,
		loaderDigest: DIGEST,
		buildDigest: DIGEST,
		workspaceOverrideDigest: null,
	};
	const calibrationUnsigned = {
		...benchmarkCalibration(),
		operationalLimitsDigest: limits.limitsDigest,
		thresholds: { passAt1: 1, targetPassCount: 1, floorPassCount: 0 },
	};
	const calibration = {
		...calibrationUnsigned,
		calibrationDigest: benchmarkCalibrationDigest(calibrationUnsigned),
	};
	const manifestUnsigned = {
		...makeManifest({
			executionClass: "verified-local/rootless-podman-network-off",
			oracleDigest,
			oracleId: trusted.entry.oracleId,
		}),
		skill,
		safetyPolicyDigest: safety.policyDigest,
		operationalLimitsDigest: limits.limitsDigest,
		oracleRegistryDigest: trusted.trustedRegistry.registry.registryDigest,
		calibrationId: calibration.calibrationId,
	};
	const manifest = {
		...manifestUnsigned,
		manifestDigest: benchmarkManifestDigest(manifestUnsigned),
	};
	const lock = createBenchmarkLock(manifest);
	const context: BenchmarkOracleProofContext = {
		eventType: "node",
		challengeId: "challenge-1",
		before: { state: "planned" },
		after: { state: "verified" },
	};
	const runId = "run-signed";
	const resultUnsigned = {
		schemaVersion: "ctf-oracle-result-1" as const,
		oracleId: trusted.entry.oracleId,
		runId,
		challengeId: "challenge-1",
		nonce: "nonce-1",
		candidateDigest: DIGEST,
		inputDigest: DIGEST,
		verdict: "fail" as const,
		verifierVersion: "oracle-v1",
		outputDigest: DIGEST,
		sanitizedSummary: "failed",
	};
	const result = {
		...resultUnsigned,
		signature: sign(null, Buffer.from(canonicalJson(resultUnsigned)), trusted.privateKey).toString("base64"),
	};
	const runtimeDigest = oracleResultDigest(result);
	const evidenceRefs = [DIGEST, runtimeDigest];
	const key = trusted.trustedRegistry.keys[0];
	if (key === undefined) throw new Error("fixture oracle key missing");
	const run: MetricRunRecord = {
		...metricRun({
			runId,
			seed: repeatSeed(manifest.benchmarkId, "challenge-1", 0),
			benchmarkLockDigest: lock.lockDigest,
			effectiveSkillDigest: canonicalDigest(skill),
			calibrationDigest: calibration.calibrationDigest,
			preflightReportDigest: evidenceRefs[0],
			runtimeEvidenceDigest: evidenceRefs[1],
			evidenceRefs,
			preflightProof: signedBenchmarkProof("preflight", context, trusted, evidenceRefs),
			runtimeProof: signedBenchmarkProof("oracle", context, trusted, evidenceRefs),
			signedOracleProof: {
				verified: true,
				result,
				entry: trusted.entry,
				key,
				registryDigest: trusted.trustedRegistry.registry.registryDigest,
			},
		}),
		oracleProofContext: context,
	};
	return {
		input: {
			manifest,
			lock,
			calibration,
			eligibleDenominator: 1,
			eligibleChallengeIds: ["challenge-1"],
			effectiveSkill: skill,
			operationalLimits: limits,
			safetyMaxima: safety,
			oracle: { trustedRegistry: trusted.trustedRegistry },
		},
		run,
		context,
		trusted,
	};
}

describe("benchmark contracts", () => {
	it("pins the multi-category LA CTF archive sources without making them scoreable", () => {
		const expected = [
			{ challengePath: "2026/misc/endians", challengeId: "lactf-2026-misc-endians" },
			{ challengePath: "2026/rev/ooo", challengeId: "lactf-2026-rev-ooo" },
			{ challengePath: "2026/rev/flag-finder", challengeId: "lactf-2026-rev-flag-finder" },
			{
				challengePath: "2026/crypto/not-so-lazy-trigrams",
				challengeId: "lactf-2026-crypto-not-so-lazy-trigrams",
			},
			{ challengePath: "2026/pwn/tic-tac-no", challengeId: "lactf-2026-pwn-tic-tac-no" },
			{ challengePath: "2026/web/single-trust", challengeId: "lactf-2026-web-single-trust" },
		] as const;
		expect(LACTF_2026_CORPUS_SOURCES).toHaveLength(expected.length);
		expect(
			LACTF_2026_CORPUS_SOURCES.map(({ challengePath, challengeId }) => ({ challengePath, challengeId })),
		).toEqual([...expected]);
		expect(LACTF_2026_CORPUS_SOURCE).toBe(LACTF_2026_CORPUS_SOURCES[0]);
		for (const source of LACTF_2026_CORPUS_SOURCES) {
			expect(source.repositoryUrl).toBe("https://github.com/uclaacm/lactf-archive");
			expect(source.sourceCommit).toBe("3379d4a7b36680764a34e7dc817cc3c94c244764");
			expect(source.scored).toBe(false);
			expect(source.permission).toBe("required");
			expect(source.trustedOracle).toBe("unavailable");
			expect(source.calibration).toBe("unavailable");
			expect(source.runtimeEvidence).toBe("unavailable");
		}
	});

	it("emits a deterministic non-scored five-repeat fixture report", () => {
		const manifest = makeManifest();
		const lock = createBenchmarkLock(manifest);
		const seeds = manifest.seedSchedule?.["challenge-1"];
		if (seeds === undefined) throw new Error("expected seed schedule");
		const fixtureUnsigned: Omit<MetricFixture, "fixtureDigest"> = {
			schemaVersion: "gjc-ctf-metric-fixture-1" as const,
			fixtureId: "fixture-repeat-1",
			benchmarkLockDigest: requireDigest(lock.lockDigest, "fixture benchmark lock digest"),
			runs: seeds.map((_seed, repeatIndex) => ({
				runId: `fixture-run-${repeatIndex}`,
				challengeId: "challenge-1",
				repeatIndex,
				seed: benchmarkRepeatSeed(manifest.benchmarkId, "challenge-1", repeatIndex),
				outcome: repeatIndex === 0 ? ("unknown" as const) : ("fail" as const),
				validatedSolve: false,
				wallTimeMs: 10,
			})),
		};
		const fixture = { ...fixtureUnsigned, fixtureDigest: metricFixtureDigest(fixtureUnsigned) };
		const request = {
			manifest,
			lock,
			calibration: benchmarkCalibration(),
			fixture,
			lineage: {
				backendPolicyDigest: requireDigest(manifest.backendPolicyDigest, "fixture backend policy digest"),
				oracleRegistryDigest: requireDigest(manifest.oracleRegistryDigest, "fixture oracle registry digest"),
				preflightDigest: DIGEST,
				effectiveSkillDigest: canonicalDigest(manifest.skill),
			},
			oracleAdmission: "unavailable" as const,
		};
		const result = runDeterministicFixtureBenchmark(request);

		expect(result.status).toBe("ready");
		if (result.status !== "ready") throw new Error(result.reason);
		expect(result.report).toMatchObject({
			scored: false,
			reason: "local_fixture",
			counts: { pass: 0, fail: 4, unknown: 1 },
		});
		expect(result.report.runs).toHaveLength(5);
		expect(result.report.runs.every(run => run.validatedSolve === false)).toBe(true);

		const forgedUnsigned: Omit<MetricFixture, "fixtureDigest"> = {
			...fixtureUnsigned,
			runs: fixtureUnsigned.runs.map((run, index) =>
				index === 0
					? { ...run, seed: benchmarkRepeatSeed("forged-benchmark", "challenge-1", 0) }
					: run,
			),
		};
		const forged = {
			...forgedUnsigned,
			fixtureDigest: metricFixtureDigest(forgedUnsigned),
		};
		expect(runDeterministicFixtureBenchmark({ ...request, fixture: forged }).status).toBe("unavailable");
	});
	it("rejects recomputed-but-tampered metric report metadata", () => {
		const report = metricReport();
		const { fingerprint: _seedFingerprint, ...seedBase } = report;
		const tamperedSeedUnsigned = {
			...seedBase,
			seeds: [`sha256:${"f".repeat(64)}`, ...(report.seeds ?? []).slice(1)],
		} as Omit<MetricsReportV1, "fingerprint">;
		const tamperedSeed = { ...tamperedSeedUnsigned, fingerprint: metricsFingerprint(tamperedSeedUnsigned) };
		expectCtfCode(() => validateMetricsReport(tamperedSeed), "benchmark_lock_mismatch");

		const { fingerprint: _idsFingerprint, ...idsBase } = report;
		const tamperedIdsUnsigned = { ...idsBase, eligibleChallengeIds: ["challenge-forged"] } as Omit<
			MetricsReportV1,
			"fingerprint"
		>;
		const tamperedIds = { ...tamperedIdsUnsigned, fingerprint: metricsFingerprint(tamperedIdsUnsigned) };
		expectCtfCode(() => validateMetricsReport(tamperedIds), "benchmark_lock_mismatch");

		const tamperedFingerprint = { ...report, fingerprint: "f".repeat(64) };
		expectCtfCode(() => validateMetricsReport(tamperedFingerprint), "digest_mismatch");
		const tamperedDenominatorBase = {
			...seedBase,
			categoryAggregates: [
				{ category: "category-1", numerator: 0, denominator: 2, excludedCount: 0, unknownCount: 0 },
			],
		} as Omit<MetricsReportV1, "fingerprint">;
		const tamperedDenominator = {
			...tamperedDenominatorBase,
			fingerprint: metricsFingerprint(tamperedDenominatorBase),
		};
		expectCtfCode(() => validateMetricsReport(tamperedDenominator), "invalid_manifest");
	});
	it("rejects escaped solver-visible paths and placeholder metadata", () => {
		for (const solverVisibleAllowlist of [
			"../escape",
			"C:\\escape",
			"\\\\server\\share",
			"name\0suffix",
			"nested/../../escape",
		]) {
			expectCtfCode(() => {
				const manifest = makeManifest({ solverVisibleAllowlist: [solverVisibleAllowlist] });
				return validateBenchmarkManifest(manifest);
			}, "benchmark_provenance_missing");
		}
		expectCtfCode(
			() =>
				validateBenchmarkManifest(
					makeManifest({ executionClass: "unsupported" as BenchmarkCorpusEntry["executionClass"] }),
				),
			"benchmark_provenance_missing",
		);
		expectCtfCode(
			() => validateBenchmarkManifest(makeManifest({ permissionRef: "fixture" })),
			"benchmark_provenance_missing",
		);
		expectCtfCode(
			() => validateBenchmarkManifest(makeManifest({ sourceRef: "placeholder:source" })),
			"benchmark_provenance_missing",
		);
	});

	it("rejects a forged eligible oracle even when the lock is rebuilt", () => {
		const authority = trustedOracle("challenge-1");
		const oracleDigest = oracleEntryDigest(authority.entry);
		const manifest = makeManifest({ oracleDigest, oracleId: authority.entry.oracleId }, "benchmark-fixed-budget");
		const boundManifest = { ...manifest, oracleRegistryDigest: authority.trustedRegistry.registry.registryDigest };
		const bound = { ...boundManifest, manifestDigest: benchmarkManifestDigest(boundManifest) };
		const lock = createBenchmarkLock(bound);
		const calibration = benchmarkCalibration();
		const request = {
			manifest: bound,
			lock,
			calibration,
			oracle: { ...authority, oracleId: authority.entry.oracleId, oracleDigest },
			safetyPolicyDigest: DIGEST,
		};
		expectCtfCode(() => preflightBenchmark(request), "benchmark_provenance_missing");

		const forged = {
			...bound,
			corpus: [{ ...bound.corpus[0], oracleId: "oracle-forged" }],
		};
		const forgedManifest = { ...forged, manifestDigest: benchmarkManifestDigest(forged) };
		const forgedLock = createBenchmarkLock(forgedManifest);
		expectCtfCode(
			() => preflightBenchmark({ ...request, manifest: forgedManifest, lock: forgedLock }),
			"benchmark_provenance_missing",
		);
	});
	it("rejects deferred corpus entries from fixed-budget denominator and preflight", () => {
		const authority = trustedOracle("challenge-1");
		const oracleDigest = oracleEntryDigest(authority.entry);
		const base = makeManifest({ oracleDigest, oracleId: authority.entry.oracleId }, "benchmark-fixed-budget");
		const bound = {
			...base,
			oracleRegistryDigest: authority.trustedRegistry.registry.registryDigest,
		};
		const deferredEntry = {
			...bound.corpus[0],
			challengeId: "challenge-2",
			executionClass: "external-untrusted/proxmox-deferred" as const,
		};
		const { seeds: _legacySeeds, ...boundWithoutLegacySeeds } = bound;
		const unsigned = {
			...boundWithoutLegacySeeds,
			corpus: [bound.corpus[0], deferredEntry],
			seedSchedule: benchmarkSeedSchedule("benchmark-1", ["challenge-1", "challenge-2"]),
		};
		const manifest = { ...unsigned, manifestDigest: benchmarkManifestDigest(unsigned) };
		expectCtfCode(() => benchmarkEligibleDenominator(manifest), "benchmark_provenance_missing");
		const lock = createBenchmarkLock(manifest);
		expectCtfCode(
			() =>
				preflightBenchmark({
					manifest,
					lock,
					calibration: benchmarkCalibration(),
					oracle: { ...authority, oracleId: authority.entry.oracleId, oracleDigest },
					safetyPolicyDigest: DIGEST,
				}),
			"benchmark_provenance_missing",
		);
	});

	it("counts first-valid time only for validated oracle passes and rejects invalid input", () => {
		const calibration = benchmarkCalibration();
		const summary = summarizeMetricRuns([metricRun()], { calibration, eligibleDenominator: 1 });
		expect(summary.firstValidTimeMs).toEqual({ status: "unknown", reason: "no valid solve time observed" });
		const invalid = metricRun({ firstValidTimeMs: 0 });
		expectCtfCode(() => summarizeMetricRuns([invalid], { calibration, eligibleDenominator: 1 }), "invalid_manifest");
		const passed = metricRun({ outcome: "pass", validatedSolve: true, firstValidTimeMs: 90 });
		expect(summarizeMetricRuns([passed], { calibration, eligibleDenominator: 1 }).firstValidTimeMs).toEqual({
			status: "known",
			value: 90,
		});
	});
	it("accepts a manifest-bound result/report and rejects caller-lineage tampering", () => {
		const manifest = makeManifest();
		const lock = createBenchmarkLock(manifest);
		const calibration = benchmarkCalibration();
		const runs = SEEDS.map((seed, repeatIndex) =>
			metricRun({
				runId: `run-${repeatIndex}`,
				repeatIndex,
				seed,
				benchmarkLockDigest: lock.lockDigest,
				calibrationDigest: calibration.calibrationDigest,
			}),
		);
		const resultRequest = {
			manifest,
			lock,
			calibration,
			eligibleDenominator: 1,
			eligibleChallengeIds: ["challenge-1"],
			runs,
		};
		expect(evaluateBenchmarkResult(resultRequest).status).toBe("unavailable");
		expect(evaluateBenchmarkResult({ ...resultRequest, eligibleChallengeIds: ["forged"] }).status).toBe(
			"unavailable",
		);
		expect(evaluateBenchmarkResult({ ...resultRequest, objective: "benchmark-fixed-budget" }).status).toBe(
			"unavailable",
		);
		expect(
			evaluateBenchmarkResult({
				...resultRequest,
				runs: [runs[0], ...runs.slice(1).map(run => ({ ...run, category: "forged" }))],
			}).status,
		).toBe("unavailable");
		const unknownSummary = summarizeMetricRuns([{ ...runs[0], outcome: "unknown" }], {
			manifest,
			lock,
			calibration,
			eligibleDenominator: 1,
			eligibleChallengeIds: ["challenge-1"],
		});
		expect(unknownSummary.passAt1).toEqual({ status: "unknown", reason: "no fully observed challenge runs" });
		expect(unknownSummary.unknownRuns).toBe(1);

		const forgedSeeds = [`sha256:${"f".repeat(64)}`, ...SEEDS.slice(1)] as [string, string, string, string, string];
		const forgedLockUnsigned = { ...lock, seeds: forgedSeeds };
		const forgedLock = { ...forgedLockUnsigned, lockDigest: benchmarkLockDigest(forgedLockUnsigned) };
		expect(evaluateBenchmarkResult({ ...resultRequest, lock: forgedLock }).status).toBe("unavailable");

		const { fingerprint: _reportFingerprint, ...reportBase } = metricReport({
			benchmarkLockDigest: lock.lockDigest,
			calibrationDigest: calibration.calibrationDigest,
			eligibleChallengeIds: ["challenge-1"],
			seeds: SEEDS,
			runs,
		});
		const report = { ...reportBase, fingerprint: metricsFingerprint(reportBase) };
		const reportRequest = {
			manifest,
			lock,
			calibration,
			eligibleDenominator: 1,
			eligibleChallengeIds: ["challenge-1"],
			report,
		};
		expect(evaluateBenchmarkReport(reportRequest).status).toBe("unavailable");
		expect(evaluateBenchmarkReport({ ...reportRequest, eligibleChallengeIds: ["forged"] }).status).toBe(
			"unavailable",
		);
		expect(
			evaluateBenchmarkReport({
				...reportRequest,
				report: { ...report, categoryAggregates: [{ ...report.categoryAggregates[0], category: "forged" }] },
			}).status,
		).toBe("unavailable");
	});
	it("rejects forged signatures and alternate trusted-entry digests", () => {
		const trusted = trustedOracle("challenge-1");
		const entryDigest = oracleEntryDigest(trusted.entry);
		const manifest = makeManifest({
			executionClass: "verified-local/rootless-podman-network-off",
			oracleDigest: entryDigest,
		});
		const boundManifest = {
			...manifest,
			oracleRegistryDigest: trusted.trustedRegistry.registry.registryDigest,
		};
		const refs = [DIGEST, sha256Hex("benchmark-contract-evidence")];
		const context: BenchmarkOracleProofContext = {
			eventType: "node",
			challengeId: "challenge-1",
			before: { state: "planned" },
			after: { state: "verified" },
		};
		const preflight = signedBenchmarkProof("preflight", context, trusted, refs);
		const runtime = signedBenchmarkProof("oracle", context, trusted, refs);
		expect(() =>
			verifyBenchmarkOracleTransitionProof(preflight, context, refs, boundManifest, trusted.trustedRegistry),
		).not.toThrow();
		expect(() =>
			verifyBenchmarkOracleTransitionProof(
				{ ...preflight, signature: "forged" },
				context,
				refs,
				boundManifest,
				trusted.trustedRegistry,
			),
		).toThrow();
		expect(() =>
			verifyBenchmarkOracleTransitionProof(
				{ ...runtime, oracleEntryDigest: sha256Hex("forged-oracle-entry") },
				context,
				refs,
				boundManifest,
				trusted.trustedRegistry,
			),
		).toThrow();
	});
	it("accepts a valid signed run and rejects a forged per-run transition signature", () => {
		const fixture = scoredMetricFixture();
		const summary = summarizeMetricRuns([fixture.run], fixture.input);
		expect(summary.failureRuns).toBe(1);
		const runtimeProof = fixture.run.runtimeProof;
		if (runtimeProof === undefined) throw new Error("fixture runtime proof missing");
		const forged: MetricRunRecord = {
			...fixture.run,
			runtimeProof: { ...runtimeProof, signature: "forged" },
		};
		expectCtfCode(() => summarizeMetricRuns([forged], fixture.input), "oracle_integrity_error");
	});
	it("binds every challenge repeat to a canonical schedule, including colon IDs", () => {
		expect(benchmarkRepeatSeed("bench:a", "challenge", 0)).not.toBe(benchmarkRepeatSeed("bench", "a:challenge", 0));
		const base = makeManifest();
		const { seeds: _legacySeeds, ...baseWithoutLegacySeeds } = base;
		const challengeIds = ["challenge-1", "challenge:2"];
		const seedSchedule = benchmarkSeedSchedule("benchmark-1", challengeIds);
		const unsigned = {
			...baseWithoutLegacySeeds,
			corpus: [base.corpus[0], { ...base.corpus[0], challengeId: "challenge:2", category: "category-2" }],
			seedSchedule,
		};
		const manifest = { ...unsigned, manifestDigest: benchmarkManifestDigest(unsigned) };
		const lock = createBenchmarkLock(manifest);
		const forgedSchedule = {
			...seedSchedule,
			"challenge:2": [`sha256:${"f".repeat(64)}`, ...seedSchedule["challenge:2"].slice(1)] as [
				string,
				string,
				string,
				string,
				string,
			],
		};
		const forgedManifestUnsigned = { ...manifest, seedSchedule: forgedSchedule };
		const forgedManifest = {
			...forgedManifestUnsigned,
			manifestDigest: benchmarkManifestDigest(forgedManifestUnsigned),
		};
		expectCtfCode(() => validateBenchmarkManifest(forgedManifest), "benchmark_lock_mismatch");
		expect(lock.seedSchedule).toEqual(seedSchedule);
		const runs = challengeIds.map((challengeId, index) =>
			metricRun({
				runId: `run-${index}`,
				challengeId,
				seed: seedSchedule[challengeId][0],
				benchmarkLockDigest: lock.lockDigest,
			}),
		);
		const {
			seeds: _reportLegacySeeds,
			fingerprint: _reportFingerprint,
			...reportWithoutLegacySeeds
		} = metricReport({
			benchmarkLockDigest: lock.lockDigest,
			eligibleChallengeIds: challengeIds,
			seedSchedule,
			categoryAggregates: [
				{ category: "category-1", numerator: 0, denominator: 2, excludedCount: 0, unknownCount: 0 },
			],
			runs,
		});
		const report = { ...reportWithoutLegacySeeds, fingerprint: metricsFingerprint(reportWithoutLegacySeeds) };
		expect(validateMetricsReport(report)).toEqual(report);
		const forgedRuns = [{ ...runs[0] }, { ...runs[1], seed: seedSchedule["challenge-1"][0] }];
		const forgedUnsigned = { ...reportWithoutLegacySeeds, runs: forgedRuns };
		expectCtfCode(
			() => validateMetricsReport({ ...forgedUnsigned, fingerprint: metricsFingerprint(forgedUnsigned) }),
			"benchmark_lock_mismatch",
		);
	});
});
