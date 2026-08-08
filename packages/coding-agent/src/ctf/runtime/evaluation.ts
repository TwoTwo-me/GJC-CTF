import { randomBytes } from "node:crypto";
import { type Digest, isDigest, sha256Hex } from "../contracts/digest";
import {
	type CandidateEncoding,
	type EvaluationLineageV1,
	type EvaluationPreflightV1,
	type EvaluationResultV1,
	type EvaluationSpecV1,
	evaluationLineageDigest,
	evaluationResultDigest,
	validateEvaluationPreflight,
	validateEvaluationResult,
	validateEvaluationSpec,
} from "../contracts/evaluation";
import { oracleResultDigest } from "../contracts/oracle";
import { type TrustedOracleRegistry, verifyTrustedOracleResult } from "./oracle";

const secretLeaseBrand: unique symbol = Symbol("ctf-secret-lease");
/** Opaque runtime capability resolved only by the trusted injected driver; it never contains or serializes raw secret bytes. */
export type SecretLease = Readonly<{ readonly [secretLeaseBrand]: true }>;
export type EvaluationSecretRole = "service" | "checker";
export type SecretSink = Readonly<{
	role: EvaluationSecretRole;
	writeOnce(bytes: Uint8Array): Promise<void>;
	revoke(): Promise<void>;
}>;
export type CandidateSubmission = Readonly<{ encoding: CandidateEncoding; value: string }>;
export type PublicCapability =
	| Readonly<{ kind: "checker"; adapterId: string; available: true }>
	| Readonly<{ kind: "service"; adapterId: string; transport: "stdio" | "http"; origin?: string }>
	| Readonly<{
			kind: "browser";
			adapterId: string;
			origin: string;
			entryPath: string;
			downloads: false;
			rawCdp: false;
	  }>;
export type EvaluationAdapterSession = Readonly<{ capability: PublicCapability; destroy(): Promise<void> }>;
export type EvaluationRuntimeAdapter = Readonly<{
	adapterId: string;
	roles: readonly string[];
	start(context: EvaluationAdapterContext): Promise<EvaluationAdapterSession>;
}>;
export type EvaluationAdapterContext = Readonly<{
	runId: string;
	challengeId: string;
	nonce: string;
	instanceCommitmentDigest: Digest;
	secretLease?: SecretLease;
	signal?: AbortSignal;
}>;
export type EvaluationLineageInput = Readonly<
	Omit<EvaluationLineageV1, "candidateDigest" | "instanceCommitmentDigest" | "verifiedOracleDigest" | "lineageDigest">
>;
export type CandidateCollector = (
	request: Readonly<{
		runId: string;
		challengeId: string;
		nonce: string;
		instanceCommitmentDigest: Digest;
		capabilities: readonly PublicCapability[];
		signal?: AbortSignal;
	}>,
) => Promise<CandidateSubmission>;
export type TrustedOracleCallback = (
	request: Readonly<{
		runId: string;
		challengeId: string;
		nonce: string;
		candidateDigest: Digest;
		inputDigest: Digest;
	}>,
) => Promise<unknown>;
export type LocalEvaluationRequest = Readonly<{
	spec: EvaluationSpecV1;
	preflight: EvaluationPreflightV1;
	lineage: EvaluationLineageInput;
	adapters: readonly EvaluationRuntimeAdapter[];
	collectCandidate: CandidateCollector;
	trustedOracle?: TrustedOracleRegistry;
	requestOracle?: TrustedOracleCallback;
	signal?: AbortSignal;
}>;

type SecretRecord = {
	broker: SecretBroker;
	role: EvaluationSecretRole;
	secret: Uint8Array;
	delivered: boolean;
	revoked: boolean;
};
type SinkRevocation = Readonly<{ revoke(): Promise<void> }>;
const leaseRecords = new WeakMap<object, SecretRecord>();
const sinkRevocations = new WeakMap<object, SinkRevocation>();
class SecretBroker {
	readonly #secret = randomBytes(32);
	readonly #sinkRevocations: SinkRevocation[] = [];
	#destroyed = false;
	commitment(): Digest {
		return sha256Hex(this.#secret);
	}
	lease(role: EvaluationSecretRole): SecretLease {
		if (this.#destroyed) throw new Error("secret broker is destroyed");
		const lease = Object.freeze<SecretLease>({ [secretLeaseBrand]: true });
		leaseRecords.set(lease, { broker: this, role, secret: this.#secret, delivered: false, revoked: false });
		return lease;
	}
	retainSink(sink: SecretSink): SinkRevocation {
		const retained = sinkRevocations.get(sink);
		if (retained !== undefined) {
			this.#sinkRevocations.push(retained);
			return retained;
		}
		const revoke = sink.revoke.bind(sink);
		let revoked = false;
		let pending: Promise<void> | undefined;
		const owner: SinkRevocation = {
			revoke: async () => {
				if (pending !== undefined) return pending;
				if (revoked) return;
				revoked = true;
				pending = Promise.resolve().then(revoke);
				return pending;
			},
		};
		try {
			Object.defineProperty(sink, "revoke", { configurable: true, value: owner.revoke });
		} catch {
			// Immutable sinks remain revocable through their retained owner.
		}
		sinkRevocations.set(sink, owner);
		this.#sinkRevocations.push(owner);
		return owner;
	}
	async revokeSinks(): Promise<void> {
		const failures: unknown[] = [];
		for (let index = this.#sinkRevocations.length - 1; index >= 0; index -= 1) {
			try {
				await this.#sinkRevocations[index]!.revoke();
			} catch {
				failures.push(new Error("secret sink revocation failed"));
			}
		}
		if (failures.length > 0) throw new AggregateError(failures, "evaluation secret cleanup failed");
	}
	destroy(): void {
		this.#destroyed = true;
		this.#secret.fill(0);
	}
}
/** Adapter-only boundary: writes a temporary secret copy to a matching trusted sink once, then zeroes it. */
export async function deliverSecretLease(
	lease: SecretLease,
	role: EvaluationSecretRole,
	sink: SecretSink,
): Promise<void> {
	const record = leaseRecords.get(lease);
	if (
		record === undefined ||
		record.broker === undefined ||
		record.revoked ||
		record.delivered ||
		record.role !== role ||
		sink.role !== role
	)
		throw new Error("secret lease is invalid");
	const revocation = record.broker.retainSink(sink);
	record.delivered = true;
	const copy = new Uint8Array(record.secret);
	try {
		await sink.writeOnce(copy);
	} catch {
		record.revoked = true;
		try {
			await revocation.revoke();
		} catch {
			throw new AggregateError(
				[new Error("secret sink delivery failed"), new Error("secret sink revocation failed")],
				"evaluation secret delivery cleanup failed",
			);
		}
		throw new Error("secret sink delivery failed");
	} finally {
		copy.fill(0);
	}
}
function candidateBytes(candidate: CandidateSubmission, maxBytes: number): Uint8Array | undefined {
	if (typeof candidate.value !== "string") return undefined;
	if (candidate.encoding === "utf8") {
		if (candidate.value.length > maxBytes) return undefined;
		const bytes = new TextEncoder().encode(candidate.value);
		return bytes.byteLength <= maxBytes ? bytes : undefined;
	}
	if (
		candidate.encoding !== "base64" ||
		candidate.value.length > Math.ceil(maxBytes / 3) * 4 ||
		!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(candidate.value)
	)
		return undefined;
	const bytes = Buffer.from(candidate.value, "base64");
	return bytes.byteLength <= maxBytes && bytes.toString("base64") === candidate.value ? bytes : undefined;
}
type PublicFailureReason =
	| "adapter identity mismatch"
	| "adapter set is unavailable"
	| "adapter startup failed"
	| "candidate collection failed"
	| "candidate encoding or size is invalid"
	| "evaluation cancelled"
	| "evaluation cleanup failed"
	| "evaluation identity mismatch"
	| "evaluation preflight failed"
	| "trusted oracle verification is unavailable";
class EvaluationCancelled extends Error {}
function cancellationRequested(signal: AbortSignal | undefined): boolean {
	return signal?.aborted === true;
}
function requireDigest(value: unknown, field: string): Digest {
	if (!isDigest(value)) throw new Error(`${field} is invalid`);
	return value;
}
function buildLineage(
	input: EvaluationLineageInput,
	candidateDigest: Digest,
	instanceCommitmentDigest: Digest,
	verifiedOracleDigest?: Digest,
): EvaluationLineageV1 {
	const unsigned = {
		...input,
		schemaVersion: "ctf-evaluation-lineage-1" as const,
		candidateDigest,
		instanceCommitmentDigest,
		...(verifiedOracleDigest === undefined ? {} : { verifiedOracleDigest }),
	};
	return { ...unsigned, lineageDigest: evaluationLineageDigest(unsigned) };
}
function unavailable(
	evaluationId: string,
	lineage: EvaluationLineageV1,
	phase: "preflight" | "adapter" | "candidate" | "verification",
	code: "not_available" | "not_supported" | "not_feasible" | "preflight_failed",
	reason: PublicFailureReason,
): EvaluationResultV1 {
	const unsigned = {
		schemaVersion: "ctf-evaluation-result-1" as const,
		kind: "unavailable" as const,
		evaluationId,
		lineage,
		phase,
		code,
		sanitizedReason: reason,
	};
	return validateEvaluationResult({ ...unsigned, resultDigest: evaluationResultDigest(unsigned) });
}
async function destroySessions(sessions: readonly EvaluationAdapterSession[]): Promise<void> {
	const failures: unknown[] = [];
	for (let index = sessions.length - 1; index >= 0; index -= 1) {
		try {
			await sessions[index]!.destroy();
		} catch (error) {
			failures.push(error);
		}
	}
	if (failures.length > 0) throw new AggregateError(failures, "evaluation session cleanup failed");
}
/** Local services/checkers only prepare public capabilities. Solver candidates come solely from collectCandidate. */
export async function evaluateLocalCandidate(request: LocalEvaluationRequest): Promise<EvaluationResultV1> {
	const spec = validateEvaluationSpec(request.spec);
	const preflight = validateEvaluationPreflight(request.preflight);
	const broker = new SecretBroker();
	const emptyDigest = sha256Hex(new Uint8Array());
	let lineage = buildLineage(request.lineage, emptyDigest, broker.commitment());
	const sessions: EvaluationAdapterSession[] = [];
	let primary: EvaluationResultV1 | undefined;
	const complete = (result: EvaluationResultV1): EvaluationResultV1 => {
		primary = result;
		return result;
	};
	try {
		try {
			if (!preflight.passed)
				return complete(
					unavailable(spec.evaluationId, lineage, "preflight", "preflight_failed", "evaluation preflight failed"),
				);
			if (
				request.lineage.challengeId !== spec.challengeId ||
				request.lineage.specDigest !== spec.specDigest ||
				request.lineage.descriptorDigest !== spec.descriptorDigest ||
				request.lineage.preflightDigest !== preflight.preflightDigest
			)
				return complete(
					unavailable(spec.evaluationId, lineage, "adapter", "not_available", "evaluation identity mismatch"),
				);
			if (
				request.adapters.length !== spec.adapters.length ||
				new Set(request.adapters.map(adapter => adapter.adapterId)).size !== request.adapters.length
			)
				return complete(
					unavailable(spec.evaluationId, lineage, "adapter", "not_available", "adapter set is unavailable"),
				);
			const nonce = `nonce-${randomBytes(18).toString("base64url")}`;
			for (const adapterSpec of spec.adapters) {
				if (cancellationRequested(request.signal))
					return complete(
						unavailable(spec.evaluationId, lineage, "adapter", "not_available", "evaluation cancelled"),
					);
				const adapter = request.adapters.find(value => value.adapterId === adapterSpec.adapterId);
				if (adapter === undefined || adapter.roles.join(",") !== adapterSpec.roles.join(","))
					return complete(
						unavailable(spec.evaluationId, lineage, "adapter", "not_available", "adapter identity mismatch"),
					);
				const role =
					adapterSpec.roles[0] === "service" || adapterSpec.roles[0] === "checker"
						? adapterSpec.roles[0]
						: undefined;
				const session = await adapter.start({
					runId: request.lineage.runId,
					challengeId: spec.challengeId,
					nonce,
					instanceCommitmentDigest: broker.commitment(),
					...(role === undefined ? {} : { secretLease: broker.lease(role) }),
					signal: request.signal,
				});
				sessions.push(session);
				if (cancellationRequested(request.signal))
					return complete(
						unavailable(spec.evaluationId, lineage, "adapter", "not_available", "evaluation cancelled"),
					);
			}
			if (cancellationRequested(request.signal))
				return complete(
					unavailable(spec.evaluationId, lineage, "candidate", "not_available", "evaluation cancelled"),
				);
			let candidate: CandidateSubmission;
			try {
				candidate = await request.collectCandidate({
					runId: request.lineage.runId,
					challengeId: spec.challengeId,
					nonce,
					instanceCommitmentDigest: broker.commitment(),
					capabilities: sessions.map(session => session.capability),
					signal: request.signal,
				});
			} catch {
				return complete(
					unavailable(
						spec.evaluationId,
						lineage,
						"candidate",
						"not_available",
						cancellationRequested(request.signal) ? "evaluation cancelled" : "candidate collection failed",
					),
				);
			}
			if (cancellationRequested(request.signal))
				return complete(
					unavailable(spec.evaluationId, lineage, "candidate", "not_available", "evaluation cancelled"),
				);
			const bytes =
				candidate.encoding === spec.candidate.encoding
					? candidateBytes(candidate, spec.candidate.maxBytes)
					: undefined;
			if (bytes === undefined)
				return complete(
					unavailable(
						spec.evaluationId,
						lineage,
						"candidate",
						"not_feasible",
						"candidate encoding or size is invalid",
					),
				);
			const candidateDigest = sha256Hex(bytes);
			lineage = buildLineage(request.lineage, candidateDigest, broker.commitment());
			if (request.trustedOracle === undefined || request.requestOracle === undefined) {
				if (cancellationRequested(request.signal))
					return complete(
						unavailable(spec.evaluationId, lineage, "candidate", "not_available", "evaluation cancelled"),
					);
				const unsigned = {
					schemaVersion: "ctf-evaluation-result-1" as const,
					kind: "candidate" as const,
					evaluationId: spec.evaluationId,
					lineage,
					candidateDigest,
				};
				return complete(validateEvaluationResult({ ...unsigned, resultDigest: evaluationResultDigest(unsigned) }));
			}
			try {
				const value = await request.requestOracle({
					runId: request.lineage.runId,
					challengeId: spec.challengeId,
					nonce,
					candidateDigest,
					inputDigest: requireDigest(request.lineage.inputDigest, "evaluation input digest"),
				});
				if (cancellationRequested(request.signal))
					return complete(
						unavailable(spec.evaluationId, lineage, "verification", "not_available", "evaluation cancelled"),
					);
				const verified = verifyTrustedOracleResult(request.trustedOracle, value, {
					runId: request.lineage.runId,
					challengeId: spec.challengeId,
					nonce,
					candidateDigest,
					inputDigest: requireDigest(request.lineage.inputDigest, "evaluation input digest"),
				});
				const verifiedOracleDigest = oracleResultDigest(verified.result);
				lineage = buildLineage(request.lineage, candidateDigest, broker.commitment(), verifiedOracleDigest);
				const unsigned = {
					schemaVersion: "ctf-evaluation-result-1" as const,
					kind: "verified" as const,
					evaluationId: spec.evaluationId,
					lineage,
					candidateDigest,
					verdict: verified.result.verdict,
					oracleId: verified.result.oracleId,
					verifiedOracleDigest,
				};
				return complete(validateEvaluationResult({ ...unsigned, resultDigest: evaluationResultDigest(unsigned) }));
			} catch {
				return complete(
					unavailable(
						spec.evaluationId,
						lineage,
						"verification",
						"not_available",
						cancellationRequested(request.signal)
							? "evaluation cancelled"
							: "trusted oracle verification is unavailable",
					),
				);
			}
		} catch {
			return complete(
				unavailable(
					spec.evaluationId,
					lineage,
					"adapter",
					"not_available",
					cancellationRequested(request.signal) ? "evaluation cancelled" : "adapter startup failed",
				),
			);
		} finally {
			const cleanupFailures: unknown[] = [];
			try {
				await destroySessions(sessions);
			} catch {
				cleanupFailures.push(new Error("evaluation session cleanup failed"));
			}
			try {
				await broker.revokeSinks();
			} catch {
				cleanupFailures.push(new Error("evaluation secret cleanup failed"));
			} finally {
				broker.destroy();
			}
			if (cleanupFailures.length > 0) throw new AggregateError(cleanupFailures, "evaluation cleanup failed");
			if (cancellationRequested(request.signal) && primary?.kind !== "unavailable") throw new EvaluationCancelled();
		}
	} catch (error) {
		if (error instanceof EvaluationCancelled)
			return unavailable(
				spec.evaluationId,
				lineage,
				primary?.kind === "verified" ? "verification" : "candidate",
				"not_available",
				"evaluation cancelled",
			);
		const phase = primary?.kind === "unavailable" ? primary.phase : "adapter";
		return unavailable(spec.evaluationId, lineage, phase, "not_available", "evaluation cleanup failed");
	}
}
export const runLocalEvaluation = evaluateLocalCandidate;
