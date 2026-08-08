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
	type VerifiedEvaluationEvidenceV1,
	validateEvaluationPreflight,
	validateEvaluationResult,
	validateEvaluationSpec,
	validateVerifiedEvaluationEvidence,
	verifiedEvaluationEvidenceDigest,
} from "../contracts/evaluation";
import { type OracleEvaluationIdentityV2, oracleResultDigestV2 } from "../contracts/oracle";
import type { AnchoredOracleAuthority } from "./oracle";

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
export type OwnedEvaluationOperation<T> = Readonly<{
	result: Promise<T>;
	terminate(reason?: unknown): Promise<void>;
	quiesced: Promise<void>;
}>;
export type EvaluationAdapterSession = Readonly<{ capability: PublicCapability; destroy(): Promise<void> }>;
export type EvaluationRuntimeAdapter = Readonly<{
	adapterId: string;
	roles: readonly string[];
	start(context: EvaluationAdapterContext): OwnedEvaluationOperation<EvaluationAdapterSession>;
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
) => OwnedEvaluationOperation<CandidateSubmission>;
export type TrustedOracleExecutor = Readonly<{
	execute(
		request: Readonly<{ identity: OracleEvaluationIdentityV2; candidate: Uint8Array; signal?: AbortSignal }>,
	): OwnedEvaluationOperation<Readonly<{ registry: unknown; result: unknown }>>;
}>;
export type EvaluationReceiptAuthority = Readonly<{
	competitionId: string;
	fencingToken: number;
}>;
export type LocalEvaluationOutcome = EvaluationResultV1 | VerifiedEvaluationEvidenceV1;
export type LocalEvaluationRequest = Readonly<{
	spec: EvaluationSpecV1;
	preflight: EvaluationPreflightV1;
	lineage: EvaluationLineageInput;
	adapters: readonly EvaluationRuntimeAdapter[];
	collectCandidate: CandidateCollector;
	receiptAuthority?: EvaluationReceiptAuthority;
	oracleAuthority?: AnchoredOracleAuthority;
	trustedOracleExecutor?: TrustedOracleExecutor;
	signal?: AbortSignal;
	/** Absolute evaluation deadline in Unix milliseconds. */
	deadline?: number;
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
	async revokeSinks(run: <T>(operation: () => Promise<T>) => Promise<T>): Promise<void> {
		const failures: unknown[] = [];
		for (let index = this.#sinkRevocations.length - 1; index >= 0; index -= 1) {
			try {
				await run(() => this.#sinkRevocations[index]!.revoke());
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
const DEFAULT_EVALUATION_TIMEOUT_MS = 30_000;
const CLEANUP_TIMEOUT_MS = 1_000;

type BoundedPhase = Readonly<{
	signal: AbortSignal;
	run<T>(operation: OwnedEvaluationOperation<T>): Promise<T>;
	dispose(): void;
}>;

class CleanupFailure extends Error {}

function awaitBounded<T>(value: Promise<T>, deadline: number): Promise<T> {
	const remaining = deadline - Date.now();
	if (remaining <= 0) return Promise.reject(new CleanupFailure("evaluation cleanup did not quiesce"));
	return Promise.race([
		value,
		new Promise<T>((_, reject) =>
			setTimeout(() => reject(new CleanupFailure("evaluation cleanup did not quiesce")), remaining),
		),
	]);
}
function ownedOperation<T>(value: OwnedEvaluationOperation<T>): OwnedEvaluationOperation<T> {
	if (
		value === null ||
		typeof value !== "object" ||
		!(value.result instanceof Promise) ||
		typeof value.terminate !== "function" ||
		!(value.quiesced instanceof Promise)
	) {
		throw new CleanupFailure("evaluation operation ownership is invalid");
	}
	return value;
}

function boundedPhase(signal: AbortSignal | undefined, deadline: number): BoundedPhase {
	const controller = new AbortController();
	const abort = () => controller.abort(signal?.reason ?? "evaluation cancelled");
	const remaining = deadline - Date.now();
	let timer: ReturnType<typeof setTimeout> | undefined;
	if (signal?.aborted || remaining <= 0) abort();
	else {
		signal?.addEventListener("abort", abort, { once: true });
		timer = setTimeout(() => controller.abort("evaluation deadline reached"), remaining);
	}
	return {
		signal: controller.signal,
		run: async <T>(value: OwnedEvaluationOperation<T>): Promise<T> => {
			const operation = ownedOperation(value);
			let termination: Promise<void> | undefined;
			const terminate = () => {
				termination ??= awaitBounded(
					Promise.resolve().then(() => operation.terminate(controller.signal.reason)),
					Date.now() + CLEANUP_TIMEOUT_MS,
				);
				return termination;
			};
			const quiesce = async () => {
				try {
					await awaitBounded(operation.quiesced, Date.now() + CLEANUP_TIMEOUT_MS);
				} catch {
					throw new CleanupFailure("evaluation operation did not quiesce");
				}
			};
			let onAbort: (() => void) | undefined;
			if (controller.signal.aborted) {
				await terminate();
				await quiesce();
				throw new Error("evaluation phase cancelled");
			}
			const aborted = new Promise<never>((_, reject) => {
				onAbort = () => void terminate().then(() => reject(new Error("evaluation phase cancelled")), reject);
				controller.signal.addEventListener("abort", onAbort, { once: true });
			});
			try {
				let result: T;
				try {
					result = await Promise.race([operation.result, aborted]);
				} catch (error) {
					await terminate();
					await quiesce();
					throw error;
				}
				try {
					await quiesce();
				} catch (error) {
					await terminate();
					await quiesce();
					throw error;
				}
				return result;
			} finally {
				if (onAbort !== undefined) controller.signal.removeEventListener("abort", onAbort);
			}
		},
		dispose: () => {
			if (timer !== undefined) clearTimeout(timer);
			signal?.removeEventListener("abort", abort);
		},
	};
}

function capabilityMatches(
	adapterSpec: EvaluationSpecV1["adapters"][number],
	value: unknown,
): PublicCapability | undefined {
	try {
		if (value === null || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype)
			return undefined;
		const capability = value as Record<string, unknown>;
		const keys = Reflect.ownKeys(capability);
		if (
			keys.some(key => {
				const descriptor = Object.getOwnPropertyDescriptor(capability, key);
				return (
					typeof key !== "string" ||
					descriptor === undefined ||
					descriptor.get !== undefined ||
					descriptor.set !== undefined
				);
			})
		)
			return undefined;
		const exactKeys = (...expected: readonly string[]) =>
			keys.length === expected.length && expected.every(key => Object.hasOwn(capability, key));
		if (typeof capability.adapterId !== "string" || capability.adapterId !== adapterSpec.adapterId) return undefined;
		if (adapterSpec.kind === "offline-checker") {
			if (
				!exactKeys("kind", "adapterId", "available") ||
				capability.kind !== "checker" ||
				capability.available !== true
			)
				return undefined;
			return Object.freeze({ kind: "checker" as const, adapterId: capability.adapterId, available: true as const });
		}
		if (
			adapterSpec.kind === "browser-session" ||
			!exactKeys("kind", "adapterId", "transport", ...(adapterSpec.origin === undefined ? [] : ["origin"])) ||
			capability.kind !== "service" ||
			(capability.transport !== "stdio" && capability.transport !== "http") ||
			capability.transport !== adapterSpec.transport ||
			capability.origin !== adapterSpec.origin
		)
			return undefined;
		const transport = capability.transport;
		return Object.freeze({
			kind: "service" as const,
			adapterId: capability.adapterId,
			transport,
			...(adapterSpec.origin === undefined ? {} : { origin: capability.origin as string }),
		});
	} catch {
		return undefined;
	}
}

async function destroySessions(sessions: readonly EvaluationAdapterSession[], deadline: number): Promise<void> {
	const failures: unknown[] = [];
	for (let index = sessions.length - 1; index >= 0; index -= 1) {
		try {
			await awaitBounded(sessions[index]!.destroy(), deadline);
		} catch {
			failures.push(new Error("evaluation session cleanup failed"));
		}
	}
	if (failures.length > 0) throw new AggregateError(failures, "evaluation session cleanup failed");
}

/** Local services/checkers only prepare public capabilities. Solver candidates come solely from collectCandidate. */
export async function evaluateLocalCandidate(request: LocalEvaluationRequest): Promise<LocalEvaluationOutcome> {
	const spec = validateEvaluationSpec(request.spec);
	const preflight = validateEvaluationPreflight(request.preflight);
	const deadline =
		typeof request.deadline === "number" && Number.isFinite(request.deadline)
			? Math.floor(request.deadline)
			: Date.now() + DEFAULT_EVALUATION_TIMEOUT_MS;
	const broker = new SecretBroker();
	const emptyDigest = sha256Hex(new Uint8Array());
	let lineage = buildLineage(request.lineage, emptyDigest, broker.commitment());
	const sessions: EvaluationAdapterSession[] = [];
	const admittedCapabilities: PublicCapability[] = [];
	let pendingEvidence: Omit<VerifiedEvaluationEvidenceV1, "receiptDigest"> | undefined;
	const phase = boundedPhase(request.signal, deadline);
	const cancelled = () => request.signal?.aborted === true || phase.signal.aborted;

	const execute = async (): Promise<EvaluationResultV1> => {
		if (!preflight.passed)
			return unavailable(spec.evaluationId, lineage, "preflight", "preflight_failed", "evaluation preflight failed");
		if (
			request.lineage.challengeId !== spec.challengeId ||
			request.lineage.specDigest !== spec.specDigest ||
			request.lineage.descriptorDigest !== spec.descriptorDigest ||
			request.lineage.preflightDigest !== preflight.preflightDigest
		)
			return unavailable(spec.evaluationId, lineage, "adapter", "not_available", "evaluation identity mismatch");
		if (
			request.adapters.length !== spec.adapters.length ||
			new Set(request.adapters.map(adapter => adapter.adapterId)).size !== request.adapters.length
		)
			return unavailable(spec.evaluationId, lineage, "adapter", "not_available", "adapter set is unavailable");

		const nonce = `nonce-${randomBytes(18).toString("base64url")}`;
		for (const adapterSpec of spec.adapters) {
			if (cancelled())
				return unavailable(spec.evaluationId, lineage, "adapter", "not_available", "evaluation cancelled");
			if (adapterSpec.kind === "browser-session")
				return unavailable(spec.evaluationId, lineage, "adapter", "not_available", "adapter identity mismatch");
			const adapter = request.adapters.find(value => value.adapterId === adapterSpec.adapterId);
			if (adapter === undefined || adapter.roles.join(",") !== adapterSpec.roles.join(","))
				return unavailable(spec.evaluationId, lineage, "adapter", "not_available", "adapter identity mismatch");
			const role =
				adapterSpec.roles[0] === "service" || adapterSpec.roles[0] === "checker" ? adapterSpec.roles[0] : undefined;
			const starting = adapter.start({
				runId: request.lineage.runId,
				challengeId: spec.challengeId,
				nonce,
				instanceCommitmentDigest: broker.commitment(),
				...(role === undefined ? {} : { secretLease: broker.lease(role) }),
				signal: phase.signal,
			});
			let session: EvaluationAdapterSession;
			try {
				session = await phase.run(starting);
			} catch (error) {
				return unavailable(
					spec.evaluationId,
					lineage,
					"adapter",
					"not_available",
					error instanceof CleanupFailure
						? "evaluation cleanup failed"
						: cancelled()
							? "evaluation cancelled"
							: "adapter startup failed",
				);
			}
			const capability = capabilityMatches(adapterSpec, session.capability);
			if (capability === undefined)
				return unavailable(spec.evaluationId, lineage, "adapter", "not_available", "adapter identity mismatch");
			sessions.push(session);
			admittedCapabilities.push(capability);
			if (cancelled())
				return unavailable(spec.evaluationId, lineage, "adapter", "not_available", "evaluation cancelled");
		}

		let candidate: CandidateSubmission;
		try {
			candidate = await phase.run(
				request.collectCandidate({
					runId: request.lineage.runId,
					challengeId: spec.challengeId,
					nonce,
					instanceCommitmentDigest: broker.commitment(),
					capabilities: admittedCapabilities,
					signal: phase.signal,
				}),
			);
		} catch (error) {
			return unavailable(
				spec.evaluationId,
				lineage,
				"candidate",
				"not_available",
				error instanceof CleanupFailure
					? "evaluation cleanup failed"
					: cancelled()
						? "evaluation cancelled"
						: "candidate collection failed",
			);
		}
		if (cancelled())
			return unavailable(spec.evaluationId, lineage, "candidate", "not_available", "evaluation cancelled");
		const bytes =
			candidate.encoding === spec.candidate.encoding
				? candidateBytes(candidate, spec.candidate.maxBytes)
				: undefined;
		if (bytes === undefined)
			return unavailable(
				spec.evaluationId,
				lineage,
				"candidate",
				"not_feasible",
				"candidate encoding or size is invalid",
			);
		const candidateDigest = sha256Hex(bytes);
		lineage = buildLineage(request.lineage, candidateDigest, broker.commitment());
		const candidateResult = (): EvaluationResultV1 => {
			const unsigned = {
				schemaVersion: "ctf-evaluation-result-1" as const,
				kind: "candidate" as const,
				evaluationId: spec.evaluationId,
				lineage,
				candidateDigest,
			};
			return validateEvaluationResult({ ...unsigned, resultDigest: evaluationResultDigest(unsigned) });
		};
		const evidenceRequested =
			request.receiptAuthority !== undefined ||
			request.oracleAuthority !== undefined ||
			request.trustedOracleExecutor !== undefined;
		if (!evidenceRequested) {
			bytes.fill(0);
			return candidateResult();
		}
		if (
			request.receiptAuthority === undefined ||
			request.oracleAuthority === undefined ||
			request.trustedOracleExecutor === undefined
		) {
			bytes.fill(0);
			return unavailable(
				spec.evaluationId,
				lineage,
				"verification",
				"not_available",
				"trusted oracle verification is unavailable",
			);
		}
		try {
			const identity: OracleEvaluationIdentityV2 = {
				evaluationId: spec.evaluationId,
				competitionId: request.receiptAuthority.competitionId,
				runId: request.lineage.runId,
				challengeId: spec.challengeId,
				nonce,
				candidateDigest,
				inputDigest: requireDigest(request.lineage.inputDigest, "evaluation input digest"),
				instanceCommitmentDigest: broker.commitment(),
			};
			const oracleCandidate = new Uint8Array(bytes);
			bytes.fill(0);
			let response: Readonly<{ registry: unknown; result: unknown }>;
			try {
				response = await phase.run(
					request.trustedOracleExecutor!.execute({ identity, candidate: oracleCandidate, signal: phase.signal }),
				);
			} finally {
				oracleCandidate.fill(0);
			}
			if (cancelled())
				return unavailable(spec.evaluationId, lineage, "verification", "not_available", "evaluation cancelled");
			const verified = request.oracleAuthority.verify(response.registry, response.result, identity);
			const verifiedOracleDigest = oracleResultDigestV2(verified.result);
			lineage = buildLineage(request.lineage, candidateDigest, broker.commitment(), verifiedOracleDigest);
			pendingEvidence = {
				schemaVersion: "ctf-verified-evaluation-evidence-1",
				kind: "evidence",
				evaluationId: spec.evaluationId,
				competitionId: identity.competitionId,
				runId: identity.runId,
				challengeId: identity.challengeId,
				lineage,
				oracleResult: verified.result,
				oracleRegistryDigest: verified.oracleRegistryDigest,
				registrySignerFingerprint: verified.registrySignerFingerprint,
				resultSignerFingerprint: verified.resultSignerFingerprint,
				fencingToken: request.receiptAuthority.fencingToken,
			};
			return candidateResult();
		} catch (error) {
			bytes.fill(0);
			return unavailable(
				spec.evaluationId,
				lineage,
				"verification",
				"not_available",
				error instanceof CleanupFailure
					? "evaluation cleanup failed"
					: cancelled()
						? "evaluation cancelled"
						: "trusted oracle verification is unavailable",
			);
		}
	};

	let result: EvaluationResultV1;
	try {
		result = await execute();
	} catch {
		result = unavailable(
			spec.evaluationId,
			lineage,
			"adapter",
			"not_available",
			cancelled() ? "evaluation cancelled" : "adapter startup failed",
		);
	} finally {
		phase.dispose();
	}
	const cleanupDeadline = Date.now() + CLEANUP_TIMEOUT_MS;
	const cleanupFailures: unknown[] = [];
	try {
		await destroySessions(sessions, cleanupDeadline);
	} catch {
		cleanupFailures.push(new Error("evaluation session cleanup failed"));
	}
	try {
		await broker.revokeSinks(operation => awaitBounded(operation(), cleanupDeadline));
	} catch {
		cleanupFailures.push(new Error("evaluation secret cleanup failed"));
	}
	broker.destroy();
	if (cleanupFailures.length > 0)
		return unavailable(
			spec.evaluationId,
			lineage,
			result.kind === "unavailable" ? result.phase : "adapter",
			"not_available",
			"evaluation cleanup failed",
		);
	if (cancelled() && result.kind !== "unavailable")
		return unavailable(
			spec.evaluationId,
			lineage,
			pendingEvidence === undefined ? "candidate" : "verification",
			"not_available",
			"evaluation cancelled",
		);
	if (pendingEvidence !== undefined && result.kind !== "unavailable") {
		const evidence = { ...pendingEvidence, receiptDigest: verifiedEvaluationEvidenceDigest(pendingEvidence) };
		return validateVerifiedEvaluationEvidence(evidence);
	}
	return result;
}
export const runLocalEvaluation = evaluateLocalCandidate;
