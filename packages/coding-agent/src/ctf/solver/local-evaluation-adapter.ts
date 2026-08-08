import { assertBrowserSessionTarget } from "../runtime/adapters";
import type { SolverAttemptLimits, SolverRoute } from "./router";

const MAX_ACTIONS = 64;
const MAX_ACTION_BYTES = 64 * 1024;
const MAX_TOTAL_BYTES = 256 * 1024;
const CLEANUP_TIMEOUT_MS = 250;

type InteractiveAdapterKind = Exclude<SolverRoute["adapterKind"], "offline-checker">;

type AdapterIdentity = Readonly<{
	challengeId: string;
	routeDigest: string;
	adapterKind: InteractiveAdapterKind;
}>;

export type LocalEvaluationRunBinding = Readonly<{
	competitionId: string;
	runId: string;
	challengeId: string;
	fencingToken: number;
}>;
declare const trustedBrowserFixtureAuthority: unique symbol;

export type LocalBrowserFixtureAuthority = Readonly<{
	challengeId: "lactf-2026-web-single-trust";
	binding: LocalEvaluationRunBinding;
	origin: string;
	entryPath: string;
	downloads: false;
	rawCdp: false;
	credentials: false;
	serviceWorkers: false;
	externalNetwork: false;
	filesystemDisclosure: false;
	readonly [trustedBrowserFixtureAuthority]: true;
}>;

const issuedBrowserFixtureAuthorities = new WeakSet<object>();
const consumedBrowserFixtureAuthorities = new WeakSet<object>();

function takeTrustedBrowserFixtureAuthority(
	authority: LocalBrowserFixtureAuthority | undefined,
	binding: LocalEvaluationRunBinding,
): void {
	if (authority === undefined)
		throw new Error("local browser sessions are disabled pending reviewed network enforcement");
	if (!issuedBrowserFixtureAuthorities.has(authority) || consumedBrowserFixtureAuthorities.has(authority))
		throw new Error("local browser session fixture authority is not trusted");
	if (
		authority.challengeId !== "lactf-2026-web-single-trust" ||
		authority.binding.competitionId !== binding.competitionId ||
		authority.binding.runId !== binding.runId ||
		authority.binding.challengeId !== binding.challengeId ||
		authority.binding.fencingToken !== binding.fencingToken ||
		authority.downloads !== false ||
		authority.rawCdp !== false ||
		authority.credentials !== false ||
		authority.serviceWorkers !== false ||
		authority.externalNetwork !== false ||
		authority.filesystemDisclosure !== false
	)
		throw new Error("local browser session fixture authority is not trusted");
	try {
		assertBrowserSessionTarget(authority);
	} catch {
		throw new Error("local browser session fixture authority is not trusted");
	}
	consumedBrowserFixtureAuthorities.add(authority);
}
export type LocalEvaluationAdapterLifecycle = { close(): Promise<void> };
export type LocalEvaluationAcquisition = Readonly<{
	service: Promise<LocalProcessService | LocalBrowserSession>;
	terminate(): Promise<void>;
}>;

export type LocalBrowserAction =
	| Readonly<{ type: "navigate"; path: string }>
	| Readonly<{ type: "click"; selector: string }>
	| Readonly<{ type: "fill"; selector: string; value: string }>;

export type LocalProcessService = Readonly<{
	send(content: Uint8Array): Promise<void>;
	receive(options: Readonly<{ maxBytes: number; timeoutMs: number }>): Promise<Uint8Array>;
	restart(): Promise<void>;
	close(): Promise<void>;
	observation?: Readonly<{ status?: string; exitCode?: number }>;
}>;

export type LocalBrowserSession = Readonly<{
	action(action: LocalBrowserAction): Promise<void>;
	close(): Promise<void>;
	/**
	 * This opaque, run-bound authority can only be issued by a future trusted
	 * runtime browser driver. Structural lookalikes are rejected.
	 */
	fixtureAuthority?: LocalBrowserFixtureAuthority;
	observation?: Readonly<{ status?: string; exitCode?: number }>;
}>;

export type LocalEvaluationAdapterProvider = AdapterIdentity &
	Readonly<{
		open(
			input: Readonly<{
				signal: AbortSignal;
				attemptLimits: SolverAttemptLimits;
				binding: LocalEvaluationRunBinding;
			}>,
		): LocalEvaluationAcquisition;
	}>;

export type LocalEvaluationAdapter =
	| Readonly<{
			adapterKind: "process-service";
			observation?: Readonly<{ status?: string; exitCode?: number }>;
			process: Readonly<{
				send(content: Uint8Array): Promise<void>;
				receive(): Promise<Uint8Array>;
				restart(): Promise<void>;
			}>;
			close(): Promise<void>;
	  }>
	| Readonly<{
			adapterKind: "browser-session";
			observation?: Readonly<{ status?: string; exitCode?: number }>;
			browser: Readonly<{ action(action: LocalBrowserAction): Promise<void> }>;
			close(): Promise<void>;
	  }>;

const seenServices = new Set<object>();

function isInteractiveKind(value: SolverRoute["adapterKind"]): value is InteractiveAdapterKind {
	return value === "process-service" || value === "browser-session";
}

function bounded(signal: AbortSignal, deadline: number) {
	let actions = 0;
	let bytes = 0;
	return {
		assertAction(actionBytes = 0): void {
			if (signal.aborted) throw new Error("local evaluation adapter is cancelled");
			if (!Number.isSafeInteger(actionBytes) || actionBytes < 0 || actionBytes > MAX_ACTION_BYTES)
				throw new Error("local evaluation adapter action exceeds byte bound");
			if (++actions > MAX_ACTIONS) throw new Error("local evaluation adapter action limit exhausted");
			bytes += actionBytes;
			if (bytes > MAX_TOTAL_BYTES) throw new Error("local evaluation adapter byte limit exhausted");
			if (Date.now() >= deadline) throw new Error("local evaluation adapter time limit exhausted");
		},
		chargeBytes(charge: number): void {
			if (!Number.isSafeInteger(charge) || charge < 0 || charge > MAX_ACTION_BYTES)
				throw new Error("local evaluation adapter action exceeds byte bound");
			bytes += charge;
			if (bytes > MAX_TOTAL_BYTES) throw new Error("local evaluation adapter byte limit exhausted");
		},
		remainingMs(): number {
			const remaining = deadline - Date.now();
			if (signal.aborted || remaining <= 0) throw new Error("local evaluation adapter time limit exhausted");
			return remaining;
		},
	};
}

function raceBounded<T>(promise: Promise<T>, signal: AbortSignal, deadline: number, label: string): Promise<T> {
	const remaining = deadline - Date.now();
	if (signal.aborted) return Promise.reject(new Error("local evaluation adapter is cancelled"));
	if (remaining <= 0) return Promise.reject(new Error("local evaluation adapter time limit exhausted"));
	return new Promise<T>((resolve, reject) => {
		const timer = setTimeout(() => finish(new Error("local evaluation adapter time limit exhausted")), remaining);
		const abort = () => finish(new Error("local evaluation adapter is cancelled"));
		const finish = (error?: Error, value?: T): void => {
			clearTimeout(timer);
			signal.removeEventListener("abort", abort);
			if (error !== undefined) reject(error);
			else resolve(value as T);
		};
		signal.addEventListener("abort", abort, { once: true });
		promise.then(
			value => finish(undefined, value),
			error => finish(error instanceof Error ? error : new Error(`local evaluation adapter ${label} failed`)),
		);
	});
}
function cleanupDeadline(): number {
	return Date.now() + CLEANUP_TIMEOUT_MS;
}

function closeOnce(close: () => Promise<void>): () => Promise<void> {
	let closing: Promise<void> | undefined;
	return () => (closing ??= Promise.resolve().then(close));
}

function observationOf(
	observation: LocalProcessService["observation"] | LocalBrowserSession["observation"],
): Readonly<{ status?: string; exitCode?: number }> | undefined {
	if (observation === undefined) return undefined;
	const result: { status?: string; exitCode?: number } = {};
	if (typeof observation.status === "string") result.status = observation.status.slice(0, 256);
	if (Number.isSafeInteger(observation.exitCode)) result.exitCode = observation.exitCode;
	return Object.keys(result).length === 0 ? undefined : Object.freeze(result);
}

/** Opens a route- and run-bound provider and exposes only bounded local interaction methods to AgentSession. */
export async function openLocalEvaluationAdapter(
	provider: LocalEvaluationAdapterProvider,
	route: SolverRoute,
	signal: AbortSignal,
	binding: LocalEvaluationRunBinding,
	lifecycle?: LocalEvaluationAdapterLifecycle,
): Promise<LocalEvaluationAdapter> {
	if (!isInteractiveKind(route.adapterKind)) throw new Error("offline routes do not use local evaluation adapters");
	if (
		provider.challengeId !== route.challengeId ||
		provider.routeDigest !== route.routeDigest ||
		provider.adapterKind !== route.adapterKind ||
		binding.challengeId !== route.challengeId ||
		!binding.competitionId ||
		!binding.runId ||
		!Number.isSafeInteger(binding.fencingToken)
	)
		throw new Error("local evaluation adapter provider does not match the reviewed route or run");
	const deadline = Date.now() + route.attemptLimits.wallClockMs;
	const controller = new AbortController();
	const abort = () => controller.abort(signal.reason);
	if (signal.aborted) abort();
	else signal.addEventListener("abort", abort, { once: true });
	let acquisition: LocalEvaluationAcquisition;
	try {
		acquisition = provider.open({
			signal: controller.signal,
			attemptLimits: route.attemptLimits,
			binding: Object.freeze({ ...binding }),
		});
	} catch {
		signal.removeEventListener("abort", abort);
		throw new Error("local evaluation adapter acquisition failed");
	}
	if (
		acquisition === null ||
		typeof acquisition !== "object" ||
		typeof acquisition.terminate !== "function" ||
		acquisition.service === undefined ||
		typeof acquisition.service.then !== "function"
	) {
		signal.removeEventListener("abort", abort);
		throw new Error("local evaluation adapter acquisition is invalid");
	}
	const terminate = closeOnce(async () => {
		controller.abort(new Error("local evaluation adapter closed"));
		await raceBounded(
			Promise.resolve().then(() => acquisition.terminate()),
			new AbortController().signal,
			cleanupDeadline(),
			"acquisition termination",
		);
	});
	if (lifecycle !== undefined) lifecycle.close = terminate;
	let service: LocalProcessService | LocalBrowserSession;
	let closeService: (() => Promise<void>) | undefined;
	try {
		service = await raceBounded(acquisition.service, controller.signal, deadline, "open");
		if (seenServices.has(service as object))
			throw new Error("local evaluation adapter provider reused a quarantined service");
		seenServices.add(service as object);
		closeService = closeOnce(async () => {
			let closeError: unknown;
			try {
				await raceBounded(
					Promise.resolve().then(() => service.close()),
					new AbortController().signal,
					cleanupDeadline(),
					"close",
				);
			} catch (error) {
				closeError = error;
			}
			try {
				await terminate();
			} catch (error) {
				if (closeError !== undefined)
					throw new AggregateError(
						[closeError, error],
						"local evaluation adapter close and acquisition termination failed",
					);
				throw error;
			}
			if (closeError !== undefined) throw closeError;
			signal.removeEventListener("abort", abort);
		});
		const close = closeService;
		const limits = bounded(controller.signal, deadline);
		const operation = async <T>(label: string, call: () => Promise<T>): Promise<T> => {
			try {
				return await raceBounded(Promise.resolve().then(call), controller.signal, deadline, label);
			} catch (error) {
				controller.abort(error);
				try {
					await close();
				} catch (cleanupError) {
					throw new AggregateError([error, cleanupError], "local evaluation adapter operation and cleanup failed");
				}
				throw error;
			}
		};
		if (route.adapterKind === "process-service") {
			if (!("send" in service) || !("receive" in service) || !("restart" in service))
				throw new Error("local evaluation adapter provider kind does not match the reviewed route");
			return Object.freeze({
				adapterKind: route.adapterKind,
				observation: observationOf(service.observation),
				process: Object.freeze({
					async send(content: Uint8Array): Promise<void> {
						limits.assertAction(content.byteLength);
						await operation("send", () => (service as LocalProcessService).send(new Uint8Array(content)));
					},
					async receive(): Promise<Uint8Array> {
						limits.assertAction();
						const content = await operation("receive", () =>
							(service as LocalProcessService).receive({
								maxBytes: MAX_ACTION_BYTES,
								timeoutMs: limits.remainingMs(),
							}),
						);
						if (content.byteLength > MAX_ACTION_BYTES)
							throw new Error("local evaluation adapter receive exceeds byte bound");
						limits.chargeBytes(content.byteLength);
						return new Uint8Array(content);
					},
					async restart(): Promise<void> {
						limits.assertAction();
						await operation("restart", () => (service as LocalProcessService).restart());
					},
				}),
				close,
			});
		}
		if (!("action" in service))
			throw new Error("local evaluation adapter provider kind does not match the reviewed route");
		takeTrustedBrowserFixtureAuthority((service as LocalBrowserSession).fixtureAuthority, binding);
		return Object.freeze({
			adapterKind: route.adapterKind,
			observation: observationOf(service.observation),
			browser: Object.freeze({
				async action(action: LocalBrowserAction): Promise<void> {
					const actionBytes = new TextEncoder().encode(JSON.stringify(action)).byteLength;
					limits.assertAction(actionBytes);
					await operation("browser action", () => (service as LocalBrowserSession).action(action));
				},
			}),
			close,
		});
	} catch (error) {
		controller.abort(error);
		try {
			await (closeService ?? terminate)();
		} catch (terminationError) {
			throw new AggregateError([error, terminationError], "local evaluation adapter acquisition cleanup failed");
		} finally {
			signal.removeEventListener("abort", abort);
		}
		throw error;
	}
}

export function matchingLocalEvaluationProviders(
	providers: readonly LocalEvaluationAdapterProvider[],
	route: SolverRoute,
): readonly LocalEvaluationAdapterProvider[] {
	if (!isInteractiveKind(route.adapterKind)) return [];
	return providers.filter(
		provider =>
			provider.challengeId === route.challengeId &&
			provider.routeDigest === route.routeDigest &&
			provider.adapterKind === route.adapterKind,
	);
}
