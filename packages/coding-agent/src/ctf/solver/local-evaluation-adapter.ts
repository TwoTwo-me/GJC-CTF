import type { SolverAttemptLimits, SolverRoute } from "./router";

const MAX_ACTIONS = 64;
const MAX_ACTION_BYTES = 64 * 1024;
const MAX_TOTAL_BYTES = 256 * 1024;

type InteractiveAdapterKind = Exclude<SolverRoute["adapterKind"], "offline-checker">;

type AdapterIdentity = Readonly<{
	challengeId: string;
	routeDigest: string;
	adapterKind: InteractiveAdapterKind;
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
	observation?: Readonly<{ status?: string; exitCode?: number }>;
}>;

export type LocalEvaluationAdapterProvider = AdapterIdentity &
	Readonly<{
		open(
			input: Readonly<{ signal: AbortSignal; attemptLimits: SolverAttemptLimits }>,
		): Promise<LocalProcessService | LocalBrowserSession>;
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
			browser: Readonly<{
				action(action: LocalBrowserAction): Promise<void>;
			}>;
			close(): Promise<void>;
	  }>;

function isInteractiveKind(value: SolverRoute["adapterKind"]): value is InteractiveAdapterKind {
	return value === "process-service" || value === "browser-session";
}

function relativePath(value: string): boolean {
	if (
		!value ||
		value.includes("\0") ||
		value.includes("\\") ||
		value.startsWith("/") ||
		/^[a-z][a-z\d+.-]*:/iu.test(value)
	)
		return false;
	return !value.split(/[?#]/u)[0].split("/").includes("..");
}

function validBrowserAction(action: LocalBrowserAction): boolean {
	if (action.type === "navigate") return relativePath(action.path) && action.path.length <= 2048;
	if (action.type === "click") return action.selector.length > 0 && action.selector.length <= 1024;
	return action.selector.length > 0 && action.selector.length <= 1024 && action.value.length <= MAX_ACTION_BYTES;
}

function bounded(
	limit: SolverAttemptLimits,
	signal: AbortSignal,
): {
	assertAction(bytes?: number): void;
	chargeBytes(bytes: number): void;
	remainingMs(): number;
} {
	const startedAt = Date.now();
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
			if (Date.now() - startedAt >= limit.wallClockMs)
				throw new Error("local evaluation adapter time limit exhausted");
		},
		chargeBytes(charge: number): void {
			if (!Number.isSafeInteger(charge) || charge < 0 || charge > MAX_ACTION_BYTES)
				throw new Error("local evaluation adapter action exceeds byte bound");
			bytes += charge;
			if (bytes > MAX_TOTAL_BYTES) throw new Error("local evaluation adapter byte limit exhausted");
		},
		remainingMs(): number {
			const remaining = limit.wallClockMs - (Date.now() - startedAt);
			if (signal.aborted || remaining <= 0) throw new Error("local evaluation adapter time limit exhausted");
			return remaining;
		},
	};
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
async function openBoundedService(
	provider: LocalEvaluationAdapterProvider,
	route: SolverRoute,
	signal: AbortSignal,
): Promise<LocalProcessService | LocalBrowserSession> {
	const controller = new AbortController();
	const result = Promise.withResolvers<LocalProcessService | LocalBrowserSession>();
	let settled = false;
	let timedOut = false;
	const abort = (): void => {
		controller.abort(signal.reason);
		finish(new Error("local evaluation adapter is cancelled"));
	};
	const timeout = setTimeout(() => {
		timedOut = true;
		controller.abort(new Error("local evaluation adapter time limit exhausted"));
		finish(new Error("local evaluation adapter time limit exhausted"));
	}, route.attemptLimits.wallClockMs);
	const finish = (error?: Error, service?: LocalProcessService | LocalBrowserSession): void => {
		if (settled) {
			if (service !== undefined) void closeOnce(() => service.close())().catch(() => undefined);
			return;
		}
		settled = true;
		clearTimeout(timeout);
		signal.removeEventListener("abort", abort);
		if (error === undefined && service !== undefined) result.resolve(service);
		else result.reject(error ?? new Error("local evaluation adapter open failed"));
	};
	if (signal.aborted) abort();
	else signal.addEventListener("abort", abort, { once: true });
	if (signal.aborted) finish(new Error("local evaluation adapter is cancelled"));
	else {
		Promise.resolve()
			.then(() => provider.open({ signal: controller.signal, attemptLimits: route.attemptLimits }))
			.then(
				service => finish(undefined, service),
				error =>
					finish(
						error instanceof Error
							? error
							: new Error(
									timedOut
										? "local evaluation adapter time limit exhausted"
										: "local evaluation adapter open failed",
								),
					),
			);
	}
	return result.promise;
}

/** Opens a route-bound provider and exposes only bounded local interaction methods to AgentSession. */
export async function openLocalEvaluationAdapter(
	provider: LocalEvaluationAdapterProvider,
	route: SolverRoute,
	signal: AbortSignal,
): Promise<LocalEvaluationAdapter> {
	if (!isInteractiveKind(route.adapterKind)) throw new Error("offline routes do not use local evaluation adapters");
	if (
		provider.challengeId !== route.challengeId ||
		provider.routeDigest !== route.routeDigest ||
		provider.adapterKind !== route.adapterKind
	)
		throw new Error("local evaluation adapter provider does not match the reviewed route");
	const service = await openBoundedService(provider, route, signal);
	const close = closeOnce(() => service.close());
	const limits = bounded(route.attemptLimits, signal);
	try {
		if (route.adapterKind === "process-service") {
			if (!("send" in service) || !("receive" in service) || !("restart" in service))
				throw new Error("local evaluation adapter provider kind does not match the reviewed route");
			return Object.freeze({
				adapterKind: route.adapterKind,
				observation: observationOf(service.observation),
				process: Object.freeze({
					async send(content: Uint8Array): Promise<void> {
						limits.assertAction(content.byteLength);
						await service.send(new Uint8Array(content));
					},
					async receive(): Promise<Uint8Array> {
						limits.assertAction();
						const content = await service.receive({
							maxBytes: MAX_ACTION_BYTES,
							timeoutMs: limits.remainingMs(),
						});
						if (content.byteLength > MAX_ACTION_BYTES)
							throw new Error("local evaluation adapter receive exceeds byte bound");
						limits.chargeBytes(content.byteLength);
						return new Uint8Array(content);
					},
					async restart(): Promise<void> {
						limits.assertAction();
						await service.restart();
					},
				}),
				close,
			});
		}
		if (!("action" in service))
			throw new Error("local evaluation adapter provider kind does not match the reviewed route");
		return Object.freeze({
			adapterKind: route.adapterKind,
			observation: observationOf(service.observation),
			browser: Object.freeze({
				async action(action: LocalBrowserAction): Promise<void> {
					if (!validBrowserAction(action)) throw new Error("browser action is not local or exceeds bounds");
					limits.assertAction(action.type === "fill" ? Buffer.byteLength(action.value) : 0);
					await service.action(action);
				},
			}),
			close,
		});
	} catch (error) {
		await close();
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
