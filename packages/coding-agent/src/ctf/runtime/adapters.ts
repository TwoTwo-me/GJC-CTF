import type {
	BrowserSessionAdapterV1,
	ContainerServiceAdapterV1,
	OfflineCheckerAdapterV1,
	ProcessServiceAdapterV1,
} from "../contracts/evaluation";
import {
	deliverSecretLease,
	type EvaluationAdapterContext,
	type EvaluationAdapterSession,
	type EvaluationRuntimeAdapter,
	type PublicCapability,
	type SecretLease,
	type SecretSink,
} from "./evaluation";

export type DriverHandle = Readonly<{ destroy(): Promise<void> }>;
type SecretDriver = Readonly<{ createSecretSink(): Promise<SecretSink> }>;
/** Drivers own their sink; the factory injects the opaque lease once before starting and never exposes it to solver code. */
export type OfflineCheckerDriver = SecretDriver &
	Readonly<{
		prepare(
			request: Readonly<{
				checkerRef: string;
				checkerDigest: string;
				arguments: readonly string[];
				signal?: AbortSignal;
			}>,
		): Promise<DriverHandle>;
	}>;
export type ProcessServiceDriver = SecretDriver &
	Readonly<{
		start(
			request: Readonly<{
				serviceRef: string;
				serviceDigest: string;
				transport: "stdio" | "http";
				origin?: string;
				arguments: readonly string[];
				signal?: AbortSignal;
			}>,
		): Promise<DriverHandle>;
	}>;
export type ContainerServiceDriver = SecretDriver &
	Readonly<{
		start(request: Readonly<{ imageDigest: string; origin: string; signal?: AbortSignal }>): Promise<DriverHandle>;
	}>;
export type BrowserSessionTarget = Readonly<{ origin: string; entryPath: string; downloads: false; rawCdp: false }>;
export type BrowserSessionDriver = Readonly<{
	start(
		request: Readonly<{ browserDigest: string; target: BrowserSessionTarget; signal?: AbortSignal }>,
	): Promise<DriverHandle>;
}>;

function requireLease(context: EvaluationAdapterContext): SecretLease {
	if (context.secretLease === undefined) throw new Error("declared secret role was not delivered");
	return context.secretLease;
}
function aggregateFailure(message: string, failures: readonly unknown[]): AggregateError {
	return new AggregateError(failures, message);
}
function session(capability: PublicCapability, handle: DriverHandle, sink?: SecretSink): EvaluationAdapterSession {
	let destroyed = false;
	return {
		capability,
		async destroy() {
			if (destroyed) return;
			destroyed = true;
			const failures: unknown[] = [];
			try {
				await handle.destroy();
			} catch (error) {
				failures.push(error);
			}
			if (sink !== undefined) {
				try {
					await sink.revoke();
				} catch (error) {
					failures.push(error);
				}
			}
			if (failures.length > 0) throw aggregateFailure("evaluation session cleanup failed", failures);
		},
	};
}
async function inject(
	context: EvaluationAdapterContext,
	role: "checker" | "service",
	driver: SecretDriver,
): Promise<SecretSink> {
	const sink = await driver.createSecretSink();
	try {
		await deliverSecretLease(requireLease(context), role, sink);
		return sink;
	} catch (error) {
		try {
			await sink.revoke();
		} catch (revokeError) {
			throw aggregateFailure("evaluation secret injection cleanup failed", [error, revokeError]);
		}
		throw error;
	}
}
async function startWithSecret(
	capability: PublicCapability,
	context: EvaluationAdapterContext,
	role: "checker" | "service",
	driver: SecretDriver,
	start: () => Promise<DriverHandle>,
): Promise<EvaluationAdapterSession> {
	const sink = await inject(context, role, driver);
	try {
		return session(capability, await start(), sink);
	} catch (error) {
		try {
			await sink.revoke();
		} catch (revokeError) {
			throw aggregateFailure("evaluation session startup cleanup failed", [error, revokeError]);
		}
		throw error;
	}
}
export function createOfflineCheckerAdapter(
	adapter: OfflineCheckerAdapterV1,
	driver: OfflineCheckerDriver,
): EvaluationRuntimeAdapter {
	return {
		adapterId: adapter.adapterId,
		roles: adapter.roles,
		start: context =>
			startWithSecret(
				{ kind: "checker", adapterId: adapter.adapterId, available: true },
				context,
				"checker",
				driver,
				() =>
					driver.prepare({
						checkerRef: adapter.checkerRef,
						checkerDigest: adapter.checkerDigest,
						arguments: adapter.arguments,
						signal: context.signal,
					}),
			),
	};
}
export function createProcessServiceAdapter(
	adapter: ProcessServiceAdapterV1,
	driver: ProcessServiceDriver,
): EvaluationRuntimeAdapter {
	const capability: PublicCapability = {
		kind: "service",
		adapterId: adapter.adapterId,
		transport: adapter.transport,
		...(adapter.origin === undefined ? {} : { origin: adapter.origin }),
	};
	return {
		adapterId: adapter.adapterId,
		roles: adapter.roles,
		start: context =>
			startWithSecret(capability, context, "service", driver, () =>
				driver.start({
					serviceRef: adapter.serviceRef,
					serviceDigest: adapter.serviceDigest,
					transport: adapter.transport,
					...(adapter.origin === undefined ? {} : { origin: adapter.origin }),
					arguments: adapter.arguments,
					signal: context.signal,
				}),
			),
	};
}
export function createContainerServiceAdapter(
	adapter: ContainerServiceAdapterV1,
	driver: ContainerServiceDriver,
): EvaluationRuntimeAdapter {
	return {
		adapterId: adapter.adapterId,
		roles: adapter.roles,
		start: context =>
			startWithSecret(
				{ kind: "service", adapterId: adapter.adapterId, transport: "http", origin: adapter.origin },
				context,
				"service",
				driver,
				() => driver.start({ imageDigest: adapter.imageDigest, origin: adapter.origin, signal: context.signal }),
			),
	};
}
/** This target has no download or CDP controls and can only name a confined loopback page. */
export function assertBrowserSessionTarget(
	target: Readonly<Pick<BrowserSessionTarget, "origin" | "entryPath">>,
): BrowserSessionTarget {
	const url = new URL(target.origin);
	if (
		url.protocol !== "http:" ||
		(url.hostname !== "127.0.0.1" && url.hostname !== "localhost") ||
		url.pathname !== "/" ||
		url.search !== "" ||
		url.hash !== ""
	)
		throw new Error("browser origin must be a loopback HTTP origin");
	if (
		!target.entryPath ||
		target.entryPath.startsWith("/") ||
		target.entryPath.includes("\\") ||
		target.entryPath.split("/").includes("..")
	)
		throw new Error("browser entry path must be confined");
	return Object.freeze({ origin: target.origin, entryPath: target.entryPath, downloads: false, rawCdp: false });
}
export function createBrowserSessionAdapter(
	adapter: BrowserSessionAdapterV1,
	driver: BrowserSessionDriver,
): EvaluationRuntimeAdapter {
	const target = assertBrowserSessionTarget({ origin: adapter.origin, entryPath: adapter.entryPath });
	return {
		adapterId: adapter.adapterId,
		roles: adapter.roles,
		async start(context) {
			return session(
				{ kind: "browser", adapterId: adapter.adapterId, ...target },
				await driver.start({ browserDigest: adapter.browserDigest, target, signal: context.signal }),
			);
		},
	};
}
export const offlineCheckerAdapter = createOfflineCheckerAdapter;
export const processServiceAdapter = createProcessServiceAdapter;
export const containerServiceAdapter = createContainerServiceAdapter;
export const browserSessionAdapter = createBrowserSessionAdapter;
