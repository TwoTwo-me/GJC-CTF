import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import type {
	LocalEvaluationMaterializationView,
	LocalEvaluationRunBinding,
	LocalProcessService,
} from "./local-evaluation-adapter";
import { type SolverAttemptLimits, solverRouteFor } from "./router";

const IMAGE = "docker.io/library/debian@sha256:b5ace515e78743215a1b101a6f17e59ed74b17132139ca3af3c37e605205e973";
const CHALLENGE_ID = "lactf-2026-pwn-tic-tac-no";
const TEST_CHALLENGE_ID = "test-only-rootless-podman-provider";
const MAX_BYTES = 64 * 1024;
const REAP_TIMEOUT_MS = 250;

type ChildEvent = "spawn" | "exit" | "error" | "data";
type ChildListener = (...args: unknown[]) => void;
type PodmanChild = Readonly<{
	stdin: NodeJS.WritableStream | null;
	stdout: NodeJS.ReadableStream | null;
	kill(signal?: NodeJS.Signals): boolean;
	on(event: ChildEvent, listener: ChildListener): PodmanChild;
	once(event: ChildEvent, listener: ChildListener): PodmanChild;
	off(event: ChildEvent, listener: ChildListener): PodmanChild;
}>;
type ProviderInput = Readonly<{
	signal: AbortSignal;
	attemptLimits: SolverAttemptLimits;
	binding: LocalEvaluationRunBinding;
	materialization?: LocalEvaluationMaterializationView;
}>;
type State = "open" | "closing" | "closed";
type StagedIdentity = Readonly<{ dev: number; ino: number; size: number }>;
type Generation = {
	dir?: string;
	cidfile?: string;
	containerName?: string;
	containerId?: string;
	staged?: Readonly<{ path: string; identity: StagedIdentity }>;
	ownedChild?: OwnedChild;
	detachOutput?: () => void;
};
type OwnedChild = Readonly<{
	child: PodmanChild;
	spawned: Promise<void>;
	terminal: Promise<void>;
}>;

export type RootlessPodmanProvider = Readonly<{
	challengeId: string;
	routeDigest: string;
	adapterKind: "process-service";
	open(input: ProviderInput): Readonly<{ service: Promise<LocalProcessService>; terminate(): Promise<void> }>;
}>;
/** Non-authoritative test-only process seam. Its identity cannot match a reviewed route. */
export type RootlessPodmanProviderTestHarness = Readonly<{
	run(
		argv: readonly string[],
		options: Readonly<{ cwd?: string; stdio: "ignore" | "pipe"; env: Readonly<Record<string, string>> }>,
	): PodmanChild;
}>;

function environment(): Readonly<Record<string, string>> {
	return Object.freeze({ PATH: "/usr/bin:/bin", LANG: "C", HOME: "/nonexistent" });
}

function sha256(bytes: Uint8Array): string {
	return createHash("sha256").update(bytes).digest("hex");
}

function podman(argv: readonly string[]): readonly string[] {
	return Object.freeze(["--remote=false", ...argv]);
}

function ownChild(child: PodmanChild): OwnedChild {
	const terminal = Promise.withResolvers<void>();
	const spawned = Promise.withResolvers<void>();
	let terminalDone = false;
	const finishTerminal = (error?: Error): void => {
		if (terminalDone) return;
		terminalDone = true;
		if (error === undefined) terminal.resolve();
		else terminal.reject(error);
	};
	const onSpawn: ChildListener = () => spawned.resolve();
	const onExit: ChildListener = () => {
		spawned.reject(new Error("Podman exited before spawn"));
		finishTerminal();
	};
	const onError: ChildListener = value => {
		const error = value instanceof Error ? value : new Error("Podman child failed");
		spawned.reject(error);
		finishTerminal(error);
	};
	child.once("spawn", onSpawn);
	child.once("exit", onExit);
	child.once("error", onError);
	void spawned.promise.catch(() => undefined);
	void terminal.promise.catch(() => undefined);
	return Object.freeze({ child, spawned: spawned.promise, terminal: terminal.promise });
}

async function reap(owned: OwnedChild): Promise<void> {
	let killTimer: ReturnType<typeof setTimeout> | undefined;
	let failTimer: ReturnType<typeof setTimeout> | undefined;
	try {
		await Promise.race([
			owned.terminal,
			new Promise<void>((_, reject) => {
				killTimer = setTimeout(() => {
					try {
						owned.child.kill("SIGKILL");
					} catch {}
					failTimer = setTimeout(() => reject(new Error("Podman child did not reap")), REAP_TIMEOUT_MS);
				}, REAP_TIMEOUT_MS);
			}),
		]);
	} finally {
		if (killTimer !== undefined) clearTimeout(killTimer);
		if (failTimer !== undefined) clearTimeout(failTimer);
	}
}
async function awaitSpawn(owned: OwnedChild): Promise<void> {
	let timer: ReturnType<typeof setTimeout> | undefined;
	try {
		await Promise.race([
			owned.spawned,
			new Promise<never>((_, reject) => {
				timer = setTimeout(() => reject(new Error("Podman spawn timed out")), REAP_TIMEOUT_MS);
			}),
		]);
	} catch (error) {
		try {
			owned.child.kill("SIGKILL");
		} finally {
			await reap(owned).catch(() => undefined);
		}
		throw error;
	} finally {
		if (timer !== undefined) clearTimeout(timer);
	}
}

function productionHarness(): RootlessPodmanProviderTestHarness {
	return {
		run(argv, options) {
			return spawn("podman", argv, {
				cwd: options.cwd,
				env: options.env,
				stdio: options.stdio === "ignore" ? "ignore" : ["pipe", "pipe", "ignore"],
			}) as PodmanChild;
		},
	};
}

async function helper(
	harness: RootlessPodmanProviderTestHarness,
	argv: readonly string[],
	cwd?: string,
	captureOutput = false,
): Promise<Readonly<{ ok: boolean; output: string }>> {
	const owned = ownChild(
		harness.run(podman(argv), { cwd, stdio: captureOutput ? "pipe" : "ignore", env: environment() }),
	);
	const chunks: Uint8Array[] = [];
	const onData: ChildListener = value => {
		if (value instanceof Uint8Array) chunks.push(new Uint8Array(value));
	};
	owned.child.stdout?.on("data", onData);
	let code: number | null = null;
	const onExit: ChildListener = value => {
		code = typeof value === "number" ? value : null;
	};
	owned.child.once("exit", onExit);
	try {
		await reap(owned);
		return {
			ok: code === 0,
			output: Buffer.concat(chunks.map(chunk => Buffer.from(chunk)))
				.toString("utf8")
				.trim(),
		};
	} catch {
		return { ok: false, output: "" };
	} finally {
		owned.child.stdout?.off("data", onData);
		owned.child.off("exit", onExit);
	}
}

async function preflight(harness: RootlessPodmanProviderTestHarness, production: boolean): Promise<boolean> {
	if (production && (typeof process.getuid !== "function" || process.getuid() <= 0)) return false;
	const info = await helper(harness, ["info", "--format", "{{.Host.Security.Rootless}}"], undefined, true);
	return info.ok && info.output === "true" && (await helper(harness, ["image", "exists", IMAGE])).ok;
}
function validContainerName(value: string): boolean {
	return /^gjc-ctf-[a-f0-9]{32}$/u.test(value);
}

function validContainerId(value: string): boolean {
	return /^[a-f0-9]{64}$/u.test(value);
}

async function readContainerId(cidfile: string): Promise<string | undefined> {
	const handle = await fs.open(cidfile, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW).catch(() => undefined);
	if (handle === undefined) return undefined;
	try {
		const stat = await handle.stat();
		const named = await fs.lstat(cidfile);
		if (
			!stat.isFile() ||
			named.isSymbolicLink() ||
			named.dev !== stat.dev ||
			named.ino !== stat.ino ||
			(stat.size !== 64 && stat.size !== 65)
		)
			return undefined;
		const bytes = new Uint8Array(stat.size);
		const read = await handle.read(bytes, 0, bytes.byteLength, 0);
		if (read.bytesRead !== bytes.byteLength) return undefined;
		const value = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
		const id = value.endsWith("\n") ? value.slice(0, -1) : value;
		return validContainerId(id) && (value === id || value === `${id}\n`) ? id : undefined;
	} catch {
		return undefined;
	} finally {
		await handle.close();
	}
}

async function awaitContainerId(generation: Generation, signal: AbortSignal): Promise<string> {
	const deadline = Date.now() + REAP_TIMEOUT_MS;
	while (Date.now() < deadline) {
		if (signal.aborted || generation.cidfile === undefined) throw new Error("rootless Podman start cancelled");
		const id = await readContainerId(generation.cidfile);
		if (id !== undefined) return id;
		await Bun.sleep(10);
	}
	throw new Error("rootless Podman cidfile timed out");
}

function runArgv(chall: string, cidfile: string, containerName: string): readonly string[] {
	return podman([
		"run",
		"--pull=never",
		"--network=none",
		"--userns=keep-id",
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
		"--read-only",
		"--pids-limit=64",
		"--memory=256m",
		"--memory-swap=256m",
		"--cpus=1",
		"--log-driver=none",
		"--tmpfs",
		"/tmp:rw,noexec,nosuid,nodev,size=16m",
		"--name",
		containerName,
		"--cidfile",
		cidfile,
		"--mount",
		`type=bind,src=${chall},dst=/app/chall,ro=true`,
		"--workdir",
		"/tmp",
		IMAGE,
		"/app/chall",
	]);
}

async function stage(
	dir: string,
	bytes: Uint8Array,
	expected: string,
): Promise<Readonly<{ path: string; identity: StagedIdentity }>> {
	const target = path.join(dir, "chall");
	const handle = await fs.open(
		target,
		fsConstants.O_RDWR | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
		0o500,
	);
	try {
		await handle.writeFile(bytes);
		const stat = await handle.stat();
		const persisted = new Uint8Array(bytes.byteLength);
		let offset = 0;
		while (offset < persisted.byteLength) {
			const read = await handle.read(persisted, offset, persisted.byteLength - offset, offset);
			if (read.bytesRead === 0) throw new Error("rootless Podman staging failed");
			offset += read.bytesRead;
		}
		if (!stat.isFile() || stat.size !== bytes.byteLength || sha256(persisted) !== expected)
			throw new Error("rootless Podman staging failed");
		return Object.freeze({
			path: target,
			identity: Object.freeze({ dev: stat.dev, ino: stat.ino, size: stat.size }),
		});
	} finally {
		await handle.close();
	}
}

async function verifyStaged(
	staged: Readonly<{ path: string; identity: StagedIdentity }>,
	digest: string,
): Promise<void> {
	const handle = await fs.open(staged.path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
	try {
		const stat = await handle.stat();
		const named = await fs.lstat(staged.path);
		if (
			!stat.isFile() ||
			named.isSymbolicLink() ||
			stat.dev !== staged.identity.dev ||
			stat.ino !== staged.identity.ino ||
			stat.size !== staged.identity.size ||
			named.dev !== stat.dev ||
			named.ino !== stat.ino ||
			sha256(await handle.readFile()) !== digest
		)
			throw new Error("rootless Podman staging changed");
	} finally {
		await handle.close();
	}
}

function makeProvider(
	challengeId: string,
	routeDigest: string,
	harness: RootlessPodmanProviderTestHarness,
	production: boolean,
): RootlessPodmanProvider {
	return {
		challengeId,
		routeDigest,
		adapterKind: "process-service",
		open(input) {
			let state: State = "open";
			let generation: Generation = {};
			let queue = Promise.resolve();
			let cleanup: Promise<void> | undefined;
			const enqueue = <T>(work: () => Promise<T>): Promise<T> => {
				const result = queue.then(work, work);
				queue = result.then(
					() => undefined,
					() => undefined,
				);
				return result;
			};
			const cleanupGeneration = async (): Promise<void> => {
				const failures: unknown[] = [];
				generation.detachOutput?.();
				generation.detachOutput = undefined;
				const owned = generation.ownedChild;
				if (owned !== undefined) {
					generation.ownedChild = undefined;
					try {
						owned.child.kill("SIGKILL");
						await reap(owned);
					} catch (error) {
						generation.ownedChild = owned;
						failures.push(error);
					}
				}
				if (generation.containerName !== undefined) {
					try {
						const target = generation.containerId ?? generation.containerName;
						if (!validContainerId(target) && !validContainerName(target))
							throw new Error("rootless Podman container identity is invalid");
						const result = await helper(harness, ["rm", "--force", "--ignore", target], generation.dir);
						if (!result.ok) throw new Error("rootless Podman container removal failed");
						generation.containerId = undefined;
						generation.containerName = undefined;
					} catch (error) {
						failures.push(error);
					}
				}
				const complete =
					generation.ownedChild === undefined &&
					generation.containerName === undefined &&
					generation.containerId === undefined;
				if (complete && generation.dir !== undefined) {
					try {
						await fs.rm(generation.dir, { recursive: true, force: true });
						generation = {};
					} catch (error) {
						failures.push(error);
					}
				}
				if (failures.length === 1) throw failures[0];
				if (failures.length > 1) throw new AggregateError(failures, "rootless Podman cleanup failed");
			};
			const close = (): Promise<void> => {
				if (state === "open") state = "closing";
				cleanup ??= enqueue(async () => {
					let failure: unknown;
					for (let attempt = 0; attempt < 3; attempt++) {
						try {
							await cleanupGeneration();
							state = "closed";
							input.signal.removeEventListener("abort", abort);
							return;
						} catch (error) {
							failure = error;
							if (attempt < 2) await Bun.sleep(10);
						}
					}
					throw failure;
				});
				return cleanup;
			};
			const abort = () => {
				void close();
			};
			input.signal.addEventListener("abort", abort, { once: true });
			const service = (async (): Promise<LocalProcessService> => {
				const materialized = input.materialization;
				if (materialized === undefined || materialized.visibleFiles.length !== 1)
					throw new Error("rootless Podman materialization is unavailable");
				const chall = materialized.visibleFiles[0]!;
				if (
					chall.path !== "chall" ||
					!/^[a-f0-9]{64}$/u.test(materialized.provenanceDigest) ||
					!/^[a-f0-9]{64}$/u.test(chall.digest) ||
					sha256(chall.content) !== chall.digest
				)
					throw new Error("rootless Podman materialization digest mismatch");
				const startGeneration = async (): Promise<OwnedChild> => {
					if (state !== "open" || input.signal.aborted || !(await preflight(harness, production)))
						throw new Error("rootless Podman preflight failed");
					if (state !== "open" || input.signal.aborted) throw new Error("rootless Podman start cancelled");
					generation.dir = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-pwn-"));
					await fs.chmod(generation.dir, 0o700);
					if (state !== "open" || input.signal.aborted) throw new Error("rootless Podman start cancelled");
					generation.staged = await stage(generation.dir, chall.content, chall.digest);
					generation.cidfile = path.join(generation.dir, "container.cid");
					generation.containerName = `gjc-ctf-${randomUUID().replace(/-/gu, "")}`;
					if (!validContainerName(generation.containerName))
						throw new Error("rootless Podman container identity is invalid");
					if (state !== "open" || input.signal.aborted) throw new Error("rootless Podman start cancelled");
					await verifyStaged(generation.staged, chall.digest);
					if (state !== "open" || input.signal.aborted) throw new Error("rootless Podman start cancelled");
					const owned = ownChild(
						harness.run(runArgv(generation.staged.path, generation.cidfile, generation.containerName), {
							cwd: generation.dir,
							stdio: "pipe",
							env: environment(),
						}),
					);
					generation.ownedChild = owned;
					await awaitSpawn(owned);
					generation.containerId = await awaitContainerId(generation, input.signal);
					if (state !== "open" || input.signal.aborted) throw new Error("rootless Podman start cancelled");
					return owned;
				};
				let active = await enqueue(startGeneration);
				let output: Uint8Array[] = [];
				let outputBytes = 0;
				let terminal: Error | undefined;
				const attach = (owned: OwnedChild): void => {
					generation.detachOutput?.();
					output = [];
					outputBytes = 0;
					const onData: ChildListener = value => {
						if (!(value instanceof Uint8Array)) return;
						const copy = new Uint8Array(value);
						if (outputBytes + copy.byteLength > MAX_BYTES) {
							terminal = new Error("rootless Podman output exceeded bound");
							void close();
							return;
						}
						output.push(copy);
						outputBytes += copy.byteLength;
					};
					owned.child.stdout?.on("data", onData);
					generation.detachOutput = () => owned.child.stdout?.off("data", onData);
					void owned.terminal.then(
						() => {
							if (generation.ownedChild === owned) terminal ??= new Error("rootless Podman process exited");
						},
						error => {
							if (generation.ownedChild === owned)
								terminal ??= error instanceof Error ? error : new Error("rootless Podman process failed");
						},
					);
				};
				attach(active);
				return Object.freeze({
					async send(content) {
						if (
							terminal !== undefined ||
							state !== "open" ||
							!(content instanceof Uint8Array) ||
							content.byteLength > MAX_BYTES ||
							active.child.stdin === null
						)
							throw terminal ?? new Error("rootless Podman process is unavailable");
						await new Promise<void>((resolve, reject) =>
							active.child.stdin!.write(new Uint8Array(content), error => (error ? reject(error) : resolve())),
						);
					},
					async receive({ maxBytes, timeoutMs }) {
						if (terminal !== undefined || state !== "open")
							throw terminal ?? new Error("rootless Podman process is unavailable");
						if (
							!Number.isSafeInteger(maxBytes) ||
							maxBytes < 0 ||
							maxBytes > MAX_BYTES ||
							!Number.isSafeInteger(timeoutMs) ||
							timeoutMs < 0
						)
							throw new Error("invalid receive bound");
						if (outputBytes === 0)
							await new Promise<void>((resolve, reject) => {
								const onData: ChildListener = () => done();
								const onExit: ChildListener = () =>
									done(terminal ?? new Error("rootless Podman process exited"));
								const onError: ChildListener = value =>
									done(value instanceof Error ? value : new Error("rootless Podman process failed"));
								const onAbort = () => done(new Error("rootless Podman cancelled"));
								const timer = setTimeout(() => done(), timeoutMs);
								const done = (error?: Error) => {
									clearTimeout(timer);
									active.child.stdout?.off("data", onData);
									active.child.off("exit", onExit);
									active.child.off("error", onError);
									input.signal.removeEventListener("abort", onAbort);
									error === undefined ? resolve() : reject(error);
								};
								active.child.stdout?.once("data", onData);
								active.child.once("exit", onExit);
								active.child.once("error", onError);
								input.signal.addEventListener("abort", onAbort, { once: true });
							});
						if (terminal !== undefined) throw terminal;
						const result = new Uint8Array(Math.min(maxBytes, outputBytes));
						let offset = 0;
						while (output.length > 0 && offset < result.length) {
							const next = output[0]!;
							const take = Math.min(next.byteLength, result.length - offset);
							result.set(next.subarray(0, take), offset);
							offset += take;
							outputBytes -= take;
							if (take === next.byteLength) output.shift();
							else output[0] = next.slice(take);
						}
						return result;
					},
					async restart() {
						active = await enqueue(async () => {
							if (state !== "open" || terminal !== undefined)
								throw terminal ?? new Error("rootless Podman process is closed");
							await cleanupGeneration();
							if (state !== "open" || input.signal.aborted) throw new Error("rootless Podman restart cancelled");
							return await startGeneration();
						});
						attach(active);
					},
					close,
				});
			})().catch(async error => {
				await close();
				throw error;
			});
			return { service, terminate: close };
		},
	};
}

export function createRootlessPodmanProvider(): RootlessPodmanProvider {
	const route = solverRouteFor(CHALLENGE_ID);
	return makeProvider(CHALLENGE_ID, route.routeDigest, productionHarness(), true);
}

export function createRootlessPodmanProviderTestHarness(
	harness: RootlessPodmanProviderTestHarness,
): RootlessPodmanProvider {
	return makeProvider(TEST_CHALLENGE_ID, "test-only-not-a-reviewed-route", harness, false);
}
