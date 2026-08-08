import { describe, expect, it } from "bun:test";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import { PassThrough } from "node:stream";
import {
	createRootlessPodmanProvider,
	createRootlessPodmanProviderTestHarness,
	type RootlessPodmanProviderTestHarness,
} from "../../src/ctf/solver/rootless-podman-provider";
import { solverRouteFor } from "../../src/ctf/solver/router";

class FakeChild extends EventEmitter {
	readonly stdin = new PassThrough();
	readonly stdout = new PassThrough();
	kill(): boolean {
		queueMicrotask(() => this.emit("exit", 0));
		return true;
	}
}

function request(signal = new AbortController().signal) {
	const route = solverRouteFor("lactf-2026-pwn-tic-tac-no");
	const content = Uint8Array.from([0, 255]);
	return {
		signal,
		attemptLimits: route.attemptLimits,
		binding: { competitionId: "c", runId: "r", challengeId: route.challengeId, fencingToken: 1 },
		materialization: {
			provenanceDigest: "a".repeat(64),
			visibleFiles: [{ path: "chall", content, digest: createHash("sha256").update(content).digest("hex") }],
		},
	};
}

function testHarness(calls: string[][], runs: FakeChild[]): RootlessPodmanProviderTestHarness {
	return {
		run(argv) {
			calls.push([...argv]);
			const child = new FakeChild();
			if (argv[1] === "info") {
				queueMicrotask(() => {
					child.stdout.write("true\n");
					child.emit("exit", 0);
				});
			} else if (argv[1] === "image" || argv[1] === "rm") {
				queueMicrotask(() => child.emit("exit", 0));
			} else {
				runs.push(child);
				const cidfile = argv[argv.indexOf("--cidfile") + 1]!;
				queueMicrotask(() => {
					void fs.writeFile(cidfile, "a".repeat(64)).then(
						() => child.emit("spawn"),
						error => child.emit("error", error),
					);
				});
			}
			return child;
		},
	};
}

function normalized(argv: readonly string[]): string[] {
	return argv.map(value =>
		value
			.replace(/\/tmp\/gjc-pwn-[^/]+\/(chall|container\.cid)/u, "/private/$1")
			.replace(/gjc-ctf-[a-f0-9]{32}/u, "gjc-ctf-private"),
	);
}

describe("rootless Podman provider", () => {
	it("keeps production identity isolated from the injectable diagnostic harness", () => {
		const production = createRootlessPodmanProvider();
		const diagnostic = createRootlessPodmanProviderTestHarness(testHarness([], []));
		expect(production.challengeId).toBe("lactf-2026-pwn-tic-tac-no");
		expect(diagnostic.challengeId).not.toBe(production.challengeId);
		expect(diagnostic.routeDigest).not.toBe(production.routeDigest);
	});

	it("uses the canonical user home and allows a bounded slow preflight", async () => {
		let observedHome: string | undefined;
		const harness: RootlessPodmanProviderTestHarness = {
			run(argv, options) {
				observedHome = options.env.HOME;
				const child = new FakeChild();
				if (argv[1] === "info") {
					setTimeout(() => {
						child.stdout.write("true\n");
						child.emit("exit", 0);
					}, 300);
				} else if (argv[1] === "image" || argv[1] === "rm") {
					queueMicrotask(() => child.emit("exit", 0));
				} else {
					const cidfile = argv[argv.indexOf("--cidfile") + 1]!;
					queueMicrotask(() => {
						void fs.writeFile(cidfile, "a".repeat(64)).then(
							() => child.emit("spawn"),
							error => child.emit("error", error),
						);
					});
				}
				return child;
			},
		};
		const acquisition = createRootlessPodmanProviderTestHarness(harness).open(request());
		const service = await acquisition.service;
		expect(observedHome).toBe(await fs.realpath(os.homedir()));
		await Promise.all([service.close(), acquisition.terminate()]);
	});

	it("uses the full fixed local/rootless argv and supports serialized restart", async () => {
		const calls: string[][] = [];
		const runs: FakeChild[] = [];
		const acquisition = createRootlessPodmanProviderTestHarness(testHarness(calls, runs)).open(request());
		const service = await acquisition.service;
		const run = normalized(calls.find(call => call[1] === "run") ?? []);
		expect(run).toEqual([
			"--remote=false",
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
			"gjc-ctf-private",
			"--cidfile",
			"/private/container.cid",
			"--mount",
			"type=bind,src=/private/chall,dst=/app/chall,ro=true",
			"--workdir",
			"/tmp",
			"docker.io/library/debian@sha256:b5ace515e78743215a1b101a6f17e59ed74b17132139ca3af3c37e605205e973",
			"/app/chall",
		]);
		await Promise.all([service.restart(), service.restart()]);
		expect(calls.filter(call => call[1] === "info")).toHaveLength(3);
		expect(calls.filter(call => call[1] === "run")).toHaveLength(3);
		runs[0]!.stdout.write(Uint8Array.of(1));
		runs[2]!.stdout.write(Uint8Array.of(2));
		await Promise.resolve();
		expect(await service.receive({ maxBytes: 8, timeoutMs: 10 })).toEqual(Uint8Array.of(2));
		await Promise.all([service.close(), acquisition.terminate()]);
		expect(calls.some(call => call[1] === "rm" && call.includes("a".repeat(64)))).toBe(true);
	});

	it("copies binary I/O and makes overflow terminal", async () => {
		const calls: string[][] = [];
		const runs: FakeChild[] = [];
		const service = await createRootlessPodmanProviderTestHarness(testHarness(calls, runs)).open(request()).service;
		const child = runs[0]!;
		const written: Buffer[] = [];
		child.stdin.on("data", value => written.push(Buffer.from(value)));
		await service.send(Uint8Array.from([0, 255]));
		expect(written[0]).toEqual(Buffer.from([0, 255]));
		const bytes = Uint8Array.from([0, 255]);
		child.stdout.write(bytes);
		bytes[0] = 42;
		await Promise.resolve();
		expect(await service.receive({ maxBytes: 64 * 1024, timeoutMs: 1 })).toEqual(Uint8Array.from([0, 255]));
		child.stdout.write(new Uint8Array(64 * 1024 + 1));
		await Promise.resolve();
		await expect(service.send(new Uint8Array())).rejects.toThrow(/output exceeded bound/);
		await expect(service.receive({ maxBytes: 1, timeoutMs: 1 })).rejects.toThrow(/output exceeded bound/);
	});

	it("rejects cancellation and exact digest mismatch before launch", async () => {
		const calls: string[][] = [];
		const controller = new AbortController();
		controller.abort();
		await expect(
			createRootlessPodmanProviderTestHarness(testHarness(calls, [])).open(request(controller.signal)).service,
		).rejects.toThrow();
		const bad = request();
		bad.materialization.visibleFiles[0]!.digest = "b".repeat(64);
		await expect(createRootlessPodmanProviderTestHarness(testHarness(calls, [])).open(bad).service).rejects.toThrow(
			/digest/,
		);
	});
	it("fails closed when a fixed preflight helper returns nonzero", async () => {
		const harness: RootlessPodmanProviderTestHarness = {
			run(argv) {
				const child = new FakeChild();
				if (argv[1] === "info") {
					queueMicrotask(() => {
						child.stdout.write("true\n");
						child.emit("exit", 0);
					});
				} else {
					queueMicrotask(() => child.emit("exit", 1));
				}
				return child;
			},
		};
		await expect(createRootlessPodmanProviderTestHarness(harness).open(request()).service).rejects.toThrow(
			/preflight/,
		);
	});
	it("bounds a run that never spawns", async () => {
		const calls: string[][] = [];
		const harness: RootlessPodmanProviderTestHarness = {
			run(argv) {
				calls.push([...argv]);
				const child = new FakeChild();
				if (argv[1] === "info")
					queueMicrotask(() => {
						child.stdout.write("true\n");
						child.emit("exit", 0);
					});
				else if (argv[1] === "image") queueMicrotask(() => child.emit("exit", 0));
				return child;
			},
		};
		await expect(createRootlessPodmanProviderTestHarness(harness).open(request()).service).rejects.toThrow(
			/spawn timed out/,
		);
	});
	it("does not expose the service before a strict CID is captured", async () => {
		let cidfile: string | undefined;
		const harness: RootlessPodmanProviderTestHarness = {
			run(argv) {
				const child = new FakeChild();
				if (argv[1] === "info") {
					queueMicrotask(() => {
						child.stdout.write("true\n");
						child.emit("exit", 0);
					});
				} else if (argv[1] === "image" || argv[1] === "rm") {
					queueMicrotask(() => child.emit("exit", 0));
				} else {
					cidfile = argv[argv.indexOf("--cidfile") + 1];
					queueMicrotask(() => child.emit("spawn"));
				}
				return child;
			},
		};
		const acquisition = createRootlessPodmanProviderTestHarness(harness).open(request());
		let acquired = false;
		void acquisition.service.then(() => {
			acquired = true;
		});
		await Bun.sleep(20);
		expect(acquired).toBe(false);
		if (cidfile === undefined) throw new Error("test did not observe cidfile");
		await fs.writeFile(cidfile, `${"c".repeat(64)}\n`);
		const service = await acquisition.service;
		expect(acquired).toBe(true);
		await service.close();
	});
	it("preserves container identity and retries a failed removal", async () => {
		const calls: string[][] = [];
		let runDirectory: string | undefined;
		let removals = 0;
		const harness: RootlessPodmanProviderTestHarness = {
			run(argv, options) {
				calls.push([...argv]);
				const child = new FakeChild();
				if (argv[1] === "info") {
					queueMicrotask(() => {
						child.stdout.write("true\n");
						child.emit("exit", 0);
					});
				} else if (argv[1] === "image") {
					queueMicrotask(() => child.emit("exit", 0));
				} else if (argv[1] === "rm") {
					removals++;
					queueMicrotask(() => child.emit("exit", removals <= 2 ? 1 : 0));
				} else {
					runDirectory = options.cwd;
					const cidfile = argv[argv.indexOf("--cidfile") + 1]!;
					queueMicrotask(() => {
						void fs.writeFile(cidfile, "d".repeat(64)).then(
							() => child.emit("spawn"),
							error => child.emit("error", error),
						);
					});
				}
				return child;
			},
		};
		const acquisition = createRootlessPodmanProviderTestHarness(harness).open(request());
		const service = await acquisition.service;
		await expect(service.close()).resolves.toBeUndefined();
		if (runDirectory === undefined) throw new Error("test did not observe run directory");
		await expect(fs.lstat(runDirectory)).rejects.toMatchObject({ code: "ENOENT" });
		await expect(acquisition.terminate()).resolves.toBeUndefined();
		expect(calls.filter(call => call[1] === "rm").map(call => call.at(-1))).toEqual(Array(3).fill("d".repeat(64)));
	});
	it("uses the predetermined safe name when CID acquisition times out", async () => {
		const calls: string[][] = [];
		const harness: RootlessPodmanProviderTestHarness = {
			run(argv) {
				calls.push([...argv]);
				const child = new FakeChild();
				if (argv[1] === "info") {
					queueMicrotask(() => {
						child.stdout.write("true\n");
						child.emit("exit", 0);
					});
				} else if (argv[1] === "image" || argv[1] === "rm") {
					queueMicrotask(() => child.emit("exit", 0));
				} else {
					queueMicrotask(() => child.emit("spawn"));
				}
				return child;
			},
		};
		await expect(createRootlessPodmanProviderTestHarness(harness).open(request()).service).rejects.toThrow(
			/cidfile timed out/,
		);
		expect(calls.find(call => call[1] === "rm")?.at(-1)).toMatch(/^gjc-ctf-[a-f0-9]{32}$/u);
	});
	it("rejects normal exit and receive after close", async () => {
		const calls: string[][] = [];
		const runs: FakeChild[] = [];
		const service = await createRootlessPodmanProviderTestHarness(testHarness(calls, runs)).open(request()).service;
		runs[0]!.emit("exit", 0);
		await Promise.resolve();
		await expect(service.send(new Uint8Array())).rejects.toThrow(/process exited/);
		await service.close();
		await expect(service.receive({ maxBytes: 1, timeoutMs: 10_000 })).rejects.toThrow();
	});
	it("attempts captured-CID removal despite an unreaped child", async () => {
		const calls: string[][] = [];
		let runDirectory: string | undefined;
		const harness: RootlessPodmanProviderTestHarness = {
			run(argv, options) {
				calls.push([...argv]);
				const child = new FakeChild();
				if (argv[1] === "info") {
					queueMicrotask(() => {
						child.stdout.write("true\n");
						child.emit("exit", 0);
					});
				} else if (argv[1] === "image" || argv[1] === "rm") {
					queueMicrotask(() => child.emit("exit", 0));
				} else {
					runDirectory = options.cwd;
					const cidfile = argv[argv.indexOf("--cidfile") + 1]!;
					child.kill = () => true;
					queueMicrotask(() => {
						void fs.writeFile(cidfile, "e".repeat(64)).then(
							() => child.emit("spawn"),
							error => child.emit("error", error),
						);
					});
				}
				return child;
			},
		};
		const service = await createRootlessPodmanProviderTestHarness(harness).open(request()).service;
		await expect(service.close()).rejects.toThrow(/did not reap/);
		expect(calls.filter(call => call[1] === "rm").map(call => call.at(-1))).toEqual(["e".repeat(64)]);
		if (runDirectory === undefined) throw new Error("test did not observe run directory");
		await expect(fs.lstat(runDirectory)).resolves.toBeDefined();
	});
});
