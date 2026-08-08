import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { type Digest, sha256Hex } from "../../src/ctf/contracts/digest";
import { type CtfSolverRequest, scheduleCtfRuns } from "../../src/ctf/runtime/scheduler";
import {
	createLocalCtfSolverBackend,
	createLocalCtfSolverFixtureBackend,
	type LocalSolverAnalyzerLifecycle,
	type LocalSolverAnalyzerResult,
	type LocalSolverSession,
	type LocalSolverSessionInput,
	type LocalSolverSessionResult,
} from "../../src/ctf/solver/local-backend";
import { solverRouteFor } from "../../src/ctf/solver/router";
import { makeDescriptor } from "./fixtures";

const sessionLifecycle = (session: LocalSolverSession) => ({
	session: Promise.resolve(session),
	terminate: async () => {},
	quiesced: Promise.resolve(),
});
const analyzerLifecycle = (
	result: LocalSolverAnalyzerResult | Promise<LocalSolverAnalyzerResult>,
	quiesced: Promise<void> = Promise.resolve(),
	terminate: LocalSolverAnalyzerLifecycle["terminate"] = async () => {},
): LocalSolverAnalyzerLifecycle => ({
	result: Promise.resolve(result),
	terminate,
	quiesced,
});
const visibleDigest = (content: string): Digest => sha256Hex(content);
const request = (
	challengeId = "challenge-1",
	root = ".",
	visibleFileDigests: Readonly<Record<string, Digest>> = { "answer.txt": visibleDigest("visible") },
): CtfSolverRequest => ({
	runId: "run-1",
	challengeId,
	mode: "benchmark",
	backendId: "local-gjc-agent",
	signal: new AbortController().signal,
	materialized: { root, provenanceDigest: sha256Hex("materialized"), visibleFileDigests },
	authority: {
		competitionId: "competition-1",
		fencingToken: 1,
		intentId: "intent-1",
		skillDigest: sha256Hex("skill"),
		sandboxPolicyDigest: sha256Hex("sandbox-policy"),
	},
});

describe("local GJC solver backend", () => {
	it("passes only materialized visible files to an injected agent and retains a candidate", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-local-"));
		const artifactRoot = path.join(root, "artifacts");
		await fs.mkdir(artifactRoot);
		await fs.writeFile(path.join(root, "answer.txt"), "visible");
		await fs.writeFile(path.join(root, "secret.txt"), "must not be exposed");
		const seen: LocalSolverSessionInput[] = [];
		const backend = createLocalCtfSolverBackend({
			root,
			artifactRoot,
			challenges: new Map([
				[
					"lactf-2026-crypto-not-so-lazy-trigrams",
					makeDescriptor({
						id: "lactf-2026-crypto-not-so-lazy-trigrams",
						visibleArtifactAllowlist: ["answer.txt"],
					}),
				],
			]),
			analyzers: [
				{
					id: "not-so-lazy-trigrams",
					analyze: input =>
						analyzerLifecycle(
							(async () => {
								if (input.attempt === 0) {
									await input.runCapability.writeScratch("discarded-scratch.bin", Uint8Array.of(1));
									await input.runCapability.publish("discarded.bin", Uint8Array.of(2));
								}
								return { status: "not-applicable" };
							})(),
						),
				},
			],
			createSession: () =>
				sessionLifecycle({
					solve: async input => {
						seen.push(input);
						expect(await input.runCapability.readScratch("discarded-scratch.bin")).toBeUndefined();
						await input.runCapability.publish("accepted.bin", Uint8Array.of(3));
						return { candidate: "candidate-value" };
					},
				}),
		});
		await expect(backend.solve(request("lactf-2026-crypto-not-so-lazy-trigrams", root))).resolves.toMatchObject({
			status: "candidate",
			artifacts: ["run-1/candidate.txt", "run-1/accepted.bin"],
			artifactEvidence: [
				{
					path: "run-1/candidate.txt",
					digest: visibleDigest("candidate-value"),
					size: Buffer.byteLength("candidate-value"),
				},
				{
					path: "run-1/accepted.bin",
					digest: sha256Hex(Uint8Array.of(3)),
					size: 1,
				},
			],
		});
		expect(seen[0]?.visibleFiles.map(file => file.path)).toEqual(["answer.txt"]);
		expect(seen[0]?.attempt).toBe(1);
		expect(seen[0]?.retryFeedback).toEqual({
			schemaVersion: "ctf-solver-feedback-1",
			attempt: 0,
			code: "analyzers_not_applicable",
		});
		expect(await fs.readFile(path.join(root, "artifacts/run-1/candidate.txt"), "utf8")).toBe("candidate-value");
		await expect(fs.readFile(path.join(root, "artifacts/run-1/discarded.bin"))).rejects.toThrow();
	});

	it("runs reviewed analyzers before the agent and falls through only when no analyzer recognizes input", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-local-"));
		const artifactRoot = path.join(root, "artifacts");
		await fs.mkdir(artifactRoot);
		await fs.writeFile(path.join(root, "answer.txt"), "visible");
		let agentInvocations = 0;
		const backend = createLocalCtfSolverBackend({
			root,
			artifactRoot,
			challenges: new Map([
				[
					"lactf-2026-misc-endians",
					makeDescriptor({ id: "lactf-2026-misc-endians", visibleArtifactAllowlist: ["answer.txt"] }),
				],
			]),
			analyzers: [
				{
					id: "endians",
					analyze: () => analyzerLifecycle({ status: "candidate", result: { candidate: "analyzer-candidate" } }),
				},
			],
			createSession: () =>
				sessionLifecycle({
					solve: async () => {
						agentInvocations++;
						return { candidate: "agent-candidate" };
					},
				}),
		});
		await expect(backend.solve(request("lactf-2026-misc-endians", root))).resolves.toMatchObject({
			status: "candidate",
			artifacts: ["run-1/candidate.txt"],
			artifactEvidence: [
				{
					path: "run-1/candidate.txt",
					digest: visibleDigest("analyzer-candidate"),
					size: Buffer.byteLength("analyzer-candidate"),
				},
			],
		});
		expect(agentInvocations).toBe(0);
		expect(await fs.readFile(path.join(artifactRoot, "run-1/candidate.txt"), "utf8")).toBe("analyzer-candidate");
	});
	it("selects only the route-declared analyzer regardless of registration order and binds private route input", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-local-"));
		const artifactRoot = path.join(root, "artifacts");
		await fs.mkdir(artifactRoot);
		await fs.writeFile(path.join(root, "answer.txt"), "visible");
		const calls: string[] = [];
		const backend = createLocalCtfSolverBackend({
			root,
			artifactRoot,
			challenges: new Map([
				[
					"lactf-2026-misc-endians",
					makeDescriptor({ id: "lactf-2026-misc-endians", visibleArtifactAllowlist: ["answer.txt"] }),
				],
			]),
			analyzers: [
				{
					id: "ooo-recurrence",
					analyze: () => {
						calls.push("ooo");
						return analyzerLifecycle({ status: "not-applicable" });
					},
				},
				{
					id: "endians",
					analyze: input => {
						calls.push("endians");
						expect(input).not.toHaveProperty("root");
						expect(input).not.toHaveProperty("artifactRoot");
						expect(input.routeDigest).toBe(solverRouteFor("lactf-2026-misc-endians").routeDigest);
						expect(input.analyzerIds).toEqual(["endians"]);
						return analyzerLifecycle({ status: "candidate", result: { candidate: "route-candidate" } });
					},
				},
			],
			createSession: () => sessionLifecycle({ solve: async () => ({ candidate: "agent-candidate" }) }),
		});
		await expect(backend.solve(request("lactf-2026-misc-endians", root))).resolves.toMatchObject({
			status: "candidate",
		});
		expect(calls).toEqual(["endians"]);
	});

	it("fails closed for missing, duplicate, unknown, and tampered reviewed analyzer routes", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-local-"));
		const artifactRoot = path.join(root, "artifacts");
		await fs.mkdir(artifactRoot);
		await fs.writeFile(path.join(root, "answer.txt"), "visible");
		const descriptor = makeDescriptor({
			id: "lactf-2026-misc-endians",
			visibleArtifactAllowlist: ["answer.txt"],
		});
		const base = {
			root,
			artifactRoot,
			challenges: new Map([["lactf-2026-misc-endians", descriptor]]),
			createSession: () => sessionLifecycle({ solve: async () => ({ candidate: "agent-candidate" }) }),
		};
		const missing = createLocalCtfSolverBackend(base);
		await expect(missing.solve(request("lactf-2026-misc-endians", root))).resolves.toMatchObject({
			status: "blocked",
		});
		expect(() =>
			createLocalCtfSolverBackend({
				...base,
				analyzers: [
					{ id: "endians", analyze: () => analyzerLifecycle({ status: "not-applicable" }) },
					{ id: "endians", analyze: () => analyzerLifecycle({ status: "not-applicable" }) },
				],
			}),
		).toThrow(/more than once/);
		expect(() =>
			createLocalCtfSolverBackend({
				...base,
				analyzers: [{ id: "unknown", analyze: () => analyzerLifecycle({ status: "not-applicable" }) }],
			}),
		).toThrow(/not declared/);
		const backend = createLocalCtfSolverBackend({
			...base,
			analyzers: [{ id: "endians", analyze: () => analyzerLifecycle({ status: "not-applicable" }) }],
		});
		const tampered = structuredClone(solverRouteFor("lactf-2026-misc-endians")) as Record<string, unknown>;
		tampered.modelPattern = "tampered";
		await expect(
			backend.solve({
				...request("lactf-2026-misc-endians", root),
				materialized: {
					...request("lactf-2026-misc-endians", root).materialized,
					solverRoute: tampered,
				} as never,
			}),
		).resolves.toMatchObject({ status: "blocked" });
	});
	it("does not allow a fixture descriptor to enable an unreviewed production route", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-local-"));
		const artifactRoot = path.join(root, "artifacts");
		await fs.mkdir(artifactRoot);
		await fs.writeFile(path.join(root, "answer.txt"), "visible");
		let invoked = false;
		const backend = createLocalCtfSolverBackend({
			root,
			artifactRoot,
			challenges: new Map([["fixture-only", makeDescriptor({ id: "fixture-only" })]]),
			createSession: () => {
				invoked = true;
				return sessionLifecycle({ solve: async () => ({ candidate: "unexpected" }) });
			},
		});

		await expect(backend.solve(request("fixture-only", root))).resolves.toMatchObject({
			status: "blocked",
			reason: "challenge solver route is not reviewed",
		});
		expect(invoked).toBe(false);
	});

	it("fails closed for browser routes before matching or invoking a provider", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-local-"));
		const artifactRoot = path.join(root, "artifacts");
		await fs.mkdir(artifactRoot);
		await fs.writeFile(path.join(root, "answer.txt"), "visible");
		let providerOpened = false;
		let sessionCreated = false;
		const route = solverRouteFor("lactf-2026-web-single-trust");
		const backend = createLocalCtfSolverBackend({
			root,
			artifactRoot,
			challenges: new Map([
				[
					"lactf-2026-web-single-trust",
					makeDescriptor({ id: "lactf-2026-web-single-trust", visibleArtifactAllowlist: ["answer.txt"] }),
				],
			]),
			adapterProviders: [
				{
					challengeId: route.challengeId,
					routeDigest: route.routeDigest,
					adapterKind: "browser-session",
					open: () => {
						providerOpened = true;
						throw new Error("provider must not open");
					},
				},
			],
			createSession: () => {
				sessionCreated = true;
				return sessionLifecycle({ solve: async () => ({ candidate: "unexpected" }) });
			},
		});

		await expect(backend.solve(request("lactf-2026-web-single-trust", root))).resolves.toMatchObject({
			status: "blocked",
			reason: "browser-session routes are disabled",
		});
		expect(providerOpened).toBe(false);
		expect(sessionCreated).toBe(false);
	});

	it("does not solve after adapter acquisition or session creation completes after cancellation", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-local-"));
		const artifactRoot = path.join(root, "artifacts");
		await fs.mkdir(artifactRoot);
		await fs.writeFile(path.join(root, "answer.txt"), "visible");
		const controller = new AbortController();
		const route = solverRouteFor("lactf-2026-pwn-tic-tac-no");
		const lateSession = Promise.withResolvers<LocalSolverSession>();
		let adapterOpened = false;
		let solved = false;
		const backend = createLocalCtfSolverBackend({
			root,
			artifactRoot,
			challenges: new Map([
				[
					"lactf-2026-pwn-tic-tac-no",
					makeDescriptor({ id: "lactf-2026-pwn-tic-tac-no", visibleArtifactAllowlist: ["answer.txt"] }),
				],
			]),
			adapterProviders: [
				{
					challengeId: route.challengeId,
					routeDigest: route.routeDigest,
					adapterKind: "process-service",
					open: () => {
						adapterOpened = true;
						return {
							service: Promise.resolve({
								send: async () => {},
								receive: async () => new Uint8Array(),
								restart: async () => {},
								close: async () => {},
							}),
							terminate: async () => {},
						};
					},
				},
			],
			createSession: () => {
				controller.abort("cancelled during session creation");
				return {
					session: lateSession.promise,
					terminate: async () =>
						lateSession.resolve({
							solve: async () => {
								solved = true;
								return { candidate: "unexpected" };
							},
						}),
					quiesced: Promise.resolve(),
				};
			},
		});

		await expect(
			backend.solve({ ...request("lactf-2026-pwn-tic-tac-no", root), signal: controller.signal }),
		).resolves.toMatchObject({ status: "cancelled" });
		expect(adapterOpened).toBe(true);
		expect(solved).toBe(false);
	});
	it("fails closed when a cancelled session lifecycle never produces or quiesces", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-local-"));
		const artifactRoot = path.join(root, "artifacts");
		await fs.mkdir(artifactRoot);
		await fs.writeFile(path.join(root, "answer.txt"), "visible");
		const controller = new AbortController();
		const backend = createLocalCtfSolverBackend({
			root,
			artifactRoot,
			challenges: new Map([
				[
					"lactf-2026-crypto-not-so-lazy-trigrams",
					makeDescriptor({
						id: "lactf-2026-crypto-not-so-lazy-trigrams",
						visibleArtifactAllowlist: ["answer.txt"],
					}),
				],
			]),
			analyzers: [{ id: "not-so-lazy-trigrams", analyze: () => analyzerLifecycle({ status: "not-applicable" }) }],
			createSession: () => {
				controller.abort("cancelled while session creation is pending");
				return {
					session: new Promise<never>(() => undefined),
					terminate: async () => {},
					quiesced: new Promise<never>(() => undefined),
				};
			},
		});

		await expect(
			backend.solve({ ...request("lactf-2026-crypto-not-so-lazy-trigrams", root), signal: controller.signal }),
		).resolves.toMatchObject({ status: "failed", reason: expect.stringMatching(/quiescence/) });
	});
	it("fails closed when analyzer lifecycle quiescence hangs or rejects", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-local-"));
		const artifactRoot = path.join(root, "artifacts");
		await fs.mkdir(artifactRoot);
		await fs.writeFile(path.join(root, "answer.txt"), "visible");
		for (const createQuiescence of [
			() => new Promise<void>(() => undefined),
			() => Promise.reject(new Error("analyzer quiescence rejected")),
		]) {
			let terminated = false;
			const backend = createLocalCtfSolverBackend({
				root,
				artifactRoot,
				challenges: new Map([
					[
						"lactf-2026-misc-endians",
						makeDescriptor({ id: "lactf-2026-misc-endians", visibleArtifactAllowlist: ["answer.txt"] }),
					],
				]),
				analyzers: [
					{
						id: "endians",
						analyze: () =>
							analyzerLifecycle(
								{ status: "candidate", result: { candidate: "candidate" } },
								createQuiescence(),
								async () => {
									terminated = true;
								},
							),
					},
				],
				createSession: () => sessionLifecycle({ solve: async () => ({ candidate: "unexpected" }) }),
			});
			await expect(backend.solve(request("lactf-2026-misc-endians", root))).resolves.toMatchObject({
				status: "failed",
				reason: expect.stringMatching(/analyzer .*quiescence/),
			});
			expect(terminated).toBe(true);
			await expect(fs.access(path.join(artifactRoot, "run-1"))).rejects.toThrow();
		}
	});
	it("terminates and joins an aborted analyzer lifecycle", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-local-"));
		const artifactRoot = path.join(root, "artifacts");
		await fs.mkdir(artifactRoot);
		await fs.writeFile(path.join(root, "answer.txt"), "visible");
		const controller = new AbortController();
		const quiescence = Promise.withResolvers<void>();
		let terminated = false;
		const backend = createLocalCtfSolverBackend({
			root,
			artifactRoot,
			challenges: new Map([
				[
					"lactf-2026-misc-endians",
					makeDescriptor({ id: "lactf-2026-misc-endians", visibleArtifactAllowlist: ["answer.txt"] }),
				],
			]),
			analyzers: [
				{
					id: "endians",
					analyze: () => {
						queueMicrotask(() => controller.abort("cancelled"));
						return {
							result: new Promise<never>(() => undefined),
							terminate: async () => {
								terminated = true;
								quiescence.resolve();
							},
							quiesced: quiescence.promise,
						};
					},
				},
			],
			createSession: () => sessionLifecycle({ solve: async () => ({ candidate: "unexpected" }) }),
		});
		await expect(
			backend.solve({ ...request("lactf-2026-misc-endians", root), signal: controller.signal }),
		).resolves.toMatchObject({ status: "cancelled" });
		expect(terminated).toBe(true);
	});
	it("rejects raw analyzer promises", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-local-"));
		const artifactRoot = path.join(root, "artifacts");
		await fs.mkdir(artifactRoot);
		await fs.writeFile(path.join(root, "answer.txt"), "visible");
		const backend = createLocalCtfSolverBackend({
			root,
			artifactRoot,
			challenges: new Map([
				[
					"lactf-2026-misc-endians",
					makeDescriptor({ id: "lactf-2026-misc-endians", visibleArtifactAllowlist: ["answer.txt"] }),
				],
			]),
			analyzers: [
				{
					id: "endians",
					analyze: (() => Promise.reject(new Error("raw analyzer rejection"))) as never,
				},
			],
			createSession: () => sessionLifecycle({ solve: async () => ({ candidate: "unexpected" }) }),
		});
		await expect(backend.solve(request("lactf-2026-misc-endians", root))).resolves.toMatchObject({
			status: "failed",
			reason: expect.stringMatching(/lifecycle is invalid/),
		});
	});
	it("waits for normal session quiescence before publishing late writer artifacts", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-local-"));
		const artifactRoot = path.join(root, "artifacts");
		await fs.mkdir(artifactRoot);
		await fs.writeFile(path.join(root, "answer.txt"), "visible");
		const quiescence = Promise.withResolvers<void>();
		const backend = createLocalCtfSolverBackend({
			root,
			artifactRoot,
			challenges: new Map([
				[
					"lactf-2026-misc-endians",
					makeDescriptor({ id: "lactf-2026-misc-endians", visibleArtifactAllowlist: ["answer.txt"] }),
				],
			]),
			analyzers: [{ id: "endians", analyze: () => analyzerLifecycle({ status: "not-applicable" }) }],
			createSession: () => ({
				session: Promise.resolve({
					solve: async input => {
						queueMicrotask(() => {
							void input.runCapability
								.publish("late.txt", new TextEncoder().encode("late"))
								.then(() => quiescence.resolve());
						});
						return { candidate: "candidate" };
					},
				}),
				terminate: async () => {},
				quiesced: quiescence.promise,
			}),
		});
		await expect(backend.solve(request("lactf-2026-misc-endians", root))).resolves.toMatchObject({
			status: "candidate",
			artifacts: expect.arrayContaining(["run-1/late.txt"]),
		});
	});
	it("terminates a session when successful-result quiescence fails", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-local-"));
		const artifactRoot = path.join(root, "artifacts");
		await fs.mkdir(artifactRoot);
		await fs.writeFile(path.join(root, "answer.txt"), "visible");
		let terminated = false;
		const backend = createLocalCtfSolverBackend({
			root,
			artifactRoot,
			challenges: new Map([
				[
					"lactf-2026-misc-endians",
					makeDescriptor({ id: "lactf-2026-misc-endians", visibleArtifactAllowlist: ["answer.txt"] }),
				],
			]),
			analyzers: [{ id: "endians", analyze: () => analyzerLifecycle({ status: "not-applicable" }) }],
			createSession: () => ({
				session: Promise.resolve({ solve: async () => ({ candidate: "candidate" }) }),
				terminate: async () => {
					terminated = true;
				},
				quiesced: Promise.reject(new Error("session quiescence rejected")),
			}),
		});
		await expect(backend.solve(request("lactf-2026-misc-endians", root))).resolves.toMatchObject({
			status: "failed",
			reason: expect.stringMatching(/session quiescence/),
		});
		expect(terminated).toBe(true);
		await expect(fs.access(path.join(artifactRoot, "run-1"))).rejects.toThrow();
	});
	it("lets cancellation during adapter cleanup win before a diagnostic retry", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-local-"));
		const artifactRoot = path.join(root, "artifacts");
		await fs.mkdir(artifactRoot);
		await fs.writeFile(path.join(root, "answer.txt"), "visible");
		const controller = new AbortController();
		const route = solverRouteFor("lactf-2026-pwn-tic-tac-no");
		let sessionCreations = 0;
		const backend = createLocalCtfSolverBackend({
			root,
			artifactRoot,
			challenges: new Map([
				[
					"lactf-2026-pwn-tic-tac-no",
					makeDescriptor({ id: "lactf-2026-pwn-tic-tac-no", visibleArtifactAllowlist: ["answer.txt"] }),
				],
			]),
			adapterProviders: [
				{
					challengeId: route.challengeId,
					routeDigest: route.routeDigest,
					adapterKind: "process-service",
					open: () => ({
						service: Promise.resolve({
							send: async () => {},
							receive: async () => new Uint8Array(),
							restart: async () => {},
							close: async () => controller.abort("cancelled during adapter cleanup"),
						}),
						terminate: async () => {},
					}),
				},
			],
			createSession: () => {
				sessionCreations++;
				return sessionLifecycle({ solve: async () => ({ candidate: " " }) });
			},
		});

		await expect(
			backend.solve({ ...request("lactf-2026-pwn-tic-tac-no", root), signal: controller.signal }),
		).resolves.toMatchObject({ status: "cancelled" });
		expect(sessionCreations).toBe(1);
	});
	it("fails closed when evaluation adapter cleanup does not quiesce", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-local-"));
		const artifactRoot = path.join(root, "artifacts");
		await fs.mkdir(artifactRoot);
		await fs.writeFile(path.join(root, "answer.txt"), "visible");
		const route = solverRouteFor("lactf-2026-pwn-tic-tac-no");
		const backend = createLocalCtfSolverBackend({
			root,
			artifactRoot,
			challenges: new Map([
				[
					"lactf-2026-pwn-tic-tac-no",
					makeDescriptor({ id: "lactf-2026-pwn-tic-tac-no", visibleArtifactAllowlist: ["answer.txt"] }),
				],
			]),
			adapterProviders: [
				{
					challengeId: route.challengeId,
					routeDigest: route.routeDigest,
					adapterKind: "process-service",
					open: () => ({
						service: Promise.resolve({
							send: async () => {},
							receive: async () => new Uint8Array(),
							restart: async () => {},
							close: async () => await new Promise<never>(() => undefined),
						}),
						terminate: async () => {},
					}),
				},
			],
			createSession: () => sessionLifecycle({ solve: async () => ({ candidate: "candidate" }) }),
		});

		await expect(backend.solve(request("lactf-2026-pwn-tic-tac-no", root))).resolves.toMatchObject({
			status: "failed",
		});
	});

	it("fails closed for an unmaterialized or forbidden visible file", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-local-"));
		const descriptor = makeDescriptor({ id: "challenge-1", visibleArtifactAllowlist: ["solve.py"] });
		const backend = createLocalCtfSolverFixtureBackend({
			root,
			artifactRoot: path.join(root, "artifacts"),
			challenges: new Map([["challenge-1", descriptor]]),
			createSession: async () => ({ solve: async () => ({ candidate: "not called" }) }),
		});
		await expect(backend.solve(request("challenge-1", root))).resolves.toMatchObject({ status: "failed" });
	});

	it("rejects network-enabled descriptors and incomplete authority without invoking the agent", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-local-"));
		let invoked = false;
		const descriptor = makeDescriptor({ id: "challenge-1" });
		const backend = createLocalCtfSolverFixtureBackend({
			root,
			artifactRoot: path.join(root, "artifacts"),
			challenges: new Map([["challenge-1", descriptor]]),
			createSession: async () => {
				invoked = true;
				return { solve: async () => ({ candidate: "x" }) };
			},
		});
		await expect(
			backend.solve({
				...request("challenge-1", root),
				authority: { ...request("challenge-1", root).authority, intentId: "" },
			}),
		).resolves.toMatchObject({ status: "blocked" });
		expect(invoked).toBe(false);
	});
	it("propagates analyzer refusal and cancellation without invoking the agent", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-local-"));
		await fs.writeFile(path.join(root, "answer.txt"), "visible");
		await fs.mkdir(path.join(root, "artifacts"));
		for (const outcome of [
			{ status: "refused" as const, reason: "unsafe input" },
			{ status: "cancelled" as const, reason: "budget exhausted" },
		]) {
			let invoked = false;
			const backend = createLocalCtfSolverBackend({
				root,
				artifactRoot: path.join(root, "artifacts"),
				challenges: new Map([
					[
						"lactf-2026-misc-endians",
						makeDescriptor({ id: "lactf-2026-misc-endians", visibleArtifactAllowlist: ["answer.txt"] }),
					],
				]),
				analyzers: [{ id: "endians", analyze: () => analyzerLifecycle(outcome) }],
				createSession: () => {
					invoked = true;
					return sessionLifecycle({ solve: async () => ({ candidate: "x" }) });
				},
			});
			await expect(backend.solve(request("lactf-2026-misc-endians", root))).resolves.toMatchObject(
				outcome.status === "refused"
					? { status: "blocked", terminalKind: "terminal_refusal" }
					: { status: "cancelled" },
			);
			expect(invoked).toBe(false);
		}
	});

	it("rejects invalid authority, symlink input, aggregate input, oversized candidates, and duplicate artifacts", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-local-"));
		const artifactRoot = path.join(root, "artifacts");
		await fs.mkdir(artifactRoot);
		await fs.writeFile(path.join(root, "answer.txt"), "visible");
		const backend = (
			descriptor = makeDescriptor({ id: "challenge-1", visibleArtifactAllowlist: ["answer.txt"] }),
			result: LocalSolverSessionResult = { candidate: "x" },
		) =>
			createLocalCtfSolverFixtureBackend({
				root,
				artifactRoot,
				challenges: new Map([["challenge-1", descriptor]]),
				createSession: async () => ({ solve: async () => result }),
			});
		await expect(
			backend().solve({ ...request("challenge-1", root), authority: { ...request().authority, fencingToken: 0 } }),
		).resolves.toMatchObject({ status: "blocked" });
		await fs.symlink(path.join(root, "answer.txt"), path.join(root, "linked.txt"));
		await expect(
			backend(makeDescriptor({ id: "challenge-1", visibleArtifactAllowlist: ["linked.txt"] })).solve(
				request("challenge-1", root, { "linked.txt": visibleDigest("visible") }),
			),
		).resolves.toMatchObject({ status: "failed" });
		await expect(
			backend(undefined, { candidate: "x".repeat(64 * 1024 + 1) }).solve(request("challenge-1", root)),
		).resolves.toMatchObject({ status: "failed" });
		await expect(
			backend(undefined, {
				candidate: "x",
				artifacts: [{ path: "candidate.txt", content: new Uint8Array([1]) }],
			}).solve(request("challenge-1", root)),
		).resolves.toMatchObject({ status: "failed" });
	});
	it("requires exact materialized digests and rejects aggregate input overflow or artifact-root symlink escape", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-local-"));
		const artifactRoot = path.join(root, "artifacts");
		await fs.mkdir(artifactRoot);
		const names = Array.from({ length: 5 }, (_, index) => `input-${index}.txt`);
		const content = "x".repeat(256 * 1024);
		for (const name of names) await fs.writeFile(path.join(root, name), content);
		const descriptor = makeDescriptor({ id: "challenge-1", visibleArtifactAllowlist: names });
		const backend = createLocalCtfSolverFixtureBackend({
			root,
			artifactRoot,
			challenges: new Map([["challenge-1", descriptor]]),
			createSession: async () => ({ solve: async () => ({ candidate: "x" }) }),
		});
		const digests = Object.fromEntries(names.map(name => [name, visibleDigest(content)]));
		await expect(backend.solve(request("challenge-1", root, digests))).resolves.toMatchObject({ status: "failed" });
		await expect(
			backend.solve(request("challenge-1", root, { [names[0]]: visibleDigest(content) })),
		).resolves.toMatchObject({ status: "failed" });
		await fs.rm(artifactRoot, { recursive: true });
		await fs.symlink("/tmp", artifactRoot);
		const one = makeDescriptor({ id: "challenge-1", visibleArtifactAllowlist: [names[0]] });
		const escaped = createLocalCtfSolverFixtureBackend({
			root,
			artifactRoot,
			challenges: new Map([["challenge-1", one]]),
			createSession: async () => ({ solve: async () => ({ candidate: "x" }) }),
		});
		await expect(
			escaped.solve(request("challenge-1", root, { [names[0]]: visibleDigest(content) })),
		).resolves.toMatchObject({ status: "failed" });
	});
	it("joins a cancellation-ignoring session and removes its late artifacts", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-local-"));
		const artifactRoot = path.join(root, "artifacts");
		await fs.mkdir(artifactRoot);
		await fs.writeFile(path.join(root, "answer.txt"), "visible");
		const started = Promise.withResolvers<void>();
		const release = Promise.withResolvers<LocalSolverSessionResult>();
		const backend = createLocalCtfSolverFixtureBackend({
			root,
			artifactRoot,
			challenges: new Map([
				["challenge-1", makeDescriptor({ id: "challenge-1", visibleArtifactAllowlist: ["answer.txt"] })],
			]),
			createSession: async () => ({
				solve: async () => {
					started.resolve();
					return await release.promise;
				},
				terminate: async () => {},
			}),
		});
		const run = backend.solve(request("challenge-1", root));
		await started.promise;
		const termination = backend.terminate?.({
			runId: "run-1",
			challengeId: "challenge-1",
			ownerId: "run-1",
			competitionId: "competition-1",
			fencingToken: 1,
			reason: "cancelled",
		});
		release.resolve({ candidate: "late" });
		await termination;
		await expect(run).resolves.toMatchObject({ status: "cancelled" });
		await expect(fs.stat(path.join(artifactRoot, "run-1"))).rejects.toThrow();
	});
	it("rejects traversal, historical artifact reuse, and mismatched termination identity without deleting evidence", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-local-"));
		const artifactRoot = path.join(root, "artifacts");
		await fs.mkdir(path.join(artifactRoot, "historical-run"), { recursive: true });
		await fs.writeFile(path.join(artifactRoot, "historical-run", "candidate.txt"), "retained");
		await fs.writeFile(path.join(root, "answer.txt"), "visible");
		const started = Promise.withResolvers<void>();
		const release = Promise.withResolvers<LocalSolverSessionResult>();
		const backend = createLocalCtfSolverFixtureBackend({
			root,
			artifactRoot,
			challenges: new Map([
				["challenge-1", makeDescriptor({ id: "challenge-1", visibleArtifactAllowlist: ["answer.txt"] })],
			]),
			createSession: async () => ({
				solve: async () => {
					started.resolve();
					return await release.promise;
				},
				terminate: async () => release.resolve({ candidate: "late" }),
			}),
		});
		const traversal = { ...request("challenge-1", root), runId: "../historical-run" };
		await expect(backend.solve(traversal)).resolves.toMatchObject({ status: "blocked" });
		await backend.terminate?.({
			runId: traversal.runId,
			challengeId: "challenge-1",
			ownerId: traversal.runId,
			competitionId: "competition-1",
			fencingToken: 1,
			reason: "cancelled",
		});
		expect(await fs.readFile(path.join(artifactRoot, "historical-run", "candidate.txt"), "utf8")).toBe("retained");

		const historical = { ...request("challenge-1", root), runId: "historical-run" };
		await expect(backend.solve(historical)).resolves.toMatchObject({ status: "blocked" });
		expect(await fs.readFile(path.join(artifactRoot, "historical-run", "candidate.txt"), "utf8")).toBe("retained");

		const active = backend.solve(request("challenge-1", root));
		await started.promise;
		await expect(
			backend.terminate?.({
				runId: "run-1",
				challengeId: "other-challenge",
				ownerId: "run-1",
				competitionId: "competition-1",
				fencingToken: 1,
				reason: "cancelled",
			}),
		).rejects.toThrow(/identity/);
		await expect(
			backend.terminate?.({
				runId: "run-1",
				challengeId: "challenge-1",
				ownerId: "run-1",
				competitionId: "other-competition",
				fencingToken: 1,
				reason: "cancelled",
			}),
		).rejects.toThrow(/identity/);
		await expect(
			backend.terminate?.({
				runId: "run-1",
				challengeId: "challenge-1",
				ownerId: "run-1",
				competitionId: "competition-1",
				fencingToken: 2,
				reason: "cancelled",
			}),
		).rejects.toThrow(/identity/);
		await backend.terminate?.({
			runId: "run-1",
			challengeId: "challenge-1",
			ownerId: "run-1",
			competitionId: "competition-1",
			fencingToken: 1,
			reason: "cancelled",
		});
		await expect(active).resolves.toMatchObject({ status: "cancelled" });
	});
	it("surfaces rejected session termination without waiting for a non-settling solve", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-local-"));
		const artifactRoot = path.join(root, "artifacts");
		await fs.mkdir(artifactRoot);
		await fs.writeFile(path.join(root, "answer.txt"), "visible");
		const started = Promise.withResolvers<void>();
		const release = Promise.withResolvers<LocalSolverSessionResult>();
		const backend = createLocalCtfSolverFixtureBackend({
			root,
			artifactRoot,
			challenges: new Map([
				["challenge-1", makeDescriptor({ id: "challenge-1", visibleArtifactAllowlist: ["answer.txt"] })],
			]),
			createSession: async () => ({
				solve: async () => {
					started.resolve();
					return await release.promise;
				},
				terminate: async () => {
					throw new Error("session termination rejected");
				},
			}),
		});
		const run = backend.solve(request("challenge-1", root));
		await started.promise;
		await expect(
			backend.terminate?.({
				runId: "run-1",
				challengeId: "challenge-1",
				ownerId: "run-1",
				competitionId: "competition-1",
				fencingToken: 1,
				reason: "cancelled",
			}),
		).rejects.toThrow("session termination rejected");
		release.resolve({ candidate: "late" });
		await expect(run).resolves.toMatchObject({ status: "failed", reason: "session termination rejected" });
		await Bun.sleep(0);
		await expect(fs.stat(path.join(artifactRoot, "run-1"))).rejects.toThrow();
	});
	it("bounds a never-settling session termination acknowledgment", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-local-"));
		const artifactRoot = path.join(root, "artifacts");
		await fs.mkdir(artifactRoot);
		await fs.writeFile(path.join(root, "answer.txt"), "visible");
		const started = Promise.withResolvers<void>();
		const release = Promise.withResolvers<LocalSolverSessionResult>();
		const backend = createLocalCtfSolverFixtureBackend({
			root,
			artifactRoot,
			challenges: new Map([
				["challenge-1", makeDescriptor({ id: "challenge-1", visibleArtifactAllowlist: ["answer.txt"] })],
			]),
			createSession: async () => ({
				solve: async () => {
					started.resolve();
					return await release.promise;
				},
				terminate: async () => new Promise<never>(() => undefined),
			}),
		});
		const run = backend.solve(request("challenge-1", root));
		await started.promise;
		await expect(
			backend.terminate?.({
				runId: "run-1",
				challengeId: "challenge-1",
				ownerId: "run-1",
				competitionId: "competition-1",
				fencingToken: 1,
				reason: "cancelled",
			}),
		).rejects.toThrow(/termination timed out/u);
		release.resolve({ candidate: "late" });
		await expect(run).resolves.toMatchObject({ status: "failed", reason: expect.stringContaining("timed out") });
	});
	it("accepts authoritative session quiescence without awaiting a pending solve promise", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-local-"));
		const artifactRoot = path.join(root, "artifacts");
		await fs.mkdir(artifactRoot);
		await fs.writeFile(path.join(root, "answer.txt"), "visible");
		const started = Promise.withResolvers<void>();
		const backend = createLocalCtfSolverFixtureBackend({
			root,
			artifactRoot,
			challenges: new Map([
				["challenge-1", makeDescriptor({ id: "challenge-1", visibleArtifactAllowlist: ["answer.txt"] })],
			]),
			createSession: async () => ({
				solve: async () => {
					started.resolve();
					return await new Promise<never>(() => undefined);
				},
				terminate: async () => undefined,
			}),
		});
		void backend.solve(request("challenge-1", root));
		await started.promise;
		await expect(
			backend.terminate?.({
				runId: "run-1",
				challengeId: "challenge-1",
				ownerId: "run-1",
				competitionId: "competition-1",
				fencingToken: 1,
				reason: "cancelled",
			}),
		).resolves.toBeUndefined();
	});
	it("composes the owned local backend with a scheduler budget", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-local-"));
		const artifactRoot = path.join(root, "artifacts");
		await fs.mkdir(artifactRoot);
		await fs.writeFile(path.join(root, "answer.txt"), "visible");
		const release = Promise.withResolvers<LocalSolverSessionResult>();
		const backend = createLocalCtfSolverFixtureBackend({
			root,
			artifactRoot,
			challenges: new Map([
				["challenge-1", makeDescriptor({ id: "challenge-1", visibleArtifactAllowlist: ["answer.txt"] })],
			]),
			createSession: async () => ({
				solve: async () => await release.promise,
				terminate: async () => release.resolve({ candidate: "late" }),
			}),
		});
		const result = await scheduleCtfRuns({
			competitionId: "competition-1",
			challengeIds: ["challenge-1"],
			mode: "competition",
			concurrency: 1,
			budgetMs: 1,
			backend,
			authority: {
				fencingToken: 1,
				intentId: "intent-1",
				skillDigest: sha256Hex("skill"),
				sandboxPolicyDigest: sha256Hex("sandbox-policy"),
			},
			materializedFor: async () => ({
				root,
				provenanceDigest: sha256Hex("materialized"),
				visibleFileDigests: { "answer.txt": visibleDigest("visible") },
			}),
			terminateMaterialization: async () => {},
			createUnavailable: async challengeId => ({
				schemaVersion: "ctf-run-result-1",
				status: "unavailable",
				runId: `unavailable-${challengeId}`,
				competitionId: "competition-1",
				challengeId,
				mode: "competition",
				reason: "unavailable",
			}),
		});
		expect(result.results[0]).toMatchObject({ status: "cancelled" });
	});
	it("retries blank fixture candidates with structural feedback and safely exhausts", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-local-"));
		const artifactRoot = path.join(root, "artifacts");
		await fs.mkdir(artifactRoot);
		await fs.writeFile(path.join(root, "answer.txt"), "visible");
		const inputs: LocalSolverSessionInput[] = [];
		const backend = createLocalCtfSolverFixtureBackend({
			root,
			artifactRoot,
			challenges: new Map([
				["challenge-1", makeDescriptor({ id: "challenge-1", visibleArtifactAllowlist: ["answer.txt"] })],
			]),
			createSession: async () => ({
				solve: async input => {
					inputs.push(input);
					return { candidate: " " };
				},
			}),
		});
		await expect(backend.solve(request("challenge-1", root))).resolves.toMatchObject({
			status: "failed",
			terminalKind: "safe_exhaustion",
		});
		expect(inputs.map(input => ({ attempt: input.attempt, retryFeedback: input.retryFeedback }))).toEqual([
			{ attempt: 0, retryFeedback: undefined },
			{
				attempt: 1,
				retryFeedback: {
					schemaVersion: "ctf-solver-feedback-1",
					attempt: 0,
					code: "empty_candidate",
				},
			},
		]);
	});
});
