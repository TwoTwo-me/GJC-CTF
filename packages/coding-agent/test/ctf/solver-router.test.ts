import { describe, expect, test } from "bun:test";
import { type BootstrapResult, BUILTIN_CTF_TOOL_MANIFEST_DIGEST, toolsForCategories } from "../../src/ctf/bootstrap";
import { canonicalDigest } from "../../src/ctf/contracts/digest";
import { LACTF_CORPUS_SOURCES } from "../../src/ctf/corpus";
import {
	bootstrapCategoryPlanFor,
	closeSolverRouteCapabilities,
	LACTF_SOLVER_ROUTE_REGISTRY_DIGEST,
	LACTF_SOLVER_ROUTES,
	solverRouteFor,
	validateSolverRoute,
} from "../../src/ctf/solver/router";

function changedRoute(
	route: (typeof LACTF_SOLVER_ROUTES)[number],
	change: (value: Record<string, unknown>) => void,
): Record<string, unknown> {
	const value = structuredClone(route) as Record<string, unknown>;
	change(value);
	value.routeDigest = canonicalDigest({
		challengeId: value.challengeId,
		category: value.category,
		adapterKind: value.adapterKind,
		bootstrapCategories: value.bootstrapCategories,
		analyzerIds: value.analyzerIds,
		modelPattern: value.modelPattern,
		thinkingLevel: value.thinkingLevel,
		attemptLimits: value.attemptLimits,
	});
	return value;
}

describe("LA CTF solver route registry", () => {
	test("has one exact reviewed route for each pinned corpus source", () => {
		expect(LACTF_SOLVER_ROUTES.map(route => route.challengeId)).toEqual(
			LACTF_CORPUS_SOURCES.map(source => source.challengeId),
		);
		expect(LACTF_SOLVER_ROUTES.map(route => [route.challengeId, route.category, route.adapterKind])).toEqual([
			["lactf-2026-misc-endians", "misc", "offline-checker"],
			["lactf-2026-rev-ooo", "reverse", "offline-checker"],
			["lactf-2026-rev-flag-finder", "reverse", "offline-checker"],
			["lactf-2026-crypto-not-so-lazy-trigrams", "crypto", "offline-checker"],
			["lactf-2026-pwn-tic-tac-no", "pwn", "process-service"],
			["lactf-2026-web-single-trust", "web", "browser-session"],
		]);
		expect(solverRouteFor("lactf-2026-misc-endians").analyzerIds).toEqual(["endians"]);
		expect(solverRouteFor("lactf-2026-rev-ooo").analyzerIds).toEqual(["ooo-recurrence"]);
		expect(solverRouteFor("lactf-2026-rev-flag-finder").analyzerIds).toEqual(["regex-grid-z3"]);
		expect(
			LACTF_SOLVER_ROUTES.filter(
				route =>
					route.challengeId !== "lactf-2026-misc-endians" &&
					route.challengeId !== "lactf-2026-rev-ooo" &&
					route.challengeId !== "lactf-2026-rev-flag-finder",
			).every(route => route.analyzerIds.length === 0),
		).toBe(true);
	});

	test("fails closed for unknown challenge IDs and altered route identities", () => {
		expect(() => solverRouteFor("lactf-2026-unknown")).toThrow(/not reviewed/);
		const route = solverRouteFor("lactf-2026-crypto-not-so-lazy-trigrams");
		for (const change of [
			(value: Record<string, unknown>) => {
				value.category = "web";
			},
			(value: Record<string, unknown>) => {
				value.category = "forensics";
			},
			(value: Record<string, unknown>) => {
				value.bootstrapCategories = ["essential", "forensics"];
			},
			(value: Record<string, unknown>) => {
				value.analyzerIds = ["invented-analyzer"];
			},
			(value: Record<string, unknown>) => {
				value.analyzerIds = ["regex-grid-z3", "regex-grid-z3"];
			},
			(value: Record<string, unknown>) => {
				value.adapterKind = "browser-session";
			},
			(value: Record<string, unknown>) => {
				value.modelPattern = "other-model";
			},
			(value: Record<string, unknown>) => {
				const limits = value.attemptLimits as Record<string, unknown>;
				limits.wallClockMs = 1;
				limits.limitsDigest = canonicalDigest({
					wallClockMs: 1,
					cpuTimeMs: limits.cpuTimeMs,
					memoryMiB: limits.memoryMiB,
				});
			},
		])
			expect(() => validateSolverRoute(changedRoute(route, change))).toThrow(
				/reviewed registry|challenge or category/,
			);
	});

	test("rejects invalid digests and challenge-supplied command fields", () => {
		const route = structuredClone(solverRouteFor("lactf-2026-misc-endians")) as Record<string, unknown>;
		(route.attemptLimits as Record<string, unknown>).limitsDigest = "0".repeat(64);
		expect(() => validateSolverRoute(route)).toThrow(/limits digest/);
		const commandRoute = structuredClone(solverRouteFor("lactf-2026-misc-endians")) as Record<string, unknown>;
		commandRoute.commands = [["sh", "-c", "id"]];
		expect(() => validateSolverRoute(commandRoute)).toThrow(/unreviewed fields/);
	});

	test("has deterministic digests and returns a declarative bootstrap plan", () => {
		expect(LACTF_SOLVER_ROUTE_REGISTRY_DIGEST).toBe(
			canonicalDigest(LACTF_SOLVER_ROUTES.map(route => route.routeDigest)),
		);
		const plan = bootstrapCategoryPlanFor("lactf-2026-web-single-trust");
		expect(plan).toEqual({
			challengeId: "lactf-2026-web-single-trust",
			categories: ["essential", "web", "network", "runtime"],
			planDigest: canonicalDigest({
				challengeId: "lactf-2026-web-single-trust",
				categories: ["essential", "web", "network", "runtime"],
			}),
		});
	});

	test("does not carry archive solution or metadata fields", () => {
		for (const route of LACTF_SOLVER_ROUTES) {
			expect(Object.keys(route).some(key => /solution|flag|archive/i.test(key))).toBe(false);
			expect(Object.keys(route.attemptLimits).some(key => /solution|flag|archive/i.test(key))).toBe(false);
		}
	});
	test("closes each reviewed route over its exact manifest-ordered tool set and seals digest drift", () => {
		for (const route of LACTF_SOLVER_ROUTES) {
			const required = toolsForCategories(route.bootstrapCategories);
			const bootstrap: BootstrapResult = {
				schemaVersion: "ctf-tool-bootstrap-result-1",
				mode: "dry-run",
				platform: "linux",
				bootstrapManifestDigest: BUILTIN_CTF_TOOL_MANIFEST_DIGEST,
				observations: required.map((tool, index) => ({
					tool: tool.id,
					category: tool.category,
					status: "ready" as const,
					version: "1",
					executable: { path: `/operator/bin/${tool.binary}`, sha256: canonicalDigest(`${index}`) },
				})),
				commands: [],
			};
			const result = closeSolverRouteCapabilities({ challengeId: route.challengeId, bootstrap });
			expect(result.closed).toBe(true);
			if (!result.closed) throw new Error("reviewed route did not close");
			expect(result.closure.tools.map(tool => tool.toolId)).toEqual(required.map(tool => tool.id));
			expect(result.closure.categoryPlanDigest).toBe(bootstrapCategoryPlanFor(route.challengeId).planDigest);
			expect(result.closure.closureDigest).toBe(
				canonicalDigest({
					schemaVersion: result.closure.schemaVersion,
					challengeId: result.closure.challengeId,
					routeDigest: result.closure.routeDigest,
					categoryPlanDigest: result.closure.categoryPlanDigest,
					bootstrapManifestDigest: result.closure.bootstrapManifestDigest,
					platform: result.closure.platform,
					tools: result.closure.tools,
					reviewedInstallArgvDigests: result.closure.reviewedInstallArgvDigests,
				}),
			);
		}
	});

	test("refuses closure when bootstrap digest, command evidence, or a required identity drifts", () => {
		const route = solverRouteFor("lactf-2026-rev-flag-finder");
		const required = toolsForCategories(route.bootstrapCategories);
		const bootstrap: BootstrapResult = {
			schemaVersion: "ctf-tool-bootstrap-result-1",
			mode: "dry-run",
			platform: "linux",
			bootstrapManifestDigest: canonicalDigest("drift"),
			observations: required.map(tool => ({
				tool: tool.id,
				category: tool.category,
				status: "ready" as const,
				version: "1",
				executable: { path: `/operator/bin/${tool.binary}`, sha256: canonicalDigest("tool") },
			})),
			commands: [],
		};
		expect(closeSolverRouteCapabilities({ challengeId: route.challengeId, bootstrap }).closed).toBe(false);
		expect(
			closeSolverRouteCapabilities({
				challengeId: route.challengeId,
				bootstrap: {
					...bootstrap,
					bootstrapManifestDigest: BUILTIN_CTF_TOOL_MANIFEST_DIGEST,
					commands: [["apt-get", "install"]],
				},
			}).closed,
		).toBe(false);
		expect(
			closeSolverRouteCapabilities({
				challengeId: route.challengeId,
				bootstrap: {
					...bootstrap,
					bootstrapManifestDigest: BUILTIN_CTF_TOOL_MANIFEST_DIGEST,
					observations: bootstrap.observations.slice(0, -1),
				},
			}).closed,
		).toBe(false);
	});
});
