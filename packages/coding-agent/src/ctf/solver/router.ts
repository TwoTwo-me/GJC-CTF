import type { BootstrapCategory } from "../bootstrap";
import { canonicalDigest, type Digest, digestsEqual, isDigest } from "../contracts/digest";
import { LACTF_CORPUS_SOURCES } from "../corpus";

type SolverCategory = "misc" | "reverse" | "crypto" | "pwn" | "web";
type EvaluationAdapterKind = "offline-checker" | "process-service" | "browser-session";
type ThinkingLevel = "medium" | "high";
type AnalyzerId = "endians" | "ooo-recurrence" | "regex-grid-z3";

export type SolverAttemptLimits = Readonly<{
	wallClockMs: number;
	cpuTimeMs: number;
	memoryMiB: number;
	limitsDigest: Digest;
}>;

export type SolverRoute = Readonly<{
	challengeId: string;
	category: SolverCategory;
	adapterKind: EvaluationAdapterKind;
	bootstrapCategories: readonly BootstrapCategory[];
	analyzerIds: readonly AnalyzerId[];
	modelPattern: string;
	thinkingLevel: ThinkingLevel;
	attemptLimits: SolverAttemptLimits;
	routeDigest: Digest;
}>;

export type BootstrapCategoryPlan = Readonly<{
	challengeId: string;
	categories: readonly BootstrapCategory[];
	planDigest: Digest;
}>;

export class SolverRouteError extends Error {
	readonly code = "invalid_solver_route" as const;
}

const CATEGORY_BOOTSTRAP = Object.freeze({
	misc: Object.freeze<readonly BootstrapCategory[]>(["essential"]),
	reverse: Object.freeze<readonly BootstrapCategory[]>(["essential", "reverse"]),
	crypto: Object.freeze<readonly BootstrapCategory[]>(["essential", "crypto"]),
	pwn: Object.freeze<readonly BootstrapCategory[]>(["essential", "pwn", "runtime"]),
	web: Object.freeze<readonly BootstrapCategory[]>(["essential", "web", "network", "runtime"]),
});

const SOURCE_CATEGORIES = new Map<string, SolverCategory>([
	["lactf-2026-misc-endians", "misc"],
	["lactf-2026-rev-ooo", "reverse"],
	["lactf-2026-rev-flag-finder", "reverse"],
	["lactf-2026-crypto-not-so-lazy-trigrams", "crypto"],
	["lactf-2026-pwn-tic-tac-no", "pwn"],
	["lactf-2026-web-single-trust", "web"],
]);

function fail(message: string): never {
	throw new SolverRouteError(message);
}

function digestLimits(limits: Omit<SolverAttemptLimits, "limitsDigest">): Digest {
	return canonicalDigest(limits);
}

function createAttemptLimits(wallClockMs: number, cpuTimeMs: number, memoryMiB: number): SolverAttemptLimits {
	const limits = { wallClockMs, cpuTimeMs, memoryMiB };
	return Object.freeze({ ...limits, limitsDigest: digestLimits(limits) });
}
export function solverRouteDigest(route: unknown): Digest {
	return canonicalDigest(route, ["routeDigest"]);
}

function createRoute(
	input: Omit<SolverRoute, "bootstrapCategories" | "attemptLimits" | "routeDigest"> & {
		attemptLimits: Omit<SolverAttemptLimits, "limitsDigest">;
	},
): SolverRoute {
	const route: Omit<SolverRoute, "routeDigest"> = {
		challengeId: input.challengeId,
		category: input.category,
		adapterKind: input.adapterKind,
		bootstrapCategories: CATEGORY_BOOTSTRAP[input.category],
		analyzerIds: Object.freeze([...input.analyzerIds]),
		modelPattern: input.modelPattern,
		thinkingLevel: input.thinkingLevel,
		attemptLimits: createAttemptLimits(
			input.attemptLimits.wallClockMs,
			input.attemptLimits.cpuTimeMs,
			input.attemptLimits.memoryMiB,
		),
	};
	return Object.freeze({ ...route, routeDigest: solverRouteDigest(route) });
}

/** The registry is deliberately finite: every corpus source has exactly one reviewed route. */
export const LACTF_SOLVER_ROUTES: readonly SolverRoute[] = Object.freeze([
	createRoute({
		challengeId: "lactf-2026-misc-endians",
		category: "misc",
		adapterKind: "offline-checker",
		analyzerIds: ["endians"],
		modelPattern: "gpt-5",
		thinkingLevel: "medium",
		attemptLimits: { wallClockMs: 30_000, cpuTimeMs: 20_000, memoryMiB: 512 },
	}),
	createRoute({
		challengeId: "lactf-2026-rev-ooo",
		category: "reverse",
		adapterKind: "offline-checker",
		analyzerIds: ["ooo-recurrence"],
		modelPattern: "gpt-5",
		thinkingLevel: "high",
		attemptLimits: { wallClockMs: 90_000, cpuTimeMs: 60_000, memoryMiB: 1_024 },
	}),
	createRoute({
		challengeId: "lactf-2026-rev-flag-finder",
		category: "reverse",
		adapterKind: "offline-checker",
		analyzerIds: ["regex-grid-z3"],
		modelPattern: "gpt-5",
		thinkingLevel: "high",
		attemptLimits: { wallClockMs: 90_000, cpuTimeMs: 60_000, memoryMiB: 1_024 },
	}),
	createRoute({
		challengeId: "lactf-2026-crypto-not-so-lazy-trigrams",
		category: "crypto",
		adapterKind: "offline-checker",
		analyzerIds: [],
		modelPattern: "gpt-5",
		thinkingLevel: "high",
		attemptLimits: { wallClockMs: 90_000, cpuTimeMs: 60_000, memoryMiB: 1_024 },
	}),
	createRoute({
		challengeId: "lactf-2026-pwn-tic-tac-no",
		category: "pwn",
		adapterKind: "process-service",
		analyzerIds: [],
		modelPattern: "gpt-5",
		thinkingLevel: "high",
		attemptLimits: { wallClockMs: 120_000, cpuTimeMs: 90_000, memoryMiB: 2_048 },
	}),
	createRoute({
		challengeId: "lactf-2026-web-single-trust",
		category: "web",
		adapterKind: "browser-session",
		analyzerIds: [],
		modelPattern: "gpt-5",
		thinkingLevel: "high",
		attemptLimits: { wallClockMs: 120_000, cpuTimeMs: 90_000, memoryMiB: 2_048 },
	}),
]);

const registryChallengeIds = new Set(LACTF_SOLVER_ROUTES.map(route => route.challengeId));
if (
	registryChallengeIds.size !== LACTF_SOLVER_ROUTES.length ||
	registryChallengeIds.size !== LACTF_CORPUS_SOURCES.length ||
	LACTF_CORPUS_SOURCES.some(
		source => !registryChallengeIds.has(source.challengeId) || !SOURCE_CATEGORIES.has(source.challengeId),
	)
)
	throw new SolverRouteError("solver route registry must cover each pinned corpus source exactly once");

const ROUTES_BY_CHALLENGE = new Map(LACTF_SOLVER_ROUTES.map(route => [route.challengeId, route]));
export function solverRouteRegistryDigest(routes: readonly SolverRoute[] = LACTF_SOLVER_ROUTES): Digest {
	return canonicalDigest(routes.map(route => route.routeDigest));
}

export const LACTF_SOLVER_ROUTE_REGISTRY_DIGEST = solverRouteRegistryDigest();
export const REVIEWED_SOLVER_ANALYZER_IDS: ReadonlySet<string> = new Set(
	LACTF_SOLVER_ROUTES.flatMap(route => route.analyzerIds),
);

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function sameStringArray(value: unknown, expected: readonly string[]): boolean {
	return (
		Array.isArray(value) && value.length === expected.length && value.every((item, index) => item === expected[index])
	);
}

function assertExactKeys(value: Record<string, unknown>, keys: readonly string[]): void {
	if (Object.keys(value).length !== keys.length || Object.keys(value).some(key => !keys.includes(key)))
		fail("solver route contains unreviewed fields");
}

/** Validate a supplied route by its complete reviewed identity; no partial or challenge-defined routes are accepted. */
export function validateSolverRoute(value: unknown): SolverRoute {
	if (!isRecord(value)) fail("solver route must be an object");
	assertExactKeys(value, [
		"challengeId",
		"category",
		"adapterKind",
		"bootstrapCategories",
		"analyzerIds",
		"modelPattern",
		"thinkingLevel",
		"attemptLimits",
		"routeDigest",
	]);
	if (typeof value.challengeId !== "string" || typeof value.category !== "string")
		fail("solver route identity is invalid");
	const expected = ROUTES_BY_CHALLENGE.get(value.challengeId);
	if (expected === undefined || SOURCE_CATEGORIES.get(value.challengeId) !== value.category)
		fail("solver route challenge or category is not reviewed");
	if (!isRecord(value.attemptLimits)) fail("solver route limits are invalid");
	assertExactKeys(value.attemptLimits, ["wallClockMs", "cpuTimeMs", "memoryMiB", "limitsDigest"]);
	const { wallClockMs, cpuTimeMs, memoryMiB, limitsDigest } = value.attemptLimits;
	if (
		typeof wallClockMs !== "number" ||
		!Number.isSafeInteger(wallClockMs) ||
		wallClockMs <= 0 ||
		typeof cpuTimeMs !== "number" ||
		!Number.isSafeInteger(cpuTimeMs) ||
		cpuTimeMs <= 0 ||
		typeof memoryMiB !== "number" ||
		!Number.isSafeInteger(memoryMiB) ||
		memoryMiB <= 0 ||
		!isDigest(limitsDigest)
	)
		fail("solver route limits digest is invalid");
	if (!digestsEqual(digestLimits({ wallClockMs, cpuTimeMs, memoryMiB }), limitsDigest))
		fail("solver route limits digest is invalid");
	if (
		!isDigest(value.routeDigest) ||
		!digestsEqual(
			solverRouteDigest({
				challengeId: value.challengeId,
				category: value.category,
				adapterKind: value.adapterKind,
				bootstrapCategories: value.bootstrapCategories,
				analyzerIds: value.analyzerIds,
				modelPattern: value.modelPattern,
				thinkingLevel: value.thinkingLevel,
				attemptLimits: value.attemptLimits,
			}),
			value.routeDigest,
		)
	)
		fail("solver route digest is invalid");
	if (
		value.adapterKind !== expected.adapterKind ||
		!sameStringArray(value.bootstrapCategories, expected.bootstrapCategories) ||
		!sameStringArray(value.analyzerIds, expected.analyzerIds) ||
		value.modelPattern !== expected.modelPattern ||
		value.thinkingLevel !== expected.thinkingLevel ||
		!digestsEqual(value.routeDigest, expected.routeDigest)
	)
		fail("solver route does not match the reviewed registry");
	return expected;
}

export function solverRouteFor(challengeId: unknown): SolverRoute {
	if (typeof challengeId !== "string") fail("solver route challenge ID is invalid");
	const route = ROUTES_BY_CHALLENGE.get(challengeId);
	if (route === undefined) fail("solver route challenge is not reviewed");
	return route;
}
/** Fixture-only compatibility route. Production callers must use solverRouteFor. */
export function fixtureSolverRouteFor(challengeId: string): SolverRoute {
	if (challengeId.length === 0) fail("fixture solver route challenge ID is invalid");
	return createRoute({
		challengeId,
		category: "misc",
		adapterKind: "offline-checker",
		analyzerIds: [],
		modelPattern: "gpt-5",
		thinkingLevel: "medium",
		attemptLimits: { wallClockMs: 30_000, cpuTimeMs: 20_000, memoryMiB: 512 },
	});
}

/** Returns declarative categories only; callers must separately use the reviewed bootstrap flow. */
export function bootstrapCategoryPlanFor(challengeId: unknown): BootstrapCategoryPlan {
	const route = solverRouteFor(challengeId);
	const plan = { challengeId: route.challengeId, categories: route.bootstrapCategories };
	return Object.freeze({ ...plan, planDigest: canonicalDigest(plan) });
}

export const getSolverRoute = solverRouteFor;
export const createBootstrapCategoryPlan = bootstrapCategoryPlanFor;
