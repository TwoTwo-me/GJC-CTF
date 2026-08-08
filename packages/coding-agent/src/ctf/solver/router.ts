import {
	type BootstrapCategory,
	type BootstrapResult,
	BUILTIN_CTF_TOOL_MANIFEST,
	BUILTIN_CTF_TOOL_MANIFEST_DIGEST,
	type ExecutableIdentity,
	toolsForCategories,
} from "../bootstrap";
import { canonicalDigest, type Digest, digestsEqual, isDigest } from "../contracts/digest";
import { LACTF_CORPUS_SOURCES } from "../corpus";

type SolverCategory = "misc" | "reverse" | "crypto" | "pwn" | "web";
type EvaluationAdapterKind = "offline-checker" | "process-service" | "browser-session";
type ThinkingLevel = "medium" | "high";
type AnalyzerId = "endians" | "ooo-recurrence" | "regex-grid-z3" | "not-so-lazy-trigrams";
export const REVIEWED_SOLVER_MODEL_IDENTITY = "openai-codex/gpt-5.6-sol" as const;

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
export type SolverCapabilityTool = Readonly<{
	toolId: string;
	category: BootstrapCategory;
	version: string;
	executable: ExecutableIdentity;
	probeArgvDigest: Digest;
}>;

export type SolverCapabilityClosureV1 = Readonly<{
	schemaVersion: "ctf-solver-capability-closure-1";
	challengeId: string;
	routeDigest: Digest;
	categoryPlanDigest: Digest;
	bootstrapManifestDigest: Digest;
	platform: "linux" | "darwin" | "win32";
	tools: readonly SolverCapabilityTool[];
	reviewedInstallArgvDigests: readonly Digest[];
	closureDigest: Digest;
}>;

export type SolverCapabilityClosureResult =
	| Readonly<{ closed: true; closure: SolverCapabilityClosureV1 }>
	| Readonly<{
			closed: false;
			observations: BootstrapResult["observations"];
			reviewedCommands: BootstrapResult["commands"];
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
		modelPattern: REVIEWED_SOLVER_MODEL_IDENTITY,
		thinkingLevel: "medium",
		attemptLimits: { wallClockMs: 30_000, cpuTimeMs: 20_000, memoryMiB: 512 },
	}),
	createRoute({
		challengeId: "lactf-2026-rev-ooo",
		category: "reverse",
		adapterKind: "offline-checker",
		analyzerIds: ["ooo-recurrence"],
		modelPattern: REVIEWED_SOLVER_MODEL_IDENTITY,
		thinkingLevel: "high",
		attemptLimits: { wallClockMs: 90_000, cpuTimeMs: 60_000, memoryMiB: 1_024 },
	}),
	createRoute({
		challengeId: "lactf-2026-rev-flag-finder",
		category: "reverse",
		adapterKind: "offline-checker",
		analyzerIds: ["regex-grid-z3"],
		modelPattern: REVIEWED_SOLVER_MODEL_IDENTITY,
		thinkingLevel: "high",
		attemptLimits: { wallClockMs: 90_000, cpuTimeMs: 60_000, memoryMiB: 1_024 },
	}),
	createRoute({
		challengeId: "lactf-2026-crypto-not-so-lazy-trigrams",
		category: "crypto",
		adapterKind: "offline-checker",
		analyzerIds: ["not-so-lazy-trigrams"],
		modelPattern: REVIEWED_SOLVER_MODEL_IDENTITY,
		thinkingLevel: "high",
		attemptLimits: { wallClockMs: 90_000, cpuTimeMs: 60_000, memoryMiB: 1_024 },
	}),
	createRoute({
		challengeId: "lactf-2026-pwn-tic-tac-no",
		category: "pwn",
		adapterKind: "process-service",
		analyzerIds: [],
		modelPattern: REVIEWED_SOLVER_MODEL_IDENTITY,
		thinkingLevel: "high",
		attemptLimits: { wallClockMs: 120_000, cpuTimeMs: 90_000, memoryMiB: 2_048 },
	}),
	createRoute({
		challengeId: "lactf-2026-web-single-trust",
		category: "web",
		adapterKind: "browser-session",
		analyzerIds: [],
		modelPattern: REVIEWED_SOLVER_MODEL_IDENTITY,
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
const fixtureRoutes = new WeakSet<object>();
const DIAGNOSTIC_RETRY_LIMITS = new Map<string, number>(LACTF_SOLVER_ROUTES.map(route => [route.challengeId, 1]));
export const LACTF_DIAGNOSTIC_RETRY_POLICY_DIGEST = canonicalDigest(
	LACTF_SOLVER_ROUTES.map(route => ({
		challengeId: route.challengeId,
		routeDigest: route.routeDigest,
		diagnosticRetryLimit: DIAGNOSTIC_RETRY_LIMITS.get(route.challengeId),
	})),
);
export function diagnosticRetryLimitFor(route: SolverRoute): number {
	if (fixtureRoutes.has(route)) return 1;
	const reviewed = validateSolverRoute(route);
	const limit = DIAGNOSTIC_RETRY_LIMITS.get(reviewed.challengeId);
	if (limit === undefined || !Number.isSafeInteger(limit) || limit < 0 || limit > 3)
		fail("solver diagnostic retry policy is invalid");
	return limit;
}
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
	const route = createRoute({
		challengeId,
		category: "misc",
		adapterKind: "offline-checker",
		analyzerIds: [],
		modelPattern: REVIEWED_SOLVER_MODEL_IDENTITY,
		thinkingLevel: "medium",
		attemptLimits: { wallClockMs: 30_000, cpuTimeMs: 20_000, memoryMiB: 512 },
	});
	fixtureRoutes.add(route);
	return route;
}

/** Returns declarative categories only; callers must separately use the reviewed bootstrap flow. */
export function bootstrapCategoryPlanFor(challengeId: unknown): BootstrapCategoryPlan {
	const route = solverRouteFor(challengeId);
	const plan = { challengeId: route.challengeId, categories: route.bootstrapCategories };
	return Object.freeze({ ...plan, planDigest: canonicalDigest(plan) });
}

export const getSolverRoute = solverRouteFor;
export const createBootstrapCategoryPlan = bootstrapCategoryPlanFor;
/**
 * Composes reviewed route requirements with bootstrap evidence. This is preflight
 * evidence only: it neither schedules work nor grants solve, oracle, or scoring authority.
 */
export function closeSolverRouteCapabilities(
	input: Readonly<{
		challengeId: unknown;
		bootstrap: BootstrapResult;
	}>,
): SolverCapabilityClosureResult {
	const route = solverRouteFor(input.challengeId);
	const plan = bootstrapCategoryPlanFor(route.challengeId);
	const required = toolsForCategories(plan.categories);
	const bootstrap = input.bootstrap;
	const reviewedInstallArgvDigests = reviewedCommandDigests(
		bootstrap,
		required.map(tool => tool.id),
	);
	if (
		bootstrap.bootstrapManifestDigest !== BUILTIN_CTF_TOOL_MANIFEST_DIGEST ||
		canonicalDigest(BUILTIN_CTF_TOOL_MANIFEST) !== BUILTIN_CTF_TOOL_MANIFEST_DIGEST ||
		reviewedInstallArgvDigests === undefined
	)
		return Object.freeze({
			closed: false,
			observations: bootstrap.observations,
			reviewedCommands: bootstrap.commands,
		});
	const byId = new Map(bootstrap.observations.map(observation => [observation.tool, observation]));
	const tools: SolverCapabilityTool[] = [];
	for (const requiredTool of required) {
		const observation = byId.get(requiredTool.id);
		if (
			observation === undefined ||
			observation.category !== requiredTool.category ||
			observation.status !== "ready" ||
			observation.version === undefined ||
			observation.executable === undefined ||
			!pathIsAbsolute(observation.executable.path)
		)
			return Object.freeze({
				closed: false,
				observations: bootstrap.observations,
				reviewedCommands: bootstrap.commands,
			});
		tools.push(
			Object.freeze({
				toolId: requiredTool.id,
				category: requiredTool.category,
				version: observation.version,
				executable: observation.executable,
				probeArgvDigest: canonicalDigest(requiredTool.versionArgv),
			}),
		);
	}
	if (bootstrap.observations.length !== required.length)
		return Object.freeze({
			closed: false,
			observations: bootstrap.observations,
			reviewedCommands: bootstrap.commands,
		});
	const closureBase = {
		schemaVersion: "ctf-solver-capability-closure-1" as const,
		challengeId: route.challengeId,
		routeDigest: route.routeDigest,
		categoryPlanDigest: plan.planDigest,
		bootstrapManifestDigest: BUILTIN_CTF_TOOL_MANIFEST_DIGEST,
		platform: bootstrap.platform,
		tools: Object.freeze(tools),
		reviewedInstallArgvDigests: Object.freeze(reviewedInstallArgvDigests),
	};
	return Object.freeze({
		closed: true,
		closure: Object.freeze({ ...closureBase, closureDigest: canonicalDigest(closureBase) }),
	});
}

function pathIsAbsolute(value: string): boolean {
	return value.startsWith("/") || /^[A-Za-z]:[\\/]/.test(value);
}
function reviewedCommandDigests(
	bootstrap: BootstrapResult,
	requiredToolIds: readonly string[],
): readonly Digest[] | undefined {
	if (bootstrap.commands.length === 0) return [];
	const manager = bootstrap.packageManager;
	if (manager === undefined) return undefined;
	const allowedPackages = new Set(
		BUILTIN_CTF_TOOL_MANIFEST.tools
			.filter(tool => requiredToolIds.includes(tool.id))
			.map(tool => tool.packages[manager])
			.filter((packageName): packageName is string => packageName !== undefined),
	);
	const prefix =
		manager === "apt"
			? ["apt-get", "install", "-y"]
			: manager === "brew"
				? ["brew", "install"]
				: manager === "pacman"
					? ["pacman", "-S", "--noconfirm"]
					: manager === "dnf"
						? ["dnf", "install", "-y"]
						: ["winget", "install", "--exact", "--id"];
	for (const command of bootstrap.commands) {
		const logical = command[0] === "sudo" ? command.slice(2) : command;
		if (prefix.some((part, index) => logical[index] !== part)) return undefined;
		const packages =
			manager === "winget"
				? logical.filter(
						(part, index) => index > 3 && part !== "--source" && part !== "winget" && !part.startsWith("--"),
					)
				: logical.slice(prefix.length);
		if (packages.length === 0 || packages.some(packageName => !allowedPackages.has(packageName))) return undefined;
	}
	return bootstrap.commands.map(command => canonicalDigest(command));
}
