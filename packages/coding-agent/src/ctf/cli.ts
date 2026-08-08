import { readFile } from "node:fs/promises";
import * as z from "zod/v4";
import packageJson from "../../package.json" with { type: "json" };
import { type BootstrapCategory, type BootstrapResult, bootstrapCtfTools } from "./bootstrap";
import {
	BackendRefSchema,
	CtfIdSchema,
	DigestSchema,
	OperationalLimitsRefSchema,
	TrustedOracleRegistryV1Schema,
} from "./contracts";
import { CtfError, errorEnvelope } from "./contracts/errors";
import embeddedDashboardArchive from "./dashboard/embedded-client.generated.txt" with { type: "text" };
import { createCtfWorkspaceDashboardProjectionReader, readCtfDashboardSnapshot } from "./dashboard/projection-reader";
import { startCtfDashboard } from "./dashboard/server";
import {
	type LactfVersionStatisticsInspection,
	projectLactfVersionStatisticsInspection,
	validateLactfVersionStatisticsArtifact,
} from "./evidence/version-observation";
import {
	type CtfRunMode,
	createUnavailableRun,
	prepareCtfSolverRun,
	resumeUnavailableRun,
} from "./runtime/run-orchestrator";
import { type CtfPreparedRun, type CtfRunAuthority, type CtfSolverBackend, scheduleCtfRuns } from "./runtime/scheduler";
import {
	CtfWorkspaceError,
	discoverCtfWorkspace,
	initCtfWorkspace,
	makeChallengeDescriptor,
	registerChallenge,
} from "./workspace";

const VERSION = packageJson.version;
export const CTF_BIN_NAME = "gjc-ctf" as const;
export const CTF_DASHBOARD_EMBEDDED_ARCHIVE = embeddedDashboardArchive;

export const CTF_COMMANDS = [
	"init",
	"challenge add",
	"solve",
	"status",
	"dashboard",
	"resume",
	"bootstrap",
	"stats inspect",
] as const;
export type CtfCommand = (typeof CTF_COMMANDS)[number];
export type CtfCliInvocation =
	| { kind: "help" }
	| { kind: "version" }
	| { kind: "command"; command: CtfCommand; args: readonly string[] };

export interface CtfCliRuntime {
	backends?: ReadonlyMap<string, CtfSolverBackend>;
	authorityFor?: (input: Readonly<{ challengeId: string; runId: string; index: number }>) => Promise<CtfRunAuthority>;
	prepareRun?: (
		input: Readonly<{ challengeId: string; runId: string; index: number; backendId: string }>,
	) => Promise<CtfPreparedRun>;
	bootstrap?: (
		input: Readonly<{ categories?: readonly BootstrapCategory[]; mode: "dry-run" | "apply" }>,
	) => Promise<BootstrapResult>;
}

export class CtfUsageError extends Error {
	readonly code = "CTF_USAGE_ERROR" as const;
	readonly exitCode = 2;
	constructor(message: string) {
		super(message);
		this.name = "CtfUsageError";
	}
}

export function renderCtfHelp(): string {
	return `${[
		`Usage: ${CTF_BIN_NAME} <command>`,
		"",
		"Commands:",
		`  ${CTF_BIN_NAME} init [DIR] [--json]`,
		`  ${CTF_BIN_NAME} challenge add --id ID --category CATEGORY --path PATH --trust-level LEVEL --execution-class CLASS --source-revision REV --source-sha SHA --oracle-id ID --descriptor-json PATH`,
		`  ${CTF_BIN_NAME} solve CHALLENGE_ID... [--mode competition|benchmark --benchmark-lock ID]`,
		`  ${CTF_BIN_NAME} status [CHALLENGE_ID] --json`,
		`  ${CTF_BIN_NAME} dashboard [--port PORT]`,
		`  ${CTF_BIN_NAME} bootstrap [--category CATEGORY...] [--apply] [--json]`,
		`  ${CTF_BIN_NAME} resume [RUN_ID] [--json]`,
		`  ${CTF_BIN_NAME} stats inspect --input PATH [--json]`,
		"",
		"Options:",
		`  -h, --help       Show this help`,
		`  -v, --version    Show the CTF CLI version`,
		`  --concurrency N  Maximum concurrent challenge runs (default: 1)`,
		`  --budget-ms N    Per-run wall-time budget`,
		`  --backend ID     Explicit solver backend identity`,
		`  --descriptor-json PATH  Strict registration metadata JSON (limits, calibration, safety, backend, allowlist)`,
	].join("\n")}\n`;
}

function parseCommand(argv: readonly string[]): { command: CtfCommand; args: readonly string[] } {
	const [first, second, ...rest] = argv;
	if (first === "challenge" && second === "add") return { command: "challenge add", args: rest };
	if (first === "challenge") throw new CtfUsageError('Expected "challenge add".');
	if (first === "stats" && second === "inspect") return { command: "stats inspect", args: rest };
	if (first === "stats") throw new CtfUsageError('Expected "stats inspect".');
	if (first === undefined) throw new CtfUsageError(`A command is required. Use ${CTF_BIN_NAME} --help for usage.`);
	if ((CTF_COMMANDS as readonly string[]).includes(first))
		return {
			command: first as CtfCommand,
			args: [second, ...rest].filter((value): value is string => value !== undefined),
		};
	throw new CtfUsageError(`Unknown command "${first}". Use ${CTF_BIN_NAME} --help for usage.`);
}

export function parseCtfArgv(argv: readonly string[]): CtfCliInvocation {
	if (argv.length === 1 && ["--help", "-h", "help"].includes(argv[0] ?? "")) return { kind: "help" };
	if (argv.length === 1 && ["--version", "-v"].includes(argv[0] ?? "")) return { kind: "version" };
	const parsed = parseCommand(argv);
	return { kind: "command", ...parsed };
}

function flag(args: readonly string[], name: string): string | undefined {
	const index = args.indexOf(name);
	return index >= 0 ? args[index + 1] : undefined;
}

function parsePositiveIntegerFlag(args: readonly string[], name: string): number | undefined {
	const value = flag(args, name);
	if (value === undefined) return undefined;
	const parsed = Number(value);
	if (!Number.isSafeInteger(parsed) || parsed < 1) throw new CtfUsageError(`${name} must be a positive integer.`);
	return parsed;
}

function positionalArgs(args: readonly string[]): readonly string[] {
	const valueFlags = new Set(["--mode", "--benchmark-lock", "--concurrency", "--budget-ms", "--backend"]);
	const values: string[] = [];
	for (let index = 0; index < args.length; index += 1) {
		const value = args[index];
		if (value.startsWith("--")) {
			if (valueFlags.has(value)) index += 1;
			continue;
		}
		values.push(value);
	}
	return values;
}

function requiredFlag(args: readonly string[], name: string): string {
	const value = flag(args, name);
	if (!value || value.startsWith("--")) throw new CtfUsageError(`Missing required ${name}.`);
	return value;
}
function requiredUniqueFlag(args: readonly string[], name: string): string {
	const occurrences = args.reduce((count, value) => count + (value === name ? 1 : 0), 0);
	if (occurrences > 1) throw new CtfUsageError(`${name} may be specified only once.`);
	return requiredFlag(args, name);
}

function wantsJson(args: readonly string[]): boolean {
	return args.includes("--json");
}
const STATS_INSPECT_ARGUMENT_ERROR = "Stats inspection arguments are invalid.";

export function parseStatsInspectCommandArgs(args: readonly string[]): Readonly<{ input: string; json: boolean }> {
	let input: string | undefined;
	let json = false;
	for (let index = 0; index < args.length; index += 1) {
		const argument = args[index];
		if (argument === "--input") {
			if (input !== undefined) throw new CtfUsageError(STATS_INSPECT_ARGUMENT_ERROR);
			const path = args[++index];
			if (!path || path.startsWith("--")) throw new CtfUsageError(STATS_INSPECT_ARGUMENT_ERROR);
			input = path;
			continue;
		}
		if (argument === "--json") {
			if (json) throw new CtfUsageError(STATS_INSPECT_ARGUMENT_ERROR);
			json = true;
			continue;
		}
		throw new CtfUsageError(STATS_INSPECT_ARGUMENT_ERROR);
	}
	if (input === undefined) throw new CtfUsageError(STATS_INSPECT_ARGUMENT_ERROR);
	return { input, json };
}

function renderStatsInspection(inspection: LactfVersionStatisticsInspection): string {
	return `${[
		"LA CTF version statistics inspection",
		`Versions inspected: ${inspection.versionsInspected}`,
		"Independently verified solves: 0",
		"Status: unscored diagnostic observation",
		"Comparison: unavailable",
		"Tier 2: unauthorized",
		`Limitations: ${inspection.limitationsRecorded} recorded; no benchmark comparison is available.`,
	].join("\n")}\n`;
}
const BOOTSTRAP_CATEGORIES = [
	"essential",
	"crypto",
	"forensics",
	"network",
	"pwn",
	"reverse",
	"runtime",
	"web",
] as const satisfies readonly BootstrapCategory[];

export function parseBootstrapCommandArgs(args: readonly string[]): Readonly<{
	categories?: readonly BootstrapCategory[];
	mode: "dry-run" | "apply";
	json: boolean;
}> {
	const categories: BootstrapCategory[] = [];
	let apply = false;
	let json = false;
	for (let index = 0; index < args.length; index++) {
		const argument = args[index];
		if (argument === "--category") {
			const category = args[++index];
			if (!category || category.startsWith("--") || !BOOTSTRAP_CATEGORIES.includes(category as BootstrapCategory)) {
				throw new CtfUsageError("--category must be followed by a supported CTF tool category.");
			}
			if (categories.includes(category as BootstrapCategory)) {
				throw new CtfUsageError(`Duplicate bootstrap category "${category}".`);
			}
			categories.push(category as BootstrapCategory);
			continue;
		}
		if (argument === "--apply") {
			if (apply) throw new CtfUsageError("--apply may be specified only once.");
			apply = true;
			continue;
		}
		if (argument === "--json") {
			if (json) throw new CtfUsageError("--json may be specified only once.");
			json = true;
			continue;
		}
		throw new CtfUsageError(`Unknown bootstrap argument "${argument ?? ""}".`);
	}
	if (apply && categories.length === 0) {
		throw new CtfUsageError("--apply requires at least one explicit --category.");
	}
	return {
		categories: categories.length === 0 ? undefined : categories,
		mode: apply ? "apply" : "dry-run",
		json,
	};
}

const TrustedRegistrationAuthoritySchema = z
	.object({
		trustedRegistry: TrustedOracleRegistryV1Schema.optional(),
		trustedOracleRegistry: TrustedOracleRegistryV1Schema.optional(),
		oracleRegistry: TrustedOracleRegistryV1Schema.optional(),
		registry: TrustedOracleRegistryV1Schema.optional(),
		registryDigest: DigestSchema.optional(),
		oracleRegistryDigest: DigestSchema.optional(),
		oracleId: CtfIdSchema.optional(),
		selectedOracleId: CtfIdSchema.optional(),
		oracleEntryDigest: DigestSchema.optional(),
		entryDigest: DigestSchema.optional(),
		oracleDigest: DigestSchema.optional(),
		backendDigest: DigestSchema.optional(),
		imageDigest: DigestSchema.optional(),
	})
	.strict();

const ChallengeDescriptorMetadataSchema = z
	.object({
		limits: OperationalLimitsRefSchema,
		safetyPolicyDigest: DigestSchema,
		calibrationId: CtfIdSchema,
		backend: BackendRefSchema,
		visibleArtifactAllowlist: z.array(z.string().min(1)).max(4096),
		networkMode: z.literal("off").optional(),
		oracleId: CtfIdSchema.optional(),
		trustedAuthority: TrustedRegistrationAuthoritySchema.optional(),
		registrationAuthority: TrustedRegistrationAuthoritySchema.optional(),
		registrationMode: z.enum(["fixture", "unavailable", "competition", "scored", "benchmark"]).optional(),
	})
	.strict();

type ChallengeDescriptorMetadata = z.infer<typeof ChallengeDescriptorMetadataSchema>;

function metadataIssueMessage(error: z.ZodError): string {
	const issue = error.issues[0];
	if (!issue) return "unknown validation error";
	const path = issue.path.length === 0 ? "" : ` at ${issue.path.join(".")}`;
	return `${issue.message}${path}`;
}

async function readChallengeDescriptorMetadata(path: string): Promise<ChallengeDescriptorMetadata> {
	let raw: string;
	try {
		raw = await readFile(path, "utf8");
	} catch {
		throw new CtfUsageError(`Unable to read --descriptor-json file "${path}".`);
	}

	let value: unknown;
	try {
		value = JSON.parse(raw) as unknown;
	} catch {
		throw new CtfUsageError(`--descriptor-json file "${path}" must contain valid JSON.`);
	}

	const parsed = ChallengeDescriptorMetadataSchema.safeParse(value);
	if (!parsed.success) {
		throw new CtfUsageError(`--descriptor-json metadata is invalid: ${metadataIssueMessage(parsed.error)}.`);
	}
	if (parsed.data.limits.calibrationId !== parsed.data.calibrationId) {
		throw new CtfUsageError("--descriptor-json calibrationId must match limits.calibrationId.");
	}
	if (parsed.data.limits.safetyPolicyDigest !== parsed.data.safetyPolicyDigest) {
		throw new CtfUsageError("--descriptor-json safetyPolicyDigest must match limits.safetyPolicyDigest.");
	}
	return parsed.data;
}

function requiredChoiceFlag<T extends string>(args: readonly string[], name: string, choices: readonly T[]): T {
	const value = requiredFlag(args, name);
	if (!choices.includes(value as T)) throw new CtfUsageError(`${name} must be one of ${choices.join(", ")}.`);
	return value as T;
}

function writeError(error: unknown): void {
	if (error instanceof CtfWorkspaceError) {
		const message = CTF_WORKSPACE_ERROR_MESSAGES[error.code] ?? "CTF command failed.";
		process.stderr.write(`${CTF_BIN_NAME}: ${message}\n`);
		process.exitCode = error.retryable ? 75 : 1;
		return;
	}
	throw error;
}

function wantsJsonArgv(argv: readonly string[]): boolean {
	return argv.includes("--json");
}
const CTF_WORKSPACE_ERROR_API_CODES: Record<CtfWorkspaceError["code"], CtfError["code"]> = {
	manifest_missing: "invalid_manifest",
	unmarked_directory: "invalid_manifest",
	invalid_manifest: "invalid_manifest",
	unknown_manifest_version: "invalid_manifest",
	manifest_digest_mismatch: "invalid_manifest",
	digest_mismatch: "digest_mismatch",
	unknown_schema_major: "unknown_schema_major",
	challenge_conflict: "invalid_registration",
	idempotency_conflict: "idempotency_conflict",
	revision_conflict: "revision_conflict",
	invalid_registration: "invalid_registration",
	registration_repair_required: "registration_repair_required",
	oracle_integrity_error: "oracle_integrity_error",
	integrity_error: "integrity_error",
};

const CTF_WORKSPACE_ERROR_MESSAGES: Record<CtfWorkspaceError["code"], string> = {
	manifest_missing: "CTF workspace manifest is missing.",
	unmarked_directory: "CTF workspace directory is not marked as a workspace.",
	invalid_manifest: "CTF workspace manifest is invalid.",
	unknown_manifest_version: "CTF workspace manifest schema is unsupported.",
	manifest_digest_mismatch: "CTF workspace manifest integrity check failed.",
	digest_mismatch: "CTF workspace integrity check failed.",
	unknown_schema_major: "CTF data schema is unsupported.",
	challenge_conflict: "CTF challenge registration conflicts with an existing challenge.",
	idempotency_conflict: "CTF challenge registration repeats a conflicting request.",
	revision_conflict: "CTF workspace revision conflicts with the current revision.",
	invalid_registration: "CTF challenge registration is invalid.",
	registration_repair_required: "CTF challenge registration requires repair.",
	oracle_integrity_error: "CTF trusted oracle authority is unavailable or invalid.",
	integrity_error: "CTF workspace integrity check failed.",
};
function writeJsonError(error: unknown): void {
	if (error instanceof CtfWorkspaceError) {
		const apiCode = CTF_WORKSPACE_ERROR_API_CODES[error.code];
		const message = CTF_WORKSPACE_ERROR_MESSAGES[error.code];
		process.stdout.write(
			`${JSON.stringify(errorEnvelope(new CtfError(apiCode, message, { retryable: error.retryable })))}\n`,
		);
		process.exitCode = error.retryable ? 75 : 1;
		return;
	}
	if (error instanceof CtfUsageError) {
		process.stdout.write(
			`${JSON.stringify({
				schemaVersion: "ctf-api-1",
				error: { code: "invalid_api_request", message: error.message, retryable: false },
			})}\n`,
		);
		process.exitCode = error.exitCode;
		return;
	}
	if (error instanceof CtfError) {
		process.stdout.write(`${JSON.stringify(errorEnvelope(error))}\n`);
		process.exitCode = error.retryable ? 75 : 1;
		return;
	}
	process.stdout.write(
		`${JSON.stringify({
			schemaVersion: "ctf-api-1",
			error: { code: "unsupported_operation", message: "CTF command failed.", retryable: false },
		})}\n`,
	);
	process.exitCode = 1;
}

async function runCommand(command: CtfCommand, args: readonly string[], runtime: CtfCliRuntime): Promise<void> {
	if (command === "stats inspect") {
		const parsed = parseStatsInspectCommandArgs(args);
		let observation: ReturnType<typeof validateLactfVersionStatisticsArtifact>;
		try {
			observation = validateLactfVersionStatisticsArtifact(
				JSON.parse(await readFile(parsed.input, "utf8")) as unknown,
			);
		} catch {
			throw new CtfUsageError("Stats inspection input is not a valid active v2 diagnostic observation.");
		}
		const inspection = projectLactfVersionStatisticsInspection(observation);
		process.stdout.write(parsed.json ? `${JSON.stringify(inspection)}\n` : renderStatsInspection(inspection));
		return;
	}
	if (command === "bootstrap") {
		const parsed = parseBootstrapCommandArgs(args);
		const result =
			runtime.bootstrap === undefined
				? await bootstrapCtfTools({ categories: parsed.categories, mode: parsed.mode })
				: await runtime.bootstrap({ categories: parsed.categories, mode: parsed.mode });
		process.stdout.write(`${JSON.stringify(result)}\n`);
		return;
	}
	if (command === "init") {
		const directory = args.find(value => !value.startsWith("--")) ?? process.cwd();
		const result = await initCtfWorkspace(directory, VERSION);
		const output = {
			schemaVersion: "ctf-cli-1",
			competitionId: result.workspace.manifest.competitionId,
			manifestPath: result.workspace.manifestPath,
			stateRoot: result.workspace.stateRoot,
			created: result.created,
			noOp: result.noOp,
			manifestDigest: result.workspace.manifest.manifestDigest,
			skill: result.skill,
			skillArtifactPath: result.skillArtifactPath,
			skillArtifactCreated: result.skillArtifactCreated,
		};
		if (wantsJson(args)) process.stdout.write(`${JSON.stringify(output)}\n`);
		else
			process.stdout.write(
				`${result.created ? "Initialized" : "Already initialized"} CTF competition ${output.competitionId}\n`,
			);
		return;
	}
	if (command === "status") {
		const workspace = await discoverCtfWorkspace();
		const requestedChallengeId = args.find(value => !value.startsWith("--"));
		const challenges =
			requestedChallengeId === undefined
				? workspace.manifest.challenges
				: workspace.manifest.challenges.filter(challenge => challenge.id === requestedChallengeId);
		if (requestedChallengeId !== undefined && challenges.length === 0) {
			throw new CtfUsageError(`Unknown challenge id "${requestedChallengeId}".`);
		}
		const reader = createCtfWorkspaceDashboardProjectionReader(workspace);
		const snapshot = await readCtfDashboardSnapshot(
			reader,
			requestedChallengeId === undefined ? undefined : { challengeId: requestedChallengeId },
		);
		const canonical = snapshot.canonical.status === "available" ? snapshot.canonical.metadata : undefined;
		const projection = snapshot.projection.status === "available" ? snapshot.projection.metadata : undefined;
		const output = {
			schemaVersion: "ctf-cli-1",
			competitionId: workspace.manifest.competitionId,
			manifestRevision: workspace.manifest.manifestRevision,
			manifestDigest: workspace.manifest.manifestDigest,
			challenges,
			canonicalStatus: snapshot.canonical.status,
			projectionStatus: snapshot.projectionStatus,
			runStatus: "unavailable" as const,
			runOwnerHealth: "unavailable" as const,
			blockers: [],
			evidence: [],
			lanes: [],
			routes: [],
			usage: { wallTimeMs: undefined, inputTokens: undefined, outputTokens: undefined, costCents: undefined },
			...(canonical === undefined
				? {}
				: {
						canonicalRevision: canonical.canonicalRevision,
						canonicalDigest: canonical.canonicalDigest,
						benchmarkLockDigest: canonical.benchmarkLockDigest,
						effectiveSkillDigest: canonical.effectiveSkillDigest,
					}),
			...(projection === undefined
				? {}
				: {
						projectionRevision: projection.projectionRevision,
						projectionDigest: projection.projectionDigest,
					}),
		};
		if (wantsJson(args)) process.stdout.write(`${JSON.stringify(output)}\n`);
		else
			process.stdout.write(
				`Competition ${output.competitionId}: ${output.challenges.length} challenge(s); projection ${output.projectionStatus}\n`,
			);
		return;
	}
	if (command === "challenge add") {
		const metadataPath = requiredUniqueFlag(args, "--descriptor-json");
		const metadata = await readChallengeDescriptorMetadata(metadataPath);
		const oracleId = requiredFlag(args, "--oracle-id");
		if (metadata.oracleId !== undefined && metadata.oracleId !== oracleId) {
			throw new CtfUsageError("--descriptor-json oracleId must match --oracle-id.");
		}
		const workspace = await discoverCtfWorkspace();
		const descriptor = makeChallengeDescriptor({
			id: requiredFlag(args, "--id"),
			category: requiredFlag(args, "--category"),
			sourcePath: requiredFlag(args, "--path"),
			sourceRevision: requiredFlag(args, "--source-revision"),
			sourceSha256: requiredFlag(args, "--source-sha"),
			trustLevel: requiredChoiceFlag(args, "--trust-level", ["fixture", "verified-local", "external-untrusted"]),
			executionClass: requiredChoiceFlag(args, "--execution-class", [
				"static",
				"rootless-podman-network-off",
				"proxmox-deferred",
			]),
			visibleArtifactAllowlist: metadata.visibleArtifactAllowlist,
			backend: metadata.backend,
			networkMode: metadata.networkMode ?? "off",
			limits: metadata.limits,
			safetyPolicyDigest: metadata.safetyPolicyDigest,
			calibrationId: metadata.calibrationId,
			oracleId,
		});
		const updated = await registerChallenge(workspace, descriptor, {
			mode: metadata.registrationMode ?? "competition",
			trustedAuthority: metadata.trustedAuthority,
			registrationAuthority: metadata.registrationAuthority,
		});
		process.stdout.write(
			`${JSON.stringify({ schemaVersion: "ctf-cli-1", challengeId: descriptor.id, manifestRevision: updated.manifest.manifestRevision, manifestDigest: updated.manifest.manifestDigest })}\n`,
		);
		return;
	}
	if (command === "solve") {
		const workspace = await discoverCtfWorkspace();
		const challengeIds = positionalArgs(args);
		if (challengeIds.length === 0) throw new CtfUsageError("solve requires at least one registered challenge id.");
		const unknownChallenge = challengeIds.find(
			challengeId => !workspace.manifest.challenges.some(challenge => challenge.id === challengeId),
		);
		if (unknownChallenge !== undefined) throw new CtfUsageError(`Unknown challenge id "${unknownChallenge}".`);
		const modeValue = flag(args, "--mode") ?? "competition";
		if (modeValue !== "competition" && modeValue !== "benchmark") {
			throw new CtfUsageError("--mode must be competition or benchmark.");
		}
		const mode: CtfRunMode = modeValue;
		if (mode === "benchmark" && !flag(args, "--benchmark-lock")) {
			throw new CtfUsageError("benchmark solve requires --benchmark-lock.");
		}
		const concurrency = Math.min(parsePositiveIntegerFlag(args, "--concurrency") ?? 1, challengeIds.length);
		const budgetMs = parsePositiveIntegerFlag(args, "--budget-ms");
		const backendId = flag(args, "--backend");
		if (backendId?.startsWith("--")) throw new CtfUsageError("--backend requires a backend id.");
		const backend = backendId === undefined ? undefined : runtime.backends?.get(backendId);
		const scheduled = await scheduleCtfRuns({
			competitionId: workspace.manifest.competitionId,
			challengeIds,
			mode,
			concurrency,
			budgetMs,
			backend,
			prepareRun:
				backend === undefined
					? undefined
					: (runtime.prepareRun ??
						(input =>
							prepareCtfSolverRun(workspace, {
								challengeId: input.challengeId,
								runId: input.runId,
								mode,
								backendId: input.backendId,
								signal: input.signal,
							}))),
			authorityFor: backend === undefined ? undefined : runtime.authorityFor,
			createUnavailable: (challengeId, runMode) => createUnavailableRun(workspace, challengeId, runMode),
		});
		const results = scheduled.results;
		const output =
			challengeIds.length === 1
				? results[0]
				: {
						...scheduled,
						status: backend === undefined ? ("unavailable" as const) : scheduled.status,
						scheduler: { concurrency, budgetMs, backend: backendId },
					};
		process.stdout.write(`${JSON.stringify(output)}\n`);
		process.exitCode = 1;
		return;
	}
	if (command === "resume") {
		const runId = args.find(value => !value.startsWith("--"));
		if (!runId) throw new CtfUsageError("resume requires a run id.");
		const workspace = await discoverCtfWorkspace();
		const result = await resumeUnavailableRun(workspace, runId);
		process.stdout.write(`${JSON.stringify(result)}\n`);
		process.exitCode = 1;
		return;
	}
	if (command === "dashboard") {
		const requestedPort = flag(args, "--port");
		const port = requestedPort === undefined ? undefined : Number.parseInt(requestedPort, 10);
		if (port !== undefined && (!Number.isInteger(port) || port < 0 || port > 65535)) {
			throw new CtfUsageError("--port must be an integer between 0 and 65535.");
		}
		const workspace = await discoverCtfWorkspace();
		const projectionReader = createCtfWorkspaceDashboardProjectionReader(workspace);
		const handle = await startCtfDashboard({
			port,
			projectionReader,
			stateIdentity: { competitionId: workspace.manifest.competitionId, stateRoot: workspace.stateRoot },
			embeddedArchive: CTF_DASHBOARD_EMBEDDED_ARCHIVE,
			buildClient: false,
		});
		process.stdout.write(
			`${JSON.stringify({ schemaVersion: "ctf-cli-1", url: handle.url, port: handle.port, readOnly: true })}\n`,
		);
		return;
	}
	throw new CtfUsageError(`Command "${command}" is not implemented yet.`);
}

export async function runCtfCli(argv: readonly string[], runtime: CtfCliRuntime = {}): Promise<void> {
	try {
		const invocation = parseCtfArgv(argv);
		if (invocation.kind === "help") return void process.stdout.write(renderCtfHelp());
		if (invocation.kind === "version") return void process.stdout.write(`${CTF_BIN_NAME}/${VERSION}\n`);
		await runCommand(invocation.command, invocation.args, runtime);
	} catch (error) {
		if (wantsJsonArgv(argv)) {
			writeJsonError(error);
			return;
		}
		if (error instanceof CtfUsageError) {
			process.stderr.write(`${CTF_BIN_NAME}: ${error.message}\n\n${renderCtfHelp()}`);
			process.exitCode = error.exitCode;
			return;
		}
		writeError(error);
	}
}

if (import.meta.main) await runCtfCli(process.argv.slice(2));
