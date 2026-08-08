import * as fs from "node:fs/promises";
import * as path from "node:path";
import { type Digest, sha256Hex } from "./contracts/digest";
import { CtfError } from "./contracts/errors";

const LACTF_REPOSITORY_URL = "https://github.com/uclaacm/lactf-archive" as const;
const LACTF_COMMIT = "3379d4a7b36680764a34e7dc817cc3c94c244764" as const;

export type LactfCorpusSource = Readonly<{
	repositoryUrl: typeof LACTF_REPOSITORY_URL;
	sourceCommit: typeof LACTF_COMMIT;
	challengePath:
		| "2026/misc/endians"
		| "2026/rev/ooo"
		| "2026/rev/flag-finder"
		| "2026/crypto/not-so-lazy-trigrams"
		| "2026/pwn/tic-tac-no"
		| "2026/web/single-trust";
	challengeId:
		| "lactf-2026-misc-endians"
		| "lactf-2026-rev-ooo"
		| "lactf-2026-rev-flag-finder"
		| "lactf-2026-crypto-not-so-lazy-trigrams"
		| "lactf-2026-pwn-tic-tac-no"
		| "lactf-2026-web-single-trust";
	visibleFiles: readonly string[];
	scored: false;
	permission: "required";
	trustedOracle: "unavailable";
	calibration: "unavailable";
	runtimeEvidence: "unavailable";
}>;
export type CorpusSource = LactfCorpusSource;

export const LACTF_2026_CORPUS_SOURCES: readonly LactfCorpusSource[] = Object.freeze([
	Object.freeze({
		repositoryUrl: LACTF_REPOSITORY_URL,
		sourceCommit: LACTF_COMMIT,
		challengePath: "2026/misc/endians",
		challengeId: "lactf-2026-misc-endians",
		visibleFiles: Object.freeze(["chall.txt"]),
		scored: false,
		permission: "required",
		trustedOracle: "unavailable",
		calibration: "unavailable",
		runtimeEvidence: "unavailable",
	}),
	Object.freeze({
		repositoryUrl: LACTF_REPOSITORY_URL,
		sourceCommit: LACTF_COMMIT,
		challengePath: "2026/rev/ooo",
		challengeId: "lactf-2026-rev-ooo",
		visibleFiles: Object.freeze(["ooo.py"]),
		scored: false,
		permission: "required",
		trustedOracle: "unavailable",
		calibration: "unavailable",
		runtimeEvidence: "unavailable",
	}),
	Object.freeze({
		repositoryUrl: LACTF_REPOSITORY_URL,
		sourceCommit: LACTF_COMMIT,
		challengePath: "2026/rev/flag-finder",
		challengeId: "lactf-2026-rev-flag-finder",
		visibleFiles: Object.freeze(["Dockerfile", "src/index.html", "src/script.js"]),
		scored: false,
		permission: "required",
		trustedOracle: "unavailable",
		calibration: "unavailable",
		runtimeEvidence: "unavailable",
	}),
	Object.freeze({
		repositoryUrl: LACTF_REPOSITORY_URL,
		sourceCommit: LACTF_COMMIT,
		challengePath: "2026/crypto/not-so-lazy-trigrams",
		challengeId: "lactf-2026-crypto-not-so-lazy-trigrams",
		visibleFiles: Object.freeze(["chall.py", "ct.txt"]),
		scored: false,
		permission: "required",
		trustedOracle: "unavailable",
		calibration: "unavailable",
		runtimeEvidence: "unavailable",
	}),
	Object.freeze({
		repositoryUrl: LACTF_REPOSITORY_URL,
		sourceCommit: LACTF_COMMIT,
		challengePath: "2026/pwn/tic-tac-no",
		challengeId: "lactf-2026-pwn-tic-tac-no",
		visibleFiles: Object.freeze(["chall"]),
		scored: false,
		permission: "required",
		trustedOracle: "unavailable",
		calibration: "unavailable",
		runtimeEvidence: "unavailable",
	}),
	Object.freeze({
		repositoryUrl: LACTF_REPOSITORY_URL,
		sourceCommit: LACTF_COMMIT,
		challengePath: "2026/web/single-trust",
		challengeId: "lactf-2026-web-single-trust",
		visibleFiles: Object.freeze(["index.html", "index.js", "package-lock.json", "package.json", "static/style.css"]),
		scored: false,
		permission: "required",
		trustedOracle: "unavailable",
		calibration: "unavailable",
		runtimeEvidence: "unavailable",
	}),
]);

export const LACTF_2026_CORPUS_SOURCE: LactfCorpusSource = LACTF_2026_CORPUS_SOURCES[0];
export const LACTF_CORPUS_SOURCES = LACTF_2026_CORPUS_SOURCES;

export type CorpusFileHash = Readonly<{ relativePath: string; sha256: Digest }>;
export type CorpusProvenance = Readonly<{
	repositoryUrl: string;
	sourceCommit: string;
	challengePath: string;
	files: readonly CorpusFileHash[];
}>;
export type CorpusPermissionEvidence = Readonly<{ reference: string; grantedBy: string; grantedAt: string }>;
export type CorpusEntry = Readonly<{
	source: CorpusSource;
	provenance: CorpusProvenance;
	permissionEvidence?: CorpusPermissionEvidence;
	installCommands?: readonly string[];
}>;
export type MaterializedCorpus = Readonly<{
	challengeId: string;
	root: string;
	provenance: CorpusProvenance;
	scored: false;
	permissionEvidence?: CorpusPermissionEvidence;
}>;
export type MaterializedCorpusAuthority = Readonly<{
	provenanceDigest: Digest;
	visibleFileDigests: Readonly<Record<string, Digest>>;
}>;


function fail(
	code: "integrity_error" | "missing_provenance" | "missing_evidence" | "unsupported_operation",
	message: string,
): never {
	throw new CtfError(code, message);
}

function relativeSafe(value: string): boolean {
	return (
		value.length > 0 &&
		!path.posix.isAbsolute(value) &&
		!value.split(/[\\/]/u).some(part => part === ".." || part === "")
	);
}

function configuredSource(source: CorpusSource): LactfCorpusSource {
	const match = LACTF_2026_CORPUS_SOURCES.find(candidate => candidate.challengeId === source.challengeId);
	if (
		match === undefined ||
		source.repositoryUrl !== match.repositoryUrl ||
		source.sourceCommit !== match.sourceCommit ||
		source.challengePath !== match.challengePath ||
		JSON.stringify(source.visibleFiles) !== JSON.stringify(match.visibleFiles)
	) {
		fail("missing_provenance", "corpus source is not an approved pinned source");
	}
	return match;
}
function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactProvenance(expected: CorpusProvenance, candidate: unknown): boolean {
	if (
		!isRecord(candidate) ||
		candidate.repositoryUrl !== expected.repositoryUrl ||
		candidate.sourceCommit !== expected.sourceCommit ||
		candidate.challengePath !== expected.challengePath ||
		!Array.isArray(candidate.files) ||
		candidate.files.length !== expected.files.length
	)
		return false;
	return candidate.files.every(
		(file, index) =>
			isRecord(file) &&
			file.relativePath === expected.files[index]?.relativePath &&
			file.sha256 === expected.files[index]?.sha256,
	);
}


function within(root: string, candidate: string): boolean {
	const relative = path.relative(root, candidate);
	return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
}

async function hashFile(filePath: string): Promise<Digest> {
	return sha256Hex(await fs.readFile(filePath));
}

export function validateCorpusEntry(entry: CorpusEntry): void {
	const { source, provenance } = entry;
	configuredSource(source);
	if (source.scored !== false) fail("integrity_error", `${source.challengeId} must remain non-scored`);
	if (source.permission !== "required")
		fail("missing_provenance", `${source.challengeId} requires permission evidence`);
	if (
		source.repositoryUrl !== provenance.repositoryUrl ||
		source.sourceCommit !== provenance.sourceCommit ||
		source.challengePath !== provenance.challengePath
	) {
		fail("missing_provenance", "corpus provenance does not exactly match the pinned source");
	}
	if (!/^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(source.repositoryUrl))
		fail("missing_provenance", "repository URL must be an exact HTTPS repository URL");
	if (!/^[a-f0-9]{40}$/u.test(source.sourceCommit))
		fail("missing_provenance", "source commit must be a full lowercase commit hash");
	if (!relativeSafe(source.challengePath)) fail("integrity_error", "challenge path must be a safe relative path");
	if (
		source.visibleFiles.length === 0 ||
		new Set(source.visibleFiles).size !== source.visibleFiles.length ||
		source.visibleFiles.some(file => !relativeSafe(file))
	) {
		fail("integrity_error", "visible corpus files must be unique safe relative paths");
	}
	const seen = new Set<string>();
	for (const file of provenance.files) {
		if (!relativeSafe(file.relativePath) || seen.has(file.relativePath))
			fail("integrity_error", `invalid or duplicate corpus file path: ${file.relativePath}`);
		if (!/^[a-f0-9]{64}$/u.test(file.sha256)) fail("integrity_error", `invalid SHA-256 for ${file.relativePath}`);
		seen.add(file.relativePath);
	}
	if (seen.size !== source.visibleFiles.length || source.visibleFiles.some(relativePath => !seen.has(relativePath))) {
		fail("missing_provenance", "corpus provenance must bind exactly the visible file set");
	}
	if (entry.permissionEvidence !== undefined) {
		const { reference, grantedBy, grantedAt } = entry.permissionEvidence;
		if (!reference.trim() || !grantedBy.trim() || Number.isNaN(Date.parse(grantedAt))) {
			fail("missing_evidence", "corpus permission evidence is invalid");
		}
	}
	if (entry.installCommands?.length)
		fail("unsupported_operation", "challenge-controlled install commands are not permitted");
}

async function realRegularFile(root: string, relative: string): Promise<string> {
	const lexical = path.resolve(root, relative);
	if (!within(root, lexical)) fail("integrity_error", "corpus file escapes its root");
	let cursor = root;
	for (const segment of relative.split("/")) {
		cursor = path.join(cursor, segment);
		const component = await fs.lstat(cursor).catch(() => undefined);
		if (component?.isSymbolicLink()) fail("integrity_error", "corpus file path contains a symbolic link");
	}
	const stat = await fs.lstat(lexical).catch(() => undefined);
	if (!stat?.isFile()) fail("integrity_error", "corpus file is not a regular file");
	const real = await fs.realpath(lexical);
	if (!within(root, real)) fail("integrity_error", "corpus file escapes its root");
	return real;
}
async function materializedFilesMatch(
	root: string,
	expected: Readonly<Record<string, Digest>>,
): Promise<void> {
	const rootPath = path.resolve(root);
	const rootStat = await fs.lstat(rootPath).catch(() => undefined);
	if (!rootStat?.isDirectory() || rootStat.isSymbolicLink())
		fail("integrity_error", "materialized corpus root must be a real directory");
	if ((await fs.realpath(rootPath)) !== rootPath)
		fail("integrity_error", "materialized corpus root is not canonical");
	const discovered = new Set<string>();
	const visit = async (directory: string, relativeDirectory: string): Promise<void> => {
		for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
			const relativePath = relativeDirectory ? path.posix.join(relativeDirectory, entry.name) : entry.name;
			const candidate = path.join(directory, entry.name);
			if (entry.isSymbolicLink()) fail("integrity_error", "materialized corpus contains a symbolic link");
			if (entry.isDirectory()) {
				if (!expectedDirectories.has(relativePath))
					fail("missing_provenance", "materialized corpus contains an extra directory");
				await visit(candidate, relativePath);
				continue;
			}
			if (!entry.isFile()) fail("integrity_error", "materialized corpus contains a non-regular file");
			discovered.add(relativePath);
		}
	};
	const expectedPaths = Object.keys(expected);
	const expectedDirectories = new Set<string>();
	for (const relativePath of expectedPaths) {
		let directory = path.posix.dirname(relativePath);
		while (directory !== ".") {
			expectedDirectories.add(directory);
			directory = path.posix.dirname(directory);
		}
	}
	await visit(rootPath, "");
	if (
		discovered.size !== expectedPaths.length ||
		expectedPaths.some(relativePath => !discovered.has(relativePath))
	)
		fail("missing_provenance", "materialized corpus visible file set does not match registered provenance");
	for (const relativePath of expectedPaths) {
		const file = await realRegularFile(rootPath, relativePath);
		if ((await hashFile(file)) !== expected[relativePath])
			fail("integrity_error", `materialized corpus hash mismatch: ${relativePath}`);
	}
}

export async function validateMaterializedCorpus(
	entry: CorpusEntry,
	materialized: unknown,
): Promise<MaterializedCorpusAuthority> {
	validateCorpusEntry(entry);
	if (
		!isRecord(materialized) ||
		materialized.challengeId !== entry.source.challengeId ||
		materialized.scored !== false ||
		typeof materialized.root !== "string" ||
		materialized.root.length === 0
	)
		fail("missing_provenance", `materialized corpus is not pinned for ${entry.source.challengeId}`);
	const expected = entry.provenance;
	if (!exactProvenance(expected, materialized.provenance))
		fail("missing_provenance", `materialized corpus provenance does not match ${entry.source.challengeId}`);
	const visibleFileDigests = Object.freeze(
		Object.fromEntries(expected.files.map(file => [file.relativePath, file.sha256])),
	);
	await materializedFilesMatch(materialized.root, visibleFileDigests);
	return Object.freeze({
		provenanceDigest: corpusContentDigest(expected),
		visibleFileDigests,
	});
}

async function createConfinedDestination(destination: string): Promise<string> {
	const parent = path.dirname(destination);
	await fs.mkdir(parent, { recursive: true });
	if ((await fs.realpath(parent)) !== parent) fail("integrity_error", "corpus destination parent is not canonical");
	if (await fs.lstat(destination).catch(() => undefined)) fail("integrity_error", "corpus destination already exists");
	await fs.mkdir(destination);
	const real = await fs.realpath(destination);
	if (real !== destination) fail("integrity_error", "corpus destination is not canonical");
	return real;
}

export async function materializeCorpusEntry(
	entry: CorpusEntry,
	checkoutRoot: string,
	destinationRoot: string,
): Promise<MaterializedCorpus> {
	validateCorpusEntry(entry);
	const checkout = await fs.realpath(path.resolve(checkoutRoot));
	const sourceLexical = path.resolve(checkout, entry.source.challengePath);
	if (!within(checkout, sourceLexical)) fail("integrity_error", "challenge path escapes checkout root");
	const sourceStat = await fs.lstat(sourceLexical).catch(() => undefined);
	if (!sourceStat?.isDirectory() || sourceStat.isSymbolicLink())
		fail("integrity_error", "challenge root must be a real directory");
	const sourceRoot = await fs.realpath(sourceLexical);
	if (!within(checkout, sourceRoot)) fail("integrity_error", "challenge path escapes checkout root");
	const expected = new Map(entry.provenance.files.map(file => [file.relativePath, file.sha256]));
	const files = [...entry.source.visibleFiles].sort();
	const destination = await createConfinedDestination(path.resolve(destinationRoot));
	for (const relative of files) {
		const source = await realRegularFile(sourceRoot, relative);
		if ((await hashFile(source)) !== expected.get(relative))
			fail("integrity_error", `corpus hash mismatch: ${relative}`);
		const target = path.resolve(destination, relative);
		if (!within(destination, target)) fail("integrity_error", "corpus file escapes its destination");
		await fs.mkdir(path.dirname(target), { recursive: true });
		if (!within(destination, await fs.realpath(path.dirname(target))))
			fail("integrity_error", "corpus destination directory escapes its root");
		await fs.copyFile(source, target, fs.constants.COPYFILE_EXCL);
	}
	return Object.freeze({
		challengeId: entry.source.challengeId,
		root: destination,
		provenance: entry.provenance,
		scored: false,
		...(entry.permissionEvidence ? { permissionEvidence: entry.permissionEvidence } : {}),
	});
}

export function corpusContentDigest(provenance: CorpusProvenance): Digest {
	return sha256Hex(
		JSON.stringify({
			repositoryUrl: provenance.repositoryUrl,
			sourceCommit: provenance.sourceCommit,
			challengePath: provenance.challengePath,
			files: [...provenance.files].sort((a, b) => a.relativePath.localeCompare(b.relativePath)),
		}),
	);
}

export function canScoreCorpusEntry(entry: CorpusEntry): boolean {
	validateCorpusEntry(entry);
	return false;
}

export async function buildCorpusProvenance(sourceRoot: string, source: CorpusSource): Promise<CorpusProvenance> {
	configuredSource(source);
	const root = await fs.realpath(path.resolve(sourceRoot));
	const files = [...source.visibleFiles].sort();
	return {
		repositoryUrl: source.repositoryUrl,
		sourceCommit: source.sourceCommit,
		challengePath: source.challengePath,
		files: await Promise.all(
			files.map(async relativePath => ({
				relativePath,
				sha256: await hashFile(await realRegularFile(root, relativePath)),
			})),
		),
	};
}

export type AcquiredCorpusCheckout = Readonly<{
	checkoutRoot: string;
	sourceCommit: typeof LACTF_COMMIT;
	repositoryUrl: typeof LACTF_REPOSITORY_URL;
}>;

async function runGit(args: readonly string[], cwd: string, home: string): Promise<string> {
	const git = Bun.which("git");
	if (git === null) fail("unsupported_operation", "git is required for corpus acquisition");
	const process = Bun.spawn([git, "-c", "core.hooksPath=/dev/null", ...args], {
		cwd,
		env: {
			PATH: processEnvPath(),
			HOME: home,
			GIT_CONFIG_NOSYSTEM: "1",
			GIT_TERMINAL_PROMPT: "0",
		},
		stdin: "ignore",
		stdout: "pipe",
		stderr: "pipe",
	});
	const [stdout, stderr, exitCode] = await Promise.all([
		new Response(process.stdout).text(),
		new Response(process.stderr).text(),
		process.exited,
	]);
	if (exitCode !== 0) {
		void stderr;
		fail("missing_provenance", "corpus acquisition failed");
	}
	return stdout.trim();
}

function processEnvPath(): string {
	return process.env.PATH ?? "/usr/local/bin:/usr/bin:/bin";
}

/** Acquire the one approved public archive at its immutable commit without running repository code. */
export async function acquireLactfCorpus(source: CorpusSource, cacheRoot: string): Promise<AcquiredCorpusCheckout> {
	configuredSource(source);
	const cache = path.resolve(cacheRoot);
	await fs.mkdir(cache, { recursive: true });
	const cacheReal = await fs.realpath(cache);
	if (cacheReal !== cache) fail("integrity_error", "corpus cache root is not canonical");
	const destination = path.join(cache, `lactf-archive-${LACTF_COMMIT}`);
	const existing = await fs.lstat(destination).catch(() => undefined);
	const home = path.join(cache, ".git-home");
	await fs.mkdir(home, { recursive: true });
	if (existing === undefined) {
		const temporary = `${destination}.tmp-${process.pid}-${Date.now()}`;
		try {
			await runGit(
				["clone", "--filter=blob:none", "--no-checkout", "--template=", LACTF_REPOSITORY_URL, temporary],
				cache,
				home,
			);
			await runGit(["fetch", "--depth=1", "origin", LACTF_COMMIT], temporary, home);
			await runGit(["checkout", "--detach", LACTF_COMMIT], temporary, home);
			await fs.rename(temporary, destination);
		} catch (error) {
			await fs.rm(temporary, { recursive: true, force: true });
			throw error;
		}
	} else if (!existing.isDirectory() || existing.isSymbolicLink()) {
		fail("integrity_error", "corpus checkout cache is not a real directory");
	}
	const checkoutRoot = await fs.realpath(destination);
	if (!within(cacheReal, checkoutRoot)) fail("integrity_error", "corpus checkout escapes its cache");
	const [head, remote] = await Promise.all([
		runGit(["rev-parse", "HEAD"], checkoutRoot, home),
		runGit(["remote", "get-url", "origin"], checkoutRoot, home),
	]);
	if (head !== LACTF_COMMIT || remote !== LACTF_REPOSITORY_URL) {
		fail("missing_provenance", "corpus checkout does not match the pinned source");
	}
	return Object.freeze({
		checkoutRoot,
		sourceCommit: LACTF_COMMIT,
		repositoryUrl: LACTF_REPOSITORY_URL,
	});
}
