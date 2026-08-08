import * as path from "node:path";
import { canonicalDigest } from "./contracts/digest";

export type BootstrapCategory =
	| "essential"
	| "crypto"
	| "forensics"
	| "network"
	| "pwn"
	| "reverse"
	| "runtime"
	| "web";
export type BootstrapPlatform = "linux" | "darwin" | "win32";
export type BootstrapPackageManager = "apt" | "brew" | "pacman" | "dnf" | "winget";

export type CtfToolSpec = Readonly<{
	id: string;
	category: BootstrapCategory;
	binary: string;
	versionArgv: readonly string[];
	minimumVersion?: string;
	packages: Readonly<Partial<Record<BootstrapPackageManager, string>>>;
	platforms?: readonly BootstrapPlatform[];
}>;

export type CtfToolBootstrapManifest = Readonly<{
	schemaVersion: "ctf-tool-bootstrap-1";
	origin: "builtin";
	tools: readonly CtfToolSpec[];
}>;

export type BootstrapObservation = Readonly<{
	tool: string;
	category: BootstrapCategory;
	status: "ready" | "installable" | "unsupported" | "invalid";
	version?: string;
	argv?: readonly string[];
	reason?: string;
}>;

export type BootstrapResult = Readonly<{
	schemaVersion: "ctf-tool-bootstrap-result-1";
	mode: "dry-run" | "apply";
	platform: BootstrapPlatform;
	packageManager?: BootstrapPackageManager;
	observations: readonly BootstrapObservation[];
	commands: readonly (readonly string[])[];
}>;

export type BootstrapCommandRunner = (
	argv: readonly string[],
) => Promise<Readonly<{ exitCode: number; stdout: string; stderr: string }>>;

const CATEGORY_TOOLS: Record<BootstrapCategory, readonly CtfToolSpec[]> = {
	essential: [
		{
			id: "python",
			category: "essential",
			binary: "python3",
			versionArgv: ["python3", "--version"],
			packages: { apt: "python3", brew: "python", pacman: "python", dnf: "python3", winget: "Python.Python.3.12" },
		},
		{
			id: "git",
			category: "essential",
			binary: "git",
			versionArgv: ["git", "--version"],
			packages: { apt: "git", brew: "git", pacman: "git", dnf: "git", winget: "Git.Git" },
		},
	],
	crypto: [
		{
			id: "openssl",
			category: "crypto",
			binary: "openssl",
			versionArgv: ["openssl", "version"],
			packages: {
				apt: "openssl",
				brew: "openssl@3",
				pacman: "openssl",
				dnf: "openssl",
				winget: "ShiningLight.OpenSSL",
			},
		},
	],
	forensics: [
		{
			id: "file",
			category: "forensics",
			binary: "file",
			versionArgv: ["file", "--version"],
			packages: { apt: "file", brew: "file", pacman: "file", dnf: "file" },
		},
	],
	network: [
		{
			id: "curl",
			category: "network",
			binary: "curl",
			versionArgv: ["curl", "--version"],
			packages: { apt: "curl", brew: "curl", pacman: "curl", dnf: "curl", winget: "cURL.cURL" },
		},
	],
	pwn: [
		{
			id: "gcc",
			category: "pwn",
			binary: "gcc",
			versionArgv: ["gcc", "--version"],
			packages: { apt: "gcc", brew: "gcc", pacman: "gcc", dnf: "gcc" },
		},
		{
			id: "gdb",
			category: "pwn",
			binary: "gdb",
			versionArgv: ["gdb", "--version"],
			packages: { apt: "gdb", brew: "gdb", pacman: "gdb", dnf: "gdb" },
		},
		{
			id: "socat",
			category: "pwn",
			binary: "socat",
			versionArgv: ["socat", "-V"],
			packages: { apt: "socat", brew: "socat", pacman: "socat", dnf: "socat" },
		},
	],
	reverse: [
		{
			id: "objdump",
			category: "reverse",
			binary: "objdump",
			versionArgv: ["objdump", "--version"],
			packages: { apt: "binutils", brew: "binutils", pacman: "binutils", dnf: "binutils" },
		},
		{
			id: "z3",
			category: "reverse",
			binary: "z3",
			versionArgv: ["z3", "--version"],
			packages: { apt: "z3", brew: "z3", pacman: "z3", dnf: "z3" },
		},
	],
	runtime: [
		{
			id: "cargo",
			category: "runtime",
			binary: "cargo",
			versionArgv: ["cargo", "--version"],
			packages: { apt: "cargo", brew: "rust", pacman: "rust", dnf: "cargo", winget: "Rustlang.Rustup" },
		},
		{
			id: "docker",
			category: "runtime",
			binary: "docker",
			versionArgv: ["docker", "--version"],
			packages: {
				apt: "docker.io",
				brew: "docker",
				pacman: "docker",
				dnf: "docker",
				winget: "Docker.DockerDesktop",
			},
		},
		{
			id: "podman",
			category: "runtime",
			binary: "podman",
			versionArgv: ["podman", "--version"],
			packages: { apt: "podman", brew: "podman", pacman: "podman", dnf: "podman", winget: "RedHat.Podman" },
		},
	],
	web: [
		{
			id: "jq",
			category: "web",
			binary: "jq",
			versionArgv: ["jq", "--version"],
			packages: { apt: "jq", brew: "jq", pacman: "jq", dnf: "jq", winget: "jqlang.jq" },
		},
	],
};

function freezeToolSpec(tool: CtfToolSpec): CtfToolSpec {
	return Object.freeze({
		...tool,
		versionArgv: Object.freeze([...tool.versionArgv]),
		packages: Object.freeze({ ...tool.packages }),
		...(tool.platforms === undefined ? {} : { platforms: Object.freeze([...tool.platforms]) }),
	});
}

function freezeManifest(manifest: CtfToolBootstrapManifest): CtfToolBootstrapManifest {
	return Object.freeze({
		...manifest,
		tools: Object.freeze(manifest.tools.map(freezeToolSpec)),
	});
}

export const CTF_TOOL_CATEGORIES = Object.freeze(Object.keys(CATEGORY_TOOLS) as BootstrapCategory[]);
export const BUILTIN_CTF_TOOL_MANIFEST: CtfToolBootstrapManifest = freezeManifest({
	schemaVersion: "ctf-tool-bootstrap-1",
	origin: "builtin",
	tools: Object.values(CATEGORY_TOOLS).flat(),
});
const BUILTIN_CTF_TOOL_MANIFEST_DIGEST = canonicalDigest(BUILTIN_CTF_TOOL_MANIFEST);

export class CtfBootstrapError extends Error {
	readonly code = "invalid_tool_bootstrap" as const;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function validateCtfToolBootstrapManifest(value: unknown): CtfToolBootstrapManifest {
	if (
		!isRecord(value) ||
		value.schemaVersion !== "ctf-tool-bootstrap-1" ||
		value.origin !== "builtin" ||
		!Array.isArray(value.tools)
	) {
		throw new CtfBootstrapError(
			"Tool manifests must be the signed-in source builtin schema; challenge-provided manifests are rejected.",
		);
	}
	const tools: CtfToolSpec[] = [];
	for (const item of value.tools) {
		if (
			!isRecord(item) ||
			typeof item.id !== "string" ||
			typeof item.category !== "string" ||
			!CTF_TOOL_CATEGORIES.includes(item.category as BootstrapCategory) ||
			typeof item.binary !== "string" ||
			!Array.isArray(item.versionArgv) ||
			item.versionArgv.some(arg => typeof arg !== "string") ||
			!isRecord(item.packages)
		) {
			throw new CtfBootstrapError("Invalid CTF tool declaration.");
		}
		const packages: Partial<Record<BootstrapPackageManager, string>> = {};
		for (const manager of ["apt", "brew", "pacman", "dnf", "winget"] as const) {
			const packageName = item.packages[manager];
			if (packageName !== undefined) {
				if (typeof packageName !== "string" || packageName.length === 0 || /[\0\r\n]/.test(packageName))
					throw new CtfBootstrapError("Invalid package name in CTF tool declaration.");
				packages[manager] = packageName;
			}
		}
		if (Object.keys(packages).length === 0)
			throw new CtfBootstrapError("CTF tool declaration has no supported package manager.");
		const minimumVersion = typeof item.minimumVersion === "string" ? item.minimumVersion : undefined;
		const platforms = Array.isArray(item.platforms)
			? item.platforms.filter(
					(platform): platform is BootstrapPlatform =>
						platform === "linux" || platform === "darwin" || platform === "win32",
				)
			: undefined;
		tools.push({
			id: item.id,
			category: item.category as BootstrapCategory,
			binary: item.binary,
			versionArgv: [...item.versionArgv] as string[],
			packages,
			...(minimumVersion === undefined ? {} : { minimumVersion }),
			...(platforms === undefined ? {} : { platforms }),
		});
	}
	const ids = new Set<string>();
	for (const tool of tools) {
		if (ids.has(tool.id)) throw new CtfBootstrapError("Duplicate CTF tool declaration.");
		ids.add(tool.id);
	}
	const manifest = freezeManifest({
		schemaVersion: "ctf-tool-bootstrap-1" as const,
		origin: "builtin" as const,
		tools,
	});
	if (canonicalDigest(manifest) !== BUILTIN_CTF_TOOL_MANIFEST_DIGEST)
		throw new CtfBootstrapError("Tool manifest is not the reviewed builtin allowlist.");
	return manifest;
}

export function toolsForCategories(categories: readonly BootstrapCategory[]): readonly CtfToolSpec[] {
	const wanted = new Set(categories);
	return BUILTIN_CTF_TOOL_MANIFEST.tools.filter(tool => wanted.has(tool.category));
}

export function detectCtfPlatform(platform = process.platform): BootstrapPlatform {
	if (platform === "linux" || platform === "darwin" || platform === "win32") return platform;
	throw new CtfBootstrapError(`Unsupported platform: ${platform}`);
}

export async function detectCtfPackageManager(
	platform = detectCtfPlatform(),
	env: NodeJS.ProcessEnv = process.env,
): Promise<BootstrapPackageManager | undefined> {
	const candidates: readonly BootstrapPackageManager[] =
		platform === "darwin" ? ["brew"] : platform === "win32" ? ["winget"] : ["apt", "dnf", "pacman"];
	for (const manager of candidates) {
		const paths = (env.PATH ?? "").split(path.delimiter);
		const executable = manager === "apt" ? "apt-get" : manager;
		for (const directory of paths) {
			try {
				if ((await Bun.file(path.join(directory, executable)).stat()).isFile()) return manager;
			} catch {
				/* unavailable */
			}
		}
	}
	return undefined;
}

function packageInstallArgvs(
	manager: BootstrapPackageManager,
	packages: readonly string[],
	elevate: boolean,
): readonly (readonly string[])[] {
	if (manager === "winget")
		return Object.freeze(
			packages.map(packageName =>
				Object.freeze([
					"winget",
					"install",
					"--exact",
					"--id",
					packageName,
					"--accept-source-agreements",
					"--accept-package-agreements",
					"--disable-interactivity",
				]),
			),
		);
	const command = Object.freeze(
		manager === "apt"
			? ["apt-get", "install", "-y", ...packages]
			: manager === "brew"
				? ["brew", "install", ...packages]
				: manager === "pacman"
					? ["pacman", "-S", "--noconfirm", ...packages]
					: ["dnf", "install", "-y", ...packages],
	);
	return Object.freeze([Object.freeze(elevate && manager !== "brew" ? ["sudo", "-n", ...command] : [...command])]);
}

function assertReviewedManifest(manifest: CtfToolBootstrapManifest, reviewedDigest: string): void {
	if (reviewedDigest !== BUILTIN_CTF_TOOL_MANIFEST_DIGEST || canonicalDigest(manifest) !== reviewedDigest)
		throw new CtfBootstrapError("Tool manifest drifted from the reviewed builtin allowlist.");
}

function versionAtLeast(output: string, minimum: string | undefined): boolean {
	if (minimum === undefined) return true;
	const actual = output.match(/\d+(?:\.\d+){0,3}/)?.[0];
	if (actual === undefined) return false;
	const parse = (value: string): number[] => value.split(".").map(part => Number.parseInt(part, 10));
	const left = parse(actual);
	const right = parse(minimum);
	for (let index = 0; index < Math.max(left.length, right.length); index += 1) {
		const difference = (left[index] ?? 0) - (right[index] ?? 0);
		if (difference !== 0) return difference > 0;
	}
	return true;
}

export async function runExactArgv(
	argv: readonly string[],
): Promise<Readonly<{ exitCode: number; stdout: string; stderr: string }>> {
	if (argv.length === 0 || argv.some(arg => arg.includes("\0")))
		throw new CtfBootstrapError("Refusing an empty or NUL-containing command.");
	try {
		const child = Bun.spawn([...argv], { stdout: "pipe", stderr: "pipe" });
		const [stdout, stderr, exitCode] = await Promise.all([
			new Response(child.stdout).text(),
			new Response(child.stderr).text(),
			child.exited,
		]);
		return { exitCode, stdout, stderr };
	} catch {
		return { exitCode: 127, stdout: "", stderr: "executable unavailable" };
	}
}

export async function bootstrapCtfTools(
	input: Readonly<{
		categories?: readonly BootstrapCategory[];
		mode?: "dry-run" | "apply";
		platform?: BootstrapPlatform;
		packageManager?: BootstrapPackageManager;
		manifest?: unknown;
		run?: BootstrapCommandRunner;
		elevate?: boolean;
	}>,
): Promise<BootstrapResult> {
	if (input.mode !== undefined && input.mode !== "dry-run" && input.mode !== "apply")
		throw new CtfBootstrapError("Unsupported bootstrap mode.");
	if (input.categories?.some(category => !CTF_TOOL_CATEGORIES.includes(category)))
		throw new CtfBootstrapError("Unsupported CTF tool category.");
	if (input.mode === "apply" && (input.categories === undefined || input.categories.length === 0))
		throw new CtfBootstrapError("Apply mode requires at least one explicit tool category.");
	const manifest =
		input.manifest === undefined ? BUILTIN_CTF_TOOL_MANIFEST : validateCtfToolBootstrapManifest(input.manifest);
	const reviewedDigest = canonicalDigest(manifest);
	const platform = input.platform ?? detectCtfPlatform();
	const manager = input.packageManager ?? (await detectCtfPackageManager(platform));
	const elevate =
		input.elevate ??
		(platform !== "win32" && manager !== "brew" && typeof process.getuid === "function" && process.getuid() !== 0);
	const selected =
		input.categories === undefined
			? manifest.tools
			: manifest.tools.filter(tool => input.categories?.includes(tool.category));
	const run = input.run ?? runExactArgv;
	const observations: BootstrapObservation[] = [];
	const missing: CtfToolSpec[] = [];
	for (const tool of selected) {
		if (tool.platforms !== undefined && !tool.platforms.includes(platform)) {
			observations.push({
				tool: tool.id,
				category: tool.category,
				status: "unsupported",
				reason: `unsupported on ${platform}`,
			});
			continue;
		}
		const result = await run(tool.versionArgv);
		const version = `${result.stdout}\n${result.stderr}`.trim();
		if (result.exitCode === 0 && versionAtLeast(version, tool.minimumVersion))
			observations.push({ tool: tool.id, category: tool.category, status: "ready", version });
		else if (manager !== undefined && tool.packages[manager] !== undefined) {
			missing.push(tool);
			observations.push({
				tool: tool.id,
				category: tool.category,
				status: "installable",
				argv: [manager, tool.packages[manager] as string],
				...(result.exitCode === 0 ? { version, reason: `version below minimum ${tool.minimumVersion}` } : {}),
			});
		} else
			observations.push({
				tool: tool.id,
				category: tool.category,
				status: "unsupported",
				reason:
					result.exitCode === 0
						? `version below minimum ${tool.minimumVersion}`
						: "tool missing and no detected package manager",
			});
	}
	assertReviewedManifest(manifest, reviewedDigest);
	const commands =
		manager === undefined || missing.length === 0
			? []
			: packageInstallArgvs(
					manager,
					missing.map(tool => tool.packages[manager] as string),
					elevate,
				);
	if (input.mode === "apply") {
		if (commands.length === 0 && observations.some(observation => observation.status !== "ready"))
			throw new CtfBootstrapError("Selected tools cannot be installed on this platform.");
		assertReviewedManifest(manifest, reviewedDigest);
		for (const command of commands) {
			const install = await run(command);
			if (install.exitCode !== 0)
				throw new CtfBootstrapError(`Tool installation failed with exit code ${install.exitCode}.`);
		}
		for (const tool of missing) {
			const result = await run(tool.versionArgv);
			const version = `${result.stdout}\n${result.stderr}`.trim();
			if (result.exitCode !== 0 || !versionAtLeast(version, tool.minimumVersion))
				throw new CtfBootstrapError(`Installed tool did not pass verification: ${tool.id}.`);
			const index = observations.findIndex(observation => observation.tool === tool.id);
			observations[index] = { tool: tool.id, category: tool.category, status: "ready", version };
		}
		if (observations.some(observation => observation.status !== "ready"))
			throw new CtfBootstrapError("Selected tools remain unavailable after bootstrap.");
	}
	return {
		schemaVersion: "ctf-tool-bootstrap-result-1",
		mode: input.mode ?? "dry-run",
		platform,
		packageManager: manager,
		observations,
		commands,
	};
}
