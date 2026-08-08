import { createHash } from "node:crypto";
import { readFile, realpath, stat } from "node:fs/promises";
import * as path from "node:path";
import { canonicalDigest, type Digest } from "./contracts/digest";

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

export type ExecutableIdentity = Readonly<{
	path: string;
	sha256: Digest;
}>;

export type BootstrapObservation = Readonly<{
	tool: string;
	category: BootstrapCategory;
	status: "ready" | "installable" | "unsupported" | "invalid";
	version?: string;
	argv?: readonly string[];
	executable?: ExecutableIdentity;
	reason?: string;
}>;

export type BootstrapResult = Readonly<{
	schemaVersion: "ctf-tool-bootstrap-result-1";
	mode: "dry-run" | "apply";
	platform: BootstrapPlatform;
	bootstrapManifestDigest: Digest;
	packageManager?: BootstrapPackageManager;
	packageManagerIdentity?: ExecutableIdentity;
	elevationIdentity?: ExecutableIdentity;
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
export const BUILTIN_CTF_TOOL_MANIFEST_DIGEST: Digest = canonicalDigest(BUILTIN_CTF_TOOL_MANIFEST);

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

export type TrustedExecutablePolicy = Readonly<{
	roots: readonly string[];
	operatorCwd: string;
	rejectedRoots?: readonly string[];
}>;

export function defaultTrustedExecutablePolicy(
	platform: BootstrapPlatform = detectCtfPlatform(),
): TrustedExecutablePolicy {
	const executableRoot = path.dirname(process.execPath);
	const filesystemRoot = path.parse(process.execPath).root;
	const roots =
		platform === "linux"
			? ["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin", executableRoot]
			: platform === "darwin"
				? ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", executableRoot]
				: [executableRoot, path.join(filesystemRoot, "Windows", "System32")];
	return Object.freeze({
		roots: Object.freeze([...new Set(roots.map(root => path.resolve(root)))]),
		operatorCwd: filesystemRoot,
		rejectedRoots: Object.freeze([path.resolve(process.cwd())]),
	});
}

function isWithin(candidate: string, root: string): boolean {
	const relative = path.relative(root, candidate);
	return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function assertTrustedPolicy(policy: TrustedExecutablePolicy): readonly string[] {
	const operatorCwd = path.resolve(policy.operatorCwd);
	if (!path.isAbsolute(policy.operatorCwd) || operatorCwd === path.resolve("."))
		throw new CtfBootstrapError("Operator cwd must be an absolute non-current directory.");
	if (policy.roots.length === 0) throw new CtfBootstrapError("At least one trusted executable root is required.");
	const rejected = (policy.rejectedRoots ?? []).map(root => path.resolve(root));
	if (rejected.some(root => isWithin(operatorCwd, root)))
		throw new CtfBootstrapError("Operator cwd must not be a challenge or competition root.");
	return policy.roots.map(root => {
		const resolved = path.resolve(root);
		if (
			!path.isAbsolute(root) ||
			resolved === path.resolve(".") ||
			rejected.some(blocked => isWithin(resolved, blocked))
		)
			throw new CtfBootstrapError("Executable roots must be trusted absolute operator roots.");
		return resolved;
	});
}

function sha256(bytes: Uint8Array): Digest {
	return createHash("sha256").update(bytes).digest("hex") as Digest;
}

async function identityAt(candidate: string, roots: readonly string[]): Promise<ExecutableIdentity | undefined> {
	try {
		const resolved = await realpath(candidate);
		if (
			!path.isAbsolute(resolved) ||
			!roots.some(root => resolved === root || resolved.startsWith(`${root}${path.sep}`))
		)
			return undefined;
		if (!(await stat(resolved)).isFile()) return undefined;
		return Object.freeze({ path: resolved, sha256: sha256(await readFile(resolved)) });
	} catch {
		return undefined;
	}
}

export async function resolveTrustedExecutable(
	binary: string,
	policy: TrustedExecutablePolicy,
): Promise<ExecutableIdentity | undefined> {
	if (binary.length === 0 || path.basename(binary) !== binary || binary.includes("\0")) return undefined;
	const roots = assertTrustedPolicy(policy);
	for (const root of roots) {
		const identity = await identityAt(path.join(root, binary), roots);
		if (identity !== undefined) return identity;
	}
	return undefined;
}

async function assertCurrentIdentity(identity: ExecutableIdentity, policy: TrustedExecutablePolicy): Promise<void> {
	const current = await identityAt(identity.path, assertTrustedPolicy(policy));
	if (current === undefined || current.path !== identity.path || current.sha256 !== identity.sha256)
		throw new CtfBootstrapError("Executable identity drifted before invocation.");
}

function executableName(manager: BootstrapPackageManager): string {
	return manager === "apt" ? "apt-get" : manager;
}

export async function detectCtfPackageManager(
	platform: BootstrapPlatform,
	policy: TrustedExecutablePolicy,
): Promise<BootstrapPackageManager | undefined> {
	const candidates: readonly BootstrapPackageManager[] =
		platform === "darwin" ? ["brew"] : platform === "win32" ? ["winget"] : ["apt", "dnf", "pacman"];
	for (const manager of candidates)
		if ((await resolveTrustedExecutable(executableName(manager), policy)) !== undefined) return manager;
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
					"--source",
					"winget",
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

function assertReviewedManifest(manifest: CtfToolBootstrapManifest, reviewedDigest: Digest): void {
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
	input: Readonly<{ identity: ExecutableIdentity; policy: TrustedExecutablePolicy }>,
): Promise<Readonly<{ exitCode: number; stdout: string; stderr: string }>> {
	if (argv.length === 0 || !path.isAbsolute(argv[0] ?? "") || argv.some(arg => arg.includes("\0")))
		throw new CtfBootstrapError("Refusing a non-absolute or NUL-containing command.");
	await assertCurrentIdentity(input.identity, input.policy);
	try {
		const child = Bun.spawn([...argv], {
			cwd: input.policy.operatorCwd,
			env: { PATH: "" },
			stdout: "pipe",
			stderr: "pipe",
		});
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
		trustedExecutables?: TrustedExecutablePolicy;
	}>,
): Promise<BootstrapResult> {
	if (input.mode !== undefined && input.mode !== "dry-run" && input.mode !== "apply")
		throw new CtfBootstrapError("Unsupported bootstrap mode.");
	if (input.categories?.some(category => !CTF_TOOL_CATEGORIES.includes(category)))
		throw new CtfBootstrapError("Unsupported CTF tool category.");
	if (input.mode === "apply" && (input.categories === undefined || input.categories.length === 0))
		throw new CtfBootstrapError("Apply mode requires at least one explicit tool category.");
	const trustedExecutables =
		input.trustedExecutables ?? defaultTrustedExecutablePolicy(input.platform ?? detectCtfPlatform());
	assertTrustedPolicy(trustedExecutables);
	const manifest =
		input.manifest === undefined ? BUILTIN_CTF_TOOL_MANIFEST : validateCtfToolBootstrapManifest(input.manifest);
	const reviewedDigest = canonicalDigest(manifest) as Digest;
	const platform = input.platform ?? detectCtfPlatform();
	const manager = input.packageManager ?? (await detectCtfPackageManager(platform, trustedExecutables));
	const managerIdentity =
		manager === undefined ? undefined : await resolveTrustedExecutable(executableName(manager), trustedExecutables);
	if (manager !== undefined && managerIdentity === undefined)
		throw new CtfBootstrapError("Reviewed package manager is unavailable in trusted roots.");
	const elevate =
		input.elevate ??
		(platform !== "win32" && manager !== "brew" && typeof process.getuid === "function" && process.getuid() !== 0);
	const elevationIdentity = elevate ? await resolveTrustedExecutable("sudo", trustedExecutables) : undefined;
	const selected =
		input.categories === undefined
			? manifest.tools
			: manifest.tools.filter(tool => input.categories?.includes(tool.category));
	const invoke = async (identity: ExecutableIdentity, tail: readonly string[]) => {
		await assertCurrentIdentity(identity, trustedExecutables);
		const argv = Object.freeze([identity.path, ...tail]);
		return input.run === undefined ? runExactArgv(argv, { identity, policy: trustedExecutables }) : input.run(argv);
	};
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
		const identity = await resolveTrustedExecutable(tool.binary, trustedExecutables);
		const result =
			identity === undefined
				? { exitCode: 127, stdout: "", stderr: "executable unavailable" }
				: await invoke(identity, tool.versionArgv.slice(1));
		const version = `${result.stdout}\n${result.stderr}`.trim();
		if (identity !== undefined && result.exitCode === 0 && versionAtLeast(version, tool.minimumVersion))
			observations.push({ tool: tool.id, category: tool.category, status: "ready", version, executable: identity });
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
			const commandIdentity = command[0] === "sudo" ? elevationIdentity : managerIdentity;
			if (commandIdentity === undefined) throw new CtfBootstrapError("Installer identity is unavailable.");
			const tail =
				command[0] === "sudo"
					? [command[1] as string, managerIdentity?.path as string, ...command.slice(3)]
					: command.slice(1);
			const install = await invoke(commandIdentity, tail);
			if (install.exitCode !== 0)
				throw new CtfBootstrapError(`Tool installation failed with exit code ${install.exitCode}.`);
		}
		for (const tool of missing) {
			const identity = await resolveTrustedExecutable(tool.binary, trustedExecutables);
			if (identity === undefined)
				throw new CtfBootstrapError(`Installed tool did not pass verification: ${tool.id}.`);
			const result = await invoke(identity, tool.versionArgv.slice(1));
			const version = `${result.stdout}\n${result.stderr}`.trim();
			if (result.exitCode !== 0 || !versionAtLeast(version, tool.minimumVersion))
				throw new CtfBootstrapError(`Installed tool did not pass verification: ${tool.id}.`);
			const index = observations.findIndex(observation => observation.tool === tool.id);
			observations[index] = {
				tool: tool.id,
				category: tool.category,
				status: "ready",
				version,
				executable: identity,
			};
		}
		if (observations.some(observation => observation.status !== "ready"))
			throw new CtfBootstrapError("Selected tools remain unavailable after bootstrap.");
	}
	return Object.freeze({
		schemaVersion: "ctf-tool-bootstrap-result-1",
		mode: input.mode ?? "dry-run",
		platform,
		bootstrapManifestDigest: reviewedDigest,
		...(manager === undefined ? {} : { packageManager: manager }),
		...(managerIdentity === undefined ? {} : { packageManagerIdentity: managerIdentity }),
		...(elevationIdentity === undefined ? {} : { elevationIdentity }),
		observations: Object.freeze(observations),
		commands: Object.freeze(commands),
	});
}
