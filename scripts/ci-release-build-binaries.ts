#!/usr/bin/env bun

import * as fs from "node:fs/promises";
import * as path from "node:path";
import { buildCtfDashboard } from "../packages/coding-agent/src/ctf/dashboard/build";
import {
	generateCtfDashboardArchive,
	validateCtfDashboardArchive,
} from "../packages/coding-agent/scripts/generate-ctf-dashboard-archive";
import { buildReleaseCompileArgs, buildReleaseCtfCompileArgs } from "../packages/coding-agent/scripts/compile-args";

interface BinaryTarget {
	id: string;
	platform: string;
	arch: string;
	target: string;
	outfile: string;
}

const repoRoot = path.join(import.meta.dir, "..");
const binariesDir = path.join(repoRoot, "packages", "coding-agent", "binaries");
const codingAgentDir = path.join(repoRoot, "packages", "coding-agent");
const ctfDashboardDist = path.join(codingAgentDir, "src", "ctf", "dashboard", "dist");
const ctfDashboardArchive = path.join(codingAgentDir, "src", "ctf", "dashboard", "embedded-client.generated.txt");
const ctfEntrypoint = path.join(codingAgentDir, "bin", "gjc-ctf.js");
const ctfSkill = path.join(codingAgentDir, "src", "ctf", "skills", "ctf.md");

const isDryRun = process.argv.includes("--dry-run");
const targets: BinaryTarget[] = [
	{
		id: "darwin-arm64",
		platform: "darwin",
		arch: "arm64",
		target: "bun-darwin-arm64",
		outfile: "packages/coding-agent/binaries/gjc-darwin-arm64",
	},
	{
		id: "darwin-x64",
		platform: "darwin",
		arch: "x64",
		target: "bun-darwin-x64-baseline",
		outfile: "packages/coding-agent/binaries/gjc-darwin-x64",
	},
	{
		id: "linux-x64",
		platform: "linux",
		arch: "x64",
		target: "bun-linux-x64-baseline",
		outfile: "packages/coding-agent/binaries/gjc-linux-x64",
	},
	{
		id: "linux-arm64",
		platform: "linux",
		arch: "arm64",
		target: "bun-linux-arm64",
		outfile: "packages/coding-agent/binaries/gjc-linux-arm64",
	},
	{
		id: "win32-x64",
		platform: "win32",
		arch: "x64",
		target: "bun-windows-x64-modern",
		outfile: "packages/coding-agent/binaries/gjc-windows-x64.exe",
	},
];

function parseRequestedTargets(): Set<string> | null {
	const flagIndexes = process.argv.flatMap((arg, index) => (arg === "--targets" ? [index] : []));
	const inlineFlags = process.argv.filter(arg => arg.startsWith("--targets="));
	if (flagIndexes.length + inlineFlags.length > 1) throw new Error("Release targets may be specified only once.");
	if (flagIndexes.length === 1) {
		const flagValue = process.argv[(flagIndexes[0] as number) + 1];
		if (flagValue === undefined || flagValue.startsWith("--") || flagValue.trim().length === 0)
			throw new Error("--targets requires a non-empty comma-separated target list.");
		return new Set(
			flagValue
				.split(",")
				.map(value => value.trim())
				.filter(Boolean),
		);
	}
	if (inlineFlags.length === 1) {
		const flagValue = (inlineFlags[0] as string).slice("--targets=".length);
		if (flagValue.trim().length === 0)
			throw new Error("--targets requires a non-empty comma-separated target list.");
		return new Set(
			flagValue
				.split(",")
				.map(value => value.trim())
				.filter(Boolean),
		);
	}
	const envValue = Bun.env.RELEASE_TARGETS;
	if (envValue === undefined || envValue.trim().length === 0) return null;
	const requested = new Set(
		envValue
			.split(",")
			.map(value => value.trim())
			.filter(Boolean),
	);
	if (requested.size === 0) throw new Error("RELEASE_TARGETS requires a non-empty comma-separated target list.");
	return requested;
}

function hostDefaultTargets(): BinaryTarget[] {
	// A bare invocation (no --targets / RELEASE_TARGETS) is a single-host
	// dogfood build, not a full release. Only the host's platform/arch can be
	// built here because `embed:native` requires a matching prebuilt addon, and
	// cross-arch addons are produced per-runner in CI. Default to the host
	// target instead of every release target so we never demand native addons
	// for architectures this machine cannot produce.
	return targets.filter(target => target.platform === process.platform && target.arch === process.arch);
}

function shouldAdhocSignDarwinBinary(target: BinaryTarget): boolean {
	return target.platform === "darwin" && process.platform === "darwin";
}

async function runCommand(command: string[], cwd: string, env: NodeJS.ProcessEnv = Bun.env): Promise<void> {
	const proc = Bun.spawn(command, {
		cwd,
		env,
		stdout: "inherit",
		stderr: "inherit",
	});
	const exitCode = await proc.exited;
	if (exitCode !== 0) {
		throw new Error(`Command failed with exit code ${exitCode}: ${command.join(" ")}`);
	}
}
function ctfOutputPath(target: BinaryTarget): string {
	const filename = path.basename(target.outfile);
	const extension = filename.endsWith(".exe") ? ".exe" : "";
	const stem = extension ? filename.slice(0, -extension.length) : filename;
	if (!stem.startsWith("gjc-")) throw new Error(`Unexpected GJC output path: ${target.outfile}`);
	return path.join(path.dirname(target.outfile), `gjc-ctf-${stem.slice("gjc-".length)}${extension}`);
}

async function ensureCtfFile(filePath: string): Promise<void> {
	let stat: Awaited<ReturnType<typeof fs.stat>>;
	try {
		stat = await fs.stat(filePath);
	} catch (error) {
		throw new Error(
			`Required CTF build asset is unavailable: ${path.relative(repoRoot, filePath)} (${error instanceof Error ? error.message : String(error)})`,
		);
	}
	if (!stat.isFile() || stat.size === 0) {
		throw new Error(`Required CTF build asset is missing or empty: ${path.relative(repoRoot, filePath)}`);
	}
}

async function generateCtfBuildAssets(): Promise<void> {
	if (isDryRun) {
		console.log(`DRY RUN CTF assets ${path.relative(repoRoot, ctfEntrypoint)} ${path.relative(repoRoot, ctfSkill)}`);
		return;
	}
	await ensureCtfFile(ctfEntrypoint);
	await ensureCtfFile(ctfSkill);
	await buildCtfDashboard({ outDir: ctfDashboardDist, minify: true });
	await generateCtfDashboardArchive({ inputDir: ctfDashboardDist, outputPath: ctfDashboardArchive });
	await validateCtfDashboardArchive({ inputDir: ctfDashboardDist, outputPath: ctfDashboardArchive });
	for (const filePath of [
		ctfEntrypoint,
		ctfSkill,
		path.join(ctfDashboardDist, "index.html"),
		path.join(ctfDashboardDist, "index.js"),
		path.join(ctfDashboardDist, "styles.css"),
		ctfDashboardArchive,
	]) {
		await ensureCtfFile(filePath);
	}
}

async function validateCompiledCtfBinary(target: BinaryTarget): Promise<void> {
	await ensureCtfFile(path.join(repoRoot, ctfOutputPath(target)));
}

async function embedNative(target: BinaryTarget): Promise<void> {
	if (isDryRun) {
		console.log(`DRY RUN bun --cwd=packages/natives run embed:native [${target.platform}/${target.arch}]`);
		return;
	}

	const embedEnv = {
		...Bun.env,
		TARGET_PLATFORM: target.platform,
		TARGET_ARCH: target.arch,
		...(target.arch === "x64" ? { EMBED_VARIANTS: "baseline" } : {}),
	};

	await runCommand(["bun", "--cwd=packages/natives", "run", "embed:native"], repoRoot, embedEnv);
}

async function buildBinary(target: BinaryTarget): Promise<void> {
	console.log(`Building ${target.outfile}...`);
	await embedNative(target);
	const compileArgs = buildReleaseCompileArgs(target.target, target.outfile);
	const ctfOutfile = ctfOutputPath(target);
	const ctfCompileArgs = buildReleaseCtfCompileArgs(target.target, ctfOutfile);
	console.log(`Building ${ctfOutfile}...`);
	if (isDryRun) {
		console.log(`DRY RUN ${compileArgs.join(" ")}`);
		console.log(`DRY RUN ${ctfCompileArgs.join(" ")}`);
		return;
	}

	const buildEnv = shouldAdhocSignDarwinBinary(target)
		? { ...Bun.env, BUN_NO_CODESIGN_MACHO_BINARY: "1" }
		: Bun.env;
	await runCommand(compileArgs, repoRoot, buildEnv);
	await runCommand(ctfCompileArgs, repoRoot, buildEnv);
	await validateCompiledCtfBinary(target);

	// Bun 1.3.12 emits a truncated Mach-O signature on darwin builds.
	if (shouldAdhocSignDarwinBinary(target)) {
		await runCommand(["codesign", "--force", "--sign", "-", path.join(repoRoot, target.outfile)], repoRoot);
		await runCommand(["codesign", "--force", "--sign", "-", path.join(repoRoot, ctfOutfile)], repoRoot);
	}
}

async function generateBundle(): Promise<void> {
	if (isDryRun) {
		console.log("DRY RUN bun --cwd=packages/stats scripts/generate-client-bundle.ts --generate");
		return;
	}
	await runCommand(["bun", "--cwd=packages/stats", "scripts/generate-client-bundle.ts", "--generate"], repoRoot);
}

async function resetArtifacts(): Promise<void> {
	if (isDryRun) {
		console.log("DRY RUN bun --cwd=packages/natives run embed:native --reset");
		console.log("DRY RUN bun --cwd=packages/stats scripts/generate-client-bundle.ts --reset");
		return;
	}
	await runCommand(["bun", "--cwd=packages/natives", "run", "embed:native", "--reset"], repoRoot);
	await runCommand(["bun", "--cwd=packages/stats", "scripts/generate-client-bundle.ts", "--reset"], repoRoot);
}

async function main(): Promise<void> {
	const requestedTargets = parseRequestedTargets();
	const selectedTargets = requestedTargets
		? targets.filter(target => requestedTargets.has(target.id))
		: hostDefaultTargets();

	if (requestedTargets) {
		const unknownTargets = [...requestedTargets].filter(
			requestedTarget => !targets.some(target => target.id === requestedTarget),
		);
		if (unknownTargets.length > 0) {
			throw new Error(`Unknown release target(s): ${unknownTargets.join(", ")}`);
		}
	}

	if (selectedTargets.length === 0) {
		if (requestedTargets) {
			throw new Error("No release targets selected.");
		}
		throw new Error(
			`No release target matches this host (${process.platform}-${process.arch}). ` +
				`Pass --targets <id> or set RELEASE_TARGETS to build a specific target.`,
		);
	}

	await fs.mkdir(binariesDir, { recursive: true });
	await generateCtfBuildAssets();
	await generateBundle();
	try {
		for (const target of selectedTargets) {
			await buildBinary(target);
		}
	} finally {
		await resetArtifacts();
	}
}

await main();
