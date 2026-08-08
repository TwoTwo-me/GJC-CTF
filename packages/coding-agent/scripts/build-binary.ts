#!/usr/bin/env bun

import * as path from "node:path";
import { buildCtfDashboard } from "../src/ctf/dashboard/build";
import { buildDevCompileArgs, buildDevCtfCompileArgs } from "./compile-args";
import { generateCtfDashboardArchive, validateCtfDashboardArchive } from "./generate-ctf-dashboard-archive";

const packageDir = path.join(import.meta.dir, "..");
const outputPath = path.join(packageDir, "dist", "gjc");
const nativeDir = path.join(packageDir, "..", "natives", "native");
const ctfDashboardDist = path.join(packageDir, "src", "ctf", "dashboard", "dist");
const ctfDashboardArchive = path.join(packageDir, "src", "ctf", "dashboard", "embedded-client.generated.txt");
const ctfEntrypoint = path.join(packageDir, "bin", "gjc-ctf.js");
const ctfSkill = path.join(packageDir, "src", "ctf", "skills", "ctf.md");
const ctfOutput = "dist/gjc-ctf";
const ctfOutputPath = path.join(packageDir, ctfOutput);

function shouldAdhocSignDarwinBinary(): boolean {
	return process.platform === "darwin";
}

async function runCommand(command: string[], env: NodeJS.ProcessEnv = Bun.env): Promise<void> {
	const proc = Bun.spawn(command, {
		cwd: packageDir,
		env,
		stdout: "inherit",
		stderr: "inherit",
	});
	const exitCode = await proc.exited;
	if (exitCode !== 0) {
		throw new Error(`Command failed with exit code ${exitCode}: ${command.join(" ")}`);
	}
}
async function stageWorkspaceNativeAddons(): Promise<void> {
	await Array.fromAsync(new Bun.Glob("pi_natives.*.node").scan({ cwd: nativeDir }), async filename => {
		await Bun.write(path.join(packageDir, "dist", filename), Bun.file(path.join(nativeDir, filename)));
	});
}
async function generateCtfBuildAssets(): Promise<void> {
	for (const filePath of [ctfEntrypoint, ctfSkill]) {
		if (!(await Bun.file(filePath).exists())) {
			throw new Error(`Required CTF build asset is missing: ${path.relative(packageDir, filePath)}`);
		}
	}
	await buildCtfDashboard({ outDir: ctfDashboardDist, minify: true });
	await generateCtfDashboardArchive({
		inputDir: ctfDashboardDist,
		outputPath: ctfDashboardArchive,
	});
	await validateCtfBuildInputs();
}
async function validateCtfBuildInputs(): Promise<void> {
	const dashboardAssets = [
		ctfEntrypoint,
		ctfSkill,
		path.join(ctfDashboardDist, "index.html"),
		path.join(ctfDashboardDist, "index.js"),
		path.join(ctfDashboardDist, "styles.css"),
		ctfDashboardArchive,
	];
	for (const filePath of dashboardAssets) {
		const file = Bun.file(filePath);
		if (!(await file.exists()) || (await file.size) === 0) {
			throw new Error(`Required CTF build asset is missing or empty: ${path.relative(packageDir, filePath)}`);
		}
	}
	await validateCtfDashboardArchive({ inputDir: ctfDashboardDist, outputPath: ctfDashboardArchive });
}

async function validateCompiledCtfBinary(): Promise<void> {
	const binary = Bun.file(ctfOutputPath);
	if (!(await binary.exists()) || (await binary.size) === 0) {
		throw new Error(`CTF compile did not emit ${path.relative(packageDir, ctfOutputPath)}`);
	}
}

async function main(): Promise<void> {
	await generateCtfBuildAssets();
	await runCommand(["bun", "--cwd=../stats", "scripts/generate-client-bundle.ts", "--generate"]);
	try {
		await runCommand(["bun", "--cwd=../natives", "run", "embed:native"]);
		try {
			const buildEnv = shouldAdhocSignDarwinBinary() ? { ...Bun.env, BUN_NO_CODESIGN_MACHO_BINARY: "1" } : Bun.env;
			await runCommand(buildDevCompileArgs(), buildEnv);
			await runCommand(buildDevCtfCompileArgs(ctfOutput), buildEnv);
			await validateCompiledCtfBinary();
			await validateCtfBuildInputs();

			await stageWorkspaceNativeAddons();
			// Bun 1.3.12 emits a truncated Mach-O signature on darwin builds.
			if (shouldAdhocSignDarwinBinary()) {
				await runCommand(["codesign", "--force", "--sign", "-", outputPath]);
				await runCommand(["codesign", "--force", "--sign", "-", ctfOutputPath]);
			}
		} finally {
			await runCommand(["bun", "--cwd=../natives", "run", "embed:native", "--reset"]);
		}
	} finally {
		await runCommand(["bun", "--cwd=../stats", "scripts/generate-client-bundle.ts", "--reset"]);
	}
}

await main();
