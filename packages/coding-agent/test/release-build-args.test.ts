import { describe, expect, it } from "bun:test";

import * as path from "node:path";

import {
	buildDevCompileArgs,
	buildDevCtfCompileArgs,
	buildReleaseCompileArgs,
	buildReleaseCtfCompileArgs,
	devCtfEntrypoints,
	releaseCtfEntrypoints,
	releaseEntrypoints,
} from "../scripts/compile-args";

const releaseArgs = buildReleaseCompileArgs("bun-darwin-arm64", "packages/coding-agent/binaries/gjc-darwin-arm64");

function valuesAfter(args: string[], flag: string): string[] {
	const values: string[] = [];
	for (let index = 0; index < args.length - 1; index += 1) {
		if (args[index] === flag) {
			values.push(args[index + 1]);
		}
	}
	return values;
}

describe("release build compile args", () => {
	it("keeps minify and names flags in the release config", () => {
		expect(releaseArgs).toContain("--minify");
		expect(releaseArgs).toContain("--keep-names");
	});

	it("minifies both dev and release builds", () => {
		expect(buildDevCompileArgs()).toContain("--minify");
		expect(releaseArgs).toContain("--minify");
	});

	it("does not ship handlebars as a bunfs extra entrypoint (#1939)", () => {
		// --minify silently dropped the handlebars extra entrypoint from the
		// bunfs bundle, crashing v0.9.3–v0.9.6 compiled releases at startup.
		// handlebars is bundled via a statically-traceable require instead.
		expect(releaseEntrypoints).not.toContain("./node_modules/handlebars/lib/index.js");
		expect(releaseArgs).not.toContain("./node_modules/handlebars/lib/index.js");
		expect(buildDevCompileArgs()).not.toContain("../../node_modules/handlebars/lib/index.js");
	});

	it("marks release binaries with release build metadata", () => {
		expect(valuesAfter(releaseArgs, "--define")).toContain('process.env.PI_COMPILED="true"');
		expect(valuesAfter(releaseArgs, "--define")).toContain('process.env.GJC_BUILD_CHANNEL="release"');
		expect(valuesAfter(releaseArgs, "--define")).not.toContain('process.env.GJC_BUILD_CHANNEL="dev"');
	});

	it("marks dev-compiled binaries as dev builds explicitly", () => {
		const devDefines = valuesAfter(buildDevCompileArgs(), "--define");
		expect(devDefines).toContain('process.env.PI_COMPILED="true"');
		expect(devDefines).toContain('process.env.GJC_BUILD_CHANNEL="dev"');
	});

	it("includes worker entrypoints in release args", () => {
		expect(releaseEntrypoints).toContain("./packages/stats/src/sync-worker.ts");
		expect(releaseEntrypoints).toContain("./packages/coding-agent/src/tools/browser/tab-worker-entry.ts");
		expect(releaseEntrypoints).toContain("./packages/coding-agent/src/eval/js/worker-entry.ts");
		expect(releaseArgs).toContain("./packages/stats/src/sync-worker.ts");
		expect(releaseArgs).toContain("./packages/coding-agent/src/tools/browser/tab-worker-entry.ts");
		expect(releaseArgs).toContain("./packages/coding-agent/src/eval/js/worker-entry.ts");
	});

	it("does not list models.json as an extra compile entrypoint", () => {
		// Bun does not emit `.json` extra entrypoints into the compiled bunfs.
		// The bundled model catalog is embedded via the `with { type: "file" }`
		// import in @gajae-code/ai instead, so re-adding these args would regress
		// release binary startup.
		expect(releaseEntrypoints).not.toContain("./packages/ai/src/models.json");
		expect(releaseArgs).not.toContain("./packages/ai/src/models.json");
		expect(buildDevCompileArgs()).not.toContain("../ai/src/models.json");
	});

	it("embeds the CTF skill through its static text import, not as a second entrypoint", () => {
		const releaseCtfArgs = buildReleaseCtfCompileArgs(
			"bun-darwin-arm64",
			"packages/coding-agent/binaries/gjc-ctf-darwin-arm64",
		);
		const devCtfArgs = buildDevCtfCompileArgs();
		expect(releaseCtfEntrypoints).not.toContain("./packages/coding-agent/src/ctf/skills/ctf.md");
		expect(devCtfEntrypoints).not.toContain("./src/ctf/skills/ctf.md");
		expect(releaseCtfArgs).not.toContain("./packages/coding-agent/src/ctf/skills/ctf.md");
		expect(devCtfArgs).not.toContain("./src/ctf/skills/ctf.md");
	});

	it("has exactly one target and outfile", () => {
		expect(valuesAfter(releaseArgs, "--target")).toEqual(["bun-darwin-arm64"]);
		expect(valuesAfter(releaseArgs, "--outfile")).toEqual(["packages/coding-agent/binaries/gjc-darwin-arm64"]);
	});

	it("release script dry-run executes the builder output unmodified", () => {
		const repoRoot = path.resolve(import.meta.dir, "../../..");
		const result = Bun.spawnSync({
			cmd: [process.execPath, "scripts/ci-release-build-binaries.ts", "--dry-run"],
			cwd: repoRoot,
			stdout: "pipe",
			stderr: "pipe",
		});
		const stdout = result.stdout.toString();
		expect(result.exitCode, result.stderr.toString() || stdout).toBe(0);

		const buildLines = stdout.split("\n").filter(line => line.includes("bun build --compile"));
		expect(buildLines.length).toBeGreaterThan(0);
		expect(buildLines.some(line => line.includes("/gjc-ctf-") || line.includes("\\gjc-ctf-"))).toBe(true);
		for (const line of buildLines) {
			const argv = line.replace(/^DRY RUN /, "").split(" ");
			const target = valuesAfter(argv, "--target")[0];
			const outfile = valuesAfter(argv, "--outfile")[0];
			expect(target).toBeDefined();
			expect(outfile).toBeDefined();
			const builder = path.basename(outfile as string).startsWith("gjc-ctf-")
				? buildReleaseCtfCompileArgs
				: buildReleaseCompileArgs;
			expect(line).toBe(`DRY RUN ${builder(target as string, outfile as string).join(" ")}`);
		}
	});
	it("rejects empty or duplicate explicit release target selectors", () => {
		const repoRoot = path.resolve(import.meta.dir, "../../..");
		for (const args of [
			["--dry-run", "--targets="],
			["--dry-run", "--targets"],
			["--dry-run", "--targets=linux-x64", "--targets=darwin-arm64"],
		]) {
			const result = Bun.spawnSync({
				cmd: [process.execPath, "scripts/ci-release-build-binaries.ts", ...args],
				cwd: repoRoot,
				stdout: "pipe",
				stderr: "pipe",
			});
			expect(result.exitCode).not.toBe(0);
			expect(result.stderr.toString()).toMatch(/targets.*(?:non-empty|only once)/i);
		}
	});
	it("carries CTF binaries through smoke, upload, download, and release", async () => {
		const repoRoot = path.resolve(import.meta.dir, "../../..");
		const workflow = await Bun.file(path.join(repoRoot, ".github", "workflows", "ci.yml")).text();
		expect(workflow).toContain("ctf_binary_path:");
		expect(workflow).toContain('"${{ matrix.ctf_binary_path }}" --version');
		expect(workflow).toContain("name: gjc-ctf-binary-${{ matrix.target_id }}");
		expect(workflow).toContain("pattern: gjc-ctf-binary-*");
		expect(workflow).toContain("files: release-binaries/gjc-*");
	});
});
