import { describe, expect, test } from "bun:test";
import {
	BUILTIN_CTF_TOOL_MANIFEST,
	bootstrapCtfTools,
	runExactArgv,
	validateCtfToolBootstrapManifest,
} from "../../src/ctf/bootstrap";

describe("CTF safe tool bootstrap", () => {
	test("dry-run reports missing tools without executing an install", async () => {
		const calls: string[][] = [];
		const result = await bootstrapCtfTools({
			categories: ["network"],
			platform: "linux",
			packageManager: "apt",
			elevate: false,
			run: async argv => {
				calls.push([...argv]);
				return { exitCode: 127, stdout: "", stderr: "missing" };
			},
		});
		expect(result.mode).toBe("dry-run");
		expect(result.commands).toEqual([["apt-get", "install", "-y", "curl"]]);
		expect(calls).toEqual([["curl", "--version"]]);
	});
	test("uses non-interactive privilege elevation only for reviewed system package managers", async () => {
		const result = await bootstrapCtfTools({
			categories: ["network"],
			platform: "linux",
			packageManager: "apt",
			elevate: true,
			run: async () => ({ exitCode: 127, stdout: "", stderr: "missing" }),
		});
		expect(result.commands).toEqual([["sudo", "-n", "apt-get", "install", "-y", "curl"]]);
	});

	test("apply uses one exact argv install and is idempotent when ready", async () => {
		const calls: string[][] = [];
		const result = await bootstrapCtfTools({
			categories: ["network"],
			mode: "apply",
			platform: "linux",
			packageManager: "apt",
			elevate: false,
			run: async argv => {
				calls.push([...argv]);
				if (calls.length === 1) return { exitCode: 127, stdout: "", stderr: "missing" };
				if (calls.length === 2) return { exitCode: 0, stdout: "", stderr: "" };
				return { exitCode: 0, stdout: "", stderr: "curl 8.0.0" };
			},
		});
		expect(result.observations[0]?.status).toBe("ready");
		expect(calls).toEqual([
			["curl", "--version"],
			["apt-get", "install", "-y", "curl"],
			["curl", "--version"],
		]);

		const ready = await bootstrapCtfTools({
			categories: ["network"],
			platform: "linux",
			packageManager: "apt",
			elevate: false,
			run: async argv => ({ exitCode: 0, stdout: `${argv[0]} 1`, stderr: "" }),
		});
		expect(ready.commands).toEqual([]);
	});
	test("uses one exact non-interactive winget command per reviewed package", async () => {
		const calls: string[][] = [];
		const result = await bootstrapCtfTools({
			categories: ["essential"],
			mode: "apply",
			platform: "win32",
			packageManager: "winget",
			run: async argv => {
				calls.push([...argv]);
				if (argv[0] === "winget") return { exitCode: 0, stdout: "", stderr: "" };
				const installCount = calls.filter(call => call[0] === "winget").length;
				return installCount < 2
					? { exitCode: 127, stdout: "", stderr: "missing" }
					: { exitCode: 0, stdout: `${argv[0]} 1`, stderr: "" };
			},
		});
		expect(result.commands).toEqual([
			[
				"winget",
				"install",
				"--exact",
				"--id",
				"Python.Python.3.12",
				"--accept-source-agreements",
				"--accept-package-agreements",
				"--disable-interactivity",
			],
			[
				"winget",
				"install",
				"--exact",
				"--id",
				"Git.Git",
				"--accept-source-agreements",
				"--accept-package-agreements",
				"--disable-interactivity",
			],
		]);
		expect(result.observations.every(observation => observation.status === "ready")).toBe(true);
	});

	test("deep-freezes reviewed argv and package maps before planning and execution", async () => {
		const candidate = structuredClone(BUILTIN_CTF_TOOL_MANIFEST);
		const reviewed = validateCtfToolBootstrapManifest(candidate);
		const candidateCurl = candidate.tools.find(tool => tool.id === "curl");
		const curl = reviewed.tools.find(tool => tool.id === "curl");
		if (candidateCurl === undefined || curl === undefined) throw new Error("Reviewed curl declaration is missing.");
		(candidateCurl.versionArgv as unknown as string[])[0] = "sh";
		(candidateCurl.packages as unknown as Record<string, string>).apt = "attacker-package";
		expect(curl.versionArgv).toEqual(["curl", "--version"]);
		expect(curl.packages.apt).toBe("curl");
		expect(() => {
			(curl.versionArgv as unknown as string[])[0] = "sh";
		}).toThrow();
		expect(() => {
			(curl.packages as unknown as Record<string, string>).apt = "attacker-package";
		}).toThrow();

		const calls: string[][] = [];
		const result = await bootstrapCtfTools({
			categories: ["network"],
			mode: "apply",
			platform: "linux",
			packageManager: "apt",
			elevate: false,
			run: async argv => {
				calls.push([...argv]);
				expect(() => {
					(argv as unknown as string[])[0] = "sh";
				}).toThrow();
				if (calls.length === 1) return { exitCode: 127, stdout: "", stderr: "missing" };
				if (calls.length === 2) return { exitCode: 0, stdout: "", stderr: "" };
				return { exitCode: 0, stdout: "", stderr: "curl 8.0.0" };
			},
		});

		expect(result.commands).toEqual([["apt-get", "install", "-y", "curl"]]);
		expect(calls).toEqual([
			["curl", "--version"],
			["apt-get", "install", "-y", "curl"],
			["curl", "--version"],
		]);
	});
	test("rejects challenge-controlled manifests", () => {
		expect(() =>
			validateCtfToolBootstrapManifest({ schemaVersion: "ctf-tool-bootstrap-1", origin: "challenge", tools: [] }),
		).toThrow(/challenge-provided/);
		expect(() =>
			validateCtfToolBootstrapManifest({
				schemaVersion: "ctf-tool-bootstrap-1",
				origin: "builtin",
				tools: [
					{
						id: "shell",
						category: "network",
						binary: "sh",
						versionArgv: ["sh", "-c", "id"],
						packages: { apt: "curl" },
					},
				],
			}),
		).toThrow(/reviewed builtin allowlist/);
	});

	test("fails closed when installation or post-install verification fails", async () => {
		await expect(
			bootstrapCtfTools({
				categories: ["network"],
				mode: "apply",
				platform: "linux",
				packageManager: "apt",
				elevate: false,
				run: async argv => ({
					exitCode: argv[0] === "apt-get" ? 1 : 127,
					stdout: "",
					stderr: "failed",
				}),
			}),
		).rejects.toThrow(/installation failed/);
	});
	test("fails apply when a selected tool has no install authority", async () => {
		await expect(
			bootstrapCtfTools({
				categories: ["forensics"],
				mode: "apply",
				platform: "win32",
				packageManager: "winget",
				run: async () => ({ exitCode: 127, stdout: "", stderr: "missing" }),
			}),
		).rejects.toThrow(/cannot be installed/);
	});
	test("requires an explicit reviewed profile before applying", async () => {
		await expect(bootstrapCtfTools({ mode: "apply" })).rejects.toThrow(/explicit tool category/);
		await expect(bootstrapCtfTools({ categories: ["untrusted" as never], platform: "linux" })).rejects.toThrow(
			/Unsupported CTF tool category/,
		);
	});

	test("reports an unavailable executable without aborting a dry-run", async () => {
		const result = await runExactArgv(["gjc-ctf-definitely-missing-binary", "--version"]);
		expect(result).toEqual({ exitCode: 127, stdout: "", stderr: "executable unavailable" });
	});
	test("does not interpolate shell metacharacters", async () => {
		const result = await runExactArgv(["printf", "%s", "$(touch /tmp/ctf-bootstrap-should-not-exist)"]);
		expect(result.exitCode).toBe(0);
		expect(result.stdout).toContain("$(touch /tmp/ctf-bootstrap-should-not-exist)");
	});
});
