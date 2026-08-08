import { describe, expect, test } from "bun:test";
import { rm } from "node:fs/promises";
import {
	CTF_DASHBOARD_EMBEDDED_ARCHIVE,
	parseBootstrapCommandArgs,
	parseCtfArgv,
	parseStatsInspectCommandArgs,
	renderCtfHelp,
} from "../../src/ctf/cli";
import { canonicalDigest } from "../../src/ctf/contracts/digest";
import { createCtfDashboardAssetSource } from "../../src/ctf/dashboard/server";

const VERSION_OBSERVATION_PATH = new URL("../../../../artifacts/ctf/lactf-version-observation-v2.json", import.meta.url)
	.pathname;
const CTF_BIN_PATH = new URL("../../bin/gjc-ctf.js", import.meta.url).pathname;

async function captureCliOutput(
	argv: readonly string[],
): Promise<Readonly<{ stdout: string; stderr: string; exitCode: number }>> {
	const child = Bun.spawn([process.execPath, CTF_BIN_PATH, ...argv], {
		cwd: new URL("../../../..", import.meta.url).pathname,
		stdout: "pipe",
		stderr: "pipe",
	});
	const [stdout, stderr, exitCode] = await Promise.all([
		new Response(child.stdout).text(),
		new Response(child.stderr).text(),
		child.exited,
	]);
	return { stdout, stderr, exitCode };
}

describe("gjc-ctf solve CLI surface", () => {
	test("preserves multiple challenge ids and scheduler flags", () => {
		expect(
			parseCtfArgv(["solve", "zeta", "alpha", "--concurrency", "2", "--budget-ms", "5000", "--backend", "local"]),
		).toEqual({
			kind: "command",
			command: "solve",
			args: ["zeta", "alpha", "--concurrency", "2", "--budget-ms", "5000", "--backend", "local"],
		});
	});

	test("documents bounded batch options", () => {
		const help = renderCtfHelp();
		expect(help).toContain("CHALLENGE_ID...");
		expect(help).toContain("--concurrency N");
		expect(help).toContain("--budget-ms N");
		expect(help).toContain("--backend ID");
	});
});

describe("gjc-ctf embedded dashboard surface", () => {
	test("serves the canonical embedded assets without a writable package directory", async () => {
		const source = createCtfDashboardAssetSource(CTF_DASHBOARD_EMBEDDED_ARCHIVE);
		if (source === undefined) throw new Error("embedded dashboard archive did not create an asset source");
		for (const path of ["/", "/index.js", "/styles.css"]) {
			const response = await source(path);
			expect(response?.status).toBe(200);
			expect((await response?.text())?.length).toBeGreaterThan(0);
		}
		expect(await source("/unexpected.js")).toBeUndefined();
	});
});

describe("gjc-ctf bootstrap CLI surface", () => {
	test("parses only the closed reviewed argument grammar", () => {
		expect(
			parseBootstrapCommandArgs(["--category", "essential", "--category", "reverse", "--apply", "--json"]),
		).toEqual({
			categories: ["essential", "reverse"],
			mode: "apply",
			json: true,
		});
		expect(parseBootstrapCommandArgs([])).toEqual({ categories: undefined, mode: "dry-run", json: false });
	});

	test("rejects unknown, duplicate, missing, and ambiguous arguments", () => {
		expect(() => parseBootstrapCommandArgs(["--category"])).toThrow(/supported CTF tool category/u);
		expect(() => parseBootstrapCommandArgs(["--category", "unknown"])).toThrow(/supported CTF tool category/u);
		expect(() => parseBootstrapCommandArgs(["--category", "reverse", "--category", "reverse"])).toThrow(/Duplicate/u);
		expect(() => parseBootstrapCommandArgs(["--apply"])).toThrow(/explicit --category/u);
		expect(() => parseBootstrapCommandArgs(["--json", "--json"])).toThrow(/only once/u);
		expect(() => parseBootstrapCommandArgs(["--force"])).toThrow(/Unknown bootstrap argument/u);
	});
});
describe("gjc-ctf stats inspect CLI surface", () => {
	test("uses a closed stats inspect grammar and documents the read-only command", () => {
		expect(parseCtfArgv(["stats", "inspect", "--input", "observation.json", "--json"])).toEqual({
			kind: "command",
			command: "stats inspect",
			args: ["--input", "observation.json", "--json"],
		});
		expect(parseStatsInspectCommandArgs(["--json", "--input", "observation.json"])).toEqual({
			input: "observation.json",
			json: true,
		});
		expect(() => parseCtfArgv(["stats", "write"])).toThrow(/Expected "stats inspect"/u);
		expect(() => parseStatsInspectCommandArgs([])).toThrow(/Missing required --input/u);
		expect(() => parseStatsInspectCommandArgs(["--input", "a", "--input", "b"])).toThrow(/only once/u);
		expect(() => parseStatsInspectCommandArgs(["--input", "a", "--json", "--json"])).toThrow(/only once/u);
		expect(() => parseStatsInspectCommandArgs(["--input", "a", "--seal"])).toThrow(/Unknown stats inspect argument/u);
		expect(renderCtfHelp()).toContain("stats inspect --input PATH [--json]");
	});

	test("renders only validated diagnostic observation fields as JSON or candidate-free text", async () => {
		const text = await captureCliOutput(["stats", "inspect", "--input", VERSION_OBSERVATION_PATH]);
		expect(text).toEqual({
			stdout: expect.stringContaining("Independently verified solves: 0"),
			stderr: "",
			exitCode: 0,
		});
		expect(text.stdout).toContain("Status: unscored diagnostic observation");
		expect(text.stdout).toContain("Comparison: unavailable");
		expect(text.stdout).toContain("Tier 2: unauthorized");
		expect(text.stdout).toContain("Limitations:");
		const json = await captureCliOutput(["stats", "inspect", "--input", VERSION_OBSERVATION_PATH, "--json"]);
		expect(json.stderr).toBe("");
		expect(json.exitCode).toBe(0);
		expect(JSON.parse(json.stdout)).toMatchObject({
			schemaVersion: "gjc-ctf-version-observation-2",
			comparison: { benchmarkStatus: "unavailable", comparable: false },
		});
	});

	test("rejects malformed, wrong-schema, revoked, extra, digest-mismatched, and self-sealed inputs without partial output", async () => {
		const current = (await Bun.file(VERSION_OBSERVATION_PATH).json()) as Record<string, unknown>;
		const { observationDigest: _observationDigest, ...unsigned } = current;
		const selfSealed = {
			...unsigned,
			generatedAt: "2026-08-08T07:52:55.180Z",
		};
		const temporaryFiles = [
			`/tmp/gjc-ctf-stats-malformed-${crypto.randomUUID()}.json`,
			`/tmp/gjc-ctf-stats-extra-${crypto.randomUUID()}.json`,
			`/tmp/gjc-ctf-stats-self-sealed-${crypto.randomUUID()}.json`,
			`/tmp/gjc-ctf-stats-digest-${crypto.randomUUID()}.json`,
		];
		try {
			await Bun.write(temporaryFiles[0]!, "{");
			await Bun.write(temporaryFiles[1]!, JSON.stringify({ ...current, unexpected: true }));
			await Bun.write(temporaryFiles[3]!, JSON.stringify(selfSealed));
			await Bun.write(
				temporaryFiles[2]!,
				JSON.stringify({ ...selfSealed, observationDigest: canonicalDigest(selfSealed) }),
			);
			for (const path of [
				temporaryFiles[0]!,
				temporaryFiles[1]!,
				temporaryFiles[2]!,
				temporaryFiles[3]!,
				new URL("../../../../artifacts/ctf/lactf-deadline-version-observation-v1.json", import.meta.url).pathname,
				new URL("../../../../artifacts/ctf/lactf-expanded-v2-version-observation.json", import.meta.url).pathname,
			]) {
				const result = await captureCliOutput(["stats", "inspect", "--input", path, "--json"]);
				expect(result.stderr).toBe("");
				expect(result.exitCode).toBe(2);
				expect(result.stdout).toBe(
					`${JSON.stringify({
						schemaVersion: "ctf-api-1",
						error: {
							code: "invalid_api_request",
							message: "Stats inspection input is not a valid active v2 diagnostic observation.",
							retryable: false,
						},
					})}\n`,
				);
				expect(result.stdout).not.toContain(path);
			}
		} finally {
			await Promise.all(temporaryFiles.map(path => rm(path, { force: true })));
		}
	});
});
