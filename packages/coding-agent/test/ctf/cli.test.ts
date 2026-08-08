import { describe, expect, test } from "bun:test";
import { parseBootstrapCommandArgs, parseCtfArgv, renderCtfHelp } from "../../src/ctf/cli";

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

describe("gjc-ctf bootstrap CLI surface", () => {
	test("parses only the closed reviewed argument grammar", () => {
		expect(parseBootstrapCommandArgs(["--category", "essential", "--category", "reverse", "--apply", "--json"])).toEqual({
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
