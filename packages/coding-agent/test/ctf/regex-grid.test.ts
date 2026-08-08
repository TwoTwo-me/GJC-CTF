import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
	analyzeRegexGridSource,
	analyzeRegexGridSourceWithZ3,
	reviewZ3Executable,
} from "../../src/ctf/solver/analyzers/regex-grid";

const PINNED_SCRIPT = "/tmp/lactf-archive-gjc/2026/rev/flag-finder/src/script.js";
const HAS_PINNED_SCRIPT = await fs.access(PINNED_SCRIPT).then(
	() => true,
	() => false,
);
const Z3_BINARY = Bun.which("z3");
const Z3_CAPABILITY = Z3_BINARY === null ? undefined : await reviewZ3Executable(Z3_BINARY);
const MINIMAL_NONOGRAM_SOURCE = "const len = 1; const theFlag = /^(?=(?:#){1}(?:\\.)*)(#)(?<=.{1})(?<!.{2})$/;";

describe("regex grid analyzer", () => {
	it("derives and independently validates a bitmap from a fixed-length lookahead", () => {
		const result = analyzeRegexGridSource("const len = 4; const theFlag = /^(?=\\.#\\.#).{4}$/;");
		expect(result).toEqual({ ok: true, candidate: ".#.#", diagnostics: ["derived 1 fixed-length grid constraints"] });
	});

	it("refuses malformed sources without producing a candidate", () => {
		const result = analyzeRegexGridSource("const len = 4; const theFlag = /^(?=\\.#).{4}$/;");
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.reason).toBe("no-grid-constraints");
	});

	it.skipIf(Z3_CAPABILITY === undefined)("solves a minimal nonogram with the reviewed Z3 capability", async () => {
		const result = await analyzeRegexGridSourceWithZ3(MINIMAL_NONOGRAM_SOURCE, { z3: Z3_CAPABILITY });
		expect(result).toEqual({
			ok: true,
			candidate: "#",
			diagnostics: ["solved 1x1 bounded nonogram constraints with z3"],
		});
	});

	it.skipIf(!HAS_PINNED_SCRIPT)(
		"requires an explicit reviewed Z3 authority for the pinned visible challenge source",
		async () => {
			const source = await fs.readFile(PINNED_SCRIPT, "utf8");
			const result = await analyzeRegexGridSourceWithZ3(source);
			expect(result).toMatchObject({ ok: false, reason: "missing-z3" });
		},
	);

	it.skipIf(!HAS_PINNED_SCRIPT || Z3_CAPABILITY === undefined)(
		"derives a candidate with an explicit reviewed Z3 capability",
		async () => {
			const source = await fs.readFile(PINNED_SCRIPT, "utf8");
			const result = await analyzeRegexGridSourceWithZ3(source, {
				z3: Z3_CAPABILITY!,
				timeoutMs: 60_000,
			});
			expect(result.ok).toBe(true);
			if (!result.ok) return;
			expect(result.candidate).toHaveLength(1919);
		},
		30_000,
	);

	it("refuses unsafe regex syntax without executing it", () => {
		const result = analyzeRegexGridSource("const len = 4; const theFlag = /^(a+)+$/;");
		expect(result).toMatchObject({ ok: false, reason: "unsupported-regex" });
	});

	it("retains cancellation and test-runner failure as typed refusals", async () => {
		const controller = new AbortController();
		controller.abort();
		await expect(
			analyzeRegexGridSourceWithZ3("const len = 1; const theFlag = /x/;", { signal: controller.signal }),
		).resolves.toMatchObject({ ok: false, reason: "cancelled" });
	});
	it("copies reviewed Z3 into a private content-addressed cache and rejects a replaced copy", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-z3-review-"));
		const source = path.join(root, "z3");
		const cache = path.join(root, "cache");
		await fs.writeFile(source, "#!/bin/sh\nprintf 'Z3 version 1.2.3\\n'\n", { mode: 0o700 });
		const capability = await reviewZ3Executable(source, { cacheDirectory: cache });
		expect(capability.executable).not.toBe(source);
		expect(capability.executable.startsWith(cache)).toBe(true);
		await fs.writeFile(capability.executable, "#!/bin/sh\nexit 1\n", { mode: 0o700 });
		await expect(analyzeRegexGridSourceWithZ3(MINIMAL_NONOGRAM_SOURCE, { z3: capability })).resolves.toMatchObject({
			ok: false,
			reason: "unreviewed-z3",
		});
		await expect(reviewZ3Executable(source, { cacheDirectory: cache })).rejects.toThrow("cache copy digest mismatch");
	});
});
