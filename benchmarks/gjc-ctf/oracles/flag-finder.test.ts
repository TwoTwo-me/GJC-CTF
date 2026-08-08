import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { describe, expect, test } from "bun:test";
import { sha256Hex } from "../../../packages/coding-agent/src/ctf/contracts/digest";
import { extractFlagFinderChecker, verifyFlagFinder } from "./flag-finder";

const source = new TextEncoder().encode(`
	const len = 3;
	const theFlag = /^#..$/;
`);
const digest = sha256Hex(source);

function verify(candidate: string, input = "...") {
	return verifyFlagFinder({ source, expectedSourceDigest: digest, input, candidate });
}

describe("flag-finder local oracle", () => {
	test("extracts only static declarations with literal boundaries", () => {
		const checker = extractFlagFinderChecker(source);
		expect(checker.length).toBe(3);
		expect(checker.pattern.test("#..")).toBe(true);

		for (const invalid of [
			"const len = 3; const theFlag = new RegExp('^#..$');",
			"const len = 3; const theFlag = /^#..$/g;",
			"const len = 3; const theFlag = /^#..$/; const theFlag = /^...$/;",
			"const len = 3 + 0; const theFlag = /^#..$/;",
		]) {
			expect(() => extractFlagFinderChecker(new TextEncoder().encode(invalid))).toThrow();
		}
	});

	test("accepts and rejects candidate grids inside the oracle", () => {
		expect(verify("#..")).toMatchObject({ verdict: "pass", sourceDigest: digest });
		expect(verify("...")).toMatchObject({ verdict: "fail", reason: "grid does not satisfy checker" });
		expect(verify("#.")).toMatchObject({ verdict: "fail", reason: "grid length does not match checker" });
	});

	test("rejects malformed grids and source tampering", () => {
		expect(verify("#a.")).toMatchObject({ verdict: "fail", reason: "grid contains unsupported characters" });
		expect(verify("#..", ".x.")).toMatchObject({ verdict: "fail", reason: "grid contains unsupported characters" });
		const tampered = new TextEncoder().encode("const len = 3; const theFlag = /^...$/;");
		const result = verifyFlagFinder({ source: tampered, expectedSourceDigest: digest, input: "...", candidate: "..." });
		expect(result).toMatchObject({ verdict: "unavailable", reason: "source digest mismatch" });
	});

	test("returns only verdict, digests, and sanitized reasons", () => {
		const candidate = "#..";
		const output = verify(candidate);
		expect(Object.keys(output).sort()).toEqual(["candidateDigest", "inputDigest", "sourceDigest", "verdict"]);
		expect(JSON.stringify(output)).not.toContain(candidate);
		expect(output.candidateDigest).toBe(sha256Hex(candidate));
	});

	test("parses the pinned visible checker when its archive is available", async () => {
		const pinned = "/tmp/tmp.3VmxDRGOcp/archive/2026/rev/flag-finder/src/script.js";
		if (!existsSync(pinned)) return;
		const checker = extractFlagFinderChecker(new Uint8Array(await readFile(pinned)));
		expect(checker.length).toBeGreaterThan(0);
		expect(checker.pattern.flags).toBe("");
	});
});
