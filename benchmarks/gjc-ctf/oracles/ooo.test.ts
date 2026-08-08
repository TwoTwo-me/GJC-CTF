import { createHash } from "node:crypto";
import { describe, expect, test } from "bun:test";
import { analyzeOooRecurrenceSource } from "../../../packages/coding-agent/src/ctf/solver/analyzers/ooo-recurrence";
import { verifyOooCandidate } from "./ooo";

const operations = `def о(a, b):
    return a+b
def ο(a, b):
    return a-b
def օ(a, b):
    return a*b
def ỏ(a, b):
    return a//b
def ơ(a, b):
    return a^b
def ó(a, b):
    return a|b
def ὀ(a, b):
    return a&b
def ὸ(a, b):
    return b-a
def ὄ(a, b):
    return a
def ὂ(a, b):
    return b
def ȯ(a, b):
    return a % b`;

function reviewedSource(constants: number[]): string {
	return [
		operations,
		"    ",
		"",
		`ὁ = [${constants.join(", ")}]`,
		"",
		`guess = input("What's the flag? ") # remember, flags start with lactf{`,
		"",
		"if (len(guess) < len(ὁ)):",
		'    print("That\'s too short :(")',
		"    exit()",
		"    ",
		"for ö in range(len(ὁ)-1):",
		"    ό = ord(guess[ö])",
		"    ὃ = ord(guess[ö+1])",
		"    if (о(ὄ(ό,ὃ),ὂ(ό,ὃ)) != ὁ[ơ(ö,ȯ(օ(ό,ὃ),ό))]):",
		'        print("That\'s not the flag :(")',
		"        exit()",
		"    ",
		'print("That\'s the flag! :)")',
		"",
	].join("\n");
}

function sha256(value: string): string {
	return createHash("sha256").update(value).digest("hex");
}

const source = reviewedSource([200, 201, 202]);
const expectedSourceDigest = sha256(source);

function verify(candidate: string, checkerSource = source, expectedDigest = expectedSourceDigest) {
	return verifyOooCandidate({ source: checkerSource, candidate, expectedSourceDigest: expectedDigest });
}

describe("ooo local oracle", () => {
	test("accepts the reviewed checker semantics and permits trailing characters", () => {
		const accepted = verify("dde");
		const withExtraCharacter = verify("ddez");

		expect(accepted.verdict).toBe("pass");
		expect(withExtraCharacter.verdict).toBe("pass");
		expect(accepted.sourceDigest).toBe(expectedSourceDigest);
		expect(accepted.inputDigest).toBe(expectedSourceDigest);
		expect(accepted.candidateDigest).toBe(sha256("dde"));
	});

	test("rejects incorrect and short candidates", () => {
		expect(verify("dce").verdict).toBe("fail");
		expect(verify("dd").verdict).toBe("fail");
	});

	test("differentially accepts analyzer output across fresh checker fixtures", () => {
		const candidates = [
			"lactf{a}",
			"lactf{synthetic-ooo-01}",
			"lactf{mixed_123_symbols!?}",
			"lactf{accent-é}",
			"lactf{astral-😀}",
		];

		for (const candidate of candidates) {
			const codePoints = Array.from(candidate, character => character.codePointAt(0) as number);
			const constants = [...codePoints.slice(0, -1).map((value, index) => value + codePoints[index + 1]), 0];
			const checkerSource = reviewedSource(constants);
			const analysis = analyzeOooRecurrenceSource(checkerSource);

			expect(analysis.ok).toBe(true);
			if (!analysis.ok) continue;
			expect(analysis.candidate).toBe(candidate);
			expect(
				verifyOooCandidate({
					source: checkerSource,
					candidate: analysis.candidate,
					expectedSourceDigest: sha256(checkerSource),
				}).verdict,
			).toBe("pass");
		}
	});

	test("binds verification to the reviewed source bytes", () => {
		const changedSource = source.replace("[200, 201, 202]", "[200, 201, 203]");
		const changed = verify("dde", changedSource);

		expect(changed.verdict).toBe("unavailable");
		expect(changed.reason).toBe("source digest mismatch");
		expect(changed.sourceDigest).not.toBe(expectedSourceDigest);
	});

	test("fails closed when Unicode operator identities or checker code change", () => {
		const malformedOperatorSource = source.replace("def о(a, b):", "def o(a, b):");
		const malformed = verify("dde", malformedOperatorSource, sha256(malformedOperatorSource));
		const unexpectedCode = verify("dde", `${source}# extra`, sha256(`${source}# extra`));

		expect(malformed.verdict).toBe("unavailable");
		expect(unexpectedCode.verdict).toBe("unavailable");
	});

	test("returns digests and generic reasons without candidate leakage", () => {
		const candidate = "unique-candidate-value";
		const output = verify(candidate);
		const serialized = JSON.stringify(output);

		expect(Object.keys(output).sort()).toEqual(["candidateDigest", "inputDigest", "reason", "sourceDigest", "verdict"]);
		expect(serialized).not.toContain(candidate);
		expect(output.candidateDigest).toBe(sha256(candidate));
	});
});
