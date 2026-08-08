import { createHash } from "node:crypto";

export type OooVerdict = "pass" | "fail" | "unavailable";

export interface OooOracleResult {
	verdict: OooVerdict;
	sourceDigest: string;
	inputDigest: string;
	candidateDigest: string;
	reason?: string;
}

export interface OooOracleRequest {
	source: Uint8Array | string;
	candidate: string;
	/** SHA-256 of the reviewed checker bytes. Required to bind this local verifier. */
	expectedSourceDigest?: string;
}

const SHA256_HEX = /^[a-f0-9]{64}$/;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

const OPERATION_LINES = [
	"def о(a, b):\n    return a+b",
	"def ο(a, b):\n    return a-b",
	"def օ(a, b):\n    return a*b",
	"def ỏ(a, b):\n    return a//b",
	"def ơ(a, b):\n    return a^b",
	"def ó(a, b):\n    return a|b",
	"def ὀ(a, b):\n    return a&b",
	"def ὸ(a, b):\n    return b-a",
	"def ὄ(a, b):\n    return a",
	"def ὂ(a, b):\n    return b",
	"def ȯ(a, b):\n    return a % b",
].join("\n");
const CONSTANT_PREFIX = `${OPERATION_LINES}\n    \n\nὁ = [`;

const CHECKER_SUFFIX = [
	"",
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

function digest(value: Uint8Array): string {
	return createHash("sha256").update(value).digest("hex");
}

function sourceBytes(source: Uint8Array | string): Uint8Array {
	return typeof source === "string" ? textEncoder.encode(source) : source;
}

function result(sourceDigest: string, candidateDigest: string, verdict: OooVerdict, reason?: string): OooOracleResult {
	return {
		verdict,
		sourceDigest,
		inputDigest: sourceDigest,
		candidateDigest,
		...(reason === undefined ? {} : { reason }),
	};
}

function parseConstants(source: string): number[] | undefined {
	const marker = "ὁ = [";
	const start = source.indexOf(marker);
	if (start === -1) return undefined;
	const end = source.indexOf("]", start + marker.length);
	if (end === -1) return undefined;
	const constantsText = source.slice(start + marker.length, end);
	if (source !== `${CONSTANT_PREFIX}${constantsText}]${CHECKER_SUFFIX}`) return undefined;
	if (!/^(?:0|[1-9]\d*)(?:, (?:0|[1-9]\d*))*$/.test(constantsText)) return undefined;
	const constants = constantsText.split(", ").map(Number);
	return constants.length >= 2 && constants.every((value) => Number.isSafeInteger(value) && value >= 0) ? constants : undefined;
}

function isWellFormedUnicode(value: string): boolean {
	for (let index = 0; index < value.length; index += 1) {
		const codeUnit = value.charCodeAt(index);
		if (codeUnit < 0xd800 || codeUnit > 0xdfff) continue;
		if (codeUnit > 0xdbff || index + 1 === value.length) return false;
		const next = value.charCodeAt(index + 1);
		if (next < 0xdc00 || next > 0xdfff) return false;
		index += 1;
	}
	return true;
}

/**
 * Evaluates only the reviewed visible checker language. The expected source digest
 * is supplied by trusted authority; this oracle never accepts an unbound source.
 */
export function verifyOooCandidate(request: OooOracleRequest): OooOracleResult {
	const bytes = sourceBytes(request.source);
	const sourceDigest = digest(bytes);
	const candidateDigest = digest(textEncoder.encode(request.candidate));

	if (request.expectedSourceDigest === undefined || !SHA256_HEX.test(request.expectedSourceDigest)) {
		return result(sourceDigest, candidateDigest, "unavailable", "missing or invalid expected source digest");
	}
	if (sourceDigest !== request.expectedSourceDigest) return result(sourceDigest, candidateDigest, "unavailable", "source digest mismatch");

	let source: string;
	try {
		source = textDecoder.decode(bytes);
	} catch {
		return result(sourceDigest, candidateDigest, "unavailable", "source is not valid UTF-8");
	}
	const constants = parseConstants(source);
	if (constants === undefined) return result(sourceDigest, candidateDigest, "unavailable", "source contains unsupported checker code");
	if (typeof request.candidate !== "string" || !isWellFormedUnicode(request.candidate)) {
		return result(sourceDigest, candidateDigest, "fail", "candidate is not well-formed Unicode");
	}

	const characters = Array.from(request.candidate);
	if (characters.length < constants.length) return result(sourceDigest, candidateDigest, "fail", "candidate is too short");
	try {
		for (let index = 0; index < constants.length - 1; index += 1) {
			const left = characters[index].codePointAt(0);
			const right = characters[index + 1].codePointAt(0);
			if (left === undefined || right === undefined || left === 0) throw new Error("checker evaluation error");
			const expectedIndex = index ^ ((left * right) % left);
			if (!Number.isSafeInteger(expectedIndex) || expectedIndex < 0 || expectedIndex >= constants.length) throw new Error("checker evaluation error");
			if (left + right !== constants[expectedIndex]) return result(sourceDigest, candidateDigest, "fail", "candidate does not satisfy checker");
		}
	} catch {
		return result(sourceDigest, candidateDigest, "fail", "checker evaluation error");
	}
	return result(sourceDigest, candidateDigest, "pass");
}

export const oooSha256 = digest;
