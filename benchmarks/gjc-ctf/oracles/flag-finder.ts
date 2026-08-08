import { canonicalDigest, sha256Hex, type Digest } from "../../../packages/coding-agent/src/ctf/contracts/digest";

export type FlagFinderVerdict = "pass" | "fail" | "unavailable";

export type FlagFinderOracleRequest = Readonly<{
	source: Uint8Array;
	expectedSourceDigest: Digest;
	input: string;
	candidate: string;
}>;

export type FlagFinderOracleResult = Readonly<{
	verdict: FlagFinderVerdict;
	sourceDigest: Digest;
	inputDigest: Digest;
	candidateDigest: Digest;
	reason?: string;
}>;

export type FlagFinderChecker = Readonly<{
	length: number;
	pattern: RegExp;
}>;

class ExtractionError extends Error {}

const decoder = new TextDecoder("utf-8", { fatal: true });
const identifier = /[A-Za-z0-9_$]/;

function isIdentifierCharacter(value: string | undefined): boolean {
	return value !== undefined && identifier.test(value);
}

function skipTrivia(source: string, offset: number): number {
	while (offset < source.length) {
		if (/\s/.test(source[offset]!)) {
			offset += 1;
			continue;
		}
		if (source.startsWith("//", offset)) {
			const end = source.indexOf("\n", offset + 2);
			offset = end === -1 ? source.length : end + 1;
			continue;
		}
		if (source.startsWith("/*", offset)) {
			const end = source.indexOf("*/", offset + 2);
			if (end === -1) throw new ExtractionError("unterminated comment");
			offset = end + 2;
			continue;
		}
		return offset;
	}
	return offset;
}

function skipQuoted(source: string, offset: number, quote: string): number {
	offset += 1;
	while (offset < source.length) {
		if (source[offset] === "\\") {
			offset += 2;
			continue;
		}
		if (source[offset] === quote) return offset + 1;
		offset += 1;
	}
	throw new ExtractionError("unterminated string");
}

function readIdentifier(source: string, offset: number): readonly [string, number] {
	if (!/[A-Za-z_$]/.test(source[offset] ?? "")) throw new ExtractionError("expected identifier");
	const start = offset;
	offset += 1;
	while (isIdentifierCharacter(source[offset])) offset += 1;
	return [source.slice(start, offset), offset];
}

function readRegexLiteral(source: string, offset: number): readonly [string, string, number] {
	if (source[offset] !== "/") throw new ExtractionError("theFlag must be a regex literal");
	let pattern = "";
	let inClass = false;
	offset += 1;
	while (offset < source.length) {
		const character = source[offset]!;
		if (character === "\\") {
			if (offset + 1 >= source.length) throw new ExtractionError("unterminated regex literal");
			pattern += character + source[offset + 1]!;
			offset += 2;
			continue;
		}
		if (character === "[") inClass = true;
		if (character === "]") inClass = false;
		if (character === "/" && !inClass) {
			offset += 1;
			break;
		}
		if (character === "\n" || character === "\r") throw new ExtractionError("unterminated regex literal");
		pattern += character;
		offset += 1;
	}
	if (offset > source.length || source[offset - 1] !== "/") throw new ExtractionError("unterminated regex literal");
	const flagsStart = offset;
	while (/[A-Za-z]/.test(source[offset] ?? "")) offset += 1;
	return [pattern, source.slice(flagsStart, offset), offset];
}

/** Extracts only static top-level `const len` and `const theFlag` declarations. */
export function extractFlagFinderChecker(sourceBytes: Uint8Array): FlagFinderChecker {
	let source: string;
	try {
		source = decoder.decode(sourceBytes);
	} catch {
		throw new ExtractionError("source is not valid UTF-8");
	}

	let foundLength: number | undefined;
	let foundPattern: RegExp | undefined;
	let offset = 0;
	while (offset < source.length) {
		offset = skipTrivia(source, offset);
		if (offset >= source.length) break;
		const character = source[offset]!;
		if (character === '"' || character === "'" || character === "`") {
			offset = skipQuoted(source, offset, character);
			continue;
		}
		if (!source.startsWith("const", offset) || isIdentifierCharacter(source[offset - 1]) || isIdentifierCharacter(source[offset + 5])) {
			offset += 1;
			continue;
		}

		let cursor = skipTrivia(source, offset + 5);
		const [name, afterName] = readIdentifier(source, cursor);
		if (name !== "len" && name !== "theFlag") {
			offset = afterName;
			continue;
		}
		cursor = skipTrivia(source, afterName);
		if (source[cursor] !== "=") throw new ExtractionError(`${name} must have a static initializer`);
		cursor = skipTrivia(source, cursor + 1);

		if (name === "len") {
			const match = /^(0|[1-9][0-9]*)/.exec(source.slice(cursor));
			if (match === null) throw new ExtractionError("len must be an integer literal");
			cursor += match[0].length;
			cursor = skipTrivia(source, cursor);
			if (source[cursor] !== ";") throw new ExtractionError("len declaration must end at its literal");
			const length = Number(match[0]);
			if (!Number.isSafeInteger(length) || length < 1 || length > 100_000 || foundLength !== undefined)
				throw new ExtractionError("len declaration is invalid or duplicated");
			foundLength = length;
			offset = cursor + 1;
			continue;
		}

		const [pattern, flags, afterRegex] = readRegexLiteral(source, cursor);
		cursor = skipTrivia(source, afterRegex);
		if (source[cursor] !== ";") throw new ExtractionError("theFlag declaration must end at its regex literal");
		if (flags !== "" || foundPattern !== undefined || pattern.length > 32_768)
			throw new ExtractionError("theFlag regex declaration is invalid or duplicated");
		try {
			foundPattern = new RegExp(pattern, flags);
		} catch {
			throw new ExtractionError("theFlag regex is invalid");
		}
		offset = cursor + 1;
	}

	if (foundLength === undefined || foundPattern === undefined) throw new ExtractionError("required checker declarations are unavailable");
	return Object.freeze({ length: foundLength, pattern: foundPattern });
}

function result(
	verdict: FlagFinderVerdict,
	sourceDigest: Digest,
	inputDigest: Digest,
	candidateDigest: Digest,
	reason?: string,
): FlagFinderOracleResult {
	return reason === undefined
		? { verdict, sourceDigest, inputDigest, candidateDigest }
		: { verdict, sourceDigest, inputDigest, candidateDigest, reason };
}

/**
 * Verifies a grid with source-bound, static checker semantics. It never returns source,
 * input, candidate, or regex contents.
 */
export function verifyFlagFinder(request: FlagFinderOracleRequest): FlagFinderOracleResult {
	const sourceDigest = sha256Hex(request.source);
	const inputDigest = canonicalDigest({ sourceDigest, input: request.input });
	const candidateDigest = sha256Hex(request.candidate);
	if (sourceDigest !== request.expectedSourceDigest)
		return result("unavailable", sourceDigest, inputDigest, candidateDigest, "source digest mismatch");
	if (!/^[.#]*$/.test(request.input) || !/^[.#]*$/.test(request.candidate))
		return result("fail", sourceDigest, inputDigest, candidateDigest, "grid contains unsupported characters");

	let checker: FlagFinderChecker;
	try {
		checker = extractFlagFinderChecker(request.source);
	} catch {
		return result("unavailable", sourceDigest, inputDigest, candidateDigest, "checker source is unavailable");
	}
	if (request.candidate.length !== checker.length)
		return result("fail", sourceDigest, inputDigest, candidateDigest, "grid length does not match checker");
	return checker.pattern.test(request.candidate)
		? result("pass", sourceDigest, inputDigest, candidateDigest)
		: result("fail", sourceDigest, inputDigest, candidateDigest, "grid does not satisfy checker");
}

export const verifyFlagFinderLocal = verifyFlagFinder;
