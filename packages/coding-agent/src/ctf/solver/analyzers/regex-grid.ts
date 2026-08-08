import { createHash } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { createLocalSolverAnalyzerLifecycle, type LocalSolverAnalyzer } from "../local-backend";

const MAX_SOURCE_BYTES = 256 * 1024;
const MAX_REGEX_CHARS = 64 * 1024;
const MAX_GRID_LENGTH = 10_000;
const MAX_LOOKAHEADS = 512;
const MAX_VARIANTS = 2;
const MAX_SMT_BYTES = 4 * 1024 * 1024;
const MAX_SOLVER_OUTPUT_BYTES = 256 * 1024;
const DEFAULT_SOLVER_TIMEOUT_MS = 15_000;
const MAX_Z3_BINARY_BYTES = 128 * 1024 * 1024;
const MAX_Z3_VERSION_BYTES = 16 * 1024;
const REVIEWED_Z3_CAPABILITIES = new WeakSet<object>();
const reviewedZ3Brand: unique symbol = Symbol("reviewed-z3");

export type RegexGridRefusal =
	| "source-too-large"
	| "missing-length"
	| "invalid-length"
	| "missing-regex"
	| "unsupported-regex"
	| "no-grid-constraints"
	| "ambiguous-grid-constraint"
	| "conflicting-grid-constraint"
	| "missing-z3"
	| "unreviewed-z3"
	| "solver-timeout"
	| "solver-output-overflow"
	| "solver-failure"
	| "cancelled"
	| "nonmatching-candidate";

export type RegexGridAnalysis =
	| Readonly<{ ok: true; candidate: string; diagnostics: readonly string[] }>
	| Readonly<{ ok: false; reason: RegexGridRefusal; diagnostics: readonly string[] }>;

type Node = Readonly<
	| { kind: "atom"; value: string }
	| { kind: "sequence"; children: readonly Node[] }
	| { kind: "repeat"; child: Node; min: number; max: number }
>;

function failure(reason: RegexGridRefusal, detail: string): RegexGridAnalysis {
	return { ok: false, reason, diagnostics: [detail.slice(0, 160)] };
}

function appendLimited(values: readonly string[], value: string): string[] {
	return values.includes(value) || values.length >= MAX_VARIANTS ? [...values] : [...values, value];
}

function minimumLength(node: Node): number {
	switch (node.kind) {
		case "atom":
			return 1;
		case "sequence":
			return node.children.reduce((total, child) => total + minimumLength(child), 0);
		case "repeat":
			return minimumLength(node.child) * node.min;
	}
}

class PatternParser {
	private index = 0;

	constructor(private readonly source: string) {}

	parse(): Node | undefined {
		const node = this.sequence(false);
		return node === undefined || this.index !== this.source.length ? undefined : node;
	}

	private sequence(stopAtClose: boolean): Node | undefined {
		const children: Node[] = [];
		while (this.index < this.source.length && this.source[this.index] !== ")") {
			let node: Node | undefined;
			const current = this.source[this.index];
			if (current === ".") {
				this.index++;
				node = { kind: "atom", value: "?" };
			} else if (current === "#") {
				this.index++;
				node = { kind: "atom", value: "#" };
			} else if (current === "\\" && this.source[this.index + 1] === ".") {
				this.index += 2;
				node = { kind: "atom", value: "." };
			} else if (current === "(" && this.source.slice(this.index, this.index + 3) === "(?:") {
				this.index += 3;
				node = this.sequence(true);
				if (node === undefined || this.source[this.index++] !== ")") return undefined;
			} else {
				return undefined;
			}
			const repeated = this.repeat(node);
			if (repeated === undefined) return undefined;
			children.push(repeated);
		}
		if (stopAtClose && this.source[this.index] !== ")") return undefined;
		return { kind: "sequence", children };
	}

	private repeat(child: Node): Node | undefined {
		const quantifier = this.source[this.index];
		if (quantifier === "*") {
			this.index++;
			return { kind: "repeat", child, min: 0, max: Number.MAX_SAFE_INTEGER };
		}
		if (quantifier === "+") {
			this.index++;
			return { kind: "repeat", child, min: 1, max: Number.MAX_SAFE_INTEGER };
		}
		if (quantifier !== "{") return child;
		const close = this.source.indexOf("}", this.index + 1);
		if (close < 0 || !/^\d+$/u.test(this.source.slice(this.index + 1, close))) return undefined;
		const count = Number(this.source.slice(this.index + 1, close));
		if (!Number.isSafeInteger(count)) return undefined;
		this.index = close + 1;
		return { kind: "repeat", child, min: count, max: count };
	}
}

function expand(node: Node, length: number): readonly string[] {
	if (length < minimumLength(node)) return [];
	if (node.kind === "atom") return length === 1 ? [node.value] : [];
	if (node.kind === "sequence") return expandSequence(node.children, length);
	const unit = minimumLength(node.child);
	if (unit === 0) return [];
	const maximum = Math.min(node.max, Math.floor(length / unit));
	let values: string[] = [];
	for (let count = node.min; count <= maximum && values.length < MAX_VARIANTS; count++) {
		for (const value of expandSequence(
			Array.from({ length: count }, () => node.child),
			length,
		))
			values = appendLimited(values, value);
	}
	return values;
}

function expandSequence(children: readonly Node[], length: number): readonly string[] {
	if (children.length === 0) return length === 0 ? [""] : [];
	const [first, ...rest] = children;
	const restMinimum = rest.reduce((total, child) => total + minimumLength(child), 0);
	let values: string[] = [];
	for (
		let firstLength = minimumLength(first);
		firstLength <= length - restMinimum && values.length < MAX_VARIANTS;
		firstLength++
	) {
		for (const prefix of expand(first, firstLength)) {
			for (const suffix of expandSequence(rest, length - firstLength)) {
				values = appendLimited(values, prefix + suffix);
				if (values.length >= MAX_VARIANTS) break;
			}
		}
	}
	return values;
}

function extractRegex(source: string): string | undefined {
	const match = /\bconst\s+theFlag\s*=\s*\//u.exec(source);
	if (match === null) return undefined;
	const start = match.index + match[0].length;
	let escaped = false;
	for (let index = start; index < source.length; index++) {
		const current = source[index];
		if (!escaped && current === "/") return source.slice(start, index);
		escaped = !escaped && current === "\\";
		if (current !== "\\") escaped = false;
	}
	return undefined;
}

function lookaheadBodies(pattern: string): readonly string[] {
	const bodies: string[] = [];
	for (let index = 0; index < pattern.length - 2 && bodies.length < MAX_LOOKAHEADS; index++) {
		if (pattern.slice(index, index + 3) !== "(?=") continue;
		let depth = 1;
		let escaped = false;
		for (let end = index + 3; end < pattern.length; end++) {
			const current = pattern[end];
			if (!escaped && current === "(") depth++;
			else if (!escaped && current === ")" && --depth === 0) {
				bodies.push(pattern.slice(index + 3, end));
				break;
			}
			escaped = !escaped && current === "\\";
			if (current !== "\\") escaped = false;
		}
	}
	return bodies;
}

type NonogramConstraints = Readonly<{
	rows: readonly (readonly number[])[];
	columns: readonly (readonly number[])[];
}>;

function fixedUnit(node: Node): Readonly<{ index: number; value: "." | "#" }> | undefined {
	const base = node.kind === "repeat" ? node.child : node;
	if (base.kind !== "sequence" || minimumLength(base) < 1) return undefined;
	let offset = 0;
	let literal: Readonly<{ index: number; value: "." | "#" }> | undefined;
	for (const child of base.children) {
		if (child.kind === "atom" && child.value !== "?") {
			if (literal !== undefined) return undefined;
			literal = { index: offset, value: child.value as "." | "#" };
		}
		offset += minimumLength(child);
	}
	return literal;
}

function cluesFromColumnBody(body: string): Readonly<{ column: number; clues: readonly number[] }> | undefined {
	const tree = new PatternParser(body).parse();
	if (tree === undefined || tree.kind !== "sequence") return undefined;
	let column: number | undefined;
	const clues: number[] = [];
	for (const segment of tree.children) {
		const literal = fixedUnit(segment);
		if (literal === undefined) return undefined;
		if (column !== undefined && column !== literal.index) return undefined;
		column = literal.index;
		if (literal.value !== "#") continue;
		if (segment.kind === "repeat") {
			if (segment.max !== segment.min || segment.min < 1) return undefined;
			clues.push(segment.min);
		} else {
			clues.push(1);
		}
	}
	return column === undefined ? undefined : { column, clues };
}

function hashClues(body: string): readonly number[] | undefined {
	if (!/^[.*+#\\{}\d]+$/u.test(body)) return undefined;
	const clues: number[] = [];
	for (const match of body.matchAll(/#(?:\{(\d+)\})?/gu)) {
		const count = match[1] === undefined ? 1 : Number(match[1]);
		if (!Number.isSafeInteger(count) || count < 1) return undefined;
		clues.push(count);
	}
	return clues;
}

function extractNonogram(pattern: string, length: number): NonogramConstraints | undefined {
	const byColumn = new Map<number, readonly number[]>();
	for (const body of lookaheadBodies(pattern)) {
		if (body.includes("(?=") || !body.includes("\\.")) continue;
		const parsed = cluesFromColumnBody(body);
		if (parsed === undefined || byColumn.has(parsed.column)) return undefined;
		byColumn.set(parsed.column, parsed.clues);
	}
	const rowBodies = [...pattern.matchAll(/\(([^()]*)\)\(\?<=\.\{\d+\}\)\(\?<!\.\{\d+\}\)/gu)].map(match => match[1]);
	if (rowBodies.length === 0 || byColumn.size === 0) return undefined;
	const rows = rowBodies.map(hashClues);
	if (rows.some(row => row === undefined)) return undefined;
	const width = Math.max(...byColumn.keys()) + 1;
	if (width * rows.length !== length || byColumn.size !== width) return undefined;
	const columns = Array.from({ length: width }, (_, column) => byColumn.get(column));
	if (columns.some(column => column === undefined)) return undefined;
	return {
		rows: rows as readonly (readonly number[])[],
		columns: columns as readonly (readonly number[])[],
	};
}

function cell(row: number, column: number): string {
	return `c_${row}_${column}`;
}

function lineAssertions(prefix: string, cells: readonly string[], clues: readonly number[]): readonly string[] {
	if (clues.length === 0) return cells.map(name => `(assert (not ${name}))`);
	const starts = clues.map((_, index) => `${prefix}_${index}`);
	const declarations = starts.map(name => `(declare-const ${name} Int)`);
	const bounds = [`(assert (<= 0 ${starts[0]}))`];
	for (let index = 1; index < starts.length; index++)
		bounds.push(`(assert (< (+ ${starts[index - 1]} ${clues[index - 1]}) ${starts[index]}))`);
	const last = starts.length - 1;
	bounds.push(`(assert (<= (+ ${starts[last]} ${clues[last]}) ${cells.length}))`);
	const coverage = cells.map((name, position) => {
		const choices = starts.map(
			(start, index) => `(and (<= ${start} ${position}) (< ${position} (+ ${start} ${clues[index]})))`,
		);
		return `(assert (= ${name} ${choices.length === 1 ? choices[0] : `(or ${choices.join(" ")})`}))`;
	});
	return [...declarations, ...bounds, ...coverage];
}

function solverInput(nonogram: NonogramConstraints, timeoutMs: number): string {
	const height = nonogram.rows.length;
	const width = nonogram.columns.length;
	const cells = Array.from({ length: height }, (_, row) =>
		Array.from({ length: width }, (_, column) => cell(row, column)),
	);
	const declarations = cells.flat().map(name => `(declare-const ${name} Bool)`);
	const rowAssertions = nonogram.rows.flatMap((clues, row) => lineAssertions(`rs_${row}`, cells[row], clues));
	const columnAssertions = nonogram.columns.flatMap((clues, column) =>
		lineAssertions(
			`cs_${column}`,
			Array.from({ length: height }, (_, row) => cells[row][column]),
			clues,
		),
	);
	const script = [
		`(set-option :timeout ${timeoutMs})`,
		"(set-option :produce-models true)",
		...declarations,
		...rowAssertions,
		...columnAssertions,
		"(check-sat)",
		`(get-value (${cells.flat().join(" ")}))`,
		"",
	].join("\n");
	if (new TextEncoder().encode(script).byteLength > MAX_SMT_BYTES) throw new Error("solver input exceeds bound");
	return script;
}

function cluesFor(cells: Iterable<string>): readonly number[] {
	const clues: number[] = [];
	let run = 0;
	for (const cell of cells) {
		if (cell === "#") run++;
		else if (run > 0) {
			clues.push(run);
			run = 0;
		}
	}
	if (run > 0) clues.push(run);
	return clues;
}

function sameClues(actual: readonly number[], expected: readonly number[]): boolean {
	return actual.length === expected.length && actual.every((value, index) => value === expected[index]);
}

function matchesNonogram(candidate: string, nonogram: NonogramConstraints): boolean {
	const height = nonogram.rows.length;
	const width = nonogram.columns.length;
	if (candidate.length !== height * width || !/^[.#]+$/u.test(candidate)) return false;
	for (let row = 0; row < height; row++)
		if (!sameClues(cluesFor(candidate.slice(row * width, (row + 1) * width)), nonogram.rows[row])) return false;
	for (let column = 0; column < width; column++) {
		const cells = Array.from({ length: height }, (_, row) => candidate[row * width + column]);
		if (!sameClues(cluesFor(cells), nonogram.columns[column])) return false;
	}
	return true;
}

export type ReviewedZ3Capability = Readonly<{
	executable: string;
	version: string;
	digest: string;
	cacheDevice: number;
	cacheInode: number;
	[reviewedZ3Brand]: true;
}>;

async function readExecutableDigest(executable: string): Promise<string> {
	const stat = await fs.lstat(executable);
	if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 1 || stat.size > MAX_Z3_BINARY_BYTES)
		throw new Error("z3 executable identity is invalid");
	const handle = await fs.open(executable, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
	try {
		const opened = await handle.stat();
		if (opened.dev !== stat.dev || opened.ino !== stat.ino || opened.size !== stat.size)
			throw new Error("z3 executable was replaced");
		const bytes = await handle.readFile();
		const named = await fs.lstat(executable);
		if (named.dev !== opened.dev || named.ino !== opened.ino || named.size !== opened.size || named.isSymbolicLink())
			throw new Error("z3 executable was replaced");
		return createHash("sha256").update(bytes).digest("hex");
	} finally {
		await handle.close();
	}
}

async function verifiedPrivateDirectory(directory: string): Promise<string> {
	const absolute = path.resolve(directory);
	await fs.mkdir(absolute, { recursive: true, mode: 0o700 });
	await fs.chmod(absolute, 0o700);
	const real = await fs.realpath(absolute);
	const stat = await fs.lstat(real);
	if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0)
		throw new Error("z3 review cache is not private");
	return real;
}

async function z3Version(executable: string): Promise<string> {
	const child = Bun.spawn([executable, "--version"], { stdout: "pipe", stderr: "pipe" });
	let total = 0;
	const collect = async (stream: ReadableStream<Uint8Array>): Promise<Uint8Array> => {
		const chunks: Uint8Array[] = [];
		for await (const chunk of stream) {
			total += chunk.byteLength;
			if (total > MAX_Z3_VERSION_BYTES) {
				child.kill("SIGKILL");
				throw new Error("z3 version probe output exceeded its bound");
			}
			chunks.push(chunk);
		}
		return Uint8Array.from(chunks.flatMap(chunk => [...chunk]));
	};
	const [stdout, stderr, exitCode] = await Promise.all([collect(child.stdout), collect(child.stderr), child.exited]);
	if (exitCode !== 0) throw new Error("z3 version probe failed");
	const version = `${new TextDecoder().decode(stdout)}\n${new TextDecoder().decode(stderr)}`.trim();
	if (!/^Z3 version \d+\.\d+\.\d+/u.test(version)) throw new Error("z3 version probe is invalid");
	return version;
}

export async function reviewZ3Executable(
	executable: string,
	options: Readonly<{ cacheDirectory?: string }> = {},
): Promise<ReviewedZ3Capability> {
	if (!path.isAbsolute(executable)) throw new Error("z3 executable must be absolute");
	const real = await fs.realpath(executable);
	const digest = await readExecutableDigest(real);
	const cache = await verifiedPrivateDirectory(options.cacheDirectory ?? path.join(os.tmpdir(), "gjc-reviewed-z3"));
	const cached = path.join(cache, digest);
	if (!contained(cache, cached)) throw new Error("z3 review cache path escapes");
	const present = await fs.lstat(cached).catch(() => undefined);
	if (present === undefined) {
		await fs.copyFile(real, cached, fsConstants.COPYFILE_EXCL);
		await fs.chmod(cached, 0o700);
	}
	if ((await readExecutableDigest(cached)) !== digest) throw new Error("reviewed z3 cache copy digest mismatch");
	const version = await z3Version(cached);
	const cacheStat = await fs.lstat(cache);
	const capability = Object.freeze({
		executable: cached,
		version,
		digest,
		cacheDevice: cacheStat.dev,
		cacheInode: cacheStat.ino,
		[reviewedZ3Brand]: true as const,
	});
	REVIEWED_Z3_CAPABILITIES.add(capability);
	return capability;
}

function contained(root: string, target: string): boolean {
	const relative = path.relative(root, target);
	return relative === "" || (relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

async function validateReviewedCapability(capability: ReviewedZ3Capability): Promise<boolean> {
	if (!REVIEWED_Z3_CAPABILITIES.has(capability) || !path.isAbsolute(capability.executable)) return false;
	try {
		const cache = await fs.lstat(path.dirname(capability.executable));
		if (
			!cache.isDirectory() ||
			cache.isSymbolicLink() ||
			cache.dev !== capability.cacheDevice ||
			cache.ino !== capability.cacheInode ||
			(cache.mode & 0o077) !== 0
		)
			return false;
		return (await readExecutableDigest(capability.executable)) === capability.digest;
	} catch {
		return false;
	}
}

export type RegexGridZ3Options = Readonly<{
	z3?: ReviewedZ3Capability;
	timeoutMs?: number;
	signal?: AbortSignal;
}>;

async function solveWithZ3(
	script: string,
	timeoutMs: number,
	capability: ReviewedZ3Capability,
	signal: AbortSignal | undefined,
): Promise<string | RegexGridRefusal> {
	if (signal?.aborted) return "cancelled";
	const child = Bun.spawn([capability.executable, "-in", "-smt2"], { stdin: "pipe", stdout: "pipe", stderr: "pipe" });
	let timedOut = false;
	const kill = () => child.kill("SIGKILL");
	const onAbort = () => kill();
	const timeout = setTimeout(() => {
		timedOut = true;
		kill();
	}, timeoutMs + 1_000);
	signal?.addEventListener("abort", onAbort, { once: true });
	try {
		child.stdin.write(script);
		child.stdin.end();
		let total = 0;
		let overflow = false;
		const collect = async (stream: ReadableStream<Uint8Array>): Promise<Uint8Array> => {
			const chunks: Uint8Array[] = [];
			const reader = stream.getReader();
			try {
				for (;;) {
					const next = await reader.read();
					if (next.done) break;
					total += next.value.byteLength;
					if (total > MAX_SOLVER_OUTPUT_BYTES) {
						overflow = true;
						kill();
						break;
					}
					chunks.push(next.value);
				}
			} finally {
				reader.releaseLock();
			}
			const result = new Uint8Array(chunks.reduce((size, chunk) => size + chunk.byteLength, 0));
			let offset = 0;
			for (const chunk of chunks) {
				result.set(chunk, offset);
				offset += chunk.byteLength;
			}
			return result;
		};
		const [stdout, , exitCode] = await Promise.all([collect(child.stdout), collect(child.stderr), child.exited]);
		if (signal?.aborted) return "cancelled";
		if (timedOut) return "solver-timeout";
		if (overflow) return "solver-output-overflow";
		if (exitCode !== 0) return "solver-failure";
		return new TextDecoder("utf-8", { fatal: true }).decode(stdout);
	} catch {
		return signal?.aborted ? "cancelled" : "solver-failure";
	} finally {
		clearTimeout(timeout);
		signal?.removeEventListener("abort", onAbort);
	}
}

/**
 * Solves the bounded row/column nonogram subset with an explicitly reviewed
 * Z3 capability. Validation replays parsed nonogram semantics, never the
 * challenge-controlled JavaScript regular expression.
 */
export async function analyzeRegexGridSourceWithZ3(
	source: string,
	options: RegexGridZ3Options = {},
): Promise<RegexGridAnalysis> {
	if (new TextEncoder().encode(source).byteLength > MAX_SOURCE_BYTES)
		return failure("source-too-large", "source exceeds input budget");
	if (options.signal?.aborted) return failure("cancelled", "analysis cancelled");
	const lengthMatch = /\bconst\s+len\s*=\s*(\d+)\s*;/u.exec(source);
	if (lengthMatch === null) return failure("missing-length", "declared const len was not found");
	const length = Number(lengthMatch[1]);
	if (!Number.isSafeInteger(length) || length < 1 || length > MAX_GRID_LENGTH)
		return failure("invalid-length", "declared length is outside the supported bound");
	const pattern = extractRegex(source);
	if (pattern === undefined) return failure("missing-regex", "theFlag regex literal was not found");
	if (pattern.length > MAX_REGEX_CHARS) return failure("unsupported-regex", "regex exceeds input budget");
	const nonogram = extractNonogram(pattern, length);
	if (nonogram === undefined) return failure("unsupported-regex", "grid constraints are not a supported nonogram");
	const timeoutMs = options.timeoutMs ?? DEFAULT_SOLVER_TIMEOUT_MS;
	if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60_000)
		return failure("solver-failure", "solver timeout is outside the supported bound");
	let script: string;
	try {
		script = solverInput(nonogram, timeoutMs);
	} catch {
		return failure("unsupported-regex", "solver input exceeds the supported bound");
	}
	if (options.z3 === undefined) return failure("missing-z3", "reviewed z3 capability is unavailable");
	if (!(await validateReviewedCapability(options.z3)))
		return failure("unreviewed-z3", "reviewed z3 executable was replaced or tampered with");
	const output = await solveWithZ3(script, timeoutMs, options.z3, options.signal);
	if (
		output === "cancelled" ||
		output === "solver-timeout" ||
		output === "solver-output-overflow" ||
		output === "solver-failure"
	)
		return failure(output, `z3 ${output.replaceAll("-", " ")}`);
	const text = output;
	if (!text.startsWith("sat\n")) return failure("solver-failure", "z3 did not report satisfiable constraints");
	const candidate = Array<string>(nonogram.rows.length * nonogram.columns.length).fill(".");
	let count = 0;
	for (const match of text.matchAll(/\(c_(\d+)_(\d+) (true|false)\)/gu)) {
		const row = Number(match[1]);
		const column = Number(match[2]);
		if (
			!Number.isSafeInteger(row) ||
			!Number.isSafeInteger(column) ||
			row >= nonogram.rows.length ||
			column >= nonogram.columns.length
		)
			return failure("solver-failure", "z3 returned an invalid cell");
		candidate[row * nonogram.columns.length + column] = match[3] === "true" ? "#" : ".";
		count++;
	}
	const solved = candidate.join("");
	if (count !== solved.length || !matchesNonogram(solved, nonogram))
		return failure("nonmatching-candidate", "z3 bitmap does not satisfy parsed nonogram semantics");
	return {
		ok: true,
		candidate: solved,
		diagnostics: [`solved ${nonogram.rows.length}x${nonogram.columns.length} bounded nonogram constraints with z3`],
	};
}

export function createRegexGridAnalyzer(
	options: Readonly<{ visiblePath: string } & RegexGridZ3Options>,
): LocalSolverAnalyzer {
	return {
		id: "regex-grid-z3",
		analyze(input) {
			return createLocalSolverAnalyzerLifecycle(input, async ownedInput => {
				if (ownedInput.signal.aborted) return { status: "cancelled", reason: "run cancelled" };
				const visible = ownedInput.visibleFiles.find(file => file.path === options.visiblePath);
				if (visible === undefined) return { status: "not-applicable" };
				let source: string;
				try {
					source = new TextDecoder("utf-8", { fatal: true }).decode(visible.content);
				} catch {
					return { status: "refused", reason: "visible source is not valid utf-8" };
				}
				const result = await analyzeRegexGridSourceWithZ3(source, { ...options, signal: ownedInput.signal });
				if (result.ok) return { status: "candidate", result: { candidate: result.candidate } };
				if (
					result.reason === "missing-length" ||
					result.reason === "missing-regex" ||
					result.reason === "no-grid-constraints"
				)
					return { status: "not-applicable" };
				if (result.reason === "cancelled") return { status: "cancelled", reason: result.diagnostics[0] };
				return { status: "refused", reason: `${result.reason}: ${result.diagnostics[0]}` };
			});
		},
	};
}

/**
 * Derives a bitmap from the narrow fixed-stride regex-grid subset. It validates
 * only the parsed fixed constraints and does not execute challenge regexes.
 */
export function analyzeRegexGridSource(source: string): RegexGridAnalysis {
	if (new TextEncoder().encode(source).byteLength > MAX_SOURCE_BYTES)
		return failure("source-too-large", "source exceeds input budget");
	const lengthMatch = /\bconst\s+len\s*=\s*(\d+)\s*;/u.exec(source);
	if (lengthMatch === null) return failure("missing-length", "declared const len was not found");
	const length = Number(lengthMatch[1]);
	if (!Number.isSafeInteger(length) || length < 1 || length > MAX_GRID_LENGTH)
		return failure("invalid-length", "declared length is outside the supported bound");
	const pattern = extractRegex(source);
	if (pattern === undefined) return failure("missing-regex", "theFlag regex literal was not found");
	if (pattern.length > MAX_REGEX_CHARS || !/^[().*+?=<>!#\\^${}\d:]+$/u.test(pattern))
		return failure("unsupported-regex", "regex contains unsupported syntax");
	const candidate = Array<string>(length).fill("?");
	let constraints = 0;
	for (const body of lookaheadBodies(pattern)) {
		if (body.includes("(?=") || !body.includes("#") || !body.includes("\\.")) continue;
		const tree = new PatternParser(body).parse();
		if (tree === undefined) return failure("unsupported-regex", "a grid lookahead uses unsupported syntax");
		const variants = expand(tree, length);
		if (variants.length === 0) continue;
		if (variants.length > 1)
			return failure("ambiguous-grid-constraint", "a grid lookahead has multiple bounded expansions");
		constraints++;
		for (let index = 0; index < length; index++) {
			const value = variants[0][index];
			if (value === "?") continue;
			if (candidate[index] !== "?" && candidate[index] !== value)
				return failure("conflicting-grid-constraint", "grid lookaheads disagree on a position");
			candidate[index] = value;
		}
	}
	if (constraints === 0) return failure("no-grid-constraints", "no supported fixed-length grid lookahead was found");
	return {
		ok: true,
		candidate: candidate.map(value => (value === "?" ? "." : value)).join(""),
		diagnostics: [`derived ${constraints} fixed-length grid constraints`],
	};
}
