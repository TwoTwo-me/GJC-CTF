import {
	createLocalSolverAnalyzerLifecycle,
	type LocalSolverAnalyzer,
	type LocalSolverSessionInput,
} from "../local-backend";

const CHALLENGE_ID = "lactf-2026-crypto-not-so-lazy-trigrams";
const MAX_SOURCE_BYTES = 16 * 1024;
const MAX_CIPHERTEXT_BYTES = 128 * 1024;
const MIN_CLEAN_LETTERS = 180;
const ALPHABET = "abcdefghijklmnopqrstuvwxyz";
const ENGLISH_ORDER = "etaoinshrdlucmfwypvbgkjqxz";
const TRAINING_TEXT = `the quick brown fox jumps over the lazy dog this is a small collection of ordinary english prose used only to rank plausible plaintext the reader should be able to understand the message without guessing words are separated by spaces and sentences explain their ideas clearly cryptography is useful when careful analysis is combined with reproducible evidence every program should reject invalid input and preserve its stated invariants deterministic searches are easier to review than accidental answers software engineers write tests for boundary conditions and failure cases a good result follows from the visible data rather than hidden files`;
const SOURCE_MARKERS = [
	"importrandom",
	"importre",
	"trigrams=[chr(i)+chr(j)+chr(k)foriinrange(97,97+26)forjinrange(97,97+26)forkinrange(97,97+26)]",
	"sub_trigrams=[chr(i)+chr(j)+chr(k)foriinshufflei forjinshufflej forkinshufflek]".replaceAll(" ", ""),
	"defformatter(ctext,ptext):",
	"ifc.isalpha():",
	"elifcnotin(''):",
	"cleanptext=re.sub(r'[^a-zA-Z]','',ptext).lower()",
	"if(len(cleanptext)%3!=0):",
	"cleanptext+=(3-len(cleanptext)%3)*'x'",
	"sub_trigrams[trigrams.index(cleanptext[i*3:(i+1)*3])]",
	"returnformatter(ctext,ptext)",
] as const;

type AnalysisFailure =
	| "invalid-encoding"
	| "input-too-large"
	| "invalid-files"
	| "grammar-drift"
	| "unsupported-symbol"
	| "tiny-ciphertext"
	| "bound-exhausted"
	| "ambiguous-result"
	| "forward-mismatch";
export type NotSoLazyTrigramsAnalysis =
	| Readonly<{ ok: true; candidate: string }>
	| Readonly<{ ok: false; reason: AnalysisFailure }>;
export type NotSoLazyTrigramsOptions = Readonly<{
	/** Test-only bounded search controls; production defaults remain deliberately finite. */
	restarts?: number;
	iterations?: number;
}>;

type SearchResult = Readonly<{ plaintext: string; keys: readonly (readonly number[])[]; score: number }>;

function decode(bytes: Uint8Array): string | undefined {
	try {
		return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
	} catch {
		return undefined;
	}
}

function hasExactFiles(files: readonly Readonly<{ path: string; content: Uint8Array }>[]): boolean {
	return (
		files.length === 2 &&
		new Set(files.map(file => file.path)).size === 2 &&
		files.some(file => file.path === "chall.py") &&
		files.some(file => file.path === "ct.txt")
	);
}

/** Recognizes the reviewed transform structurally, without executing or importing its Python. */
function reviewedGrammar(source: string): boolean {
	if (/(?:socket|requests|subprocess|os\.)/iu.test(source)) return false;
	const stripped = source
		.replace(/#[^\n\r]*/gu, "")
		.replace(/\s+/gu, "")
		.replaceAll('"', "'");
	if (!SOURCE_MARKERS.every(marker => stripped.includes(marker))) return false;
	const permutation = "random.sample(range(97,97+26),26)";
	return stripped.split(permutation).length - 1 === 3;
}

function supportedCiphertext(cipher: string): boolean {
	for (const char of cipher) {
		const code = char.charCodeAt(0);
		if (char >= "a" && char <= "z") continue;
		if (code < 33 || code > 126 || (char >= "A" && char <= "Z")) return false;
	}
	return true;
}

function makeNgrams(): Map<string, number> {
	const clean = TRAINING_TEXT.replace(/[^a-z]/gu, "");
	const table = new Map<string, number>();
	for (let size = 3; size <= 4; size += 1)
		for (let index = 0; index + size <= clean.length; index += 1) {
			const gram = clean.slice(index, index + size);
			table.set(gram, (table.get(gram) ?? 0) + 1);
		}
	return table;
}
const NGRAMS = makeNgrams();

function score(text: string): number {
	const clean = text.replace(/[^a-z]/gu, " ");
	let total = 0;
	for (let size = 3; size <= 4; size += 1)
		for (let index = 0; index + size <= clean.length; index += 1) {
			const gram = clean.slice(index, index + size);
			if (!gram.includes(" ")) total += Math.log1p(NGRAMS.get(gram) ?? 0) - 0.35;
		}
	return total;
}

function seeded(seed: number): () => number {
	let state = seed >>> 0;
	return () => {
		state = (state * 1664525 + 1013904223) >>> 0;
		return state / 0x1_0000_0000;
	};
}

function initialKey(cipher: string, phase: number): number[] {
	const frequencies = Array<number>(26).fill(0);
	let letterIndex = 0;
	for (const char of cipher) {
		if (char >= "a" && char <= "z") {
			if (letterIndex % 3 === phase) frequencies[char.charCodeAt(0) - 97] += 1;
			letterIndex += 1;
		}
	}
	const cipherOrder = [...ALPHABET].sort(
		(a, b) => frequencies[b.charCodeAt(0) - 97] - frequencies[a.charCodeAt(0) - 97],
	);
	const key = Array<number>(26);
	for (let index = 0; index < 26; index += 1)
		key[cipherOrder[index].charCodeAt(0) - 97] = ENGLISH_ORDER.charCodeAt(index) - 97;
	return key;
}

function applyFlagCrib(cipher: string, keys: number[][]): readonly ReadonlySet<number>[] | undefined {
	const open = cipher.indexOf("{");
	if (open < 5 || open !== cipher.lastIndexOf("{") || cipher.indexOf("}", open + 1) !== cipher.lastIndexOf("}"))
		return undefined;
	const prefix = cipher.slice(open - 5, open);
	if (!/^[a-z]{5}$/u.test(prefix)) return undefined;
	let letterIndex = 0;
	for (let index = 0; index < open - 5; index += 1) if (cipher[index] >= "a" && cipher[index] <= "z") letterIndex += 1;
	const fixed = [new Set<number>(), new Set<number>(), new Set<number>()];
	for (let offset = 0; offset < 5; offset += 1) {
		const phase = (letterIndex + offset) % 3;
		const cipherIndex = prefix.charCodeAt(offset) - 97;
		const plainIndex = "lactf".charCodeAt(offset) - 97;
		const current = keys[phase].indexOf(plainIndex);
		[keys[phase][cipherIndex], keys[phase][current]] = [keys[phase][current], keys[phase][cipherIndex]];
		fixed[phase].add(cipherIndex);
	}
	return fixed;
}

function mutableIndex(random: () => number, fixed: ReadonlySet<number>): number {
	let index = Math.floor(random() * 26);
	while (fixed.has(index)) index = (index + 1) % 26;
	return index;
}

type CipherSampleSymbol = Readonly<{ char: string; phase?: number }>;

function sampleCipher(cipher: string): readonly CipherSampleSymbol[] {
	const symbols: CipherSampleSymbol[] = [];
	let letterIndex = 0;
	for (let index = 0; index < cipher.length; index += 1) {
		const char = cipher[index];
		const phase = char >= "a" && char <= "z" ? letterIndex++ % 3 : undefined;
		if (index < 900 || index >= cipher.length - 600) symbols.push(phase === undefined ? { char } : { char, phase });
	}
	return symbols;
}

function decryptSample(sample: readonly CipherSampleSymbol[], keys: readonly (readonly number[])[]): string {
	return sample
		.map(symbol =>
			symbol.phase === undefined
				? symbol.char
				: String.fromCharCode(97 + keys[symbol.phase][symbol.char.charCodeAt(0) - 97]),
		)
		.join("");
}

function decrypt(cipher: string, keys: readonly (readonly number[])[]): string {
	let output = "";
	let letterIndex = 0;
	for (const char of cipher) {
		if (char >= "a" && char <= "z") {
			output += String.fromCharCode(97 + keys[letterIndex % 3][char.charCodeAt(0) - 97]);
			letterIndex += 1;
		} else output += char;
	}
	return output;
}

function forward(plaintext: string, keys: readonly (readonly number[])[]): string | undefined {
	const inverse = keys.map(key => {
		const value = Array<number>(26);
		for (let index = 0; index < 26; index += 1) {
			if (!Number.isInteger(key[index]) || key[index] < 0 || key[index] > 25 || value[key[index]] !== undefined)
				return undefined;
			value[key[index]] = index;
		}
		return value;
	});
	if (inverse.some(value => value === undefined)) return undefined;
	let output = "";
	let letterIndex = 0;
	for (const char of plaintext) {
		if (char >= "a" && char <= "z") {
			output += String.fromCharCode(97 + inverse[letterIndex % 3]![char.charCodeAt(0) - 97]);
			letterIndex += 1;
		} else output += char;
	}
	return output;
}

function mappingsBijections(keys: readonly (readonly number[])[]): boolean {
	return (
		keys.length === 3 &&
		keys.every(
			key =>
				key.length === 26 &&
				new Set(key).size === 26 &&
				key.every(value => Number.isInteger(value) && value >= 0 && value < 26),
		)
	);
}

async function search(
	cipher: string,
	signal: AbortSignal,
	restarts: number,
	iterations: number,
): Promise<SearchResult | "cancelled" | undefined> {
	const sample = sampleCipher(cipher);
	let best: SearchResult | undefined;
	for (let restart = 0; restart < restarts; restart += 1) {
		const random = seeded(0x9e3779b9 ^ restart);
		const keys = [initialKey(cipher, 0), initialKey(cipher, 1), initialKey(cipher, 2)];
		const fixed = applyFlagCrib(cipher, keys);
		if (fixed === undefined) return undefined;
		for (let phase = 0; phase < keys.length; phase += 1)
			for (let shuffle = 0; shuffle < restart + 3; shuffle += 1) {
				const left = mutableIndex(random, fixed[phase]),
					right = mutableIndex(random, fixed[phase]);
				[keys[phase][left], keys[phase][right]] = [keys[phase][right], keys[phase][left]];
			}
		let plaintext = decryptSample(sample, keys);
		let current = score(plaintext);
		for (let step = 0; step < iterations; step += 1) {
			if (signal.aborted) return "cancelled";
			const phase = Math.floor(random() * 3),
				left = mutableIndex(random, fixed[phase]),
				right = mutableIndex(random, fixed[phase]);
			[keys[phase][left], keys[phase][right]] = [keys[phase][right], keys[phase][left]];
			const next = decryptSample(sample, keys),
				nextScore = score(next);
			const temperature = 3 * (1 - step / iterations) + 0.05;
			if (nextScore >= current || random() < Math.exp((nextScore - current) / temperature)) {
				plaintext = next;
				current = nextScore;
			} else [keys[phase][left], keys[phase][right]] = [keys[phase][right], keys[phase][left]];
			if ((step & 255) === 0) await Promise.resolve();
		}
		for (let phase = 0; phase < keys.length; phase += 1)
			for (let left = 0; left < 25; left += 1) {
				if (fixed[phase].has(left)) continue;
				for (let right = left + 1; right < 26; right += 1) {
					if (fixed[phase].has(right)) continue;
					[keys[phase][left], keys[phase][right]] = [keys[phase][right], keys[phase][left]];
					const refined = decryptSample(sample, keys);
					const refinedScore = score(refined);
					if (refinedScore > current) {
						plaintext = refined;
						current = refinedScore;
					} else [keys[phase][left], keys[phase][right]] = [keys[phase][right], keys[phase][left]];
				}
			}
		const result: SearchResult = {
			plaintext: decrypt(cipher, keys),
			keys: keys.map(key => [...key]),
			score: current,
		};
		if (best === undefined || result.score > best.score) best = result;
	}
	return best;
}

export async function analyzeNotSoLazyTrigrams(
	input: Pick<LocalSolverSessionInput, "challengeId" | "visibleFiles" | "signal">,
	options: NotSoLazyTrigramsOptions = {},
): Promise<NotSoLazyTrigramsAnalysis | "cancelled" | "not-applicable"> {
	if (input.challengeId !== CHALLENGE_ID) return "not-applicable";
	if (input.signal.aborted) return "cancelled";
	if (!hasExactFiles(input.visibleFiles)) return { ok: false, reason: "invalid-files" };
	const chall = input.visibleFiles.find(file => file.path === "chall.py")!,
		ct = input.visibleFiles.find(file => file.path === "ct.txt")!;
	if (
		chall.content.byteLength === 0 ||
		chall.content.byteLength > MAX_SOURCE_BYTES ||
		ct.content.byteLength === 0 ||
		ct.content.byteLength > MAX_CIPHERTEXT_BYTES
	)
		return { ok: false, reason: "input-too-large" };
	const source = decode(chall.content),
		cipher = decode(ct.content);
	if (source === undefined || cipher === undefined) return { ok: false, reason: "invalid-encoding" };
	if (!reviewedGrammar(source)) return { ok: false, reason: "grammar-drift" };
	if (!supportedCiphertext(cipher)) return { ok: false, reason: "unsupported-symbol" };
	const letters = [...cipher].filter(char => char >= "a" && char <= "z").length;
	if (letters < MIN_CLEAN_LETTERS) return { ok: false, reason: "tiny-ciphertext" };
	const restarts = options.restarts ?? 3,
		iterations = options.iterations ?? 1_000;
	if (!Number.isSafeInteger(restarts) || !Number.isSafeInteger(iterations) || restarts < 3 || iterations < 1_000)
		return { ok: false, reason: "bound-exhausted" };
	const result = await search(cipher, input.signal, restarts, iterations);
	if (result === "cancelled") return "cancelled";
	if (result === undefined) return { ok: false, reason: "ambiguous-result" };
	if (!mappingsBijections(result.keys) || forward(result.plaintext, result.keys) !== cipher)
		return { ok: false, reason: "forward-mismatch" };
	const candidates = result.plaintext.match(/lactf\{[a-z0-9_]+\}/gu) ?? [];
	if (candidates.length !== 1) return { ok: false, reason: "ambiguous-result" };
	return { ok: true, candidate: candidates[0] };
}

export function createNotSoLazyTrigramsAnalyzer(options: NotSoLazyTrigramsOptions = {}): LocalSolverAnalyzer {
	return {
		id: "not-so-lazy-trigrams",
		analyze(input) {
			return createLocalSolverAnalyzerLifecycle(input, async ownedInput => {
				const analysis = await analyzeNotSoLazyTrigrams(ownedInput, options);
				if (analysis === "not-applicable") return { status: "not-applicable" };
				if (analysis === "cancelled") return { status: "cancelled", reason: "run cancelled" };
				if (!analysis.ok) return { status: "refused", reason: analysis.reason };
				return { status: "candidate", result: { candidate: analysis.candidate } };
			});
		},
	};
}
