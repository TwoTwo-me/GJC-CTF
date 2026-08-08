import { describe, expect, test } from "bun:test";
import { createLactfAnalyzers } from "../../src/ctf/solver/analyzers/lactf";
import {
	analyzeNotSoLazyTrigrams,
	createNotSoLazyTrigramsAnalyzer,
} from "../../src/ctf/solver/analyzers/not-so-lazy-trigrams";
import { solverRouteDigest, solverRouteFor } from "../../src/ctf/solver/router";

const encoder = new TextEncoder();
const CHALLENGE = "lactf-2026-crypto-not-so-lazy-trigrams";
const SOURCE = `import random
import re
with open('pt.txt', 'r') as file:
    pt = file.read()
trigrams = [chr(i)+chr(j)+chr(k) for i in range(97,97+26) for j in range(97,97+26) for k in range(97,97+26)]
shufflei = random.sample(range(97,97+26),26)
shufflej = random.sample(range(97,97+26),26)
shufflek = random.sample(range(97,97+26),26)
sub_trigrams = [chr(i)+chr(j)+chr(k) for i in shufflei for j in shufflej for k in shufflek]
def formatter(ctext, ptext):
    fctext = ""
    i = 0
    for c in ptext:
        if c.isalpha():
            fctext += ctext[i]
            i += 1
        elif c not in (' '):
            fctext += c
    return fctext
def encryption(ptext):
    cleanptext = re.sub(r'[^a-zA-Z]', '', ptext).lower()
    if(len(cleanptext) % 3 != 0):
        cleanptext += (3 - len(cleanptext) % 3) * 'x'
    ctext = "".join([sub_trigrams[trigrams.index(cleanptext[i*3:(i+1)*3])] for i, _ in enumerate(cleanptext[::3])])
    return formatter(ctext, ptext)
ct = encryption(pt)
print(ct)
with open("ct.txt", "wb") as file:
    file.write(ct.encode())
`;
const KEYS = ["qwertyuiopasdfghjklzxcvbnm", "mnbvcxzlkjhgfdsapoiuytrewq", "phqgiumeaylnofdxkrcvstzwbj"];
const PROSE =
	"the quick brown fox jumps over the lazy dog this is a small collection of ordinary english prose used only to rank plausible plaintext the reader should be able to understand the message without guessing words are separated by spaces and sentences explain their ideas clearly cryptography is useful when careful analysis is combined with reproducible evidence every program should reject invalid input and preserve its stated invariants deterministic searches are easier to review than accidental answers software engineers write tests for boundary conditions and failure cases a good result follows from the visible data rather than hidden files ";

function fixture(): readonly { path: string; content: Uint8Array }[] {
	const original = `${PROSE.repeat(4)}lactf{the_and_this_with}${PROSE.repeat(2)}`;
	const plaintext = `${original}${"x".repeat((3 - ([...original].filter(char => /[a-z]/iu.test(char)).length % 3)) % 3)}`;
	let index = 0;
	const ciphertext = [...plaintext]
		.filter(char => char !== " ")
		.map(char => {
			if (!/[a-z]/iu.test(char)) return char;
			const result = KEYS[index % 3][char.toLowerCase().charCodeAt(0) - 97];
			index += 1;
			return result;
		})
		.join("");
	return [
		{ path: "chall.py", content: encoder.encode(SOURCE) },
		{ path: "ct.txt", content: encoder.encode(ciphertext) },
	];
}

function input(files = fixture(), signal = new AbortController().signal) {
	return { challengeId: CHALLENGE, visibleFiles: files, signal };
}

describe("not-so-lazy-trigrams candidate analyzer", () => {
	test("recognizes only the exact visible set and deterministic synthetic transform", async () => {
		const first = await analyzeNotSoLazyTrigrams(input());
		const second = await analyzeNotSoLazyTrigrams(input());
		expect(first).toEqual(second);
		expect(first).toEqual({ ok: true, candidate: "lactf{the_and_this_with}" });
	});

	test("refuses non-contract files and malformed inputs", async () => {
		const files = fixture();
		for (const extra of ["pt.txt", "solve.py", "flag.txt"]) {
			expect(
				await analyzeNotSoLazyTrigrams(input([...files, { path: extra, content: encoder.encode("x") }])),
			).toEqual({ ok: false, reason: "invalid-files" });
		}
		expect(
			await analyzeNotSoLazyTrigrams(input([{ path: "chall.py", content: encoder.encode("pass") }, files[1]])),
		).toEqual({ ok: false, reason: "grammar-drift" });
		expect(
			await analyzeNotSoLazyTrigrams(input([{ path: "chall.py", content: Uint8Array.of(0xff) }, files[1]])),
		).toEqual({ ok: false, reason: "invalid-encoding" });
		expect(
			await analyzeNotSoLazyTrigrams(
				input([
					{ path: "chall.py", content: encoder.encode(SOURCE) },
					{ path: "ct.txt", content: encoder.encode("abc") },
				]),
			),
		).toEqual({ ok: false, reason: "tiny-ciphertext" });
		expect(
			await analyzeNotSoLazyTrigrams(
				input([
					{ path: "chall.py", content: encoder.encode(SOURCE) },
					{ path: "ct.txt", content: encoder.encode(`${"a".repeat(180)}🙂`) },
				]),
			),
		).toEqual({ ok: false, reason: "unsupported-symbol" });
		expect(
			await analyzeNotSoLazyTrigrams(
				input([{ path: "chall.py", content: new Uint8Array(16 * 1024 + 1) }, files[1]]),
			),
		).toEqual({ ok: false, reason: "input-too-large" });
	});

	test("fails closed for cancellation, exhausted bounds, and ambiguous searches", async () => {
		const preAborted = new AbortController();
		preAborted.abort();
		expect(await analyzeNotSoLazyTrigrams(input(fixture(), preAborted.signal))).toBe("cancelled");
		const midSearch = new AbortController();
		const pending = analyzeNotSoLazyTrigrams(input(fixture(), midSearch.signal));
		queueMicrotask(() => midSearch.abort());
		expect(await pending).toBe("cancelled");
		expect(await analyzeNotSoLazyTrigrams(input(), { restarts: 2, iterations: 100 })).toEqual({
			ok: false,
			reason: "bound-exhausted",
		});
		expect(await analyzeNotSoLazyTrigrams(input(), { restarts: 3, iterations: 100 })).toEqual({
			ok: false,
			reason: "bound-exhausted",
		});
	});

	test("is candidate-only and is atomically registered on the reviewed crypto route", async () => {
		const analyzer = createNotSoLazyTrigramsAnalyzer();
		const outcome = await analyzer.analyze(input() as never);
		expect(outcome.status).toBe("candidate");
		const route = solverRouteFor(CHALLENGE);
		expect(route.analyzerIds).toEqual(["not-so-lazy-trigrams"]);
		expect(route.routeDigest).toBe(solverRouteDigest(route));
		expect(createLactfAnalyzers().map(item => item.id)).toEqual([
			"endians",
			"ooo-recurrence",
			"regex-grid-z3",
			"not-so-lazy-trigrams",
		]);
	});
});
