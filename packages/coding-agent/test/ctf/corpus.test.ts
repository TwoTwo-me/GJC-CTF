import { afterEach, describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
	buildCorpusProvenance,
	LACTF_CORPUS_SOURCES,
	materializeCorpusEntry,
	validateCorpusEntry,
} from "../../src/ctf/corpus";

async function git(cwd: string, args: readonly string[]): Promise<void> {
	const executable = Bun.which("git");
	if (executable === null) throw new Error("git is required for corpus fixtures");
	const process = Bun.spawn([executable, ...args], { cwd, stdout: "ignore", stderr: "ignore" });
	if ((await process.exited) !== 0) throw new Error(`git fixture command failed: ${args[0] ?? ""}`);
}

async function createCheckout(root: string): Promise<{ checkout: string; challenge: string }> {
	const checkout = path.join(root, "checkout");
	const challenge = path.join(checkout, LACTF_CORPUS_SOURCES[0].challengePath);
	await fs.mkdir(challenge, { recursive: true });
	await fs.writeFile(path.join(challenge, "chall.txt"), "fixture bytes\n");
	await git(checkout, ["init"]);
	await git(checkout, ["add", "."]);
	await git(checkout, [
		"-c",
		"user.email=fixture@example.invalid",
		"-c",
		"user.name=Corpus Fixture",
		"commit",
		"-m",
		"fixture",
	]);
	await git(checkout, ["remote", "add", "origin", LACTF_CORPUS_SOURCES[0].repositoryUrl]);
	return { checkout, challenge };
}

describe("content-addressed LA CTF corpus", () => {
	const roots: string[] = [];
	afterEach(async () => {
		await Promise.all(roots.splice(0).map(root => fs.rm(root, { recursive: true, force: true })));
	});

	it("pins all configured entries and keeps them non-scored", () => {
		expect(LACTF_CORPUS_SOURCES).toHaveLength(6);
		for (const source of LACTF_CORPUS_SOURCES) {
			expect(source.repositoryUrl).toBe("https://github.com/uclaacm/lactf-archive");
			expect(source.sourceCommit).toBe("3379d4a7b36680764a34e7dc817cc3c94c244764");
			expect(source.scored).toBe(false);
		}
		const crypto = LACTF_CORPUS_SOURCES.find(
			source => source.challengeId === "lactf-2026-crypto-not-so-lazy-trigrams",
		);
		expect(crypto?.visibleFiles).toEqual(["chall.py", "ct.txt"]);
		expect(crypto?.visibleFiles).not.toContain("pt.txt");
	});

	it("rejects an unpinned checkout before materialization", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-corpus-"));
		roots.push(root);
		const { checkout, challenge } = await createCheckout(root);
		const provenance = await buildCorpusProvenance(challenge, LACTF_CORPUS_SOURCES[0]);
		await expect(
			materializeCorpusEntry(
				{ source: LACTF_CORPUS_SOURCES[0], provenance },
				checkout,
				path.join(root, "materialized"),
			),
		).rejects.toMatchObject({ code: "missing_provenance" });
	});

	it("rejects dirty, missing, extra, and symlink-substituted checkout files", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-corpus-cache-"));
		roots.push(root);
		const { checkout, challenge } = await createCheckout(root);
		const provenance = await buildCorpusProvenance(challenge, LACTF_CORPUS_SOURCES[0]);
		const entry = { source: LACTF_CORPUS_SOURCES[0], provenance };
		const materialize = () => materializeCorpusEntry(entry, checkout, path.join(root, "materialized"));

		await fs.writeFile(path.join(challenge, "chall.txt"), "substituted bytes\n");
		await expect(materialize()).rejects.toMatchObject({ code: "integrity_error" });
		await git(checkout, ["checkout", "--", "."]);
		await fs.rm(path.join(challenge, "chall.txt"));
		await expect(materialize()).rejects.toMatchObject({ code: "integrity_error" });

		await git(checkout, ["checkout", "--", "."]);

		await fs.writeFile(path.join(checkout, "untracked.txt"), "extra\n");
		await expect(materialize()).rejects.toMatchObject({ code: "integrity_error" });

		await fs.rm(path.join(checkout, "untracked.txt"));
		await fs.rm(path.join(challenge, "chall.txt"));
		await fs.symlink(path.join(root, "outside"), path.join(challenge, "chall.txt"));
		await expect(materialize()).rejects.toMatchObject({ code: "integrity_error" });
	});

	it("rejects provenance mismatch, unsafe paths, and install commands", () => {
		const source = LACTF_CORPUS_SOURCES[0];
		const base = {
			source,
			provenance: {
				repositoryUrl: source.repositoryUrl,
				sourceCommit: source.sourceCommit,
				challengePath: source.challengePath,
				files: source.visibleFiles.map(relativePath => ({
					relativePath,
					sha256: "0".repeat(64) as never,
				})),
			},
		};
		expect(() => validateCorpusEntry({ ...base, provenance: { ...base.provenance, sourceCommit: "0" } })).toThrow(
			/provenance/u,
		);
		expect(() =>
			validateCorpusEntry({
				...base,
				provenance: { ...base.provenance, files: [{ relativePath: "../escape", sha256: "0".repeat(64) as never }] },
			}),
		).toThrow(/path/u);
		expect(() => validateCorpusEntry({ ...base, installCommands: ["make install"] })).toThrow(/install/u);
	});

	it("rejects symbolic links while building provenance", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-corpus-symlink-"));
		roots.push(root);
		const challenge = path.join(root, LACTF_CORPUS_SOURCES[0].challengePath);
		await fs.mkdir(challenge, { recursive: true });
		await fs.writeFile(path.join(root, "outside"), "outside\n");
		await fs.symlink(path.join(root, "outside"), path.join(challenge, "chall.txt"));
		await expect(buildCorpusProvenance(challenge, LACTF_CORPUS_SOURCES[0])).rejects.toMatchObject({
			code: "integrity_error",
		});
	});
});
