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

	it("hashes and materializes only the recorded regular files", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-corpus-"));
		roots.push(root);
		const checkout = path.join(root, "checkout");
		const challenge = path.join(checkout, LACTF_CORPUS_SOURCES[0].challengePath);
		await fs.mkdir(challenge, { recursive: true });
		await fs.writeFile(path.join(challenge, "chall.txt"), "clean-room fixture\n");
		await fs.writeFile(path.join(challenge, "solve.py"), "must not be visible\n");
		const provenance = await buildCorpusProvenance(challenge, LACTF_CORPUS_SOURCES[0]);
		const output = await materializeCorpusEntry(
			{ source: LACTF_CORPUS_SOURCES[0], provenance },
			checkout,
			path.join(root, "materialized"),
		);
		expect(output.scored).toBe(false);
		expect(await fs.readFile(path.join(output.root, "chall.txt"), "utf8")).toBe("clean-room fixture\n");
		expect(await Bun.file(path.join(output.root, "solve.py")).exists()).toBe(false);
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

	it("rejects symbolic links in visible file paths and destination parents", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-corpus-symlink-"));
		roots.push(root);
		const checkout = path.join(root, "checkout");
		const challenge = path.join(checkout, LACTF_CORPUS_SOURCES[0].challengePath);
		await fs.mkdir(challenge, { recursive: true });
		await fs.writeFile(path.join(root, "outside"), "outside\n");
		await fs.symlink(path.join(root, "outside"), path.join(challenge, "chall.txt"));
		await expect(buildCorpusProvenance(challenge, LACTF_CORPUS_SOURCES[0])).rejects.toMatchObject({
			code: "integrity_error",
		});

		await fs.rm(path.join(challenge, "chall.txt"));
		await fs.writeFile(path.join(challenge, "chall.txt"), "safe\n");
		const provenance = await buildCorpusProvenance(challenge, LACTF_CORPUS_SOURCES[0]);
		const outsideDestination = path.join(root, "outside-destination");
		await fs.mkdir(outsideDestination);
		await fs.symlink(outsideDestination, path.join(root, "linked-parent"));
		await expect(
			materializeCorpusEntry(
				{ source: LACTF_CORPUS_SOURCES[0], provenance },
				checkout,
				path.join(root, "linked-parent", "materialized"),
			),
		).rejects.toMatchObject({ code: "integrity_error" });
	});
});
