import { afterEach, describe, expect, it } from "bun:test";
import { generateKeyPairSync, sign } from "node:crypto";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
	canonicalDigest,
	canonicalJson,
	challengeDescriptorDigest,
	oracleEntryDigest,
	oracleRegistryDigest,
	sha256Hex,
} from "../../src/ctf/contracts";
import {
	CTF_MANIFEST_FILENAME,
	CTF_STATE_DIRNAME,
	discoverCtfWorkspace,
	initCtfWorkspace,
	readCtfManifest,
	registerChallenge,
} from "../../src/ctf/workspace";
import { DIGEST_A, makeDescriptor, SKILL } from "./fixtures";

const temporaryRoots: string[] = [];

async function temporaryRoot(): Promise<string> {
	const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-workspace-"));
	temporaryRoots.push(root);
	return root;
}
function descriptorWithPaths(sourcePath: string, visibleArtifactAllowlist: string[]) {
	const base = { ...makeDescriptor(), sourcePath, visibleArtifactAllowlist };
	return { ...base, descriptorDigest: challengeDescriptorDigest(base) };
}

afterEach(async () => {
	await Promise.all(temporaryRoots.splice(0).map(root => fs.rm(root, { recursive: true, force: true })));
});

describe("CTF workspace authority", () => {
	it("initializes idempotently and keeps state confined to the selected root", async () => {
		const parent = await temporaryRoot();
		const root = path.join(parent, "competition");
		const first = await initCtfWorkspace(root, "test-tool", { skill: SKILL });
		expect(first.created).toBe(true);
		expect(first.noOp).toBe(false);
		expect(first.workspace.root).toBe(path.resolve(root));
		expect(first.workspace.stateRoot).toBe(path.join(path.resolve(root), CTF_STATE_DIRNAME));

		const manifestPath = path.join(root, CTF_MANIFEST_FILENAME);
		const before = await fs.readFile(manifestPath, "utf8");
		const second = await initCtfWorkspace(root, "different-tool", { skill: SKILL });
		expect(second.created).toBe(false);
		expect(second.noOp).toBe(true);
		expect(await fs.readFile(manifestPath, "utf8")).toBe(before);
		expect(second.workspace.manifest.competitionId).toBe(first.workspace.manifest.competitionId);

		const nested = await discoverCtfWorkspace(path.join(root, "nested", "missing.txt"));
		expect(nested.root).toBe(path.resolve(root));
		expect(nested.stateRoot).toBe(path.join(path.resolve(root), CTF_STATE_DIRNAME));

		const nonEmpty = path.join(parent, "non-empty");
		await fs.mkdir(nonEmpty);
		await fs.writeFile(path.join(nonEmpty, "unrelated.txt"), "not a CTF workspace");
		await expect(initCtfWorkspace(nonEmpty, "test-tool", { skill: SKILL })).rejects.toMatchObject({
			code: "unmarked_directory",
		});
		expect(await fs.stat(path.join(nonEmpty, CTF_MANIFEST_FILENAME)).catch(() => undefined)).toBeUndefined();
		expect(await fs.stat(path.join(nonEmpty, CTF_STATE_DIRNAME)).catch(() => undefined)).toBeUndefined();
	});
	it("realpath-checks a symlinked manifest marker before reading", async () => {
		const parent = await temporaryRoot();
		const outside = await temporaryRoot();
		const root = path.join(parent, "competition");
		await initCtfWorkspace(root, "test-tool", { skill: SKILL });

		const manifestPath = path.join(root, CTF_MANIFEST_FILENAME);
		const validManifest = await readCtfManifest(root);
		expect(validManifest.schemaVersion).toBe("ctf-manifest-1");
		const outsideManifest = path.join(outside, "manifest.json");
		await fs.writeFile(outsideManifest, await fs.readFile(manifestPath));
		await fs.rm(manifestPath);
		await fs.symlink(outsideManifest, manifestPath);

		const error = await readCtfManifest(root).then(
			() => undefined,
			reason => reason,
		);
		expect(error).toMatchObject({ code: "integrity_error" });
		expect(error).toBeInstanceOf(Error);
		expect((error as Error).message).not.toContain(outside);
		expect((error as Error).message).not.toContain(outsideManifest);
	});

	it("registers a challenge with a new digest/revision, then makes an identical registration a no-op", async () => {
		const root = await temporaryRoot();
		const initialized = await initCtfWorkspace(root, "test-tool", { skill: SKILL });
		const descriptor = makeDescriptor();

		const registered = await registerChallenge(initialized.workspace, descriptor);
		expect(registered.manifest.manifestRevision).toBe(2);
		expect(registered.manifest.challenges).toHaveLength(1);
		expect(registered.manifest.challenges[0]?.descriptorDigest).toBe(descriptor.descriptorDigest);
		expect(registered.manifest.manifestDigest).toBe(canonicalDigest(registered.manifest, ["manifestDigest"]));

		const repeated = await registerChallenge(registered, descriptor);
		expect(repeated.manifest.manifestRevision).toBe(2);
		expect(repeated.manifest.manifestDigest).toBe(registered.manifest.manifestDigest);
		expect(repeated.manifest.challenges).toEqual(registered.manifest.challenges);

		const conflicting = makeDescriptor(descriptor.id, "source-rev-2");
		await expect(registerChallenge(repeated, conflicting)).rejects.toMatchObject({
			code: "idempotency_conflict",
		});
		const persisted = await readCtfManifest(root);
		expect(persisted.manifestRevision).toBe(2);
		expect(persisted.manifestDigest).toBe(registered.manifest.manifestDigest);
	});
	it("keeps a canonical event chain intact across multiple registrations", async () => {
		const root = await temporaryRoot();
		const initialized = await initCtfWorkspace(root, "test-tool", { skill: SKILL });
		const first = await registerChallenge(initialized.workspace, makeDescriptor("challenge-one"));
		const second = await registerChallenge(first, makeDescriptor("challenge-two"));
		const third = await registerChallenge(second, makeDescriptor("challenge-three"));

		expect(third.manifest.manifestRevision).toBe(4);
		expect((await discoverCtfWorkspace(root)).manifest.manifestRevision).toBe(4);
	});

	it("rejects a missing registration event revision from the canonical chain", async () => {
		const root = await temporaryRoot();
		const initialized = await initCtfWorkspace(root, "test-tool", { skill: SKILL });
		const first = await registerChallenge(initialized.workspace, makeDescriptor("challenge-one"));
		const second = await registerChallenge(first, makeDescriptor("challenge-two"));
		await registerChallenge(second, makeDescriptor("challenge-three"));

		const eventsRoot = path.join(root, CTF_STATE_DIRNAME, "competition", "events");
		const names = await fs.readdir(eventsRoot);
		for (const name of names) {
			const event = JSON.parse(await fs.readFile(path.join(eventsRoot, name), "utf8")) as { revision?: number };
			if (event.revision === 2) {
				await fs.rm(path.join(eventsRoot, name));
				break;
			}
		}

		await expect(discoverCtfWorkspace(root)).rejects.toMatchObject({ code: "integrity_error" });
	});

	it("rejects rewiring an older registration event", async () => {
		const root = await temporaryRoot();
		const initialized = await initCtfWorkspace(root, "test-tool", { skill: SKILL });
		const first = await registerChallenge(initialized.workspace, makeDescriptor("challenge-one"));
		const second = await registerChallenge(first, makeDescriptor("challenge-two"));
		await registerChallenge(second, makeDescriptor("challenge-three"));

		const eventsRoot = path.join(root, CTF_STATE_DIRNAME, "competition", "events");
		const names = await fs.readdir(eventsRoot);
		for (const name of names) {
			const eventPath = path.join(eventsRoot, name);
			const event = JSON.parse(await fs.readFile(eventPath, "utf8")) as {
				revision?: number;
				previousEventDigest?: string;
			};
			if (event.revision === 2) {
				event.previousEventDigest = "1".repeat(64);
				await fs.writeFile(eventPath, `${JSON.stringify(event)}\n`);
				break;
			}
		}

		await expect(discoverCtfWorkspace(root)).rejects.toMatchObject({ code: "integrity_error" });
	});
	it("rejects semantically mismatched registration events before recovery writes", async () => {
		const root = await temporaryRoot();
		const initialized = await initCtfWorkspace(root, "test-tool", { skill: SKILL });
		const registered = await registerChallenge(initialized.workspace, makeDescriptor());
		const registrationRoot = path.join(root, CTF_STATE_DIRNAME, "competition", "registration");
		const [transactionName] = await fs.readdir(registrationRoot);
		if (!transactionName) throw new Error("registration transaction was not persisted");
		const transactionPath = path.join(registrationRoot, transactionName);
		const transaction = JSON.parse(await fs.readFile(transactionPath, "utf8")) as Record<string, unknown>;
		const originalEvent = transaction.challengeEvent as Record<string, unknown>;
		const semanticEvent = { ...originalEvent, eventType: "run_created" } as Record<string, unknown>;
		const semanticEventDigest = canonicalDigest(semanticEvent);
		transaction.challengeEvent = semanticEvent;
		transaction.challengeEventDigest = semanticEventDigest;
		await fs.writeFile(transactionPath, `${JSON.stringify(transaction)}\n`);

		const eventPath = path.join(
			root,
			CTF_STATE_DIRNAME,
			"competition",
			"events",
			`${semanticEvent.eventId as string}.json`,
		);
		await fs.writeFile(eventPath, `${JSON.stringify(semanticEvent)}\n`);
		const eventHeadPath = path.join(root, CTF_STATE_DIRNAME, "competition", "event-head.json");
		const eventHead = JSON.parse(await fs.readFile(eventHeadPath, "utf8")) as Record<string, unknown>;
		eventHead.eventDigest = semanticEventDigest;
		await fs.writeFile(eventHeadPath, `${JSON.stringify(eventHead)}\n`);

		const journalPath = path.join(root, CTF_STATE_DIRNAME, "competition", "registration-journal.jsonl");
		const journalLines = (await fs.readFile(journalPath, "utf8"))
			.trimEnd()
			.split("\n")
			.map(line => {
				const record = JSON.parse(line) as Record<string, unknown>;
				record.challengeEvent = semanticEvent;
				record.challengeEventDigest = semanticEventDigest;
				return JSON.stringify(record);
			});
		await fs.writeFile(journalPath, `${journalLines.join("\n")}\n`);

		const beforeManifest = await fs.readFile(path.join(root, CTF_MANIFEST_FILENAME));
		await expect(registerChallenge(registered, makeDescriptor("another-challenge"))).rejects.toMatchObject({
			code: "invalid_registration",
		});
		expect(await fs.readFile(path.join(root, CTF_MANIFEST_FILENAME))).toEqual(beforeManifest);
	});
	it("rejects arbitrary oracle registration even when a trusted registry is present", async () => {
		const root = await temporaryRoot();
		const initialized = await initCtfWorkspace(root, "test-tool", { skill: SKILL });
		const descriptorBase = {
			...makeDescriptor("arbitrary-oracle"),
			trustLevel: "verified-local" as const,
			backend: { ...makeDescriptor().backend, imageDigest: DIGEST_A },
		};
		const descriptor = { ...descriptorBase, descriptorDigest: challengeDescriptorDigest(descriptorBase) };
		const registryBase = { schemaVersion: "ctf-oracle-registry-1" as const, entries: [] };
		const registry = { ...registryBase, registryDigest: oracleRegistryDigest(registryBase) };
		const trustedRegistry = {
			registry,
			keys: [
				{
					keyId: "trusted-key",
					algorithm: "ed25519" as const,
					publicKey: "unused",
					fingerprint: sha256Hex("unused"),
					active: true,
				},
			],
		};
		await expect(
			registerChallenge(initialized.workspace, descriptor, {
				mode: "scored",
				trustedAuthority: {
					trustedRegistry,
					registryDigest: registry.registryDigest,
					oracleEntryDigest: "0".repeat(64),
					backendDigest: canonicalDigest(descriptor.backend),
					imageDigest: DIGEST_A,
				},
			}),
		).rejects.toMatchObject({ code: "oracle_integrity_error" });
		expect((await readCtfManifest(root)).manifestRevision).toBe(1);
	});
	it("binds registry, entry, backend, and image digests for scored registration", async () => {
		const root = await temporaryRoot();
		const initialized = await initCtfWorkspace(root, "test-tool", { skill: SKILL });
		const descriptorBase = {
			...makeDescriptor("scored-challenge"),
			trustLevel: "verified-local" as const,
			backend: { ...makeDescriptor().backend, imageDigest: DIGEST_A },
		};
		const descriptor = { ...descriptorBase, descriptorDigest: challengeDescriptorDigest(descriptorBase) };
		const { privateKey, publicKey } = generateKeyPairSync("ed25519");
		const publicKeyText = publicKey.export({ format: "der", type: "spki" }).toString("base64");
		const key = {
			keyId: "trusted-key",
			algorithm: "ed25519" as const,
			publicKey: publicKeyText,
			fingerprint: sha256Hex(publicKeyText),
			active: true,
		};
		const unsignedEntry = {
			schemaVersion: "ctf-oracle-entry-1" as const,
			oracleId: descriptor.oracleId,
			protocolVersion: "oracle-1",
			executableRef: "oracle://trusted",
			imageDigest: DIGEST_A,
			artifactDigest: DIGEST_A,
			backendDigest: canonicalDigest(descriptor.backend),
			allowedChallengeIds: [descriptor.id],
			publicKeyId: key.keyId,
			signerKeyId: key.keyId,
			outputSchemaVersion: "oracle-result-1",
		};
		const entry = {
			...unsignedEntry,
			signature: sign(null, Buffer.from(canonicalJson(unsignedEntry), "utf8"), privateKey).toString("base64"),
		};
		const registryBase = { schemaVersion: "ctf-oracle-registry-1" as const, entries: [entry] };
		const registry = { ...registryBase, registryDigest: oracleRegistryDigest(registryBase) };
		const trustedRegistry = { registry, keys: [key] };
		const updated = await registerChallenge(initialized.workspace, descriptor, {
			mode: "scored",
			trustedAuthority: {
				trustedRegistry,
				registryDigest: registry.registryDigest,
				oracleEntryDigest: oracleEntryDigest(entry),
				backendDigest: canonicalDigest(descriptor.backend),
				imageDigest: DIGEST_A,
			},
		});
		const registered = updated.manifest.challenges[0];
		expect(registered?.oracleId).toBe(descriptor.oracleId);
		expect(registered?.oracleRegistryDigest).toBe(registry.registryDigest);
		expect(registered?.oracleEntryDigest).toBe(oracleEntryDigest(entry));
		expect(registered?.backendDigest).toBe(canonicalDigest(descriptor.backend));
	});
	it("keeps explicitly unavailable competition registration compatible without authority", async () => {
		const root = await temporaryRoot();
		const initialized = await initCtfWorkspace(root, "test-tool", { skill: SKILL });
		const base = { ...makeDescriptor("unavailable-challenge"), trustLevel: "verified-local" as const };
		const descriptor = { ...base, descriptorDigest: challengeDescriptorDigest(base) };
		const updated = await registerChallenge(initialized.workspace, descriptor, { mode: "unavailable" });
		expect(updated.manifest.challenges[0]?.id).toBe(descriptor.id);
		expect(updated.manifest.manifestRevision).toBe(2);
	});

	it("rejects descriptors without a skill identity instead of mutating manifest state", async () => {
		const root = await temporaryRoot();
		const initialized = await initCtfWorkspace(root, "test-tool");
		const descriptor = makeDescriptor("challenge-no-skill");
		await expect(registerChallenge(initialized.workspace, descriptor)).rejects.toMatchObject({
			code: "invalid_manifest",
		});
		expect((await readCtfManifest(root)).manifestRevision).toBe(1);
	});
	it("rejects partial, blank, malformed, invalid, and identity-mismatched journal records before writing state", async () => {
		const cases: Array<{
			mutate: (text: string) => string;
			code: string;
		}> = [
			{ mutate: text => text.slice(0, -1), code: "integrity_error" },
			{ mutate: text => `${text}\n`, code: "integrity_error" },
			{ mutate: text => `{not-json}\n${text}`, code: "integrity_error" },
			{
				mutate: text => {
					const [first, ...rest] = text.trimEnd().split("\n");
					const record = JSON.parse(first) as Record<string, unknown>;
					delete record.txId;
					return `${JSON.stringify(record)}\n${rest.join("\n")}\n`;
				},
				code: "invalid_registration",
			},
			{
				mutate: text => {
					const [first, ...rest] = text.trimEnd().split("\n");
					const record = JSON.parse(first) as Record<string, unknown>;
					record.txId = "00000000-0000-0000-0000-000000000000";
					return `${JSON.stringify(record)}\n${rest.join("\n")}\n`;
				},
				code: "integrity_error",
			},
		];

		for (const testCase of cases) {
			const root = await temporaryRoot();
			const initialized = await initCtfWorkspace(root, "test-tool", { skill: SKILL });
			const registered = await registerChallenge(initialized.workspace, makeDescriptor());
			const journalPath = path.join(root, CTF_STATE_DIRNAME, "competition", "registration-journal.jsonl");
			const beforeManifest = await fs.readFile(path.join(root, CTF_MANIFEST_FILENAME));
			const beforeJournal = await fs.readFile(journalPath, "utf8");
			await fs.writeFile(journalPath, testCase.mutate(beforeJournal));
			await expect(registerChallenge(registered, makeDescriptor("another-challenge"))).rejects.toMatchObject({
				code: testCase.code,
			});
			expect(await fs.readFile(path.join(root, CTF_MANIFEST_FILENAME))).toEqual(beforeManifest);
			expect(await fs.readFile(journalPath, "utf8")).toBe(testCase.mutate(beforeJournal));
			await expect(discoverCtfWorkspace(root)).rejects.toMatchObject({ code: testCase.code });
		}
	});
	it("realpath-confines source and visible artifact paths, including missing leaves", async () => {
		const parent = await temporaryRoot();
		const outside = await temporaryRoot();
		const root = path.join(parent, "competition");
		const initialized = await initCtfWorkspace(root, "test-tool", { skill: SKILL });
		await fs.symlink(outside, path.join(root, "source-escape"), "dir");
		await expect(
			registerChallenge(initialized.workspace, descriptorWithPaths("source-escape/missing-source", ["answer.txt"])),
		).rejects.toMatchObject({
			code: "invalid_manifest",
		});

		const secondRoot = path.join(parent, "second-competition");
		const second = await initCtfWorkspace(secondRoot, "test-tool", { skill: SKILL });
		await fs.symlink(outside, path.join(secondRoot, "artifact-escape"), "dir");
		await expect(
			registerChallenge(
				second.workspace,
				descriptorWithPaths("missing-source", ["artifact-escape/missing-answer.txt"]),
			),
		).rejects.toMatchObject({
			code: "invalid_manifest",
		});

		const thirdRoot = path.join(parent, "third-competition");
		const third = await initCtfWorkspace(thirdRoot, "test-tool", { skill: SKILL });
		await fs.symlink(path.join(outside, "missing-target"), path.join(thirdRoot, "dangling-source"), "dir");
		await expect(
			registerChallenge(third.workspace, descriptorWithPaths("dangling-source/missing-source", ["answer.txt"])),
		).rejects.toMatchObject({
			code: "invalid_manifest",
		});

		const preflightRoot = path.join(parent, "preflight-competition");
		const preflight = await initCtfWorkspace(preflightRoot, "test-tool", { skill: SKILL });
		await registerChallenge(preflight.workspace, makeDescriptor("preflight-challenge"));
		await fs.symlink(outside, path.join(preflightRoot, "fixtures"), "dir");
		await expect(discoverCtfWorkspace(preflightRoot)).rejects.toMatchObject({
			code: "integrity_error",
		});
	});
	it("rejects symlinked state roots that resolve outside the competition root", async () => {
		const root = await temporaryRoot();
		const outside = await temporaryRoot();
		const initialized = await initCtfWorkspace(root, "test-tool", { skill: SKILL });
		const stateRoot = path.join(root, CTF_STATE_DIRNAME);
		await fs.rm(stateRoot, { recursive: true, force: true });
		await fs.symlink(outside, stateRoot, "dir");

		await expect(discoverCtfWorkspace(root)).rejects.toMatchObject({
			code: "integrity_error",
		});
		await expect(registerChallenge(initialized.workspace, makeDescriptor("state-root-escape"))).rejects.toMatchObject(
			{
				code: "integrity_error",
			},
		);
		expect(await fs.readdir(outside)).toEqual([]);
	});

	it("rejects registration transactions whose event payload is not bound to the transaction", async () => {
		for (const field of ["descriptorDigest", "idempotencyKey"] as const) {
			const root = await temporaryRoot();
			const initialized = await initCtfWorkspace(root, "test-tool", { skill: SKILL });
			const registered = await registerChallenge(initialized.workspace, makeDescriptor());
			const registrationRoot = path.join(root, CTF_STATE_DIRNAME, "competition", "registration");
			const [transactionName] = await fs.readdir(registrationRoot);
			if (!transactionName) throw new Error("registration transaction was not persisted");
			const transactionPath = path.join(registrationRoot, transactionName);
			const transaction = JSON.parse(await fs.readFile(transactionPath, "utf8")) as Record<string, unknown>;
			const event = transaction.challengeEvent as Record<string, unknown>;
			const payload = event.payload as Record<string, unknown>;
			transaction.challengeEvent = {
				...event,
				payload: {
					...payload,
					[field]: field === "descriptorDigest" ? "0".repeat(64) : "00000000-0000-0000-0000-000000000000",
				},
			};
			await fs.writeFile(transactionPath, `${JSON.stringify(transaction)}\n`);

			const beforeManifest = await fs.readFile(path.join(root, CTF_MANIFEST_FILENAME));
			await expect(registerChallenge(registered, makeDescriptor("another-challenge"))).rejects.toMatchObject({
				code: "invalid_registration",
			});
			expect(await fs.readFile(path.join(root, CTF_MANIFEST_FILENAME))).toEqual(beforeManifest);
			await expect(discoverCtfWorkspace(root)).rejects.toMatchObject({ code: "invalid_registration" });
		}
	});
});
