import { afterEach, describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { effectiveSkillDigest } from "../../src/ctf/contracts";
import { generatedCtfSkillInstalledIdentity, loadCtfSkillIdentity } from "../../src/ctf/skills/identity-loader";
import { CTF_MANIFEST_FILENAME, initCtfWorkspace, registerChallenge } from "../../src/ctf/workspace";
import { makeDescriptor } from "./fixtures";

const temporaryRoots: string[] = [];

async function temporaryRoot(): Promise<string> {
	const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-skill-install-"));
	temporaryRoots.push(root);
	return root;
}

afterEach(async () => {
	await Promise.all(temporaryRoots.splice(0).map(root => fs.rm(root, { recursive: true, force: true })));
});

describe("CTF generated local skill installation", () => {
	it("fresh bind publishes a confined artifact and binds its effective identity", async () => {
		const root = path.join(await temporaryRoot(), "competition");
		const result = await initCtfWorkspace(root, "test-tool");
		expect(result.skillArtifactCreated).toBe(true);
		expect(result.skillArtifactPath).toMatch(
			/^.+\/\.gjc-ctf\/skills\/artifacts\/ctf\/1\.1\.0\/[a-f0-9]{64}\/artifact\.json$/,
		);
		expect(result.workspace.manifest.skill).toEqual(result.skill);
		expect((await fs.lstat(result.skillArtifactPath!)).isFile()).toBe(true);
		const loaded = await loadCtfSkillIdentity({ competitionRoot: root, expected: result.skill });
		expect(result.skill?.digest).toBe(effectiveSkillDigest(loaded));
	});

	it("resolves the addressed artifact from an exact effective identity alone", async () => {
		const root = path.join(await temporaryRoot(), "competition");
		await initCtfWorkspace(root, "test-tool");
		const expectedEffective = generatedCtfSkillInstalledIdentity();
		const loaded = await loadCtfSkillIdentity({ competitionRoot: root, expectedEffective });
		expect(effectiveSkillDigest(loaded)).toBe(effectiveSkillDigest(expectedEffective));
	});

	it("installed identity differs from embedded identity", async () => {
		const root = path.join(await temporaryRoot(), "competition");
		const result = await initCtfWorkspace(root, "test-tool");
		const embedded = await loadCtfSkillIdentity();
		expect(result.skill?.digest).not.toBe(effectiveSkillDigest(embedded));
	});

	it("repeat init is a byte-idempotent no-op", async () => {
		const root = path.join(await temporaryRoot(), "competition");
		const first = await initCtfWorkspace(root, "test-tool");
		const manifest = await fs.readFile(path.join(root, CTF_MANIFEST_FILENAME));
		const artifact = await fs.readFile(first.skillArtifactPath!);
		const second = await initCtfWorkspace(root, "other-tool");
		expect(second).toMatchObject({ created: false, noOp: true, skillArtifactCreated: false });
		expect(await fs.readFile(path.join(root, CTF_MANIFEST_FILENAME))).toEqual(manifest);
		expect(await fs.readFile(first.skillArtifactPath!)).toEqual(artifact);
	});

	it("restores only a missing artifact for the exact generated manifest identity", async () => {
		const root = path.join(await temporaryRoot(), "competition");
		const first = await initCtfWorkspace(root, "test-tool");
		const manifest = await fs.readFile(path.join(root, CTF_MANIFEST_FILENAME));
		await fs.unlink(first.skillArtifactPath!);
		const restored = await initCtfWorkspace(root, "other-tool");
		expect(restored).toMatchObject({ created: false, noOp: true, skillArtifactCreated: true });
		expect(await fs.readFile(path.join(root, CTF_MANIFEST_FILENAME))).toEqual(manifest);
	});

	it("replays an interrupted init from its exact durable receipt", async () => {
		const root = path.join(await temporaryRoot(), "competition");
		const first = await initCtfWorkspace(root, "test-tool");
		const manifestPath = path.join(root, CTF_MANIFEST_FILENAME);
		const manifest = await fs.readFile(manifestPath);
		await fs.unlink(manifestPath);
		const recovered = await initCtfWorkspace(root, "other-tool");
		expect(recovered).toMatchObject({
			created: true,
			noOp: false,
			skillArtifactCreated: false,
		});
		expect(recovered.workspace.manifest.competitionId).toBe(first.workspace.manifest.competitionId);
		expect(await fs.readFile(manifestPath)).toEqual(manifest);
	});

	it("recreates a missing initial event head during receipt replay", async () => {
		const root = path.join(await temporaryRoot(), "competition");
		const first = await initCtfWorkspace(root, "test-tool");
		await fs.unlink(path.join(root, CTF_MANIFEST_FILENAME));
		await fs.unlink(path.join(root, ".gjc-ctf", "competition", "event-head.json"));
		const recovered = await initCtfWorkspace(root, "other-tool");
		expect(recovered.workspace.manifest.competitionId).toBe(first.workspace.manifest.competitionId);
		expect(await fs.readFile(path.join(root, ".gjc-ctf", "competition", "event-head.json"), "utf8")).toContain(
			first.workspace.manifest.competitionId,
		);
	});

	it("rejects a non-canonical init receipt without recreating the manifest", async () => {
		const root = path.join(await temporaryRoot(), "competition");
		await initCtfWorkspace(root, "test-tool");
		const manifestPath = path.join(root, CTF_MANIFEST_FILENAME);
		await fs.unlink(manifestPath);
		await fs.appendFile(path.join(root, ".gjc-ctf-init.json"), "\n");
		await expect(initCtfWorkspace(root, "other-tool")).rejects.toMatchObject({ code: "integrity_error" });
		expect(await fs.lstat(manifestPath).catch(() => undefined)).toBeUndefined();
	});

	it("never replays revision one over later challenge state", async () => {
		const root = path.join(await temporaryRoot(), "competition");
		const initialized = await initCtfWorkspace(root, "test-tool");
		await registerChallenge(initialized.workspace, makeDescriptor("registered-before-manifest-loss"), {
			mode: "unavailable",
		});
		const manifestPath = path.join(root, CTF_MANIFEST_FILENAME);
		await fs.unlink(manifestPath);
		await expect(initCtfWorkspace(root, "other-tool")).rejects.toMatchObject({ code: "integrity_error" });
		expect(await fs.lstat(manifestPath).catch(() => undefined)).toBeUndefined();
	});

	it("validates existing workspace state before restoring a missing artifact", async () => {
		const root = path.join(await temporaryRoot(), "competition");
		const result = await initCtfWorkspace(root, "test-tool");
		await fs.unlink(result.skillArtifactPath!);
		await fs.writeFile(path.join(root, ".gjc-ctf", "competition", "event-head.json"), "{}");
		await expect(initCtfWorkspace(root, "other-tool")).rejects.toMatchObject({ code: "integrity_error" });
		expect(await fs.lstat(result.skillArtifactPath!).catch(() => undefined)).toBeUndefined();
	});

	it("preserves conflicting artifact bytes", async () => {
		const root = path.join(await temporaryRoot(), "competition");
		const result = await initCtfWorkspace(root, "test-tool");
		await fs.writeFile(result.skillArtifactPath!, "conflict");
		await expect(initCtfWorkspace(root, "other-tool")).rejects.toMatchObject({ code: "integrity_error" });
		expect(await fs.readFile(result.skillArtifactPath!, "utf8")).toBe("conflict");
	});

	it("refuses a symlinked artifact leaf", async () => {
		const root = path.join(await temporaryRoot(), "competition");
		const result = await initCtfWorkspace(root, "test-tool");
		const outside = path.join(await temporaryRoot(), "outside.json");
		await fs.writeFile(outside, "outside");
		await fs.unlink(result.skillArtifactPath!);
		await fs.symlink(outside, result.skillArtifactPath!);
		await expect(initCtfWorkspace(root, "other-tool")).rejects.toMatchObject({ code: "integrity_error" });
		expect(await fs.readFile(outside, "utf8")).toBe("outside");
	});

	it("refuses a symlinked artifact ancestor", async () => {
		const root = path.join(await temporaryRoot(), "competition");
		const result = await initCtfWorkspace(root, "test-tool");
		const skills = path.join(root, ".gjc-ctf", "skills");
		const outside = await temporaryRoot();
		await fs.rm(skills, { recursive: true });
		await fs.symlink(outside, skills);
		await expect(initCtfWorkspace(root, "other-tool")).rejects.toMatchObject({ code: "integrity_error" });
		expect((await fs.lstat(skills)).isSymbolicLink()).toBe(true);
		expect(result.skillArtifactPath).toBeDefined();
	});

	it("refuses tampering and leaves the manifest unchanged", async () => {
		const root = path.join(await temporaryRoot(), "competition");
		const result = await initCtfWorkspace(root, "test-tool");
		const manifestPath = path.join(root, CTF_MANIFEST_FILENAME);
		const manifest = await fs.readFile(manifestPath);
		await fs.writeFile(result.skillArtifactPath!, "tampered");
		await expect(initCtfWorkspace(root, "other-tool")).rejects.toMatchObject({ code: "integrity_error" });
		expect(await fs.readFile(manifestPath)).toEqual(manifest);
	});

	it("does not treat a preexisting skill namespace as an initialized workspace", async () => {
		const root = path.join(await temporaryRoot(), "competition");
		await fs.mkdir(root);
		await fs.symlink(await temporaryRoot(), path.join(root, ".gjc-ctf"));
		await expect(initCtfWorkspace(root, "test-tool")).rejects.toMatchObject({ code: "unmarked_directory" });
		expect(await fs.lstat(path.join(root, CTF_MANIFEST_FILENAME)).catch(() => undefined)).toBeUndefined();
	});
});
