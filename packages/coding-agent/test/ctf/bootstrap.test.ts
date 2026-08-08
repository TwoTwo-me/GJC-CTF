import { describe, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import * as path from "node:path";
import {
	bootstrapCtfTools,
	detectCtfPackageManager,
	resolveTrustedExecutable,
	runExactArgv,
	type TrustedExecutablePolicy,
} from "../../src/ctf/bootstrap";

async function fixture(): Promise<Readonly<{ root: string; policy: TrustedExecutablePolicy }>> {
	const root = await mkdtemp(path.join(tmpdir(), "ctf-bootstrap-"));
	for (const name of ["curl", "apt-get", "sudo"]) await writeFile(path.join(root, name), `fixture-${name}`);
	return { root, policy: { roots: [root], operatorCwd: tmpdir() } };
}

describe("CTF safe tool bootstrap", () => {
	test("uses only trusted absolute executable identities rather than PATH", async () => {
		const trusted = await fixture();
		const attacker = await mkdtemp(path.join(tmpdir(), "ctf-attacker-"));
		try {
			await writeFile(path.join(attacker, "apt-get"), "attacker");
			expect(await detectCtfPackageManager("linux", trusted.policy)).toBe("apt");
			const result = await bootstrapCtfTools({
				categories: ["network"],
				platform: "linux",
				packageManager: "apt",
				elevate: false,
				trustedExecutables: trusted.policy,
				run: async argv => {
					expect(argv[0]).toBe(path.join(trusted.root, "curl"));
					return { exitCode: 0, stdout: "curl 8", stderr: "" };
				},
			});
			expect(result.observations[0]?.executable?.path).toBe(path.join(trusted.root, "curl"));
		} finally {
			await rm(trusted.root, { force: true, recursive: true });
			await rm(attacker, { force: true, recursive: true });
		}
	});

	test("rejects empty, relative, current, and challenge-controlled roots", async () => {
		const trusted = await fixture();
		try {
			await expect(resolveTrustedExecutable("curl", { roots: [""], operatorCwd: tmpdir() })).rejects.toThrow(
				/absolute/,
			);
			await expect(resolveTrustedExecutable("curl", { roots: ["bin"], operatorCwd: tmpdir() })).rejects.toThrow(
				/absolute/,
			);
			await expect(
				resolveTrustedExecutable("curl", { roots: [process.cwd()], operatorCwd: process.cwd() }),
			).rejects.toThrow(/current/);
			await expect(
				resolveTrustedExecutable("curl", {
					roots: [trusted.root],
					rejectedRoots: [trusted.root],
					operatorCwd: tmpdir(),
				}),
			).rejects.toThrow(/trusted absolute/);
		} finally {
			await rm(trusted.root, { force: true, recursive: true });
		}
	});

	test("fails closed when a bound executable mutates before invocation", async () => {
		const trusted = await fixture();
		try {
			const identity = await resolveTrustedExecutable("curl", trusted.policy);
			if (identity === undefined) throw new Error("fixture curl is missing");
			await writeFile(identity.path, "mutated");
			await expect(runExactArgv([identity.path, "--version"], { identity, policy: trusted.policy })).rejects.toThrow(
				/identity drifted/,
			);
		} finally {
			await rm(trusted.root, { force: true, recursive: true });
		}
	});

	test("dry-run only probes absolute argv and never installs", async () => {
		const trusted = await fixture();
		try {
			const calls: string[][] = [];
			const result = await bootstrapCtfTools({
				categories: ["network"],
				platform: "linux",
				packageManager: "apt",
				elevate: false,
				trustedExecutables: trusted.policy,
				run: async argv => {
					calls.push([...argv]);
					return { exitCode: 127, stdout: "", stderr: "missing" };
				},
			});
			expect(result.commands).toEqual([["apt-get", "install", "-y", "curl"]]);
			expect(calls).toEqual([[path.join(trusted.root, "curl"), "--version"]]);
		} finally {
			await rm(trusted.root, { force: true, recursive: true });
		}
	});

	test("keeps reviewed install tails while executing elevation and installer by absolute identity", async () => {
		const trusted = await fixture();
		try {
			const calls: string[][] = [];
			await bootstrapCtfTools({
				categories: ["network"],
				mode: "apply",
				platform: "linux",
				packageManager: "apt",
				elevate: true,
				trustedExecutables: trusted.policy,
				run: async argv => {
					calls.push([...argv]);
					if (calls.length === 1) return { exitCode: 127, stdout: "", stderr: "missing" };
					if (calls.length === 2) return { exitCode: 0, stdout: "", stderr: "" };
					return { exitCode: 0, stdout: "curl 8", stderr: "" };
				},
			});
			expect(calls).toEqual([
				[path.join(trusted.root, "curl"), "--version"],
				[path.join(trusted.root, "sudo"), "-n", path.join(trusted.root, "apt-get"), "install", "-y", "curl"],
				[path.join(trusted.root, "curl"), "--version"],
			]);
		} finally {
			await rm(trusted.root, { force: true, recursive: true });
		}
	});
});
