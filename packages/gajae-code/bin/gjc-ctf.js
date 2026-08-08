#!/usr/bin/env bun
import { fileURLToPath } from "node:url";

const ctfEntrypoint = fileURLToPath(new URL("../bin/gjc-ctf.js", import.meta.resolve("@gajae-code/coding-agent/cli")));
const child = Bun.spawn([process.execPath, ctfEntrypoint, ...process.argv.slice(2)], {
	stderr: "inherit",
	stdin: "inherit",
	stdout: "inherit",
});

process.exit(await child.exited);
