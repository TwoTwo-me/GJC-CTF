#!/usr/bin/env bun

import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";

const START_TIMEOUT_MS = 15_000;
const REQUEST_TIMEOUT_MS = 5_000;
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "::1", "localhost"]);
const LOCAL_URL = /https?:\/\/(?:127\.0\.0\.1|localhost|\[::1\])(?::\d+)?(?:\/[^\s"']*)?/;

function requireBinaryPath(argv: readonly string[]): string {
	if (argv.length !== 2 || argv[0] !== "--binary" || argv[1].length === 0) {
		throw new Error("usage: bun scripts/ci-ctf-dashboard-smoke.ts --binary <path>");
	}
	return path.resolve(argv[1]);
}

function isLoopbackUrl(url: URL): boolean {
	return LOOPBACK_HOSTS.has(url.hostname);
}

function assetUrls(html: string, pageUrl: URL): { script: URL; stylesheet: URL } {
	const attributes = /<(script|link)\b[^>]*\b(?:src|href)=["']([^"']+)["'][^>]*>/gi;
	let script: URL | undefined;
	let stylesheet: URL | undefined;

	for (const match of html.matchAll(attributes)) {
		const tag = match[1]?.toLowerCase();
		const reference = match[2];
		if (!tag || !reference) continue;
		const url = new URL(reference, pageUrl);
		if (url.origin !== pageUrl.origin) continue;
		if (tag === "script" && url.pathname.endsWith(".js")) script ??= url;
		if (tag === "link" && url.pathname.endsWith(".css")) stylesheet ??= url;
	}

	if (!script || !stylesheet) throw new Error("dashboard HTML did not reference local JavaScript and CSS assets");
	return { script, stylesheet };
}

async function fetchNonempty(url: URL, expectedContent: string): Promise<string> {
	const response = await fetch(url, { method: "GET", signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
	const body = await response.text();
	if (!response.ok || body.trim().length === 0) {
		throw new Error(`GET ${url.pathname} returned ${response.status} with an empty response`);
	}
	if (!response.headers.get("content-type")?.toLowerCase().includes(expectedContent)) {
		throw new Error(`GET ${url.pathname} did not return ${expectedContent}`);
	}
	return body;
}

async function run(): Promise<void> {
	const binaryPath = requireBinaryPath(process.argv.slice(2));
	const binary = await fs.stat(binaryPath);
	if (!binary.isFile()) throw new Error(`binary is not a file: ${binaryPath}`);

	const runtimeDir = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-dashboard-"));
	const workspace = path.join(runtimeDir, "workspace");
	const home = path.join(runtimeDir, "home");
	const state = path.join(runtimeDir, "state");
	await Promise.all([fs.mkdir(workspace), fs.mkdir(home), fs.mkdir(state)]);
	const environment = { ...process.env, HOME: home, XDG_DATA_HOME: state, APPDATA: state, LOCALAPPDATA: state };
	const initialize = Bun.spawn({
		cmd: [binaryPath, "init", workspace, "--json"],
		cwd: runtimeDir,
		env: environment,
		stdout: "pipe",
		stderr: "pipe",
	});
	const [initializeStdout, initializeStderr, initializeExitCode] = await Promise.all([
		new Response(initialize.stdout).text(),
		new Response(initialize.stderr).text(),
		initialize.exited,
	]);
	if (initializeExitCode !== 0) {
		await fs.rm(runtimeDir, { recursive: true, force: true });
		throw new Error(`workspace initialization failed with code ${initializeExitCode}: ${initializeStderr || initializeStdout}`);
	}

	const child = Bun.spawn({
		cmd: [binaryPath, "dashboard", "--port", "0"],
		cwd: workspace,
		env: environment,
		stdout: "pipe",
		stderr: "pipe",
	});
	let output = "";
	const consume = async (stream: ReadableStream<Uint8Array>): Promise<void> => {
		const reader = stream.getReader();
		const decoder = new TextDecoder();
		try {
			for (;;) {
				const next = await reader.read();
				if (next.done) break;
				output += decoder.decode(next.value, { stream: true });
			}
		} finally {
			reader.releaseLock();
		}
	};
	const stdout = consume(child.stdout);
	const stderr = consume(child.stderr);
	let terminatedByRunner = false;

	try {
		const deadline = Date.now() + START_TIMEOUT_MS;
		let url: URL | undefined;
		while (!url && Date.now() < deadline) {
			const exitCode = child.exitCode;
			if (exitCode !== null) throw new Error(`dashboard exited natively with code ${exitCode}: ${output}`);
			const match = LOCAL_URL.exec(output)?.[0];
			if (match) url = new URL(match);
			if (!url) await Bun.sleep(50);
		}
		if (!url) throw new Error(`dashboard did not print a local URL within ${START_TIMEOUT_MS}ms: ${output}`);
		if (!isLoopbackUrl(url)) throw new Error(`dashboard URL is not loopback: ${url}`);

		const html = await fetchNonempty(url, "text/html");
		const assets = assetUrls(html, url);
		await fetchNonempty(assets.script, "javascript");
		await fetchNonempty(assets.stylesheet, "text/css");
		if (child.exitCode !== null) throw new Error(`dashboard exited natively with code ${child.exitCode}: ${output}`);
	} finally {
		if (child.exitCode === null) {
			terminatedByRunner = true;
			child.kill();
		}
		const exitCode = await child.exited;
		await Promise.all([stdout, stderr]);
		await fs.rm(runtimeDir, { recursive: true, force: true });
		if (!terminatedByRunner && exitCode !== 0) {
			throw new Error(`dashboard exited natively with code ${exitCode}: ${output}`);
		}
	}
}

await run();
