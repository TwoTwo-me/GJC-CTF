import { describe, expect, it } from "bun:test";

import * as path from "node:path";

const scriptPath = path.join(import.meta.dir, "ci-ctf-dashboard-smoke.ts");

describe("CTF dashboard release smoke contract", () => {
	it("requires an explicit binary and starts the dashboard without shell interpolation", async () => {
		const source = await Bun.file(scriptPath).text();
		expect(source).toContain('argv[0] !== "--binary"');
		expect(source).toContain('cmd: [binaryPath, "init", workspace, "--json"]');
		expect(source).toContain('cmd: [binaryPath, "dashboard", "--port", "0"]');
		expect(source).not.toContain("shell:");
	});

	it("isolates state, accepts only loopback URLs, and fetches embedded dashboard assets", async () => {
		const source = await Bun.file(scriptPath).text();
		expect(source).toContain('HOME: home');
		expect(source).toContain('XDG_DATA_HOME: state');
		expect(source).toContain('LOCAL_URL = /https?:');
		expect(source).toContain("isLoopbackUrl(url)");
		expect(source).toContain('fetchNonempty(url, "text/html")');
		expect(source).toContain('fetchNonempty(assets.script, "javascript")');
		expect(source).toContain('fetchNonempty(assets.stylesheet, "text/css")');
		expect(source).toContain('method: "GET"');
	});

	it("uses bounded startup and request timeouts, then terminates and cleans up the child", async () => {
		const source = await Bun.file(scriptPath).text();
		expect(source).toContain("const START_TIMEOUT_MS = 15_000");
		expect(source).toContain("AbortSignal.timeout(REQUEST_TIMEOUT_MS)");
		expect(source).toContain("terminatedByRunner = true");
		expect(source).toContain("child.kill()");
		expect(source).toContain("await fs.rm(runtimeDir, { recursive: true, force: true })");
		expect(source).toContain("dashboard exited natively with code");
	});
});
