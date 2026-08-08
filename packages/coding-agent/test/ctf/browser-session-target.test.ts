import { describe, expect, test } from "bun:test";
import { assertBrowserSessionTarget } from "../../src/ctf/runtime/adapters";

describe("browser session target", () => {
	test("accepts only a canonical exact IPv4 loopback origin", () => {
		const target = assertBrowserSessionTarget({ origin: "http://127.0.0.1:43123", entryPath: "index.html" });
		expect(target).toEqual({
			origin: "http://127.0.0.1:43123",
			entryPath: "index.html",
			downloads: false,
			rawCdp: false,
			credentials: false,
			serviceWorkers: false,
			externalNetwork: false,
			filesystemDisclosure: false,
		});
		expect("secret" in target).toBe(false);
	});

	test.each([
		"http://localhost:43123",
		"http://[::1]:43123",
		"http://user:password@127.0.0.1:43123",
		"http://127.0.0.1:43123/path",
		"http://127.0.0.1:43123?query",
		"http://127.0.0.1:43123#hash",
		"http://127.0.0.1:0",
		"https://127.0.0.1:43123",
		"http://127.0.0.1",
	])("rejects substituted or non-canonical origin %s", origin => {
		expect(() => assertBrowserSessionTarget({ origin, entryPath: "index.html" })).toThrow(
			"canonical exact loopback HTTP origin",
		);
	});

	test.each([
		"/index.html",
		"../index.html",
		"nested/../index.html",
		"index.html?x=1",
		"index.html#x",
	])("rejects unconstrained entry path %s", entryPath => {
		expect(() => assertBrowserSessionTarget({ origin: "http://127.0.0.1:43123", entryPath })).toThrow(
			"browser entry path must be confined",
		);
	});
});
