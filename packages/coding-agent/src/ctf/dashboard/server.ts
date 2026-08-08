import * as fs from "node:fs/promises";
import * as path from "node:path";
import { createCtfDashboardApiHandler, createCtfDashboardErrorResponse } from "./api";
import { buildCtfDashboard } from "./build";
import { ctfDashboardPolicyResponse, inspectCtfDashboardLocalPolicy } from "./local-policy";
import { createUnavailableCtfDashboardProjectionReader } from "./projection-reader";
import {
	CTF_DASHBOARD_DEFAULT_PORT,
	type CtfDashboardAssetArchive,
	type CtfDashboardAssetSource,
	type CtfDashboardProjectionReader,
	type CtfDashboardStateIdentity,
} from "./types";

const STATIC_ROOT = path.join(import.meta.dir, "dist");
const FALLBACK_HTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>GJC CTF Dashboard</title><link rel="stylesheet" href="/styles.css"></head><body><main id="root"><p>Loading CTF dashboard…</p></main><script type="module" src="/index.js"></script></body></html>`;
const FALLBACK_JS = `const root=document.getElementById("root"); if(root) root.textContent="CTF dashboard assets are unavailable; canonical state is not connected.";`;
const FALLBACK_CSS = `:root{font-family:system-ui,sans-serif;color-scheme:dark light}body{margin:2rem;max-width:72rem}main{white-space:pre-wrap}`;

export interface CtfDashboardOptions {
	port?: number;
	projectionReader?: CtfDashboardProjectionReader;
	now?: () => Date;
	/** Source filesystem root; defaults to the dashboard build output directory. */
	staticRoot?: string;
	/** Optional compiled archive source, decoded by the generated archive helper. */
	embeddedArchive?: CtfDashboardAssetArchive | string;
	/** Inject an asset source for a compiled target or a test server. */
	assets?: CtfDashboardAssetSource;
	/** Disable the on-demand source build when embedding prebuilt assets. */
	buildClient?: boolean;
	/** A state reader is required for healthy responses; absent readers fail closed. */
	stateReader?: CtfDashboardProjectionReader;
	stateIdentity?: CtfDashboardStateIdentity;
}

export interface CtfDashboardHandle {
	readonly port: number;
	readonly url: string;
	readonly stop: () => void;
}

export class CtfDashboardArchiveError extends Error {
	readonly code = "invalid_dashboard_archive" as const;
	constructor(message: string) {
		super(message);
		this.name = "CtfDashboardArchiveError";
	}
}
function archiveSource(archive: CtfDashboardAssetArchive | string | undefined): CtfDashboardAssetSource | undefined {
	if (archive === undefined) return undefined;
	let entries: CtfDashboardAssetArchive;
	if (typeof archive === "string") {
		const encoded = archive.replaceAll(/\s/g, "");
		if (encoded.length === 0 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) {
			throw new CtfDashboardArchiveError("embedded dashboard archive is not valid base64");
		}
		try {
			const decoded = Buffer.from(encoded, "base64").toString("utf8");
			const parsed: unknown = JSON.parse(decoded);
			if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
				throw new Error("archive root is not an object");
			}
			entries = parsed as CtfDashboardAssetArchive;
		} catch (error) {
			if (error instanceof CtfDashboardArchiveError) throw error;
			throw new CtfDashboardArchiveError(
				`embedded dashboard archive is invalid: ${error instanceof Error ? error.message : String(error)}`,
			);
		}
	} else {
		entries = archive;
	}
	if (typeof entries !== "object" || entries === null || Array.isArray(entries)) {
		throw new CtfDashboardArchiveError("embedded dashboard archive root is not an object");
	}
	const expected = new Set(["index.html", "index.js", "styles.css"]);
	const names = Object.keys(entries);
	if (names.length !== expected.size || names.some(name => !expected.has(name))) {
		throw new CtfDashboardArchiveError(
			"embedded dashboard archive must contain exactly index.html, index.js, and styles.css",
		);
	}
	const decodedEntries = new Map<string, Buffer>();
	for (const name of expected) {
		const value = entries[name];
		if (
			typeof value !== "string" ||
			value.length === 0 ||
			!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
		) {
			throw new CtfDashboardArchiveError(`embedded dashboard archive entry is invalid: ${name}`);
		}
		decodedEntries.set(name, Buffer.from(value, "base64"));
	}
	return pathname => {
		const key = pathname === "/" ? "index.html" : pathname.replace(/^\//, "");
		const body = decodedEntries.get(key);
		if (body === undefined) return undefined;
		const type = key.endsWith(".html")
			? "text/html; charset=utf-8"
			: key.endsWith(".js")
				? "text/javascript; charset=utf-8"
				: "text/css; charset=utf-8";
		return new Response(body.toString("utf8"), { headers: { "Content-Type": type, "Cache-Control": "no-store" } });
	};
}
export const createCtfDashboardAssetSource = archiveSource;

async function ensureSourceBuild(root: string, enabled: boolean): Promise<void> {
	if (!enabled) return;
	const indexPath = path.join(root, "index.html");
	const scriptPath = path.join(root, "index.js");
	try {
		const [index, script] = await Promise.all([fs.stat(indexPath), fs.stat(scriptPath)]);
		if (index.isFile() && script.isFile()) return;
	} catch {
		// Build below; a missing or partial asset set is never served as healthy.
	}
	await buildCtfDashboard({ outDir: root });
}

async function staticResponse(pathname: string, root: string, assets?: CtfDashboardAssetSource): Promise<Response> {
	if (assets) {
		const asset = await assets(pathname);
		if (asset) return asset;
	}
	const requested = pathname === "/" ? "index.html" : pathname.replace(/^\//, "");
	if (!requested.includes("..") && !requested.includes("\\")) {
		const file = Bun.file(path.join(root, requested));
		if (await file.exists()) return new Response(file, { headers: { "Cache-Control": "no-store" } });
	}
	// A single-page client gets a safe fallback; missing non-client assets remain 404.
	if (pathname === "/" || (!pathname.startsWith("/api/") && !path.extname(pathname))) {
		const index = Bun.file(path.join(root, "index.html"));
		if (await index.exists()) return new Response(index, { headers: { "Cache-Control": "no-store" } });
		return new Response(FALLBACK_HTML, {
			headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
		});
	}
	if (requested === "index.js")
		return new Response(FALLBACK_JS, {
			headers: { "Content-Type": "text/javascript; charset=utf-8", "Cache-Control": "no-store" },
		});
	if (requested === "styles.css")
		return new Response(FALLBACK_CSS, {
			headers: { "Content-Type": "text/css; charset=utf-8", "Cache-Control": "no-store" },
		});
	return new Response("Not Found", { status: 404 });
}

/**
 * Start the CTF-only read dashboard. Bun.serve is explicitly pinned to IPv4
 * loopback; callers cannot provide a wildcard or externally reachable hostname.
 */
export function startCtfDashboard(options?: CtfDashboardOptions): Promise<CtfDashboardHandle>;
export function startCtfDashboard(
	port: number,
	options?: Omit<CtfDashboardOptions, "port">,
): Promise<CtfDashboardHandle>;
export async function startCtfDashboard(
	portOrOptions: number | CtfDashboardOptions = {},
	maybeOptions: Omit<CtfDashboardOptions, "port"> = {},
): Promise<CtfDashboardHandle> {
	const options: CtfDashboardOptions =
		typeof portOrOptions === "number" ? { ...maybeOptions, port: portOrOptions } : portOrOptions;
	const port = options.port ?? CTF_DASHBOARD_DEFAULT_PORT;
	const root = options.staticRoot ?? STATIC_ROOT;
	const embedded = archiveSource(options.embeddedArchive);
	const assets = options.assets ?? embedded;
	if (!assets) await ensureSourceBuild(root, options.buildClient !== false);
	const reader =
		options.stateReader ??
		options.projectionReader ??
		createUnavailableCtfDashboardProjectionReader("CTF canonical state is not connected", options.stateIdentity);
	const now = options.now ?? (() => new Date());
	const handleApi = createCtfDashboardApiHandler({ projectionReader: reader, now });
	const server = Bun.serve({
		hostname: "127.0.0.1",
		port,
		async fetch(request) {
			let url: URL;
			try {
				url = new URL(request.url);
			} catch {
				return createCtfDashboardErrorResponse(400, "invalid_request", "request URL is invalid", now);
			}
			const boundPort = server.port ?? port;
			const rejection = inspectCtfDashboardLocalPolicy(request, url, boundPort);
			if (rejection) return ctfDashboardPolicyResponse(rejection, now);
			if (url.pathname.startsWith("/api/ctf/v1/")) return await handleApi(request);
			try {
				return await staticResponse(url.pathname, root, assets);
			} catch {
				return createCtfDashboardErrorResponse(500, "asset_read_failed", "dashboard asset could not be read", now);
			}
		},
	});
	const actualPort = server.port ?? port;
	return {
		port: actualPort,
		url: `http://127.0.0.1:${actualPort}`,
		stop: () => server.stop(),
	};
}

export const startServer = startCtfDashboard;
