import * as fs from "node:fs/promises";
import * as path from "node:path";

export interface CtfDashboardBuildOptions {
	outDir?: string;
	minify?: boolean;
}

export interface CtfDashboardBuildResult {
	outDir: string;
	files: readonly ["index.html", "index.js", "styles.css"];
}

const INDEX_HTML = `<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>GJC CTF Dashboard</title>
	<link rel="stylesheet" href="./styles.css">
</head>
<body>
	<main id="root"><p>Loading CTF dashboard…</p></main>
	<script type="module" src="./index.js"></script>
</body>
</html>
`;

/** Build the source client into a small, explicit asset set for source installs. */
export async function buildCtfDashboard(options: CtfDashboardBuildOptions = {}): Promise<CtfDashboardBuildResult> {
	const sourceDir = path.join(import.meta.dir, "client");
	const outDir = options.outDir ?? path.join(import.meta.dir, "dist");
	await fs.mkdir(outDir, { recursive: true });
	const result = await Bun.build({
		entrypoints: [path.join(sourceDir, "App.tsx")],
		outdir: outDir,
		target: "browser",
		minify: options.minify ?? true,
		naming: "index.js",
	});
	if (!result.success) {
		const diagnostics = result.logs.map(log => String(log)).join("; ");
		throw new Error(`CTF dashboard client build failed${diagnostics ? `: ${diagnostics}` : ""}`);
	}
	await Promise.all([
		fs.writeFile(path.join(outDir, "index.html"), INDEX_HTML, "utf8"),
		fs.copyFile(path.join(sourceDir, "styles.css"), path.join(outDir, "styles.css")),
	]);
	return { outDir, files: ["index.html", "index.js", "styles.css"] };
}

if (import.meta.main) {
	await buildCtfDashboard({ outDir: process.argv[2] });
}
