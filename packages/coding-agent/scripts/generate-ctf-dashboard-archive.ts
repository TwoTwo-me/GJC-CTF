import * as fs from "node:fs/promises";
import * as path from "node:path";

const ASSET_NAMES = ["index.html", "index.js", "styles.css"] as const;
type AssetName = (typeof ASSET_NAMES)[number];

export interface GenerateCtfDashboardArchiveOptions {
	inputDir?: string;
	outputPath?: string;
}

function decodeBase64(value: string, label: string): Buffer {
	if (value.length === 0 || value.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
		throw new Error(`Invalid base64 ${label}`);
	}
	const decoded = Buffer.from(value, "base64");
	if (decoded.length === 0 || decoded.toString("base64") !== value) {
		throw new Error(`Invalid base64 ${label}`);
	}
	return decoded;
}

async function readDashboardAssets(inputDir: string): Promise<Record<AssetName, Buffer>> {
	const assets = {} as Record<AssetName, Buffer>;
	for (const name of ASSET_NAMES) {
		const filePath = path.join(inputDir, name);
		let bytes: Buffer;
		try {
			bytes = await fs.readFile(filePath);
		} catch (error) {
			throw new Error(
				`Required CTF dashboard asset is unavailable: ${path.relative(process.cwd(), filePath)} (${error instanceof Error ? error.message : String(error)})`,
			);
		}
		if (bytes.length === 0) throw new Error(`Required CTF dashboard asset is empty: ${filePath}`);
		assets[name] = bytes;
	}
	return assets;
}

/**
 * Verify that a generated archive is canonical and exactly matches the
 * dashboard files it claims to embed. Release builders call this after
 * generation so stale, truncated, or modified archives fail closed.
 */
export async function validateCtfDashboardArchive(options: GenerateCtfDashboardArchiveOptions = {}): Promise<void> {
	const inputDir = options.inputDir ?? path.resolve(import.meta.dir, "../src/ctf/dashboard/dist");
	const outputPath =
		options.outputPath ?? path.resolve(import.meta.dir, "../src/ctf/dashboard/embedded-client.generated.txt");
	const sourceAssets = await readDashboardAssets(inputDir);
	let raw: string;
	try {
		raw = await fs.readFile(outputPath, "utf8");
	} catch (error) {
		throw new Error(
			`Required CTF dashboard archive is unavailable: ${path.relative(process.cwd(), outputPath)} (${error instanceof Error ? error.message : String(error)})`,
		);
	}
	const encoded = raw.trim();
	if (raw !== `${encoded}\n`) throw new Error(`CTF dashboard archive is not canonical: ${outputPath}`);
	const archive = JSON.parse(decodeBase64(encoded, "CTF dashboard archive").toString("utf8")) as unknown;
	if (typeof archive !== "object" || archive === null || Array.isArray(archive)) {
		throw new Error(`CTF dashboard archive must contain an object: ${outputPath}`);
	}
	const entries = archive as Record<string, unknown>;
	const names = Object.keys(entries).sort();
	if (names.length !== ASSET_NAMES.length || names.some((name, index) => name !== [...ASSET_NAMES].sort()[index])) {
		throw new Error(`CTF dashboard archive has an unexpected asset set: ${outputPath}`);
	}
	for (const name of ASSET_NAMES) {
		const encodedAsset = entries[name];
		if (typeof encodedAsset !== "string") throw new Error(`CTF dashboard archive has invalid ${name}`);
		const actual = decodeBase64(encodedAsset, `${name} asset`);
		if (!Buffer.from(sourceAssets[name]).equals(actual)) {
			throw new Error(`CTF dashboard archive does not match ${name}: ${outputPath}`);
		}
	}
}

export async function generateCtfDashboardArchive(options: GenerateCtfDashboardArchiveOptions = {}): Promise<string> {
	const inputDir = options.inputDir ?? path.resolve(import.meta.dir, "../src/ctf/dashboard/dist");
	const outputPath =
		options.outputPath ?? path.resolve(import.meta.dir, "../src/ctf/dashboard/embedded-client.generated.txt");
	const assets = await readDashboardAssets(inputDir);
	const archive: Record<AssetName, string> = {} as Record<AssetName, string>;
	for (const name of ASSET_NAMES) {
		archive[name] = assets[name].toString("base64");
	}
	const encoded = Buffer.from(JSON.stringify(archive), "utf8").toString("base64");
	await fs.mkdir(path.dirname(outputPath), { recursive: true });
	await fs.writeFile(outputPath, `${encoded}\n`, "utf8");
	await validateCtfDashboardArchive({ inputDir, outputPath });
	return encoded;
}

export async function validateCtfBuildInputs(packageDir = path.resolve(import.meta.dir, "..")): Promise<void> {
	const dashboardDist = path.join(packageDir, "src", "ctf", "dashboard", "dist");
	const archivePath = path.join(packageDir, "src", "ctf", "dashboard", "embedded-client.generated.txt");
	const required = [
		path.join(packageDir, "bin", "gjc-ctf.js"),
		path.join(packageDir, "src", "ctf", "skills", "ctf.md"),
		path.join(dashboardDist, "index.html"),
		path.join(dashboardDist, "index.js"),
		path.join(dashboardDist, "styles.css"),
		archivePath,
	];
	for (const filePath of required) {
		let stat: Awaited<ReturnType<typeof fs.stat>>;
		try {
			stat = await fs.stat(filePath);
		} catch (error) {
			throw new Error(
				`Required CTF build asset is unavailable: ${path.relative(packageDir, filePath)} (${error instanceof Error ? error.message : String(error)})`,
			);
		}
		if (!stat.isFile() || stat.size === 0) {
			throw new Error(`Required CTF build asset is missing or empty: ${path.relative(packageDir, filePath)}`);
		}
	}
	await validateCtfDashboardArchive({ inputDir: dashboardDist, outputPath: archivePath });
}

if (import.meta.main) {
	const inputDir = process.argv[2];
	const outputPath = process.argv[3];
	await generateCtfDashboardArchive({ inputDir, outputPath });
	if (inputDir === undefined && outputPath === undefined) await validateCtfBuildInputs();
}
