import * as fs from "node:fs";
import * as path from "node:path";
import type { FileLockOptions } from "../../config/file-lock";
import {
	appendJsonl as appendJsonlPrimitive,
	appendJsonlIdempotent as appendJsonlIdempotentPrimitive,
	type AppendJsonlIdempotentOptions,
	type AppendJsonlIdempotentResult,
	type StateWriterDurability,
	type StateWriterOptions,
	updateJsonAtomic as updateJsonAtomicPrimitive,
	withWorkflowStateLock as withWorkflowStateLockPrimitive,
	writeJsonAtomic as writeJsonAtomicPrimitive,
} from "../state-writer";

/**
 * Options applied to one operation on a {@link RootedStore}.
 *
 * `cwd` is the project root used by the existing state-writer primitives. It is
 * intentionally separate from the store root: the latter is the namespace
 * boundary, while the former identifies the project's `.gjc` directory.
 */
export type RootedStoreOperationOptions = Omit<StateWriterOptions, "cwd" | "lock"> & {
	cwd?: string;
	lock?: FileLockOptions;
};
export type RootedStoreIdempotentOptions = Omit<AppendJsonlIdempotentOptions, "cwd" | "lock"> & RootedStoreOperationOptions;

export interface RootedStoreOptions {
	/** Project root passed to the existing state-writer primitives. */
	cwd?: string;
	/** Defaults for workflow lock acquisition. */
	lock?: FileLockOptions;
	/** Durability profile for writes. CTF roots default to the durable profile. */
	durability?: StateWriterDurability;
}

export interface RootedStoreConfig extends RootedStoreOptions {
	root: string;
}

/** Error raised when a rooted-store target escapes its configured root. */
export class RootedStorePathError extends Error {
	readonly root: string;
	readonly targetPath: string;
	readonly resolvedPath: string;

	constructor(root: string, targetPath: string, resolvedPath: string) {
		super(`storage target must be within configured root ${root}: ${targetPath}`);
		this.name = "RootedStorePathError";
		this.root = root;
		this.targetPath = targetPath;
		this.resolvedPath = resolvedPath;
	}
}

function resolvedRoot(root: string): string {
	if (typeof root !== "string" || !root.trim()) throw new Error("storage root is required");
	return path.resolve(root);
}

function pathWithinRoot(root: string, candidate: string): boolean {
	const relative = path.relative(root, candidate);
	return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
}
function realpathWithMissingLeafSync(target: string): string {
	const suffix: string[] = [];
	let current = target;
	for (;;) {
		try {
			const resolved = fs.realpathSync.native(current);
			return path.join(resolved, ...suffix);
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
			try {
				if (fs.lstatSync(current).isSymbolicLink()) {
					throw new Error(`refusing symlink target with missing destination: ${target}`);
				}
			} catch (lstatError) {
				if ((lstatError as NodeJS.ErrnoException).code !== "ENOENT") throw lstatError;
			}
			const parent = path.dirname(current);
			if (parent === current) return path.resolve(current, ...suffix);
			suffix.unshift(path.basename(current));
			current = parent;
		}
	}
}

/**
 * Resolve and validate a path against an explicit storage root.
 *
 * The root itself is considered within the root; file operations on a store
 * reject an empty target separately. Both relative traversal and absolute
 * paths outside the root are rejected before invoking a state-writer primitive.
 */
export function resolveRootedPath(root: string, targetPath: string): string {
	const rootPath = resolvedRoot(root);
	if (typeof targetPath !== "string" || !targetPath.trim()) throw new Error("storage target path is required");
	const resolvedPath = path.resolve(rootPath, targetPath);
	const safeRoot = realpathWithMissingLeafSync(rootPath);
	const safePath = realpathWithMissingLeafSync(resolvedPath);
	if (!pathWithinRoot(safeRoot, safePath)) throw new RootedStorePathError(rootPath, targetPath, resolvedPath);
	return resolvedPath;
}

/** Assert that a candidate path is inside (or equal to) an explicit root. */
export function assertPathWithinRoot(root: string, candidatePath: string): string {
	const rootPath = resolvedRoot(root);
	if (typeof candidatePath !== "string" || !candidatePath.trim()) throw new Error("storage candidate path is required");
	const resolvedPath = path.resolve(candidatePath);
	const safeRoot = realpathWithMissingLeafSync(rootPath);
	const safePath = realpathWithMissingLeafSync(resolvedPath);
	if (!pathWithinRoot(safeRoot, safePath)) throw new RootedStorePathError(rootPath, candidatePath, resolvedPath);
	return resolvedPath;
}

/** Non-throwing counterpart for callers that need to inspect a boundary first. */
export function isPathWithinRoot(root: string, candidatePath: string): boolean {
	try {
		assertPathWithinRoot(root, candidatePath);
		return true;
	} catch {
		return false;
	}
}

function projectRootForStorageRoot(root: string, fallback: string): string {
	let current = root;
	for (;;) {
		if (path.basename(current) === ".gjc") return path.dirname(current);
		const parent = path.dirname(current);
		if (parent === current) return fallback;
		current = parent;
	}
}

/**
 * Root-scoped facade over the sanctioned state-writer primitives.
 *
 * The facade performs its own namespace check and then passes the validated
 * absolute target to state-writer. Consequently, atomic rename, append
 * idempotency, and workflow locking retain their existing implementations and
 * semantics; this class only binds them to one explicit root.
 */
export class RootedStore {
	readonly durability: StateWriterDurability;
	readonly root: string;
	readonly cwd: string;
	readonly lock: FileLockOptions | undefined;

	constructor(root: string, options: RootedStoreOptions = {}) {
		this.root = resolvedRoot(root);
		const fallbackCwd = path.resolve(options.cwd ?? process.cwd());
		this.cwd = options.cwd
			? fallbackCwd
			: projectRootForStorageRoot(this.root, fallbackCwd);
		this.lock = options.lock;
		this.durability = options.durability ?? (path.basename(this.root) === ".gjc-ctf" ? "ctf" : "default");
	}

	/** Validate and resolve a target without touching the filesystem. */
	resolve(targetPath: string): string {
		return resolveRootedPath(this.root, targetPath);
	}

	private writerOptions(options?: RootedStoreOperationOptions): StateWriterOptions {
		return {
			...options,
			cwd: options?.cwd ?? this.cwd,
			root: this.root,
			durability: options?.durability ?? this.durability,
			lock: options?.lock ?? this.lock,
		};
	}

	writeJsonAtomic<T>(targetPath: string, value: T, options?: RootedStoreOperationOptions): Promise<string> {
		return writeJsonAtomicPrimitive(this.resolve(targetPath), value, this.writerOptions(options));
	}

	appendJsonl<T>(targetPath: string, entry: T, options?: RootedStoreOperationOptions): Promise<string> {
		return appendJsonlPrimitive(this.resolve(targetPath), entry, this.writerOptions(options));
	}

	appendJsonlIdempotent<T>(
		targetPath: string,
		entry: T,
		options: RootedStoreIdempotentOptions,
	): Promise<AppendJsonlIdempotentResult> {
		return appendJsonlIdempotentPrimitive(
			this.resolve(targetPath),
			entry,
			this.writerOptions(options) as AppendJsonlIdempotentOptions,
		);
	}

	updateJsonAtomic<T = unknown>(
		targetPath: string,
		mutator: (current: T | undefined) => T | Promise<T>,
		options?: RootedStoreOperationOptions,
	): Promise<string> {
		return updateJsonAtomicPrimitive(this.resolve(targetPath), mutator, this.writerOptions(options));
	}

	withWorkflowStateLock<T>(
		targetPath: string,
		fn: () => Promise<T>,
		options?: RootedStoreOperationOptions,
	): Promise<T> {
		return withWorkflowStateLockPrimitive(this.resolve(targetPath), fn, this.writerOptions(options));
	}

	/** Alias for callers that use the shorter lock terminology. */
	withLock<T>(targetPath: string, fn: () => Promise<T>, options?: RootedStoreOperationOptions): Promise<T> {
		return this.withWorkflowStateLock(targetPath, fn, options);
	}
}

export function createRootedStore(root: string, options?: RootedStoreOptions): RootedStore;
export function createRootedStore(config: RootedStoreConfig): RootedStore;
export function createRootedStore(
	rootOrConfig: string | RootedStoreConfig,
	options?: RootedStoreOptions,
): RootedStore {
	if (typeof rootOrConfig === "string") return new RootedStore(rootOrConfig, options);
	return new RootedStore(rootOrConfig.root, rootOrConfig);
}
