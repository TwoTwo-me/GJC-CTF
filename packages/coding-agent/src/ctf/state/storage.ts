import {
	createRootedStore,
	type RootedStore,
	type RootedStoreOperationOptions,
	type RootedStoreOptions,
} from "../../gjc-runtime/storage/rooted-store";

/**
 * The only storage capability used by CTF state authorities. Keeping this
 * interface local lets the integration layer supply a CTF-root adapter without
 * letting workers reach the underlying workflow state writer directly.
 */
export interface CtfStateStore {
	readonly root: string;
	resolve(targetPath: string): string;
	writeJsonAtomic<T>(targetPath: string, value: T, options?: RootedStoreOperationOptions): Promise<string>;
	appendJsonl<T>(targetPath: string, entry: T, options?: RootedStoreOperationOptions): Promise<string>;
	withLock<T>(targetPath: string, fn: () => Promise<T>, options?: RootedStoreOperationOptions): Promise<T>;
}

export type CtfStateStoreLike = CtfStateStore | RootedStore | string;

/**
 * Adapt a configured rooted store. The current rooted-store implementation
 * remains the enforcement point; callers using a `.gjc-ctf` root must provide
 * the separately-authorized adapter rather than bypassing this capability.
 */
export function createCtfStateStore(value: CtfStateStoreLike, options?: RootedStoreOptions): CtfStateStore {
	return typeof value === "string" ? createRootedStore(value, options) : value;
}
