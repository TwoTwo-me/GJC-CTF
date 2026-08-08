import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { CtfError } from "../../packages/coding-agent/src/ctf/contracts/errors";
import {
	LACTF_BENCHMARK_TIERS,
	LACTF_TIER_CONTROLLER_PATH,
	LactfTierController,
	createInitialLactfTierState,
	validateLactfTierState,
} from "./tier-controller";
import { authorizedVersionStatsRequest } from "./test-authority-fixture";

describe("LA CTF benchmark tier controller", () => {
	test("uses the immutable misc/reverse then crypto/pwn/web corpus tiers", () => {
		expect(LACTF_BENCHMARK_TIERS).toEqual([
		[
			"lactf-2026-misc-endians",
			"lactf-2026-rev-ooo",
			"lactf-2026-rev-flag-finder",
		],
		[
			"lactf-2026-crypto-not-so-lazy-trigrams",
			"lactf-2026-pwn-tic-tac-no",
			"lactf-2026-web-single-trust",
		],
	]);
	});

	test("does not advance for a missing report", async () => {
		const root = await mkdtemp(join(tmpdir(), "gjc-tier-controller-"));
		try {
			const controller = new LactfTierController(root);
			const state = await controller.submitReport(undefined);
			expect(state).toEqual(createInitialLactfTierState());
		} finally {
			await rm(root, { recursive: true, force: true });
		}
	});

	test("rejects digest corruption on restart", async () => {
		const root = await mkdtemp(join(tmpdir(), "gjc-tier-controller-"));
		try {
			const controller = new LactfTierController(root);
			const initial = createInitialLactfTierState();
			await mkdir(join(root, "benchmarks/gjc-ctf"), { recursive: true });
			await writeFile(join(root, LACTF_TIER_CONTROLLER_PATH), JSON.stringify(initial));
			const file = join(root, LACTF_TIER_CONTROLLER_PATH);
			const state = createInitialLactfTierState();
			await writeFile(file, JSON.stringify({ ...state, stateDigest: "0".repeat(64) }));
			await expect(controller.load()).rejects.toBeInstanceOf(CtfError);
		} finally {
			await rm(root, { recursive: true, force: true });
		}
	});

	test("serializes concurrent idempotent initialization", async () => {
		const root = await mkdtemp(join(tmpdir(), "gjc-tier-controller-"));
		try {
			const controller = new LactfTierController(root);
			const states = await Promise.all([controller.submitReport(undefined), controller.submitReport(undefined)]);
			expect(states[0]).toEqual(createInitialLactfTierState());
			expect(states[1]).toEqual(createInitialLactfTierState());
		} finally {
			await rm(root, { recursive: true, force: true });
		}
	});
	test("does not expose authority-bypassing state persistence", () => {
		const controller = new LactfTierController(".");
		expect("save" in controller).toBe(false);
	});
	test("rejects fabricated tier expansion state", () => {
		const state = createInitialLactfTierState();
		const forged = {
			...state,
			activeTier: 2,
			expansionHistory: [{ fromTier: 1, toTier: 2, reportDigest: state.stateDigest, iteration: 1 }],
		};
		expect(() => validateLactfTierState(forged)).toThrow(CtfError);
	});
	test("rejects a swapped tier authority set on restart", async () => {
		const root = await mkdtemp(join(tmpdir(), "gjc-tier-controller-"));
		try {
			const first = authorizedVersionStatsRequest();
			const second = authorizedVersionStatsRequest();
			const authority = (value: ReturnType<typeof authorizedVersionStatsRequest>) => ({
				manifest: value.manifest,
				lock: value.lock,
				calibration: value.calibration,
				oracle: value.oracle,
				oracleTrustAnchors: value.oracle.trustAnchors,
			});
			const controller = new LactfTierController(root, LACTF_TIER_CONTROLLER_PATH, {
				tier1: authority(first),
				tier2: authority(first),
			});
			const persisted = await controller.load();
			await mkdir(join(root, "benchmarks/gjc-ctf"), { recursive: true });
			await writeFile(join(root, LACTF_TIER_CONTROLLER_PATH), JSON.stringify(persisted));
			const swapped = new LactfTierController(root, LACTF_TIER_CONTROLLER_PATH, {
				tier1: authority(first),
				tier2: authority(second),
			});
			await expect(swapped.load()).rejects.toBeInstanceOf(CtfError);
		} finally {
			await rm(root, { recursive: true, force: true });
		}
	});

	test("rejects missing or self-rooted oracle trust anchors at construction", () => {
		const request = authorizedVersionStatsRequest();
		const base = {
			manifest: request.manifest,
			lock: request.lock,
			calibration: request.calibration,
			oracle: request.oracle,
		};
		expect(() => new LactfTierController(".", LACTF_TIER_CONTROLLER_PATH, {
			tier1: { ...base, oracleTrustAnchors: undefined },
			tier2: { ...base, oracleTrustAnchors: undefined },
		})).toThrow(CtfError);
		const fingerprint = request.oracle.trustAnchors.registrySignerFingerprint;
		expect(() => new LactfTierController(".", LACTF_TIER_CONTROLLER_PATH, {
			tier1: { ...base, oracleTrustAnchors: { registrySignerFingerprint: fingerprint, resultSignerFingerprint: fingerprint } },
			tier2: { ...base, oracleTrustAnchors: { registrySignerFingerprint: fingerprint, resultSignerFingerprint: fingerprint } },
		})).toThrow(CtfError);
	});

	test("rejects state that claims solves without a sealed report", () => {
		const state = createInitialLactfTierState();
		const forged = {
			...state,
			verifiedSolves: { ...state.verifiedSolves, "lactf-2026-misc-endians": true },
		};
		expect(() => validateLactfTierState(forged)).toThrow(CtfError);
	});
});
