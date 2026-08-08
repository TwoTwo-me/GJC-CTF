import { describe, expect, test } from "bun:test";
import { createLactfTier1Analyzers } from "../../src/ctf/solver/analyzers/lactf-tier1";
import { solverRouteFor, type SolverRoute } from "../../src/ctf/solver/router";

describe("LA CTF Tier 1 analyzer registry", () => {
	test("matches every reviewed active-tier route exactly", () => {
		const analyzers = createLactfTier1Analyzers();
		const analyzerIds = ["endians", "ooo-recurrence", "regex-grid-z3"] as const satisfies SolverRoute["analyzerIds"];
		expect(analyzers.map(analyzer => analyzer.id)).toEqual([...analyzerIds]);
		const routed = Object.freeze([
			...solverRouteFor("lactf-2026-misc-endians").analyzerIds,
			...solverRouteFor("lactf-2026-rev-ooo").analyzerIds,
			...solverRouteFor("lactf-2026-rev-flag-finder").analyzerIds,
		]);
		expect([...routed]).toEqual([...analyzerIds]);
	});
});
