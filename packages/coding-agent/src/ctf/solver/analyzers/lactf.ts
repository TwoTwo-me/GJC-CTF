import type { LocalSolverAnalyzer } from "../local-backend";
import { createNotSoLazyTrigramsAnalyzer, type NotSoLazyTrigramsOptions } from "./not-so-lazy-trigrams";
import { createLactfTier1Analyzers, type LactfTier1AnalyzerOptions } from "./lactf-tier1";

export type LactfAnalyzerOptions = Readonly<{
	tier1?: LactfTier1AnalyzerOptions;
	notSoLazyTrigrams?: NotSoLazyTrigramsOptions;
}>;

/** Complete reviewed LA CTF analyzer set, including candidate-only reviewed crypto analyzers. */
export function createLactfAnalyzers(options: LactfAnalyzerOptions = {}): readonly LocalSolverAnalyzer[] {
	const analyzers = [
		...createLactfTier1Analyzers(options.tier1),
		createNotSoLazyTrigramsAnalyzer(options.notSoLazyTrigrams),
	];
	if (new Set(analyzers.map(analyzer => analyzer.id)).size !== analyzers.length)
		throw new Error("LA CTF analyzer ids must be unique");
	return Object.freeze(analyzers);
}
