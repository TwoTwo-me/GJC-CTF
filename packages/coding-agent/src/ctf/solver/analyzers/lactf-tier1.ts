import type { LocalSolverAnalyzer } from "../local-backend";
import { createEndiansAnalyzer } from "./endians";
import { createOooRecurrenceAnalyzer } from "./ooo-recurrence";
import { createRegexGridAnalyzer, type RegexGridZ3Options } from "./regex-grid";

export type LactfTier1AnalyzerOptions = Readonly<{
	regexGrid?: RegexGridZ3Options;
}>;

/** Returns the complete reviewed analyzer set for the pinned LA CTF Tier 1 visible-file policy. */
export function createLactfTier1Analyzers(options: LactfTier1AnalyzerOptions = {}): readonly LocalSolverAnalyzer[] {
	return Object.freeze([
		createEndiansAnalyzer({ visiblePath: "chall.txt" }),
		createOooRecurrenceAnalyzer({ visiblePath: "ooo.py" }),
		createRegexGridAnalyzer({ visiblePath: "src/script.js", ...options.regexGrid }),
	]);
}
