import { createLocalSolverAnalyzerLifecycle, type LocalSolverAnalyzer } from "../local-backend";

const MAX_SOURCE_BYTES = 4096;

export type EndiansAnalysis =
	| Readonly<{ ok: true; candidate: string; diagnostics: readonly string[] }>
	| Readonly<{
			ok: false;
			reason: "invalid-encoding" | "invalid-candidate" | "source-too-large";
			diagnostics: readonly string[];
	  }>;

function scalarString(value: string): boolean {
	for (let index = 0; index < value.length; index += 1) {
		const unit = value.charCodeAt(index);
		if (unit >= 0xd800 && unit <= 0xdbff) {
			const next = value.charCodeAt(index + 1);
			if (next < 0xdc00 || next > 0xdfff) return false;
			index += 1;
		} else if (unit >= 0xdc00 && unit <= 0xdfff) return false;
	}
	return true;
}

function swapCodeUnits(value: string): string {
	let output = "";
	for (let index = 0; index < value.length; index += 1) {
		const unit = value.charCodeAt(index);
		output += String.fromCharCode(((unit & 0xff) << 8) | (unit >>> 8));
	}
	return output;
}

/** Decodes only the reviewed UTF-16 code-unit byte-swap puzzle form. */
export function analyzeEndiansSource(source: Uint8Array): EndiansAnalysis {
	if (source.byteLength === 0 || source.byteLength > MAX_SOURCE_BYTES) {
		return {
			ok: false,
			reason: "source-too-large",
			diagnostics: ["encoded challenge exceeds the reviewed byte limit"],
		};
	}
	let encoded: string;
	try {
		encoded = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(source);
	} catch {
		return { ok: false, reason: "invalid-encoding", diagnostics: ["encoded challenge is not valid UTF-8"] };
	}
	if (!scalarString(encoded))
		return { ok: false, reason: "invalid-encoding", diagnostics: ["encoded challenge is not scalar Unicode"] };
	const candidate = swapCodeUnits(encoded);
	if (!scalarString(candidate) || !candidate.startsWith("lactf{") || !candidate.endsWith("}")) {
		return {
			ok: false,
			reason: "invalid-candidate",
			diagnostics: ["decoded value does not satisfy the visible flag framing"],
		};
	}
	if (swapCodeUnits(candidate) !== encoded) {
		return { ok: false, reason: "invalid-encoding", diagnostics: ["encoded challenge is not canonical"] };
	}
	return { ok: true, candidate, diagnostics: ["decoded reviewed UTF-16 code-unit byte swap"] };
}

export function createEndiansAnalyzer(options: Readonly<{ visiblePath: string }>): LocalSolverAnalyzer {
	return {
		id: "endians",
		analyze(input) {
			return createLocalSolverAnalyzerLifecycle(input, async ownedInput => {
				if (ownedInput.signal.aborted) return { status: "cancelled", reason: "run cancelled" };
				const visible = ownedInput.visibleFiles.find(file => file.path === options.visiblePath);
				if (visible === undefined) return { status: "not-applicable" };
				const analysis = analyzeEndiansSource(visible.content);
				if (!analysis.ok) return { status: "refused", reason: analysis.reason };
				return { status: "candidate", result: { candidate: analysis.candidate } };
			});
		},
	};
}
