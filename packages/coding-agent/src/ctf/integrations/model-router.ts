import type { ThinkingLevel } from "@gajae-code/agent-core";
import type { Api, Model } from "@gajae-code/ai";
import { validateModelProfileName } from "../../config/model-profile-contract";
import {
	type ModelProfileDefinition,
	type ModelProfileRole,
	mergeModelProfiles,
	resolveProfileBindings,
} from "../../config/model-profiles";
import type { ModelRegistry } from "../../config/model-registry";
import { formatModelSelectorValue, resolveModelChainWithAuth } from "../../config/model-resolver";
import { type ModelSelectorValue, normalizeModelSelectorValue } from "../../config/model-selector-value";
import type { ModelsConfig } from "../../config/models-config-schema";
import type { Settings } from "../../config/settings";
import { CtfError, sha256Hex } from "../contracts";

export type CtfModelRole = Extract<ModelProfileRole, "default" | "executor" | "architect" | "planner" | "critic">;

export type CtfModelCost =
	| { status: "known"; cents: number; source: string }
	| { status: "unknown"; reason: string; source: string };

export interface CtfModelTelemetry {
	kind: "model-activation";
	profile: string;
	role: CtfModelRole;
	requestedSelectorCount: number;
	requestedSelectorFingerprints: readonly string[];
	effectiveSelector: string;
	fallback: {
		used: boolean;
		activeIndex: number;
		skippedCount: number;
	};
	escalation: "none" | "role-default" | "fallback-chain";
	cost: CtfModelCost;
	unknownCost: boolean;
	telemetryDigest: string;
}

export interface CtfModelActivation {
	profile: string;
	role: CtfModelRole;
	model: Model<Api>;
	thinkingLevel?: string;
	effectiveSelector: string;
	telemetry: CtfModelTelemetry;
}

export interface CtfModelRouterOptions {
	modelRegistry: Pick<ModelRegistry, "getAvailable" | "getApiKey">;
	settings?: Settings;
	profiles?: ModelsConfig["profiles"];
	sessionId?: string;
	cost?: (model: Model<Api>) => CtfModelCost | Promise<CtfModelCost>;
	recordTelemetry?: (telemetry: CtfModelTelemetry) => void | Promise<void>;
}

export interface CtfModelRouteRequest {
	profile: string;
	role?: CtfModelRole;
}

function safeProfileName(value: string): string {
	const normalized = value.trim();
	if (!normalized) throw new CtfError("invalid_api_request", "model profile is required");
	return normalized;
}

function roleSelector(
	definition: ModelProfileDefinition,
	role: CtfModelRole,
): { value: ModelSelectorValue | undefined; escalated: boolean } {
	const bindings = resolveProfileBindings(definition);
	if (role === "default") return { value: bindings.defaultSelector, escalated: false };
	const override = bindings.agentModelOverrides[role];
	if (override !== undefined) return { value: override, escalated: false };
	return { value: bindings.defaultSelector, escalated: true };
}

function selectorFingerprint(selector: string): string {
	return `sha256:${sha256Hex(selector)}`;
}

function effectiveSelector(model: Model<Api>, thinkingLevel: ThinkingLevel | undefined): string {
	const provider = typeof model.provider === "string" ? model.provider.trim() : "";
	const id = typeof model.id === "string" ? model.id.trim() : "";
	if (!provider || !id)
		throw new CtfError("unsupported_operation", "effective model activation has no provider or model id");
	return formatModelSelectorValue(`${provider}/${id}`, thinkingLevel);
}

function unknownCost(reason = "cost_not_available"): CtfModelCost {
	return { status: "unknown", reason, source: "ctf-model-router" };
}

function validateCost(value: CtfModelCost): CtfModelCost {
	if (
		!value ||
		typeof value !== "object" ||
		(value.status !== "known" && value.status !== "unknown") ||
		typeof value.source !== "string" ||
		!value.source.trim()
	) {
		return unknownCost("invalid_cost_provider_result");
	}
	if (value.status === "known") {
		if (!Number.isFinite(value.cents) || value.cents < 0) return unknownCost("invalid_cost_provider_result");
		return { status: "known", cents: value.cents, source: `sha256:${sha256Hex(value.source)}` };
	}
	if (typeof value.reason !== "string" || !value.reason.trim()) return unknownCost("invalid_cost_provider_result");
	return { status: "unknown", reason: "cost_unknown", source: `sha256:${sha256Hex(value.source)}` };
}

function activationError(message: string): never {
	throw new CtfError("unsupported_operation", message);
}

/**
 * Resolve CTF model requests through GJC's merged profile and auth-aware
 * resolver. This boundary exposes no API keys and never converts unknown cost
 * into a zero value.
 */
export function createCtfModelRouter(options: CtfModelRouterOptions) {
	const profiles = mergeModelProfiles(options.profiles);
	const route = async (request: CtfModelRouteRequest): Promise<CtfModelActivation> => {
		const requestedProfile = safeProfileName(request.profile);
		const role = request.role ?? "default";
		let profile: string;
		let definition: ModelProfileDefinition | undefined;
		try {
			profile = validateModelProfileName(requestedProfile, profiles);
			definition = profiles.get(profile);
		} catch {
			throw new CtfError("unsupported_operation", "requested CTF model profile is unavailable");
		}
		if (!definition) activationError("requested CTF model profile is unavailable");
		const selection = roleSelector(definition, role);
		const selectors = normalizeModelSelectorValue(selection.value);
		if (selectors.length === 0) activationError("CTF model activation has no effective selector");
		let resolution: Awaited<ReturnType<typeof resolveModelChainWithAuth>>;
		try {
			resolution = await resolveModelChainWithAuth(
				selectors,
				options.modelRegistry,
				options.settings,
				options.sessionId,
				{ managedFallback: selectors.length > 1 },
			);
		} catch {
			throw new CtfError("unsupported_operation", "CTF model resolution was rejected");
		}
		if (!resolution.model) activationError("CTF model activation failed to resolve an authenticated model");
		const model = resolution.model;
		const selector = effectiveSelector(model, resolution.thinkingLevel);
		let cost = unknownCost();
		if (options.cost) {
			try {
				cost = validateCost(await options.cost(model));
			} catch {
				cost = unknownCost("cost_provider_error");
			}
		}
		const telemetryBase = {
			kind: "model-activation" as const,
			profile,
			role,
			requestedSelectorCount: selectors.length,
			requestedSelectorFingerprints: selectors.map(selectorFingerprint),
			effectiveSelector: selector,
			fallback: {
				used: resolution.activeIndex > 0,
				activeIndex: resolution.activeIndex,
				skippedCount: resolution.skips.length,
			},
			escalation:
				resolution.activeIndex > 0
					? ("fallback-chain" as const)
					: selection.escalated
						? ("role-default" as const)
						: ("none" as const),
			cost,
			unknownCost: cost.status === "unknown",
		};
		const telemetry: CtfModelTelemetry = {
			...telemetryBase,
			telemetryDigest: `sha256:${sha256Hex(JSON.stringify(telemetryBase))}`,
		};
		if (options.recordTelemetry) await options.recordTelemetry(telemetry);
		return {
			profile,
			role,
			model,
			thinkingLevel: resolution.thinkingLevel,
			effectiveSelector: selector,
			telemetry,
		};
	};
	return { route };
}

export type CtfModelRouter = ReturnType<typeof createCtfModelRouter>;
export const createCtfModelActivationRouter = createCtfModelRouter;
