import { describe, expect, test } from "bun:test";
import {
	type LocalBrowserFixtureAuthority,
	type LocalEvaluationAdapterProvider,
	openLocalEvaluationAdapter,
} from "../../src/ctf/solver/local-evaluation-adapter";
import { solverRouteFor } from "../../src/ctf/solver/router";

const route = solverRouteFor("lactf-2026-web-single-trust");
const binding = Object.freeze({
	competitionId: "lactf-2026",
	runId: "run-1",
	challengeId: route.challengeId,
	fencingToken: 1,
});

function forgedAuthority(): LocalBrowserFixtureAuthority {
	return {
		challengeId: "lactf-2026-web-single-trust",
		binding,
		origin: "http://127.0.0.1:43123",
		entryPath: "index.html",
		downloads: false,
		rawCdp: false,
		credentials: false,
		serviceWorkers: false,
		externalNetwork: false,
		filesystemDisclosure: false,
	} as unknown as LocalBrowserFixtureAuthority;
}

function provider(authority?: LocalBrowserFixtureAuthority): LocalEvaluationAdapterProvider {
	return {
		challengeId: route.challengeId,
		routeDigest: route.routeDigest,
		adapterKind: "browser-session",
		open: () => ({
			service: Promise.resolve({
				action: async () => undefined,
				close: async () => undefined,
				fixtureAuthority: authority,
			}),
			terminate: async () => undefined,
		}),
	};
}

describe("local browser fixture authority", () => {
	test("rejects a structural authority forgery and its attempted reuse", async () => {
		const authority = forgedAuthority();
		await expect(
			openLocalEvaluationAdapter(provider(authority), route, new AbortController().signal, binding),
		).rejects.toThrow("fixture authority is not trusted");
		await expect(
			openLocalEvaluationAdapter(provider(authority), route, new AbortController().signal, binding),
		).rejects.toThrow("fixture authority is not trusted");
	});

	test("preserves the default browser rejection without a trusted driver authority", async () => {
		await expect(
			openLocalEvaluationAdapter(provider(), route, new AbortController().signal, binding),
		).rejects.toThrow("browser sessions are disabled pending reviewed network enforcement");
	});

	test("cancellation tears down a pending browser acquisition", async () => {
		const controller = new AbortController();
		controller.abort(new Error("cancelled"));
		let terminated = false;
		const cancelledProvider: LocalEvaluationAdapterProvider = {
			challengeId: route.challengeId,
			routeDigest: route.routeDigest,
			adapterKind: "browser-session",
			open: () => ({
				service: new Promise(() => undefined),
				terminate: async () => {
					terminated = true;
				},
			}),
		};
		await expect(openLocalEvaluationAdapter(cancelledProvider, route, controller.signal, binding)).rejects.toThrow(
			"local evaluation adapter is cancelled",
		);
		expect(terminated).toBe(true);
	});
});
