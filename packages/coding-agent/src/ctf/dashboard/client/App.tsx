/// <reference lib="dom" />
import {
	type CtfDashboardClientResponse,
	challengeGraphPath,
	getCtfDashboard,
	healthPath,
	runEventsPath,
	runMetricsPath,
	runPath,
} from "./api";

const tabs = ["overview", "graph", "runs", "evidence", "metrics"] as const;
type Tab = (typeof tabs)[number];

function text(value: unknown): string {
	return typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

function stateFromLocation(): { challengeId?: string; runId?: string } {
	const params = new URLSearchParams(window.location.search);
	return {
		challengeId: params.get("challenge") ?? undefined,
		runId: params.get("run") ?? undefined,
	};
}

function renderEnvelope(container: HTMLElement, response: CtfDashboardClientResponse, label: string): void {
	container.replaceChildren();
	const heading = document.createElement("h2");
	heading.textContent = label;
	container.append(heading);
	const status = document.createElement("p");
	status.className = `projection projection-${response.projectionStatus}`;
	status.textContent = `Projection: ${response.projectionStatus} · canonical ${response.canonicalRevision} · projection ${response.projectionRevision}`;
	container.append(status);
	if (response.error) {
		const error = document.createElement("pre");
		error.textContent = `${response.error.code}: ${response.error.message}`;
		container.append(error);
		return;
	}
	const payload = document.createElement("pre");
	payload.textContent = text(response.data ?? {});
	container.append(payload);
}

async function loadTab(container: HTMLElement, tab: Tab, challengeId?: string, runId?: string): Promise<void> {
	try {
		let response: CtfDashboardClientResponse;
		if (tab === "overview") response = await getCtfDashboard(healthPath());
		else if (tab === "graph") response = await getCtfDashboard(challengeGraphPath(challengeId ?? "unknown"));
		else if (tab === "runs") response = await getCtfDashboard(runPath(runId ?? "unknown"));
		else if (tab === "evidence") response = await getCtfDashboard(runEventsPath(runId ?? "unknown"));
		else response = await getCtfDashboard(runMetricsPath(runId ?? "unknown"));
		renderEnvelope(container, response, tab[0].toUpperCase() + tab.slice(1));
	} catch (error) {
		container.replaceChildren();
		const message = document.createElement("pre");
		message.textContent = error instanceof Error ? error.message : String(error);
		container.append(message);
	}
}

export function mountCtfDashboard(root: HTMLElement = document.getElementById("root") as HTMLElement): void {
	if (!root) return;
	const state = stateFromLocation();
	const nav = document.createElement("nav");
	const content = document.createElement("section");
	root.replaceChildren(nav, content);
	let active: Tab = "overview";
	const buttons = new Map<Tab, HTMLButtonElement>();
	for (const tab of tabs) {
		const button = document.createElement("button");
		button.type = "button";
		button.textContent = tab;
		button.addEventListener("click", () => {
			active = tab;
			for (const [name, candidate] of buttons)
				candidate.setAttribute("aria-current", name === active ? "page" : "false");
			void loadTab(content, active, state.challengeId, state.runId);
		});
		buttons.set(tab, button);
		nav.append(button);
	}
	const first = buttons.get(active);
	if (first) first.setAttribute("aria-current", "page");
	void loadTab(content, active, state.challengeId, state.runId);
	// Active-run polling is intentionally read-only and revision-aware at the API envelope.
	const poll = window.setInterval(() => {
		if (document.visibilityState === "hidden") return;
		void loadTab(content, active, state.challengeId, state.runId);
	}, 5000);
	window.addEventListener("beforeunload", () => window.clearInterval(poll), { once: true });
}

if (typeof document !== "undefined") mountCtfDashboard();
