import { createAgentSession } from "../../sdk/session";
import { createGjcLocalSolverSessionFactory, type GjcLocalSolverSessionOptions } from "./gjc-session";

export type ProductionGjcLocalSolverSessionOptions = Omit<GjcLocalSolverSessionOptions, "createSession">;

/** Creates clean-room local solver sessions backed by the production GJC AgentSession SDK. */
export function createProductionGjcLocalSolverSessionFactory(options: ProductionGjcLocalSolverSessionOptions = {}) {
	return createGjcLocalSolverSessionFactory({ ...options, createSession: createAgentSession });
}
