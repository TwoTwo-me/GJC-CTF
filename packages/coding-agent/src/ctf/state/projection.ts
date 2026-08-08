import type { ProjectionStatus } from "../contracts/api";
import { canonicalDigest, type Digest, digestsEqual } from "../contracts/digest";
import { CtfError } from "../contracts/errors";
import { type EventV1, eventDigest, validateEvent } from "../contracts/event";
import { CanonicalEventLog, EMPTY_EVENT_DIGEST, type EventLogReadResult } from "./event-log";
import type { CtfStateStoreLike } from "./storage";

export interface ProjectionContext<S> {
	readonly state: S;
	readonly event: EventV1;
	readonly revision: number;
}

export type ProjectionReducer<S> = (context: ProjectionContext<S>) => S | Promise<S>;

export interface ProjectionMetadata {
	readonly canonicalRevision: number;
	readonly canonicalDigest: Digest;
	readonly projectionRevision: number;
	readonly projectionDigest: Digest;
	readonly projectionStatus: ProjectionStatus;
	readonly stateDigest: Digest;
}
/** Exact canonical/projection metadata suitable for a persisted graph checkpoint. */
export interface ProjectionCheckpoint extends ProjectionMetadata {}

export interface ProjectionSnapshot<S> extends ProjectionMetadata {
	readonly state?: S;
}

/**
 * Typed rebuildable projection boundary. It intentionally has no direct write
 * primitive: every state transition is derived from a validated canonical log.
 */
export class DerivedProjection<S> {
	readonly eventLog: CanonicalEventLog;
	readonly initialState: S;
	readonly reducer: ProjectionReducer<S>;
	private currentState: S;
	private appliedRevision = 0;
	private appliedDigest: Digest = EMPTY_EVENT_DIGEST;
	private status: ProjectionStatus = "rebuilding";
	private canonical: EventLogReadResult = {
		events: [],
		revision: 0,
		digest: EMPTY_EVENT_DIGEST,
		eventCount: 0,
		complete: true,
	};

	constructor(eventLog: CanonicalEventLog | CtfStateStoreLike, initialState: S, reducer: ProjectionReducer<S>) {
		this.eventLog = eventLog instanceof CanonicalEventLog ? eventLog : new CanonicalEventLog(eventLog);
		this.initialState = initialState;
		this.currentState = initialState;
		this.reducer = reducer;
	}

	private stateDigest(): Digest {
		return canonicalDigest(this.currentState);
	}

	private metadata(): ProjectionMetadata {
		return {
			canonicalRevision: this.canonical.revision,
			canonicalDigest: this.canonical.digest,
			projectionRevision: this.appliedRevision,
			projectionDigest: this.appliedDigest,
			projectionStatus: this.status,
			stateDigest: this.stateDigest(),
		};
	}
	private assertCanonicalPrefix(canonical: EventLogReadResult): void {
		if (canonical.revision < this.appliedRevision) {
			throw new CtfError("revision_conflict", "canonical revision moved backwards");
		}
		if (this.appliedRevision === 0) {
			if (!digestsEqual(this.appliedDigest, EMPTY_EVENT_DIGEST)) {
				throw new CtfError("integrity_error", "projection has a non-empty digest at revision zero");
			}
		} else {
			const prefixEvent = canonical.events[this.appliedRevision - 1];
			if (!prefixEvent || prefixEvent.revision !== this.appliedRevision) {
				throw new CtfError("revision_conflict", "canonical prefix does not contain the applied revision");
			}
			if (!digestsEqual(eventDigest(prefixEvent), this.appliedDigest)) {
				throw new CtfError("integrity_error", "canonical prefix digest does not match the projection");
			}
		}
		if (canonical.revision === this.appliedRevision && !digestsEqual(canonical.digest, this.appliedDigest)) {
			throw new CtfError("integrity_error", "canonical data was rewritten at the applied revision");
		}
	}

	private async applyEvent(event: EventV1): Promise<void> {
		const validated = validateEvent(event);
		if (validated.revision !== this.appliedRevision + 1 || validated.previousRevision !== this.appliedRevision) {
			throw new CtfError("revision_conflict", "projection cannot skip a canonical revision");
		}
		if (!digestsEqual(validated.previousEventDigest, this.appliedDigest)) {
			throw new CtfError("integrity_error", "canonical event predecessor digest does not match the projection");
		}
		this.currentState = await this.reducer({
			state: this.currentState,
			event: validated,
			revision: validated.revision,
		});
		this.appliedRevision = validated.revision;
		this.appliedDigest = eventDigest(validated);
	}

	/** Rebuild from the beginning, discarding all derived state. */
	async rebuild(): Promise<ProjectionSnapshot<S>> {
		this.status = "rebuilding";
		try {
			const canonical = await this.eventLog.read();
			this.currentState = this.initialState;
			this.appliedRevision = 0;
			this.appliedDigest = EMPTY_EVENT_DIGEST;
			for (const event of canonical.events) await this.applyEvent(event);
			this.canonical = canonical;
			this.status = "current";
			return { ...this.metadata(), state: this.currentState };
		} catch (error) {
			this.status = "integrity_error";
			this.canonical = await this.eventLog.read().catch(() => this.canonical);
			throw error;
		}
	}

	/** Apply only the next canonical suffix; gaps and stale revisions fail closed. */
	async refresh(): Promise<ProjectionSnapshot<S>> {
		if (this.status === "integrity_error") {
			throw new CtfError("integrity_error", "projection requires a rebuild after an integrity failure");
		}
		let canonical: EventLogReadResult;
		try {
			canonical = await this.eventLog.read();
			this.assertCanonicalPrefix(canonical);
		} catch (error) {
			this.status = "integrity_error";
			throw error;
		}
		try {
			for (const event of canonical.events.slice(this.appliedRevision)) await this.applyEvent(event);
			this.canonical = canonical;
			this.status = this.appliedRevision === canonical.revision ? "current" : "lagging";
			return { ...this.metadata(), state: this.currentState };
		} catch (error) {
			this.status = "integrity_error";
			throw error;
		}
	}

	/** Metadata is safe to expose even when a projection is not current. */
	metadataOnly(): ProjectionMetadata {
		return this.metadata();
	}
	/** Return exact canonical/projection metadata for a checkpoint writer. */
	checkpoint(): ProjectionCheckpoint {
		return this.metadata();
	}

	snapshot(): ProjectionSnapshot<S> {
		if (this.status === "integrity_error") return this.metadata();
		return { ...this.metadata(), state: this.currentState };
	}
}

export const ProjectionBoundary = DerivedProjection;
export const TypedProjection = DerivedProjection;
export const RebuildableProjection = DerivedProjection;
