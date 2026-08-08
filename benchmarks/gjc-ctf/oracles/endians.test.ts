import { createHash, randomBytes } from "node:crypto";
import { describe, expect, test } from "bun:test";
import {
  ENDIANS_SOURCE_DIGEST,
  createEndiansFixture,
  verifyEndiansCandidate,
} from "./endians.js";

function digest(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function oracleFor(secret: string) {
  return { expectedCandidateDigest: digest(secret) };
}

describe("endians oracle", () => {
  test("round trips a fresh synthetic secret without exposing it in the fixture", () => {
    const secret = `synthetic-${randomBytes(18).toString("hex")}-✓`;
    const fixture = createEndiansFixture(secret);

    expect(fixture.encodedChallenge).not.toContain(secret);
    expect(JSON.stringify(fixture)).not.toContain(secret);
    expect(Object.keys(fixture)).toEqual(["encodedChallenge"]);
    expect(verifyEndiansCandidate(fixture.encodedChallenge, secret, oracleFor(secret))).toEqual({
      verdict: "pass",
      sourceDigest: ENDIANS_SOURCE_DIGEST,
      inputDigest: digest(fixture.encodedChallenge),
      candidateDigest: digest(secret),
    });
  });

  test("rejects a wrong candidate and a replay against a different fixture", () => {
    const first = "synthetic-first-123";
    const second = "synthetic-second-456";
    const firstFixture = createEndiansFixture(first);
    const secondFixture = createEndiansFixture(second);

    expect(verifyEndiansCandidate(firstFixture.encodedChallenge, "synthetic-first-124", oracleFor(first)).verdict).toBe("fail");
    expect(verifyEndiansCandidate(secondFixture.encodedChallenge, first, oracleFor(first)).verdict).toBe("fail");
    expect(verifyEndiansCandidate(secondFixture.encodedChallenge, first, oracleFor(first)).inputDigest).not.toBe(
      verifyEndiansCandidate(firstFixture.encodedChallenge, first, oracleFor(first)).inputDigest,
    );
  });

  test("rejects malformed UTF-16, non-canonical challenge data, and extra candidate data", () => {
    const secret = "synthetic-valid";
    const fixture = createEndiansFixture(secret);

    expect(verifyEndiansCandidate("\ud800", secret, oracleFor(secret)).reason).toBe("invalid challenge encoding");
    expect(verifyEndiansCandidate(fixture.encodedChallenge, `${secret}!`, oracleFor(secret)).verdict).toBe("fail");
    expect(() => createEndiansFixture("\ud800")).toThrow("UTF-16");
  });

  test("binds verification to the oracle-only digest input", () => {
    const secret = "synthetic-bound";
    const fixture = createEndiansFixture(secret);
    const result = verifyEndiansCandidate(fixture.encodedChallenge, secret, {
      expectedCandidateDigest: digest("different-synthetic-secret"),
    });

    expect(result.verdict).toBe("fail");
    expect(result.reason).toBe("candidate digest mismatch");
    expect(result.candidateDigest).toBe(digest(secret));
    expect(result.sourceDigest).toBe(ENDIANS_SOURCE_DIGEST);
  });
});
