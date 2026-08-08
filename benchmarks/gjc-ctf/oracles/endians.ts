import { createHash, timingSafeEqual } from "node:crypto";

export type EndiansPublicFixture = Readonly<{
  encodedChallenge: string;
}>;

export type EndiansOracleInput = Readonly<{
  expectedCandidateDigest: string;
}>;

export type EndiansVerification = Readonly<{
  verdict: "pass" | "fail" | "unavailable";
  sourceDigest: string;
  inputDigest: string;
  candidateDigest: string;
  reason?: string;
}>;

const encoder = new TextEncoder();
const MAX_SECRET_UTF8_BYTES = 4096;
const SOURCE_CONTRACT = "gjc-ctf/endians/encoder-v1:utf16le-code-units-as-utf16be";
const INVALID_CANDIDATE = "gjc-ctf/endians/invalid-candidate-v1";
const INVALID_CHALLENGE = "gjc-ctf/endians/invalid-challenge-v1";

export const ENDIANS_SOURCE_DIGEST = sha256(SOURCE_CONTRACT);

/** Encodes UTF-16LE code units as UTF-16BE code units, matching the public puzzle form. */
export function createEndiansFixture(secret: string): EndiansPublicFixture {
  assertSecret(secret);

  let encoded = "";
  for (let index = 0; index < secret.length; index += 1) {
    const unit = secret.charCodeAt(index);
    encoded += String.fromCharCode(((unit & 0xff) << 8) | (unit >>> 8));
  }

  assertScalarString(encoded, "encoded challenge");
  return { encodedChallenge: encoded };
}

/**
 * Verifies a submitted decoding against an oracle-private SHA-256 digest.
 * Neither the expected secret nor its digest is included in the public fixture.
 */
export function verifyEndiansCandidate(
  encodedChallenge: string,
  candidate: string,
  oracleInput: EndiansOracleInput,
): EndiansVerification {
  const expectedDigest = oracleInput?.expectedCandidateDigest;
  const inputDigest = isStrictSecret(encodedChallenge) ? sha256(encodedChallenge) : sha256(INVALID_CHALLENGE);
  const candidateDigest = isStrictSecret(candidate) ? sha256(candidate) : sha256(INVALID_CANDIDATE);

  if (!isSha256(expectedDigest)) {
    return result("unavailable", inputDigest, candidateDigest, "invalid oracle input");
  }
  if (!isStrictSecret(candidate)) {
    return result("fail", inputDigest, candidateDigest, "invalid candidate");
  }

  let decoded: string;
  try {
    decoded = decodeChallenge(encodedChallenge);
  } catch {
    return result("fail", inputDigest, candidateDigest, "invalid challenge encoding");
  }

  if (candidate.length !== decoded.length || candidate !== decoded) {
    return result("fail", inputDigest, candidateDigest, "candidate does not decode challenge");
  }
  if (!sameDigest(candidateDigest, expectedDigest)) {
    return result("fail", inputDigest, candidateDigest, "candidate digest mismatch");
  }

  return result("pass", inputDigest, candidateDigest);
}

function decodeChallenge(encodedChallenge: string): string {
  assertScalarString(encodedChallenge, "encoded challenge");
  if (encodedChallenge.length === 0 || encodedChallenge.length > MAX_SECRET_UTF8_BYTES) {
    throw new Error("invalid encoded challenge length");
  }

  let decoded = "";
  for (let index = 0; index < encodedChallenge.length; index += 1) {
    const unit = encodedChallenge.charCodeAt(index);
    decoded += String.fromCharCode(((unit & 0xff) << 8) | (unit >>> 8));
  }
  assertSecret(decoded);
  if (createEndiansFixture(decoded).encodedChallenge !== encodedChallenge) {
    throw new Error("non-canonical encoded challenge");
  }
  return decoded;
}

function assertSecret(value: string): void {
  assertScalarString(value, "secret");
  const bytes = encoder.encode(value);
  if (bytes.length === 0 || bytes.length > MAX_SECRET_UTF8_BYTES) {
    throw new Error("invalid secret length");
  }
  if (new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes) !== value) {
    throw new Error("invalid UTF-8 secret");
  }
}

function isStrictSecret(value: unknown): value is string {
  try {
    if (typeof value !== "string") return false;
    assertSecret(value);
    return true;
  } catch {
    return false;
  }
}

function assertScalarString(value: string, label: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      if (index + 1 >= value.length || value.charCodeAt(index + 1) < 0xdc00 || value.charCodeAt(index + 1) > 0xdfff) {
        throw new Error(`invalid ${label} UTF-16`);
      }
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new Error(`invalid ${label} UTF-16`);
    }
  }
}

function result(
  verdict: EndiansVerification["verdict"],
  inputDigest: string,
  candidateDigest: string,
  reason?: string,
): EndiansVerification {
  return reason === undefined
    ? { verdict, sourceDigest: ENDIANS_SOURCE_DIGEST, inputDigest, candidateDigest }
    : { verdict, sourceDigest: ENDIANS_SOURCE_DIGEST, inputDigest, candidateDigest, reason };
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function sameDigest(left: string, right: string): boolean {
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function isSha256(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}
