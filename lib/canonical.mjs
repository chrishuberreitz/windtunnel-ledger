// canonical.mjs — the determinism spine shared by commit-call (writer) and
// verify.mjs (reader). Both sides MUST produce byte-identical input for the
// same call, or a digest a verifier recomputes will not match ours.
//
// Recipe (frozen — scheme "gitchain-ots-v1"):
//   1. Reduce a call to its irreducible pre-registration tuple (committed_fields).
//   2. Serialize with RFC 8785 JSON Canonicalization Scheme (JCS): keys sorted
//      lexicographically at every depth, no insignificant whitespace, standard
//      JSON string/number forms.
//   3. digest = SHA-256(JCS(committed_fields)), lowercase hex.
//
// For our field types (strings, integers, arrays of strings, one nested string
// array) JCS is exactly "sort keys recursively, JSON.stringify the leaves with
// no whitespace." We reject non-integer numbers so a float can never sneak in a
// platform-dependent serialization and silently break cross-language verify.

import { createHash } from "node:crypto";

/** RFC 8785 canonical JSON. Deterministic across languages for our value types. */
export function jcs(value) {
  return serialize(value);
}

function serialize(v) {
  if (v === null) return "null";
  const t = typeof v;
  if (t === "string") return JSON.stringify(v); // ES JSON escaping == JCS for strings
  if (t === "boolean") return v ? "true" : "false";
  if (t === "number") {
    if (!Number.isFinite(v)) throw new Error(`non-finite number in commitment: ${v}`);
    if (!Number.isInteger(v)) throw new Error(`non-integer number in commitment: ${v} (JCS float forms are not frozen for this scheme)`);
    return String(v);
  }
  if (Array.isArray(v)) return "[" + v.map(serialize).join(",") + "]";
  if (t === "object") {
    const keys = Object.keys(v).sort(); // lexicographic by UTF-16 code unit — matches JCS for ASCII keys
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + serialize(v[k])).join(",") + "}";
  }
  throw new Error(`uncommittable value of type ${t}`);
}

export function sha256Hex(input) {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/** Hash one provenance source the same way on both sides: sha256("url|date"). */
export function provenanceHash(source) {
  return sha256Hex(`${source.source_url}|${source.date}`);
}

/**
 * The irreducible tuple whose later mutation would be fraud. Everything else on
 * a LedgerEntry (votes, dynamics, denormalized series) is derived UI state and
 * is deliberately NOT committed.
 *
 * Scheme history:
 *   gitchain-ots-v1 — the field set below, without `attribution`.
 *   gitchain-ots-v2 — adds `attribution`: WHO made this call, sealed alongside
 *     WHAT was claimed and WHEN. Bitcoin proves the timestamp; nothing in v1
 *     bound authorship, so "an instrument produced this, and a named human is
 *     accountable for it" was prose on a page — editable after the fact like any
 *     other prose. In v2 it is inside the hash. v1 entries stay valid forever
 *     (verification hashes the stored tuple, so both schemes share one code
 *     path); the version records which fields were mandatory at commit time.
 */
export function buildCommittedFields({ id, category, claim, certainty, resolves_by, provenance, intent, committed_at, seq, prev, attribution, outcome, resolved_at }) {
  const fields = {
    id,
    category,
    claim,
    certainty,
    resolves_by,
    provenance: (provenance ?? []).map(provenanceHash),
    intent,
    committed_at,
    seq,
    prev: prev ?? null,
  };
  // v2+. Omitted entirely on v1 tuples so their digests remain reproducible.
  if (attribution !== undefined) fields.attribution = attribution;
  // Present only on the final resolve commit — otherwise omitted so their absence
  // is itself canonical (an open call has no outcome to bind).
  if (outcome !== undefined) fields.outcome = outcome;
  if (resolved_at !== undefined) fields.resolved_at = resolved_at;
  return fields;
}

/** committed_fields -> { digest, canonicalJson }. canonicalJson is what gets OTS-stamped. */
export function digestOf(committedFields) {
  const canonicalJson = jcs(committedFields);
  return { digest: sha256Hex(canonicalJson), canonicalJson };
}
