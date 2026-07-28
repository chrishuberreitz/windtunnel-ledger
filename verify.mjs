#!/usr/bin/env node
// verify.mjs — the zero-trust step 4. Clone this repo, run `node verify.mjs`,
// and reproduce the entire track record trusting only Bitcoin and your own eyes.
//
// It re-does, for EVERY call, offline:
//   1. recompute digest = SHA-256(JCS(committed_fields)) and match the logged digest
//   2. walk the hash chain: seq is unbroken (+1), prev == previous line's digest
//   3. confirm each OTS-stamped file's bytes are exactly the canonical blob we hashed
//   4. (if `ots` is installed) verify each .ots against Bitcoin and print the block time
//   5. print the sealed rationale — WHY the seal was made — for v3+ entries
//
// Then prints:  N committed · M resolved · K revealed  — the public arithmetic
// that makes cherry-picking a legible tell.
//
// Trusts: Bitcoin's clock, this code, your own recompute. Not Chris, not GitHub,
// not the OpenTimestamps servers.

import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { digestOf } from "./lib/canonical.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const LOG = join(here, "calls.log.jsonl");

const GREEN = "\x1b[32m", RED = "\x1b[31m", DIM = "\x1b[2m", YEL = "\x1b[33m", RST = "\x1b[0m";
const ok = (m) => console.log(`  ${GREEN}✓${RST} ${m}`);
const bad = (m) => console.log(`  ${RED}✗ ${m}${RST}`);
const note = (m) => console.log(`  ${DIM}${m}${RST}`);

function otsAvailable() {
  try { execFileSync("ots", ["--version"], { stdio: "ignore" }); return true; } catch { return false; }
}

/** Read the block heights the proof claims, without needing a Bitcoin node.
 *  This proves the proof CONTAINS a Bitcoin attestation; it does not check that
 *  attestation against the chain. Weaker than otsVerify — always labelled so. */
function otsInfo(otsPath) {
  try {
    const out = execFileSync("ots", ["info", otsPath], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    const blocks = [...out.matchAll(/BitcoinBlockHeaderAttestation\((\d+)\)/g)].map((m) => Number(m[1]));
    if (blocks.length) return { attested: true, blocks: [...new Set(blocks)].sort((a, b) => a - b) };
    return { attested: false, pending: /PendingAttestation/.test(out) };
  } catch {
    return { attested: false };
  }
}

function otsVerify(otsPath) {
  // `ots verify` reads <file>.ots and re-hashes <file>; both must be present.
  // Full verification needs a Bitcoin node — it checks the attested block's
  // merkle root against the chain. Without one, fall back to reading the
  // attestation out of the proof and say plainly that that is what happened.
  try {
    const out = execFileSync("ots", ["verify", otsPath], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    const m = out.match(/Bitcoin block (\d+) attests existence as of (.+)/);
    if (m) return { anchored: true, block: Number(m[1]), time: m[2].trim() };
    return { anchored: false, pending: /pending|incomplete/i.test(out) };
  } catch (e) {
    const txt = String(e.stdout || "") + String(e.stderr || "");
    if (/Could not connect to Bitcoin node|rpcpassword/i.test(txt)) {
      const info = otsInfo(otsPath);
      if (info.attested) return { attestedOnly: true, blocks: info.blocks };
      return { anchored: false, noNode: true };
    }
    if (/pending|incomplete/i.test(txt)) return { anchored: false, pending: true };
    return { anchored: false, error: txt.split("\n")[0] || e.message };
  }
}

function main() {
  if (!existsSync(LOG)) { bad(`no calls.log.jsonl at ${LOG}`); process.exit(1); }
  const lines = readFileSync(LOG, "utf8").split("\n").filter((l) => l.trim());
  const hasOts = otsAvailable();
  let failures = 0;
  let prevDigest = null;
  const resolvedIds = new Set();
  let revealed = 0;

  console.log(`\nWindtunnel ledger — verifying ${lines.length} committed event(s)\n`);

  lines.forEach((line, i) => {
    let rec;
    try { rec = JSON.parse(line); } catch { bad(`line ${i + 1}: not valid JSON`); failures++; return; }
    const cf = rec.committed_fields;
    const tag = `seq ${cf?.seq ?? "?"} · ${cf?.id ?? "?"} · ${cf?.intent ?? "?"}`;
    console.log(tag);

    // 1 — recompute the fingerprint
    const { digest, canonicalJson } = digestOf(cf);
    if (digest === rec.digest) ok(`digest recomputes (${digest.slice(0, 16)}…)`);
    else { bad(`digest MISMATCH: logged ${rec.digest?.slice(0, 16)}… recomputed ${digest.slice(0, 16)}…`); failures++; }

    // 2 — chain integrity
    if (cf.seq !== i + 1) { bad(`seq broken: expected ${i + 1}, got ${cf.seq}`); failures++; }
    if ((cf.prev ?? null) !== prevDigest) { bad(`chain broken: prev != previous digest`); failures++; }
    else ok(cf.prev ? `chain link intact (prev ${String(cf.prev).slice(0, 12)}…)` : "genesis (prev: null)");
    prevDigest = digest;

    // 3 — the OTS-stamped file is exactly what we hashed
    const jcsPath = rec.anchors?.ots?.jcs_path && join(here, rec.anchors.ots.jcs_path);
    if (jcsPath && existsSync(jcsPath)) {
      const stamped = readFileSync(jcsPath, "utf8");
      if (stamped === canonicalJson) ok("stamped blob == canonical committed_fields");
      else { bad("stamped file differs from canonical form — anchor binds the wrong bytes"); failures++; }
    } else note("no local JCS blob to cross-check (proof file absent)");

    // 4 — the clock, trustlessly
    const otsPath = rec.anchors?.ots?.proof_path && join(here, rec.anchors.ots.proof_path);
    if (otsPath && existsSync(otsPath) && hasOts) {
      const r = otsVerify(otsPath);
      if (r.anchored) {
        ok(`${GREEN}Bitcoin-anchored${RST} — block ${r.block} · ${r.time}`);
        if (cf.resolves_by && r.time) {
          const anchorDay = new Date(r.time).toISOString().slice(0, 10);
          if (anchorDay <= cf.resolves_by) ok(`anchor precedes resolves_by (${anchorDay} ≤ ${cf.resolves_by})`);
          else { bad(`anchor is AFTER resolves_by — not a valid pre-registration`); failures++; }
        }
      } else if (r.attestedOnly) {
        ok(`${GREEN}Bitcoin attestation present${RST} — block ${r.blocks.join(", ")}`);
        note(`  no local Bitcoin node, so this read the attestation OUT of the proof rather than checking it AGAINST the chain.`);
        note(`  for the full trustless check, run a Bitcoin node and re-run — or look up the block yourself.`);
      } else if (r.noNode) note(`${YEL}no Bitcoin node and no attestation in the proof${RST}`);
      else if (r.pending) note(`${YEL}⏳ pending${RST} — submitted to calendars, Bitcoin confirmation not yet upgraded (run \`ots upgrade\`)`);
      else note(`ots: ${r.error ?? "not anchored"}`);
    } else if (otsPath && !hasOts) {
      note("ots CLI not installed — skipping Bitcoin check (install: pip install opentimestamps-client)");
    } else note("no .ots proof on this entry");

    // 5 — the reasoning, as sealed (scheme v3+). Printed here rather than left
    // to the website, because a reader who cloned this repo to avoid trusting
    // us should not have to visit us to find out why a number moved.
    if (typeof cf.rationale === "string" && cf.rationale) {
      ok(`rationale sealed: ${DIM}${cf.rationale}${RST}`);
      if (Array.isArray(cf.evidence) && cf.evidence.length) {
        note(`  bound to ${cf.evidence.length} evidence source hash(es); the sources themselves are published on the verify page`);
      }
    } else if (cf.intent === "revise" || cf.outcome !== undefined) {
      // A pre-v3 seal that moved a number. Say so plainly — the gap belongs in
      // the record, not papered over by silence.
      note(`${YEL}no sealed rationale${RST} — sealed under a scheme that predates v3; this proves the number moved, not why`);
    }

    // accounting
    if (cf.intent === "resolve" && cf.outcome !== undefined) resolvedIds.add(cf.id);
    if (typeof cf.claim === "string" && cf.claim.length > 0) revealed++;
    console.log("");
  });

  const committed = lines.length;
  console.log("─".repeat(52));
  console.log(`${committed} committed · ${resolvedIds.size} resolved · ${revealed} revealed`);
  if (failures === 0) console.log(`${GREEN}PASS${RST} — chain intact, every digest reproduces.\n`);
  else { console.log(`${RED}FAIL${RST} — ${failures} problem(s) above.\n`); process.exit(1); }
}

main();
