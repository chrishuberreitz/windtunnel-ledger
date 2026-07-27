# windtunnel-ledger

**The public, tamper-evident pre-registration ledger for the Windtunnel forecasting instrument.**

Every *live* Windtunnel call — its claim, its conviction, and the moment it was made — is committed here **before its outcome is knowable**, and anchored to Bitcoin's clock. This repo exists so you never have to take our word for a track record. You can reproduce the whole thing yourself, trusting only Bitcoin and your own eyes.

> A backtest can be written after the fact. A call anchored to a Bitcoin block cannot. That difference is the entire point of this repo.

---

## What's here

- **`calls.log.jsonl`** — the source of truth. One append-only, hash-chained line per commitment event (`resolve` = a call made, `revise` = a re-score, final `resolve` = an outcome recorded). Never rewritten.
- **`proofs/`** — for each entry, the exact canonical bytes that were hashed (`*.jcs.json`) and its OpenTimestamps proof (`*.ots`) anchoring that hash to a Bitcoin block.
- **`verify.mjs`** — the zero-trust verifier. Recomputes every digest, walks the whole hash chain, and checks every Bitcoin anchor. Trusts nothing you can't check.
- **`lib/canonical.mjs`** — the frozen canonicalization + hashing recipe (RFC 8785 JCS → SHA-256), byte-identical to the writer's copy.

## The frozen recipe (`scheme: gitchain-ots-v1`)

1. Reduce a call to its irreducible tuple: `{ id, category, claim, certainty, resolves_by, provenance[], intent, committed_at, seq, prev }`.
2. Canonicalize with **RFC 8785 (JCS)** — sorted keys, no insignificant whitespace.
3. `digest = SHA-256(JCS(tuple))`, lowercase hex.
4. Append the line, chained by `prev` = the previous entry's digest, `seq` = its position.
5. **OpenTimestamps** the canonical blob → Bitcoin anchor (upgrades within hours).

## Verify it yourself

```bash
git clone https://github.com/chrishuberreitz/windtunnel-ledger
cd windtunnel-ledger
pip install opentimestamps-client   # provides the `ots` CLI (optional but recommended)
node verify.mjs
```

You'll see, for every call: the digest recomputing, the chain link intact, the stamped blob matching, and — where Bitcoin has confirmed — the block height and time the call was anchored at. The footer prints `N committed · M resolved · K revealed`.

### Check one call by hand

```bash
# 1. the digest is a pure function of the committed bytes:
shasum -a 256 proofs/0002-led-live-001-resolve.jcs.json
#    → must equal the entry's `digest` in calls.log.jsonl

# 2. the clock — read the Bitcoin block this call is stamped into:
ots info proofs/0002-led-live-001-resolve.jcs.json.ots
#    → look for BitcoinBlockHeaderAttestation(959722).
#      Then look that block up in ANY block explorer, or on anyone's node,
#      and read the minute it was mined. The time comes from a source
#      that isn't us. That's the whole ballgame.

# 2b. the fully trustless version — checks the attestation AGAINST the chain
#     instead of reading it out of the proof. Needs a local Bitcoin node
#     (it verifies the block's merkle root), which is why 2 is the one
#     most people should start with:
ots verify proofs/0002-led-live-001-resolve.jcs.json.ots
```

## What this proves — and what it doesn't

It proves each call was **made when it says it was**, at the stated conviction, and that no call was silently deleted, reordered, or edited after the fact. It does **not** prove the calls are *good* — that's what the accruing live record measures over time. This layer earns the instrument the right to be scored; it doesn't do the scoring.

The engine is ours. The clock is nobody's.

---

*Part of [Attainable AI](https://attainable.ai)'s provenance substrate. Same spine underwrites the CA-Index and pre-registered audit deliverables.*
