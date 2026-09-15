# WHP Standing v1

**Fresh executable build · 1.0.0-candidate.1 · live completion boundary still open**

WHP Standing produces a signed, bounded assessment of a submitted source/provenance graph. When that object satisfies the named profile, the result is a WHP Standing Mark. When it does not, the result is a signed assessment **without** a Standing Mark. Payment buys the assessment, never a favorable finding.

This is a new implementation, not a DIP repair branch or compatibility layer. The governing institutional sources remain distinct from the new implementation. The narrower candidate profile in this build is **Structured Provenance and Passage Integrity 1.0.0**. It does not claim to assess an external workflow's behavior or to replace WHP's existing Action-Boundary Profile.

## Executed result

`evidence/verification.json` records the actual latest run. The suite executes the Node implementation, a separate Python verifier, a real localhost HTTP purchase, strict validation, autonomous buyer policy checks, recovery faults, settlement evidence checks against mocked RPC, registry changes, and durable retrieval from a separate process.

`evidence/demonstration/TEST-standing-mark.json` is an actual signed **TEST artifact**. Its Ed25519 signatures and source/authority signatures are real. Its institutional identity, buyer wallet signer, EVM payment signature, and payment rail are **test fixtures**. No funds moved. No WHP institutional issuance, live payment, external deployment, or independent third-party audit is claimed.

The requested live boundary remains: a real pre-authorized buyer payment, a WHP-authorized profile/root/key, durable production storage, actual settlement/finality, one stored Mark, and independent verification plus retrieval. Code and a test proof do not substitute for that boundary.

## Run the implemented proof

Requires Node 22.16.0 or later with `node:sqlite`, Python 3.11 or later, and the verification packages. The recorded execution used the exact versions in `evidence/verification.json`.

```sh
python3 -m pip install -r requirements-verification.txt
npm run verify
```

The proof path needs no npm install, wallet, paid API, live chain, or external database. It creates temporary SQLite files and ephemeral test keys, removes them afterward, and writes public proof artifacts under `evidence/`. Test payment signatures are not wallet-generated ECDSA signatures.

Verify the included historical test artifact by taking the root pin and fixture timestamp from `evidence/demonstration/execution-record.json`:

```sh
python3 verify/verify_mark.py evidence/demonstration/TEST-standing-mark.json \
  --root-pin ROOT_PIN_FROM_EXECUTION_RECORD \
  --allow-test \
  --registry evidence/demonstration/TEST-registry-snapshot.json \
  --at 1789462090
```

Without `--allow-test`, the verifier rejects it as `TEST_ARTIFACT_NOT_LIVE`. The saved registry snapshot is historical; it is not a fresh present-time status response. The root pin included alongside a test result is an audit fixture, not an out-of-band institutional trust anchor.

## What is implemented

The signed Mark carries the exact object/version, complete submitted graph, admitted root-signed authorities, signed profile authorization, root-signed trust-state commitments, bounded evaluation, decision hash, x402 quote, payment authorization/identity, settlement evidence, issuer signature, expiry, and retrieval/registry references. The Python implementation independently verifies signatures and replays the defined transformation/authority rules without importing producer modules.

The evaluator permits only exact **COPY** and identity-preserving **COMPOSE** transformations. It preserves qualifiers and named unknowns, intersects operation permissions, checks graph closure and warrants, and denies unsupported promotion. “SOURCE,” “CONTEXT,” “RELATION,” “PASSAGE,” and “UNKNOWN” are assessed only within this profile. “CONTINUITY” and “ACTION_BOUNDARY” remain **NOT_ASSESSED**.

The transaction store binds a buyer/reference to one immutable submission and one payment identity. It persists preparation before settlement; verifies settled evidence instead of trusting a facilitator success flag; records ambiguous outcomes as pending; atomically commits the signed bytes with the initial registry event; and returns those exact bytes on subsequent authenticated reads.

The buyer agent discovers the contract, pins trust and payment destinations, commits a cumulative spending reservation before invoking its owner's signer, uses the mandatory quote-bound EIP-3009 nonce, journals the authorization before submitting it, and independently verifies the received result. Retries do not request another wallet signature. `scripts/buy.mjs` continues recovery until verified or its explicit waiting deadline; the same journal resumes an unfinished purchase.

## Production wiring included, not integration-tested

`src/runtime.mjs`, `src/server.mjs`, `netlify/functions/standing.mjs`, `netlify.toml`, and `scripts/migrate.mjs` are included. The runtime requires explicit LIVE authority, origin, key, payment terms, RPC, facilitator, and PostgreSQL configuration. It does not create a root, invent a buyer wallet, silently choose a price/recipient, or fall back to ephemeral storage.

The `pg` adapter and Netlify wrapper have passed syntax checking only. PostgreSQL integration, fresh dependency installation/auditing, Netlify bundling/runtime, real EIP-3009 signature interoperability, real settlement and real chain finality were not executed here. No deployment or GitHub write was performed.

Read `docs/RUNTIME.md` for the exact environment contract, `docs/WIRE-CONTRACT.md` for the signed model and protocol boundary, `docs/SECURITY-AND-RECOVERY.md` for trust/failure semantics, and `docs/EXACT-COMPLETION.md` for the fixed object and actual completion ledger.

## Source layout

`src/mark.mjs` defines issuance. `src/evaluator.mjs`, `src/validation.mjs`, and `src/authority.mjs` establish its bounded warrant. `src/store.mjs`, `src/payment.mjs`, and `src/service.mjs` implement the transaction. `src/buyer.mjs` and `src/buyer-journal.mjs` implement the other side. `verify/verify_mark.py` is the independent verifier. `schemas/`, `profiles/`, and `public/openapi.json` expose the contract. `test/` contains only generated test identities and simulated payment dependencies.

Private keys, database files, credentials, upstream manuscripts, and font files are not included in the release archive. See `docs/SOURCES.md` for the distinction between governing sources, historical interoperability context, and newly derived implementation choices.
