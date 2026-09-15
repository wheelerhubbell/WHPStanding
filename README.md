# WHP Standing v1

**Fresh executable build · 1.0.0-candidate.1 · live completion boundary still open**

WHP Standing produces a signed, bounded assessment of a submitted source/provenance graph. When that object satisfies the named profile, the result is a WHP Standing Mark. When it does not, the result is a signed assessment **without** a Standing Mark. Payment buys the assessment, never a favorable finding.

This is a new implementation, not a DIP repair branch or compatibility layer. The governing institutional sources remain distinct from the new implementation. The narrower candidate profile in this build is **Structured Provenance and Passage Integrity 1.0.0**. It does not claim to assess an external workflow's behavior or to replace WHP's existing Action-Boundary Profile.

## Recovered candidate and extension evidence

The exact originally uploaded candidate was recovered without changing any candidate byte at commit `ec3d1b8710c7a55529e4c450a806a8fea5dc7fee`. The original archive and its evidence remain preserved. `evidence/recovery/candidate-identity.json` records every source hash; recovery Actions run 34960508166 actually passed the original 83 tests and promoted the source. The earlier run 34958976070 failed after successful verification, not because tests failed.

This source adds signed discovery carriers, canonical contracts and profiles, content-addressed independent verification, a no-prior-WHP-configuration cold-process test, real MCP transport, standard API-catalog metadata, and facilitator discovery forwarding. Current extension executions write separate records to `evidence/propagation-extension/`, `evidence/cold-agent/` and `evidence/postgresql/`. Do not treat historical candidate counts as extension test results.

## Execute verification

```sh
python3 -m pip install -r requirements-verification.txt
bash scripts/build-cold-sandbox.sh
npm run verify
```

The full suite requires Docker for the independent verifier sandbox and fails rather than silently skipping it. The generic image contains only Python and crypto/schema libraries, not WHP source, fixtures or URLs. The test subprocess receives one completed TEST Mark and resolves all WHP-specific knowledge through it. No real wallet is present and no money moves. PostgreSQL integration runs separately with an explicit localhost-only TEST database URL and has no production fallback.

For an archived candidate Mark, use the verifier from the archived candidate, preserving its historical root and timestamp. The new verifier requires the new signed carrier. A downloaded new verifier is bound by its SHA256 content address. The code and archived artifact do not become LIVE merely because their cryptographic signatures verify.

## Production and discovery boundary

`docs/DISCOVERY-FIELD.md` records the researched current standards and directory requirements. Serving a contract or MCP declaration is not a registration. The real publisher script refuses to publish until it verifies the deployed HTTPS origin, explicitly admitted LIVE root and functioning MCP transport, and requires external catalog read-back to record REGISTERED.

The runtime remains fail-closed until actual LIVE WHP root/profile authority, separate issuer signing key, designated Base USDC recipient, durable PostgreSQL database, canonical HTTPS origin, facilitator and trusted RPC are configured. No fixture fallback, self-sale or institutional issuance is manufactured. The production authorization inspection is preserved in Actions run 34961217519; the checked repository deployment and signing configuration was absent. No deployment or first outside sale follows from recovered source or TEST execution.

## What is implemented

The signed Mark carries the exact object/version, complete submitted graph, admitted root-signed authorities, signed profile authorization, root-signed trust-state commitments, bounded evaluation, decision hash, x402 quote, payment authorization/identity, settlement evidence, issuer signature, expiry, and retrieval/registry references. The Python implementation independently verifies signatures and replays the defined transformation/authority rules without importing producer modules.

The evaluator permits only exact **COPY** and identity-preserving **COMPOSE** transformations. It preserves qualifiers and named unknowns, intersects operation permissions, checks graph closure and warrants, and denies unsupported promotion. “SOURCE,” “CONTEXT,” “RELATION,” “PASSAGE,” and “UNKNOWN” are assessed only within this profile. “CONTINUITY” and “ACTION_BOUNDARY” remain **NOT_ASSESSED**.

The transaction store binds a buyer/reference to one immutable submission and one payment identity. It persists preparation before settlement; verifies settled evidence instead of trusting a facilitator success flag; records ambiguous outcomes as pending; atomically commits the signed bytes with the initial registry event; and returns those exact bytes on subsequent authenticated reads.

The buyer agent discovers the contract, pins trust and payment destinations, commits a cumulative spending reservation before invoking its owner's signer, uses the mandatory quote-bound EIP-3009 nonce, journals the authorization before submitting it, and independently verifies the received result. Retries do not request another wallet signature. `scripts/buy.mjs` continues recovery until verified or its explicit waiting deadline; the same journal resumes an unfinished purchase.

## Production wiring included, not integration-tested

`src/runtime.mjs`, `src/server.mjs`, `netlify/functions/standing.mjs`, `netlify.toml`, and `scripts/migrate.mjs` are included. The runtime requires explicit LIVE authority, origin, key, payment terms, RPC, facilitator, and PostgreSQL configuration. It does not create a root, invent a buyer wallet, silently choose a price/recipient, or fall back to ephemeral storage.

The `pg` adapter and Netlify wrapper have passed syntax checking only. PostgreSQL integration, fresh dependency installation/auditing, Netlify bundling/runtime, real EIP-3009 signature interoperability, real settlement and real chain finality were not executed here. The original candidate report said no deployment or GitHub write was performed during its initial local build. Recovery and subsequent source commits are separately evidenced; a source commit is still not a production deployment.

Read `docs/RUNTIME.md` for the exact environment contract, `docs/WIRE-CONTRACT.md` for the signed model and protocol boundary, `docs/SECURITY-AND-RECOVERY.md` for trust/failure semantics, and `docs/EXACT-COMPLETION.md` for the fixed object and actual completion ledger.

## Source layout

`src/mark.mjs` defines issuance. `src/evaluator.mjs`, `src/validation.mjs`, and `src/authority.mjs` establish its bounded warrant. `src/store.mjs`, `src/payment.mjs`, and `src/service.mjs` implement the transaction. `src/buyer.mjs` and `src/buyer-journal.mjs` implement the other side. `verify/verify_mark.py` is the independent verifier. `schemas/`, `profiles/`, and `public/openapi.json` expose the contract. `test/` contains only generated test identities and simulated payment dependencies.

Private keys, database files, credentials, upstream manuscripts, and font files are not included in the release archive. See `docs/SOURCES.md` for the distinction between governing sources, historical interoperability context, and newly derived implementation choices.
