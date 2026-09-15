# WHP Standing v1

**Recovered candidate plus verified discovery extension. The LIVE completion boundary remains open.**

WHP Standing provides machine-verifiable standing under explicit authority and bounds. It produces a signed, bounded assessment of a submitted source/provenance graph. A favorable assessment under the named WHP Standing Profile produces a WHP Standing Mark. A failed assessment produces a signed result without a Mark. Payment buys the evaluation, never a favorable finding.

## Authoritative source and continuity

Repository: `wheelerhubbell/WHPStanding`. This release branch is `standing-v1-propagation`. Its implementation was promoted at `a04704ae8356cc2cf4df05bf420e6dc250f33cf2` after execution succeeded. Later commits preserve packaging, regression workflows and evidence records.

The exact uploaded `WHP-Standing-v1-candidate-1.zip` was recovered without changing any candidate byte at commit `ec3d1b8710c7a55529e4c450a806a8fea5dc7fee`. The archive SHA256 is `37f38a3799baafcbdd149aa29e9994fa6ae39230d108ef35f93b842bcdea2056`. Its archive and original evidence remain preserved. `evidence/recovery/candidate-identity.json` records every recovered file hash. Recovery Actions run `34960508166` passed the original 83 tests and promoted the source. Earlier run `34958976070` failed after successful verification, during a workflow-file permission rejection; it was not a test failure.

Main received a separate concurrent discovery implementation while this extension was being prepared. The source-hash gate rejected promotion against that changed baseline. This branch starts from the exact recovered candidate, preserves the other main history, and does not silently merge or overwrite that work. Do not equate the tested branch with later main source. The import/promotion workflows are historical assembly mechanisms, not a license to overwrite later edits; their hash checks deliberately reject changed source.

## Executed evidence

Actions run `34965923192` executed **107 tests, 107 passed, zero failures, zero skips**, including all original 83 tests. Schemas validated; the separate Python verifier executed; real localhost HTTP transport and separate-process durable retrieval executed; the TEST artifact was correctly rejected as LIVE. The same run executed isolated PostgreSQL integration and committed the actual reports at `evidence/propagation-extension/`, `evidence/cold-agent/` and `evidence/postgresql/`.

The cold-process test receives exactly one completed TEST Mark and no injected WHP origin, root pin, profile or repository imports. It resolves meaning, public trust metadata, current registry status, the applicable profile, content-addressed independent verification code, the purchase contract and input schema, and reaches an actual HTTP 402 payment boundary. Downloaded verification code runs in an isolated, network-disabled container with only public artifacts mounted read-only. The process has no wallet key and creates no payment authorization. Negative cases cover tampering, semantic promotion, substituted roots, code-hash mismatch, missing discovery dependencies, stale status, changed payment terms and withdrawal. This is VERIFIED TEST traversal, not PROPAGATION-PROVEN from a LIVE issued Mark.

The PostgreSQL execution demonstrates concurrent requests converging on one simulated settlement and registry entry, byte-identical authenticated GET and POST retrieval, buyer isolation, changed-object conflict, and retrieval by a fresh process after the producer pool closes. It accessed an explicitly isolated localhost TEST database, not production storage.

Netlify package run `34966425134` used the actual pinned official `@netlify/zip-it-and-ship-it@15.5.1` bundler. It produced a Node 22 Fetch-API function package, imported its packaged application handler in a separate process, verified HTTP 503 refusal without authority/configuration, and confirmed that the content-addressed Python verifier was packaged byte-identically. The manifest, execution evidence and package are retained in that run's `whp-standing-netlify-package-34966425134` artifact. This is packaging/runtime-import verification, not deployment or verification of Netlify's production environment.

## Repeat verification

```sh
python3 -m pip install -r requirements-verification.txt
npm ci --include=optional --ignore-scripts
bash scripts/build-cold-sandbox.sh
npm run verify
```

The full suite requires Docker and fails rather than silently skipping its isolated verifier. The image contains generic Python and crypto/schema libraries, not WHP source, fixtures or URLs. `.github/workflows/verify.yml` repeats the full suite and PostgreSQL integration with an explicit disposable test database on every source push. The database script refuses a nonlocal or non-TEST database URL and has no production fallback.

Historical candidate Marks remain verifiable with their archived verifier and historical context. The new verifier requires the new signed discovery carrier. Its public source is content-addressed by SHA256. No TEST signature or artifact becomes LIVE merely because its cryptography verifies.

## Implemented capability and limits

The WHP Standing Mark carries the exact object/version, complete submitted graph, admitted root-signed authorities, signed profile authorization, root-signed trust-state commitments, bounded evaluation, decision hash, x402 quote, payment identity and authorization, settlement evidence, issuer signature, expiry, registry/retrieval references, and a signed discovery carrier. The independent Python implementation verifies cryptography and replays the defined transformation/authority rules without producer imports.

The preserved WHP Standing Profile is `WHP-STANDING-STRUCTURED-PASSAGE` version `1.0.0`, SHA256 `dc25aa63cadad8b5b02ba3cbaac552ca8273c6d6793b4eefdef16aadd180046e`. It permits exact COPY and identity-preserving COMPOSE only. It preserves qualifiers and unknowns, intersects operation permissions, checks graph closure and warrants, and denies unsupported promotion. SOURCE, CONTEXT, RELATION, PASSAGE and UNKNOWN are assessed only within this profile. CONTINUITY and ACTION_BOUNDARY remain NOT_ASSESSED. It does not establish substantive truth of source assertions, external legal authority, legal compliance, universal safety, external workflow behavior, or completeness beyond the submitted graph.

The transaction store binds one buyer/reference to one immutable submission and payment identity. Preparation is durable before settlement; actual finalized evidence is required instead of a facilitator success flag; uncertain outcomes remain pending; signed bytes and initial registry state commit atomically; authenticated retries return the original bytes without another charge.

The buyer client pins trust and payment destinations, reserves spending before asking its owner's signer, uses the mandatory quote-bound EIP-3009 nonce, journals authorization before submission, and independently verifies the result. Recovery does not request a second signature. `scripts/buy.mjs` resumes from the same durable journal. Generic random-nonce x402 clients are not silently accepted as compatible.

## Machine discovery and external registration

Implemented routes include canonical well-known metadata, RFC 9727 API-catalog metadata, OpenAPI, schemas, versioned profiles, content-addressed independent verification, searchable canonical documentation, a real stateless MCP endpoint, MCP server metadata, robots/sitemap/llms surfaces, and signed per-Mark discovery. `docs/DISCOVERY-FIELD.md` records researched current primary sources and applicability.

Facilitator-facing Bazaar metadata is forwarded without changing the buyer's signed payment identity. Provider discovery responses are retained as evidence, not treated automatically as accepted listings. Bazaar metadata or successful verification alone is not registration. The official MCP publication workflow is implemented but refuses to publish until a real HTTPS service, explicitly admitted LIVE root and functioning MCP transport are verified; it requires registry read-back to record REGISTERED. No external registration was executed in this build.

## Current production authorization boundary

The current named repository configuration inspection is `evidence/production-authorization/latest-inspection.json`, from run `34966595182` at `2026-09-15T12:02:45Z`. It found no available `NETLIFY_AUTH_TOKEN`, site identifier, canonical origin, root pin, WHP trust bundle, issuer private key, payment configuration, database URL, RPC URL or facilitator configuration under the inspected secret/variable names. This finding is scoped to those repository Actions inputs, not every external account or environment. No secret values were exported.

The immediate external authorization action is to store a Netlify personal access token authorized for WHP deployment as the repository Actions secret `NETLIFY_AUTH_TOKEN`. Do not paste it into chat. Deployment access must then actually be verified. Production origin, durable database, genuine WHP root/profile authority and separate issuer signing custody, provider interoperability, trusted RPC finality, publication and outside purchase remain separately gated and must be executed, not inferred from a token.

The designated LIVE payment recipient is `0x1050eddd8282623b0c263ed6bdbd42370bbc28d3`, Base `eip155:8453`, native USDC `0x833589fcd6edb6e08f4c7c32d4f71b54bda02913`. The runtime pins this destination and rejects TEST authority. The recipient address is not a signing key, root authority or buyer wallet.

No production deployment, real outside payment, LIVE WHP Standing Mark, accepted external registration or LIVE-Mark propagation proof was produced by these executions. Real EIP-3009/provider interoperability, settlement finality and production custody are not yet verified. No fixture fallback, self-sale or institutional issuance is manufactured.

## Source layout

`src/mark.mjs` defines issuance. `src/evaluator.mjs`, `src/validation.mjs` and `src/authority.mjs` establish the bounded warrant. `src/store.mjs`, `src/payment.mjs` and `src/service.mjs` implement the transaction. `src/buyer.mjs` and `src/buyer-journal.mjs` implement the buyer side. `src/discovery.mjs` and `src/mcp.mjs` expose discovery. `verify/verify_mark.py` is the independent verifier. `schemas/`, `profiles/` and `public/openapi.json` expose the contract. Tests use generated TEST identities and simulated payment dependencies.

Production private keys, credentials and upstream manuscripts are not included. `docs/SOURCES.md` distinguishes governing sources, historical interoperability context and derived implementation choices. `docs/RUNTIME.md`, `docs/WIRE-CONTRACT.md`, `docs/SECURITY-AND-RECOVERY.md` and `docs/EXACT-COMPLETION.md` preserve the runtime contract, signed model, security properties and fixed completion object. Dated execution evidence controls claims about what has actually run.
