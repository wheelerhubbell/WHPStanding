# WHP Standing v1

First public cryptographic contract. The candidate is development provenance, not a previous public protocol version. No candidate adapters, optional discovery fallback, dual public Mark formats or Mark v2 are implemented.

The signed Mark records what was established at issuance. The separate signed registry reports current standing. The separate signed discovery resolution identifies the current service and purchase contract. None can silently change the meaning of either of the others.

The normative contract is `contracts/WHP-STANDING-v1.md`. Its exact machine grammar, profile and independent verification material are bound by `contracts/public-v1-lock.json`. The reference verifier includes its own closed schema and independent replay implementation; it does not import producer code.

## Executable evidence

`evidence/public-v1/verification.json` records the actual public-v1 execution, test counts and evidence states. `evidence/public-v1/tests.tap` and `evidence/public-v1/test-files/` contain the complete test executions. `evidence/public-v1/cold/` contains the Mark-only, need-only and recursive TEST traces and adversarial refusals. The localhost purchase, authenticated byte-identical retrieval, separate-process restart and independent replay are in `evidence/public-v1/demonstration/`.

The original candidate archive, `evidence/verification.json`, `evidence/tests.tap`, recovery identity and original demonstration are preserved unchanged. Its 83/83 result is not substituted for the public-v1 result. The transition and preserved source commitments are recorded in `evidence/public-v1/transition.json`.

## Execute the proof

```sh
python3 -m pip install -r requirements-verification.txt
bash scripts/build-cold-sandbox.sh
npm run verify
```

Docker is required. A missing sandbox fails the proof; no cold test is skipped. The generic sandbox contains Python and cryptographic/schema libraries only. Downloaded immutable verifier code runs networkless, non-root and read-only, without repository source or secrets.

Cold A receives only one completed TEST Mark. Cold B receives an external object/action and a vendor-neutral directory interface; it must select by capability, not a brand, fixed root or fixed provider. Cold C joins the first independently verified Mark to a later unsupported object/action and the next real HTTP 402 boundary. The controlled TEST directory contains competing provider identities and an incompatible branded decoy. This proves TEST propagation, not external catalog registration or a genuine sale.

The complete external JSON object and contemplated operation survive need recognition and boundary construction. An unadmitted source key remains unestablished; schema-valid payment terms do not promise a successful assessment. The cold readers create HTTP authentication keys only, no wallets or payment authorizations.

## Semantics and authority

Structured Provenance and Passage Integrity 1.0.0 assesses exact COPY and identity-preserving COMPOSE over the submitted signed graph. Qualifications, unknowns, provenance, requested operation, admitted authority, scope, jurisdiction and time bounds survive replay. CONTINUITY and ACTION_BOUNDARY remain NOT_ASSESSED. External factual truth is not promoted by payment or a valid signature.

The Mark embeds the complete issuance profile and binds its hash, the historical authority chain, exact decision, source graph and original payment/transaction identity. Its capability and canonical resolver identity are immutable. Current service origin, OpenAPI, schemas, commercial terms and current provider metadata are signed in a fresh resolution with distinct DISCOVERY authority.

Root pinning remains mandatory for admitted institutional trust. A Mark-only reader can verify self-certifying key identity and the internal authority chain, but reports institutional admission as NOT_ESTABLISHED. An embedded root cannot appoint itself as an independently trusted WHP institution.

## Production boundary

TEST evidence is not DEPLOYED, LIVE, SOLD or ISSUED. Production needs separately authorized WHP root/profile/key custody, retained immutable materials and resolver identity, persistent discovery revision state, public hosting, durable database, buyer-owned authorized funds, interoperable facilitator and independently verified final settlement. These are not fabricated or bypassed by this build.

The production payment recipient is solely `0x1050eddd8282623b0c263ed6bdbd42370bbc28d3`, on Base `eip155:8453`, in native USDC. It is not an issuer/root/buyer identity. Full runtime requirements are in `docs/RUNTIME.md`.

An optional local PostgreSQL proof runs with `npm run verify:postgres` and an explicit `WHP_TEST_POSTGRES_URL` restricted to localhost database `whp_test`. It records its own evidence and never uses a production fallback. Source verification and any PostgreSQL TEST result do not establish a deployed service.
