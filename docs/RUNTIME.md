# Runtime contract — no production deployment performed

## Issuer runtime

The production entry point requires every value below. None is supplied from a historical DIP default.

```text
WHP_ORIGIN                         Current public, buyer-pinned HTTPS service origin
WHP_DISCOVERY_ORIGIN               Stable canonical HTTPS resolver origin, retained across service moves
WHP_RESOLUTION_SEQUENCE            Persisted nonnegative discovery publication revision
WHP_RESOLUTION_PREVIOUS_HASH       Prior canonical provider hash when revision is greater than zero
WHP_ROOT_PIN                       SHA-256 fingerprint of the independently admitted root SPKI
WHP_TRUST_BUNDLE_FILE               Mounted, root-signed LIVE trust/profile/certificate/status JSON
WHP_ISSUER_PRIVATE_KEY              Authorized Ed25519 PKCS8 PEM, supplied through secret custody
WHP_PAYMENT_REQUIREMENTS_FILE      Exact EVM token/network/recipient/amount/domain terms JSON
WHP_FACILITATOR_URL                 Explicit HTTPS facilitator supporting the implemented path
WHP_RPC_URL                         Issuer-trusted HTTPS chain RPC with finalized blocks and logs
DATABASE_URL                       Durable PostgreSQL connection string
PORT                               Standalone HTTP port; default 8080
```

The issuer certificate must include ISSUER, REGISTRY and DISCOVERY roles and the relevant scope/jurisdiction. The profile authorization must bind the exact public-v1 issuance profile hash, environment LIVE, issuer name `Wheeler Hubbell Publishing`, and effective window. Such authorization must be an actual WHP act; changing a JSON string from TEST to LIVE is not authorization.

`pg` is pinned as an optional dependency because offline proof does not need it. A real production installation must actually install and validate that dependency. A local TEST PostgreSQL execution, when present, is recorded separately in `evidence/postgresql/report.json`. It does not establish production database configuration or a dependency security audit.

```sh
npm install --include=optional
node scripts/migrate.mjs
npm start
```

Migration is an explicit authorized administrative operation on the configured production database, never an incidental side effect of an evaluation request. These commands are documentation, not operations executed in this session.

`netlify.toml` and the Netlify function are supplied for deployment assessment. They have not been bundled or deployed. The trust/payment JSON files must actually be mounted or included at the configured locations, secrets installed through authorized custody, the durable database initialized, and hosting limits verified. The function never substitutes local filesystem storage for a production database.

## Buyer runtime

The buyer needs its own durable Ed25519 HTTP-authentication key, an independently authorized wallet provider, policy, canonical signed submission, persistent SQLite journal, and independent trusted chain RPC. The owner—not this library—grants spending authority to the wallet provider.

The policy fields are `environment`, `origin`, `root_pin`, `profile_hash`, `network`, `asset`, `pay_to`, `payer`, `asset_name`, `asset_version`, `max_per_purchase`, and `max_total`. Amount limits are integer token-base-unit strings. The asset's EIP-712 name/version must be pinned; they are not accepted merely because a server proposes them. The complete policy hash scopes the journal's cumulative allowance. Replacing a policy/journal is a new owner-side authority decision, not an automatic retry mechanism.

An owner wallet-provider module exports an EIP-1193 provider as `default`. Its `request({method:'eth_signTypedData_v4', params:[payer, typedDataJSON]})` operation must work under that owner's existing permission. The included wrapper has no interactive-approval or wallet-creation bypass.

```text
WHP_BUYER_PRIVATE_KEY              Buyer's Ed25519 PKCS8 PEM
WHP_BUYER_RPC_URL                  Buyer-trusted HTTPS chain RPC, independent of issuer output
WHP_BUYER_MAX_WAIT_SECONDS         Explicit polling deadline; default 1800 seconds
```

```sh
node scripts/buy.mjs policy.json submission.json owner-provider.mjs buyer-journal.sqlite received-result.json
```

The CLI is LIVE-only and rejects TEST policies. For the no-money, no-wallet proof, use `npm run verify` instead. Production wallet signing was not invoked here. The CLI preserves the original journal and reference when it reaches a pending deadline. Retrying with the same files recovers the original authorization; it does not ask for another payment signature. The output file is created with exclusive-write semantics rather than silently overwriting an existing result.

## Issuer review/status administration

The public review route only records a challenge. An issuer administrator must adjudicate it under the appropriate authority; no positive standing follows from a review receipt.

`StandingService.applyRegistryCommand` accepts a root-signed `WHP-REGISTRY-COMMAND-v1` with `purchase_id`, `expected_previous_hash`, `status`, `reason`, and `at`. It appends an issuer-signed event without editing the old Mark. This library method is not exposed as an unauthenticated HTTP admin endpoint. Production administrator authentication, key custody and case-management operations remain deployment responsibilities.

## Immutable and current material retention

Keep every previously issued profile and verifier content address available. Schema generation retains existing immutable files. Persist the resolution revision and predecessor hash across restarts. Keep the canonical resolver identity reachable while hosting moves; publish a new signed mapping with a valid DISCOVERY delegation. Retain current-status authority for historical Marks independently of later commercial profile offers. The in-process rollback guard is not a substitute for production persistence or independent root admission.
