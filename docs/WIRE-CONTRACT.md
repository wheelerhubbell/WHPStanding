# WHP Standing v1 wire contract

## Canonical representation and signatures

WHP-JCS-I1 uses sorted UTF-16 object keys, UTF-8 output, JSON string escaping, preserved array order, and no Unicode normalization. It deliberately admits only safe integer numeric values; decimal token quantities are strings. Negative zero, nonintegral/unsafe numeric values, duplicate object keys, lone surrogates, and excessive nesting are rejected. The general canonicalizer allows depth 64. A submission reserves 16 levels for the final envelope, so its effective maximum is 48. The HTTP body ceiling is 262,144 bytes. Trust bundles are capped at 65,536 bytes. Text admission limits use UTF-16 code units. JSON Schemas describe structure; these additional byte, Unicode, graph and cross-field constraints are normative too.

An envelope is exactly `{protected, payload, signature}`. Protected fields are exactly `{type, algorithm, canonicalization, key_id}`. The algorithm is Ed25519. `key_id` is SHA-256 of canonical DER SPKI public-key bytes. The signature is canonical base64 of Ed25519 signing UTF-8 canonical JSON of `{protected, payload}`. The protected type supplies domain separation. No private key is embedded.

Source attestations and transition warrants are separately signed. Root-signed certificates grant named roles, operations, scope, jurisdiction, profile and validity windows. A root-signed profile authorization admits the exact profile digest and explicitly declares TEST or LIVE. A root-signed status snapshot commits to the exact profile authorization, certificate array and revocation array so omission is detectable. Trust requires a root fingerprint supplied independently of the Mark. The institutional identity associated with that root is an external trust establishment, not a fact created by a self-signed key.

## Submitted object and profile

The request is `WHP-STANDING-SUBMISSION-v1`. It contains a durable client reference, buyer authentication key, exact profile hash/version, named object/version/root hash, explicit bounds and operation, signed nodes, and signed warrants. Duplicate node payloads, duplicate object/version pairs, duplicate target warrants and conflicting unknown IDs are refused.

Each node preserves source locator, epistemic status, qualifiers, unknowns and blocked operations, operational permission, temporal bounds, version/status, prior-hash reference, and jurisdiction. Prior-hash references are retained, but this profile does not certify version history outside the submitted graph.

COPY requires one parent and exact equality of content and epistemic status. COMPOSE requires distinct hash-addressed members in sorted hash order, each retaining its exact content; it is not a fusion. Every parent qualifier and unknown must survive unchanged. No semantic paraphrase, probabilistic truth assessment, or model-based waiver is supported. A transformation needs a separately signed warrant with admitted evidence references and exact scoped permission. Unknowns can remove permission but cannot manufacture it.

The full graph must be connected to the submitted root and acyclic. Every dependency must be admitted within the same requested bounds. The permitted operations are the intersection of all relevant source/warrant grants minus blocking unknowns. An assessment never proves that the submitter supplied all material evidence in the outside world.

## One completed result

A positive result uses type `WHP-STANDING-MARK-v1`, version `WHP-STANDING-RESULT-v1`, and ID `WHP-SM-<purchase_id>`. A negative result uses `WHP-STANDING-ASSESSMENT-v1`, `mark_id: null`, and `standing: null`. Negative assessments remain paid, signed and retrievable. A valid signature by itself is not a positive standing determination.

The complete payload includes issuer identity, environment, key ID, purchase identity, object, profile, profile authorization, authority bundle, full submission and its hash, decision record and its hash reference, specific standing or null, effective/expiry/issuance times, commercial disclosure, signed quote, payment authorization/identity, settlement evidence, retrieval/registry paths, and explicit exclusions. The whole payload is signed together. A valid signature cannot be transplanted onto a different graph, issuer, recipient, operation, payment, result type, or retrieval identity without failing verification.

## x402 boundary

The implementation uses x402 v2 with `PAYMENT-REQUIRED` and `PAYMENT-SIGNATURE`. The 402 terms include `x402Version: 2`, the resource, accepted exact-EVM terms, and a mandatory `whp-standing` extension carrying the signed quote.

The extension is not optional compatibility decoration. Its EIP-3009 nonce is:

```text
0x + SHA256(canonical({
  domain: "WHP-STANDING-PURCHASE-BINDING-v1",
  quote: complete_signed_quote.payload
}))
```

The quote binds the buyer key, submitted input hash, profile hash, durable purchase ID, resource, recipient, token, chain, amount, expiry and charge policy. The payment's EIP-712 signature therefore commits to that exact purchase via the nonce. A generic x402 client that chooses an unrelated random nonce is not compatible until it implements this extension.

This candidate supports only direct EVM `transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)` with a 65-byte EOA-style signature representation. It does not claim Permit2, ERC-7710, smart-wallet/batch settlement, `receiveWithAuthorization`, Solana, or arbitrary facilitator settlement compatibility. The configured facilitator performs cryptographic EVM signature/funding validation. The issuer independently checks the subsequent receipt, canonical/finalized block, exact transaction calldata, AuthorizationUsed nonce event and matching Transfer event using its configured RPC. Production interoperability is still untested.

## Retrieval, recovery and current status

`GET /v1/purchases/<id>/result` is authenticated and read-only. It never initiates settlement. `POST /v1/purchases/<id>/recover` explicitly resumes the existing stored authorization. An unpaid quote may be completed by resubmitting its unchanged submission with that authorization. Another purchase/reference is not an authorized substitute for unresolved recovery.

Authentication is a buyer Ed25519 proof binding method, exact path/query, raw body hash, issued/expiry times, and a random nonce. Its lifetime is at most 120 seconds with bounded clock skew. This is not a bearer secret in a query string. A duplicate proof can repeat an idempotent operation during that window; it cannot alter the signed body or spend beyond the bound authorization.

The public registry exposes opaque IDs and result hashes, not buyer source documents. A signed snapshot contains the append-only signed event chain, current signed trust state, observation time and a maximum 300-second validity period. Expiry is calculated rather than retroactively rewriting an issued Mark. A subsequently revoked admitted authority limits current standing. Root-authorized withdrawal/supersession is terminal in this profile. Review submissions receive durable receipts, not automatic adjudication.

The independent verifier separately reports cryptographic integrity, evaluator replay, current registry standing, and chain rechecking. An offline Mark does not prove that its status is current. Embedded RPC observations are not a standalone blockchain-consensus inclusion proof. `--rpc` rechecks through the verifier user's trusted HTTPS RPC. No system here certifies outside-world truth or domain authority simply because it can verify a signature.
