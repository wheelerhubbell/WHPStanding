# WHP Standing machine-discovery field

The canonical capability is **machine-verifiable standing under explicit authority and bounds**. The canonical product, result, profile and purchased operation are WHP Standing, WHP Standing Mark, WHP Standing Profile and WHP Standing Evaluation. Wheeler Hubbell Publishing is the intended LIVE issuer and seller, not the buyer and not a payment-derived signing identity.

## Issued-object path

Each new signed result includes a discovery carrier covered by the issuer signature. It names the capability, explicit assessed and unassessed meaning, scope/authority/provenance/limitations pointers, profile ID/version/hash/URL, canonical service, current registry, independent content-addressed Python verifier, exact input schema, purchase contract and x402 boundary. No private customer input is published into external directory metadata. The public Bazaar wire example is an explicitly TEST example, not an admitted LIVE source.

`scripts/cold-agent.py` takes exactly one artifact path. Its fresh process receives no WHP-specific URLs, root pin, configuration, fixtures, repository modules or clock overrides. It reads protocol details from the signed carrier and reachable public documents, independently checks cryptography, downloads hash-bound independent replay code and runs that code in a generic read-only no-network Docker sandbox, obtains fresh registry status, resolves the exact profile and schema, creates its own HTTP-authentication key, and reaches a real HTTP 402 quote without a wallet or payment authorization. The script does not claim legal company authentication merely from TLS. The TEST suite cannot confer the production label PROPAGATION-PROVEN.

## Current legitimate surfaces, researched 2026-09-15

**x402 Bazaar.** The official declaration is `extensions.bazaar.info` plus JSON Schema. This service sends server-owned metadata to the configured facilitator on verification/settlement, separately from the immutable buyer authorization. Provider extension-response headers are preserved in durable purchase metadata without treating them as finality or registration. The exact input schema is linked by canonical `$ref`; its acceptance by an external catalog must be measured against that provider. Successful local JSON Schema validation is not external acceptance. CDP Bazaar indexing follows a settled paid request; it is not a way to conjure the initial sale. Different facilitators may maintain different catalogs. Sources: https://docs.cdp.coinbase.com/x402/seller/get-discovered ; https://docs.x402.org/extensions/bazaar ; https://raw.githubusercontent.com/x402-foundation/x402/main/typescript/packages/extensions/src/bazaar/http/types.ts .

**Official MCP Registry.** A real stateless Streamable HTTP endpoint is implemented at `/mcp`, with read-only contract/profile resources and tools that preserve HTTP proof, exact input bytes, x402 requirements and durable retrieval. `/server.json` uses the actual canonical deployed origin, not a fabricated hostname. The prepared publisher uses GitHub OIDC for `io.github.wheelerhubbell/whp-standing`, verifies a current publisher release digest, refuses vulnerable pre-1.7.6 publisher versions, checks public LIVE authority/transport first, and requires registry read-back before writing REGISTERED evidence. It has not registered an undeployed service. Sources: https://modelcontextprotocol.io/specification/2025-11-25/basic/transports ; https://github.com/modelcontextprotocol/registry/blob/main/docs/modelcontextprotocol-io/github-actions.mdx ; https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/cli/commands.md .

**API catalogs and OpenAPI.** `/.well-known/api-catalog` implements the RFC 9727 Linkset media type and canonical links. `/v1/openapi.json` names the current service origin and actual operation paths. This is self-publication, not acceptance into an external directory. Source: https://www.rfc-editor.org/rfc/rfc9727.html .

**Repository and search discovery.** Public repository/package metadata, AGENTS.md, README, canonical HTML/Service structured data, robots, sitemap and llms.txt expose the same narrow capability. llms.txt is a documentation convention, not proof of an agent crawler standard or search-engine indexing. No crawler visit, ranking, registration or buyer is inferred from publishing metadata.

**Smithery.** Its current URL publishing flow requires an existing public HTTPS Streamable HTTP server. It supports remote distribution but serving metadata is not submission. No Smithery registration is claimed. Source: https://smithery.ai/docs/build/publish .

**Glama.** Its current submission flow accepts GitHub servers and already-deployed remote connectors. Open-source license detection and server health are independently assessed. This repository's public visibility is not an open-source license grant. No Glama submission or acceptance is claimed. Source: https://glama.ai/mcp/faq .

## First-sale bootstrap and status

The public repository, canonical documentation, API catalog and actual remote MCP listing can expose the service before an outside purchase. After a genuine settled purchase, the Mark itself supplies the next cold-agent discovery path, and the configured facilitator may catalog metadata. Neither purchase demand nor recursive future sales are guaranteed by those mechanisms.

No registration, deployment, LIVE authority, real buyer payment or institutional Mark is established by this document. Source state is IMPLEMENTED only after promotion. Execution evidence belongs under `evidence/propagation-extension/`, `evidence/cold-agent/`, `evidence/postgresql/`, and actual future external acceptance reports, not inferred from this file.
