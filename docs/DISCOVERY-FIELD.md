# Discovery, status and propagation boundary

The immutable Mark binds a root-qualified capability and a canonical resolution identity, not the current hosting origin. `src/contract.mjs` constructs only immutable issuance semantics. `src/discovery.mjs` constructs current service metadata and a separate fresh, signed DISCOVERY-authorized resolution. The closed layouts are normative in `contracts/WHP-STANDING-v1.md`.

Current contract, OpenAPI and input/output schemas are hash-bound. The complete issuance profile and exact independent verifier source are content-addressed at `/v1/material/sha256/{sha256}` and retained under `public/immutable/`. Do not delete material committed by an issued public artifact when regenerating schemas.

A canonical resolver is a stable routing obligation, not a forever-true commercial endpoint. Hosting can change only through fresh authorized resolution. Revision rollback, equivocation, stale root manifests and stale status fail closed. A first reader cannot infer publication history it has never observed.

`STANDING-NEED-v1` is a provider-neutral interface. Need records preserve external object/action commitments and describe missing warrant rather than advertise a provider. Controlled multi-provider TEST discovery proves compatibility-based selection and rejects an incompatible branded decoy. It does not prove public search indexing, third-party directory acceptance or an outside sale.

The Mark-only test starts with one file. The need-only test starts with the external object, contemplated action and generic directory bootstrap. The recursive test sends its later need only after the first Mark has independently verified. All network traces and failures are recorded under `evidence/public-v1/cold/`.

Existing current-service MCP transport, OpenAPI and Bazaar metadata are retained and tested separately. Publication workflows remain disabled during this TEST contract assignment. Provider description is not public registration or LIVE commercial availability.
