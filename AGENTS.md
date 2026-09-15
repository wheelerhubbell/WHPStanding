# WHP Standing first public v1

Read `docs/FIRST-PUBLIC-V1.md` before modifying any cryptographic component. Signer, closed schema, canonicalization, authority/profile commitments, immutable discovery identity, current resolution/status, independent verifier and replay are one coupled versioned object. Preserve development provenance; do not restore candidate adapters or call this v2.

The three objects are distinct: historical Mark, current registry, current service discovery. Preserve root pinning, explicit roles, freshness, revocation/withdrawal, exact payment binding and durable retrieval. TEST never implies LIVE, SOLD, DEPLOYED or ISSUED.

Rebuild deliberate contract changes with `python3 scripts/generate-schemas.py` and `python3 scripts/freeze-contract.py`; verify reproducibility using `--check`. Changing the profile/semantic contract/program requires explicit matching root authorization. All tests, real HTTP/storage execution, independent replay, cold A/B/C and isolated PostgreSQL must pass before promotion. Never treat an old successful report as evidence for changed code.

Need recognition and generic provider matching are vendor-neutral. No missing-Mark-to-buy-WHP rule is permitted. Cold proofs start with only the specified input and generic runtime. No hard-coded provider address, fixture, issuer key, root pin, clock or repository imports may enter the consumer. Downloaded code runs only in the public-artifact sandbox.
