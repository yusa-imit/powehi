---
name: new-api-endpoint
description: Add or evolve a REST/WS/gRPC endpoint proto-first, then axum handler, rate limit, tests, and a security-auditor pass. Use when introducing a new server API surface.
---

# New API endpoint

Serial workflow — delegate steps to the right worker, do not parallelize (later steps depend on earlier).

## Steps
1. **Shape it (api-designer)**: define the protobuf message in `powehi-proto` first (rule: PascalCase messages). Match the conventions in prd.md §6.3 (`/v1/<resource>` plural).
2. **Handler (api-designer)**: axum handler converting proto ↔ domain types. It calls an inbound port (use case), never a repository directly (prd.md §6.1.2).
3. **Rate limit (mandatory)**: every public endpoint gets `tower-governor` local limiting; user-scoped limits go through the Redis token bucket (prd.md §6.4). An endpoint with no rate limit is not done.
4. **No plaintext contract**: the request/response body must never carry plaintext message content or new user PII. If routing needs a new metadata field, it must pass `threat-model-checker` (new server-visible metadata = threat-model change).
5. **Tests (test-author)**: handler unit test + a `testcontainers` integration test for the happy path + an auth-bypass test (unauthenticated request → 401) per rule `testing-conventions`.
6. **Review (security-auditor)**: SQL parameterization, auth coverage, error-message info disclosure, rate-limit coverage.
7. **Doc sync (doc-syncer)**: update the API table in prd.md §6.3.

## Done when
- Endpoint has rate limiting, an auth-bypass test, and a green `security-auditor` verdict.
- If it added server-visible metadata, `threat-model-checker` returned green/yellow (yellow = update docs).
