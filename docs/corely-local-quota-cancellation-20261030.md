# Local Codex quota outcome and cancellation

This change is for an explicitly bootstrapped owner-local experiment. It does
not enable a hosted customer-service deployment, add an upstream login, alter
pricing, or enable paid API fallback.

## Authenticated quota outcome

Native channel 57 can emit a short-lived HMAC header only when the actual
upstream Responses request returns HTTP 429 with exact error type
`usage_limit_reached`. The proof binds the actual URL, selected channel/model/
group, first attempt, nonce, call/input/schema digests and lifetime. Normal
before/after source and current-configuration proofs must still succeed.

The four request bindings are removed before upstream forwarding, including
wildcard header passthrough. A committed SSE response, generic 429, rewritten
route/status/parameters, missing proof, stale source, cancellation or partial
completion cannot authorize an account switch. Corely remains responsible for
Info-first, authenticated-quota-only Eason routing; no API route is introduced.

Go and Node tests share a fixed public test vector and separately exercise the
real native adaptor/error path against a loopback fixture. These tests prove
protocol behavior, not naturally observed account exhaustion or a provider
billing debit.

## Caller cancellation

API and Form requests now inherit the caller's context before upstream headers
arrive. Existing timeout and retry policies are unchanged. Actual loopback tests
cover cancellation before headers, cancellation during body reading, and normal
success, with one upstream attempt. Existing SSE scanners already closed bodies
on client disconnect; this fixes the missing HTTP-request lifetime propagation,
not a claim that every prior stream ignored cancellation.

## Separate private historical-regression capability

The ordinary SIWC/VM/synthetic contracts remain synthetic-only. A trusted
in-process local bootstrap may explicitly admit the fixed original-50 corpus
SHA-256 `c895a50c382ef87751f00cca0899b1660a0f77eca7b5cb72a8fc139573aba5e3`.
Its wire scope is `dataClass: historical_regression`, never `synthetic: true`.
Default callers reject this scope; no HTTP parameter or environment option
grants it. Corely separately binds user approval, new local database admission,
transaction-local facts and source freshness, rollback, disabled tools/sending/
learning, exact GPT-6.1 Sol and API-off routing.

No production acceptance or natural quota-failover acceptance is implied by
offline contract tests.
