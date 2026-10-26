# Local Codex harness pilot

This is a **local, owner-operated synthetic integration pilot** of the official
Codex agent, not an HTTP proxy, New API channel, automatic account pool or
production customer-service backend. The fixed trusted smoke remains the only
live model result. A server-enrolled candidate extension is offline-tested but
is not yet live-connected. No real customer data are accepted.

The official [Codex app-server](https://learn.chatgpt.com/docs/app-server) can embed
the full agent and owns normal ChatGPT sign-in. This differs from extracting a
Codex token and using it in a third-party Responses relay. The official
[authentication guide](https://learn.chatgpt.com/docs/auth) distinguishes ChatGPT
subscription sign-in from API-key billing, recommends API keys for automation,
and warns not to expose Codex execution to untrusted/public environments. A local
synthetic success is not proof of hosted-customer-service eligibility.

## Security and acceptance

- A new private temporary CODEX_HOME and empty workspace are used for each run;
  no existing Codex/Luna credential cache or user configuration is read or copied
  by the pilot. Authentication is held in memory by the official runtime.
- A single stdio app-server process does sign-in, account/read, model/list,
  ephemeral thread/start and turn/start. It uses native OpenAI routing, with
  ChatGPT login enforced and no API key or provider/proxy environment inherited.
- The exact expected account is info@moztech.cc. API mode, another account,
  unverified plan, hidden/missing GPT-6.1 Sol, model rerouting, tool requests,
  incomplete turns and malformed output fail closed. There is no retry loop,
  account rotation or API fallback.
- Neutral JSON-RPC metadata is non-authoritative and cannot satisfy completion.
  Unknown auth/model/tool/control events, all server requests and unexpected
  item types fail closed. The exact disabled Code Mode host warning, bound to
  the current thread, is recognized without enabling the execution host; all
  other warnings fail. Only the exact final item plus completed turn/usage pass.
- Protocol parameters are checked against the installed official runtime's
  generated schema. In runtime 0.162.0-alpha.17.2, thread-start sandbox mode is
  `read-only`, while the returned policy type is `readOnly`; these are different
  protocol types, not interchangeable spellings. This runtime does not expose
  the newer restricted `ReadOnlyAccess` override. Turn-start inherits the thread's
  verified read-only/no-network policy instead of passing that unsupported field.
- Shell, MCP apps/plugins, browsers, computer use, hooks and memory are not
  enabled. The turn inherits read-only/no-network sandboxing. This old runtime
  does not prove a restricted read-root policy; therefore only the fixed trusted
  smoke is accepted, never untrusted/arbitrary customer input or file tools.
  No candidate is saved, sent, approved or learned.
- Raw notifications, error messages, auth caches and model reasoning are never
  printed. Only the normal sign-in URL and fixed allowlisted result are exposed.
  The sign-in URL must not be copied into public issues or documentation.
- A successful result means the checked ChatGPT-authenticated harness completed
  the fixed Sol turn; per-request included-plan debit is separately unverified.
  ChatGPT purchased credits are not the same as Platform API credits.

## Invocation

Use an independently verified installed official Codex executable:

```sh
node bin/codex-harness-pilot.mjs --executable /absolute/path/to/codex --login --run-synthetic
```

The normal sign-in ceremony must identify the expected owner account. No password
or token should be passed to this program. Omitting `--run-synthetic` performs
only authentication/model preflight. Omitting `--login` does not open a ceremony;
the fresh isolated process will report AUTH_REQUIRED rather than reuse a session.

Offline tests:

```sh
node --test bin/codex-harness-pilot.test.mjs
```

## Corely integration boundary

Corely's existing external-candidate path is the appropriate downstream seam:
brand-scoped evidence packet → untrusted candidate text → independent quality
review → PENDING draft → human edit/save → exactly-once send → eligible style
learning. The current review path still uses the API. Do not replace it with the
candidate's own assessment or claim that a harness smoke moved all API usage to
the personal plan. Any later harness-backed review needs a separate independent
review turn, equivalent evidence/freshness checks and full regression/E2E.

This pilot does not modify Corely routing, New API cloud channels, deployed
services, schema, FAQ, states or review mode. Normal DEV and production remain
unchanged. No hosted usage or quota-exhaustion account switching is enabled by it.

## Verified local result — 2026-10-26

Runtime source `fc897301cf672a00de84682eee7ae673d878f49c`, official installed
Codex `0.162.0-alpha.17.2`, completed one live fixed synthetic turn after normal
Info sign-in with **Personal account** selected. The same official process
verified ChatGPT authentication, exact expected account, Pro plan, visible
`gpt-6.1-sol`, the selected model and final output, completed turn/usage, and the
same account again. No API key, custom provider endpoint, token import or API
fallback was used.

```json
{"status":"SYNTHETIC_HARNESS_PASSED","authMode":"chatgpt","expectedAccountMatch":true,"planType":"pro","model":"gpt-6.1-sol","generationCompleted":true,"outputMatched":true,"usage":{"inputTokens":9996,"outputTokens":12},"apiFallbackUsed":false,"exactPlanDebitAttested":false,"corelyConnected":false,"sendingEnabled":false,"learningEnabled":false}
```

Offline harness 76 + original SIWC 140 = **216 passing tests**. Exact source CI
[40332402606](https://github.com/moztechCEE/new-api/actions/runs/40332402606)
passed both Node 20 and 22. This focused CI does not run Go gateway or Corely
regressions, and is not customer-service quality, latency or delivery acceptance.

Seven preceding normal sign-in attempts did not produce a successful generation
receipt: initial unclassified RPC failure; `thread/start` sandbox enum mismatch;
`turn/start` unsupported readOnly.access override; lifecycle protocol mismatch;
two unclassified unsupported-event failures; then the named disabled-host
warning. These failures were preserved, not replaced by the successful result.
Pre-turn errors were reproduced without credentials. Later failed attempts had
issued turn/start and must not be described as zero model usage. All local
processes and their temporary homes were ended/removed; no remote revocation is
claimed from local cleanup.

This proves the **official, owner-operated local harness route**, not a New API
channel or automatic remotely hosted Corely backend. Exact included-plan debit,
Eason/fallback routing, customer-quality evaluation and the Corely manual
send/learning chain remain unverified. Existing API quality review is unchanged.

## Whole-Corely personal-first foundation — 2026-10-26 (not deployed)

The owner clarified that **all Corely model work**, including intent/evidence
selection, composition, independent quality review and image understanding,
must prefer Info, then Eason, and use the existing API key only after both
managed sessions prove included quota exhaustion. Replacing wording generation
alone while leaving decision and review on the API does not meet that goal.
Current learning persistence/deduplication/adoption is database/lexical work,
not another hidden LLM or embedding endpoint; future model jobs must use the
same shared routing seam. This does not authorize production changes.

The companion Corely checkout now has an opt-in shared model transport contract
for its four current workloads and all generation/review purposes. It binds the
account, exact Sol model, tenant/brand, job, complete prompt, image and strict
schema to every receipt. Only authenticated, request-bound quota exhaustion may
advance Info → Eason → API. Missing login, missing adapter, timeout, unsupported
schema, refusal and malformed output hold; they do not silently spend API
credits. Failed API attempts retain API provenance, not a personal-usage label.
The default API path remains unchanged. No transport is registered, no trusted
pipeline scope is wired yet, and no live services were switched.

The local candidate extension contains:

- `codex-harness-candidate-contract.mjs`: bounded server-enrolled `moztech-test`
  packet validation, a canonical source digest, source-type separation and
  strict candidate/citation output. The digest is not authentication; authority
  still comes from the fixed Corely OAuth/TLS transport.
- `codex-harness-corely-client.mjs`: a separate, fixed public native Corely
  client, S256/state/issuer checks, literal loopback callback, short-lived
  in-memory grant, fixed HTTPS endpoints, bounded responses, source freshness,
  identical idempotent retry, exact saved-text readback and revocation. OAuth
  values and source read receipts never enter the model. The CLI deliberately
  stops at `API_PHASES_NOT_MIGRATED` before case preparation or review, because
  the current candidate endpoint still bills API decision/review. Its explicit
  literal-true injection is only used by offline contract fixtures, not CLI.
- `codex-harness-permissions-canary.mjs`: no-credential/no-model native OS
  confinement checks on files created by the test, a symlink, writes and a
  loopback network control. The same named profile and executable digest must
  guard the candidate turn; tools/connectors/browser remain separately off.

The existing three-capability candidate grant has not been expanded into a
general model-job grant. A full model-job transport needs a separately scoped
authorization and server-owned synthetic admission, cancellation/leases,
request/output receipts and independent ephemeral review turns. No user token
is to be imported into New API or copied from Luna/Codex caches. No public
arbitrary-execution service is exposed.

Offline Node 20 clean-environment regression at the candidate-foundation freeze
passes **304/304**: original SIWC 140, fixed harness 76, permissions contract 37,
candidate/client 51. These include a fake JSON-RPC executable and injected HTTP fixtures, not
native model or cloud acceptance. An initial client fixture mutated the same
created/read object and failed two assertions; the fixture was corrected to
model an actual read mismatch, without weakening source validation.

**Native canary first failure and correction:** a main-agent independent run and a separate agent
reproduction returned `OUTSIDE_READ_ALLOWED` with zero model requests. A
synthetic-only diagnostic confirmed that the outside fixture itself was read
(exit 0, exact synthetic marker), not merely a warning on stdout. Earlier
agent-reported passing observations do not override this failure. The cause was
`:minimal=read` admitting temporary trees. The shared profile now generically
denies `:tmpdir` and `:slash_tmp`, reopening only the specific workspace read
subtree. Additional independent `/tmp` file/symlink controls and proof checks
were added. Agent and main native reruns pass with the same executable SHA
`0d5ac7aae20c4eda6242428d5e218c55ba96d8763fda2a271088ff37104b9d28`:
inside read and network-tool controls work, while outside direct/symlink reads,
workspace create/modify and loopback network are denied. Zero model requests or
existing auth-cache reads. This is not a new candidate turn or full deployment
acceptance, and the earlier fixed smoke is not used in place of this proof.

No new OAuth ceremony, candidate/model request, API fallback, cloud/VM update,
customer send, learning write or existing data change occurred in this slice.
Exact new-source CI and any repaired native canary must be recorded separately.

## Reusable managed model-session engine (offline, not connected)

`codex-harness-model-session.mjs` now exports a local in-process model port,
without a CLI prompt input, HTTP listener, account rotation or API transport.
Info and Eason must each perform an explicit normal official login in separate
empty HOME/CODEX_HOME, with ephemeral credentials held by their own official
process. No cache import or API/provider/proxy environment is inherited.
One process can remain warm, but every call uses a new ephemeral thread and
fresh workspace, with no history/resume/memory/tools/apps/browser. Independent
review must be a distinct call, never a generator self-approval.

The exact complete Corely system prompt becomes `baseInstructions`, the user
input remains user text and the full strict schema becomes `outputSchema`.
Reasoning effort is checked against the native model catalog; requested low
verbosity uses the supported thread config field, not an invented turn field.
The fixed developer boundary forbids execution or invented results, but permits
truthfully describing explicitly supplied server-verified action evidence.
Images remain `false` and are rejected, not silently dropped or sent to API.

Account/plan/model, named permission profile, effective roots, native executable
hash and call/input/schema IDs are checked. The native canary is reused. Calls
are serialized per session, have bounded abort/interrupt/unsubscribe/cleanup,
and reject unknown actions/control events, reroutes, account drift and late or
premature completion. Final text must match the correlated completed turn and
native usage. Strict output validation is independent of a success label.

Only the correlated native terminal `usageLimitExceeded` after verified managed
identity yields a quota receipt. HTTP 429, `rateLimitExceeded`, session budget,
auth failure, timeout, partial output or unknown errors are holds. The module
does not switch accounts itself; the Corely shared router owns Info → Eason →
existing API after two valid quota receipts. Native usage and authentication do
not establish exact included-plan debit. Separate frozen metadata records the
adapter version/executable hash without adding unrecognized Corely receipt keys.

Independent review found and repaired:

1. A premature turn stream during `thread/start` could be accepted before this
   call sent `turn/start`. A request-admission fence now rejects it; the same
   exploit returns `PROTOCOL_ERROR` and sends zero turn requests.
2. An unconditional ban on describing executed actions contradicted trustworthy
   post-tool facts. The boundary now preserves factual confirmation without
   giving the model execution authority.
3. Idle remote-control enablement, filesystem errors/uncertain cleanup,
   already-aborted RPC admission and a hung login-UI callback now fail closed
   with bounded fixed errors rather than leaking paths or keeping an uncertain
   warm session alive.

An earlier parallel fake-process run passed 248/249 because its test-only
one-second RPC budget timed out under concurrent fixture startup. The fixture
budget alone was adjusted to bounded production-representative values; native
defaults/gates were not relaxed. The final exact Node 20 clean-environment run
of original SIWC plus every harness suite passes **395/395**, zero fail/skip/
cancel: 140 + 76 + 37 + 51 + 91. The independent model-session review reran 91/91.
This includes synthetic stdio executables and injected HTTP/loopback fixtures,
not a real login/model call, hosted-use eligibility or customer-service E2E.

Companion Corely initial runtime `1e5a0593` passed exact CI40343696912; subsequent
pure bounded broker source `d2beac8c` has 6,818 local passing tests and is awaiting
its own exact CI. It still has no HTTP/OAuth/producer registration. The old
candidate grant is not a general model-job grant. Cross-service authenticated
DEV producers and server-enrolled synthetic SQL read fences are still needed
for candidate preparation, normal API manual final review and Worker jobs.
Normal DEV, New API VM, production and existing data remain unchanged.
