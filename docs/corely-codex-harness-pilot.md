# Local Codex harness pilot

## Latest actual result — Info direct SIWC inference passes (2026-10-27)

Runtime **d5b8f6d2b153b88c6517b0a56275a87ce061ac65** passed fresh548/548
offline tests and exact [Node20/22 CI40375664817](https://github.com/moztechCEE/new-api/actions/runs/40375664817).
Normal Info OAuth then produced a real completed `gpt-6.1-sol` response through
the public SIWC plan route: input17 / output11 / total28 tokens, expected output
hash `dda11e5f4241434fdd59c7726c7d6bad22141f13a877ff053de4b9ea71f187fb`.
Signed Info identity and granted plan scopes were verified; the process had no
API key, no fallback, and confirmed renewable-session revocation after the test.
Client correlation: `f907b636-f694-416b-8359-6edb2297c0b0`;
completion time `2026-10-26T18:14:23.185Z`.

The two resolved local defects were premature rejection of missing Content-Type
and assuming the terminal snapshot repeats previously completed output parts.
Neither required removing quality checks or changing FAQ/stage data.
This verifies an actual personal-plan-authorized inference, not the precise
subscription/credit debit amount, a New API gateway call, hosted Corely,
account failover or manual-edit/send/learning acceptance. No cloud change.
The next boundary is an explicitly approved persistent, owner-only SIWC session
on the dedicated New API DEV VM for synthetic Corely integration; no Codex/Luna
cache import. This question is pending, not an issued persistent authorization.

## 2026-10-27 SIWC VM clarification and bounded inference diagnosis

The managed native app-server restriction below must not be generalized to all
SIWC use. Official [self-hosted VM guidance](https://developers.openai.com/siwc/token-sharing-open-source/self-hosted-vms)
explicitly describes an open-source app on its owner's remote VM, using a
separate stable VM host identity and the selected tool's normal OAuth session.
This is distinct from offering a paid/hosted app to other users; it does not
automatically establish eligibility for Corely's multi-tenant hosted service.
No Codex/Luna credential cache may be substituted for this registration.

The actual check uses the public SIWC Responses route and Info's normal
authorization, with no API key fallback. A missing/incorrect Content-Type now
receives a bounded 16 KiB / 3-second structural diagnostic instead of immediately
discarding the body. Only fixed shape enums, hashed provider request IDs and a
generated client correlation ID can leave the process.

Diagnostic revision `5ef80dc9146430b61186d771f06ed39bcac5d317` passed exact
[Node20/22 CI40373017842](https://github.com/moztechCEE/new-api/actions/runs/40373017842).
Its single normal Info authorization and fixed inference returned HTTP200,
19 response headers, missing Content-Type and `SSE_SHAPED` body; no API key was
available. Client correlation: `cdf1175b-6ed2-495c-a9e5-6d64eb28382b`.
Session revocation was confirmed, with no credentials persisted.

The overly strict MIME guard was therefore a local compatibility defect, not
proof of a provider admission failure. The [official SDK stream parser](https://github.com/openai/openai-node/blob/main/src/internal/parse.ts)
chooses SSE parsing for stream requests before inspecting Content-Type. The
compatibility fix allows only missing MIME or exact SSE, then still requires
bounded valid events, exact model, matching final output and `response.completed`.
Explicit JSON/HTML/other MIME, empty bodies, failed/partial/mismatched streams
remain failures. Known plan-limit error codes are preserved without raw messages;
optional completion usage is checked and reduced to three numeric counts.

Fresh offline regression: **531/531**, zero fail/skip/cancel. The initial added
fixture incorrectly passed a ReadableStream to Buffer.from; correcting that
fixture did not change runtime success criteria. No live proof, VM credential
transfer, New API upstream channel or Corely connection is claimed by tests.

After the compatibility correction the full fresh offline suite passes
**537/537**, including headerless real-protocol completion, empty/partial/error
rejection, model/output consistency and safe usage receipts. A new live attempt
must still succeed; this test total is not personal-plan/Corely acceptance.

Runtime `96e71fc95cd909218f58ad10b7f07576752f5097` passed exact
[Node20/22 CI40373860924](https://github.com/moztechCEE/new-api/actions/runs/40373860924).
Its one fixed Info attempt reached a valid completed exact-model event, then
held on `SYNTHETIC_OUTPUT_MISMATCH` (correlation
`6afabc39-9811-4aa1-96ba-50c36ea75dbc`). No API fallback, and session revocation
confirmed. A further bounded diagnostic records only final/delta lengths,
hashes and equality flags to separate output assembly from model compliance;
it does not admit a mismatching reply. The full fresh suite remains 537/537.

Runtime `efc6b89470ad348eb3974f2395d0410832868eca` passed exact
[Node20/22 CI40374445300](https://github.com/moztechCEE/new-api/actions/runs/40374445300).
Its one normal Info attempt verified account and plan scope, completed the exact
model, and exposed the actual assembly defect: terminal text length0, streamed
text length27. The streamed hash
`dda11e5f4241434fdd59c7726c7d6bad22141f13a877ff053de4b9ea71f187fb`
exactly matches the fixed expected answer. Correlation:
`452fd656-5feb-4c1b-9efd-909ce6e6c1e5`. Revocation confirmed; no API key.

The next parser revision reconstructs text from indexed, identity-bound
`response.output_text.done` / completed output items when the terminal snapshot
contains no text, as the [official stream accumulator](https://github.com/openai/openai-node/blob/main/src/lib/responses/ResponseStream.ts)
does. It never accepts a delta alone: a terminal exact-model completion and
closed consistent output parts are required. Contradicting text, changed item or
response identity, partial/error/late data and bounds remain fail-closed.

## 2026-10-27 hosted-use correction and local guard

Fresh [official auth guidance](https://learn.chatgpt.com/docs/app-server#auth-endpoints)
explicitly excludes commercial/hosted services from app-server authentication.
The [SIWC public plan-usage terms](https://developers.openai.com/cookbook/articles/sign-in-with-chatgpt#usage-policy-and-terms)
require access confirmation before offering remotely hosted/paid apps to users;
the owner-operated OSS VM path is clarified above. Do not turn the managed
native-auth factory into Corely's cloud job relay or
use stock type57 credential import as a substitute. A normal Corely grant,
synthetic scope or operator approval does not confer provider access.

The factory now checks both real process.env and supplied sourceEnv for ten
known Cloud Run service/job/worker markers before filtering, filesystem/canary,
spawn, login or model execution. Presence including false/empty/inherited values
holds at `HOSTED_EXECUTION_REJECTED`; no approval override. This is bounded
misuse prevention, not arbitrary VM detection or an eligibility attestation.
Existing fixed local proofs remain local proofs, with exact debit unverified.

Author and main each reran fresh **528/528** offline SIWC+harness tests, zero
fail/skip/cancel; targeted134 and independent21 checks also pass. No real login,
model, API fallback, existing credential cache, cloud or Go channel mutation.
Frozen runtime **c30668cf45590b11911e0e90834af2ffc4826114** passed exact
[CI40369464872](https://github.com/moztechCEE/new-api/actions/runs/40369464872),
matching head SHA and Node20/22 SUCCESS. This is not a live model/billing test.

Normal UI currently shows New API channels0 / requests0, no Work connection
receipt, and existing SIWC support under account/workspace/client technical
review, not access confirmation. No extra inference retries were made. The
previous forward plan needs a supported hosted provider and resolved public
SIWC inference, not just a new DEV identity. Whole Corely is still BLOCKED.
Correction notice `5f401138-ef8d-41b5-8791-f7d4f1c47bc6` was queued to secondary,
one receipt pending, no read/ACK/native delivery; secondary remains paused.

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

### First native reusable-session attempt

Runtime `1bf304d8575dcdfce349c55b7d15119a954a0824` passed exact
[CI40348428192](https://github.com/moztechCEE/new-api/actions/runs/40348428192),
both Node 20/22 jobs. The main-agent native two-phase fixed synthetic probe then
held at **startup / `UNSUPPORTED_EVENT`**, before a login URL or generation.
The local process/temp home closed; no new account grant, model response, API
fallback, Corely connection, sending or learning was obtained. This first
failure is retained. It is being diagnosed using an empty-home/no-login native
startup and public notification classes only, not raw params or error text;
do not weaken unknown-event rejection or count CI as a native success.

The no-login diagnostic subsequently identified a concrete shape mismatch:
installed `RemoteControlStatusChangedNotification` defines a string status enum,
and the native startup sent `status: "disabled"`; the fake fixture/guard had
expected a nested `status.enabled: false`. Only public method/field types and
the static enum match were retained, not installation ID/server-name values or
raw params. Native `account/read` was null and no login/model/turn/API request
was made. The repair must accept only the documented disabled shape and keep
connecting/connected/errored/unknown/malformed states rejected; a new exact
source/CI and native preflight are required before another model attempt.

The minimal compatibility repair now passes **408/408** clean Node 20 offline
tests, zero fail/skip/cancel. Default fake flows emit the real native disabled
shape both idle and active, while connecting/connected/errored/unknown, the old
nested shape and malformed metadata remain rejected. The actual native
credential-free session factory now stops at expected `AUTH_REQUIRED`, not the
prior unsupported event; login-start/model/turn/API counts remain zero and its
local process/temp home were cleaned. Only the model-session pair changed;
exact new runtime CI is still required before the two-phase model retry.

### Native empty-environment / runtime-root compatibility

The disabled-notification repair was frozen as `a8972df2f1ecb648b6e2e72bc95892172302256e`
and exact [CI40350293131](https://github.com/moztechCEE/new-api/actions/runs/40350293131)
passed on Node 20/22. The next fixed two-phase attempt completed the normal
Info personal-account selection, then held at **generation / `SANDBOX_UNVERIFIED`**
before `turn/start`. The local session closed; no candidate, review, API backup,
Corely connection, send or learning result was obtained. This failure is retained.

Credential-free public-schema and native A/B controls identified the exact
contradiction: `environments: []` disables environment access and returns empty
`runtimeWorkspaceRoots`, even when a nonempty root was requested. Omitting the
environment override echoed the root, but would enable an environment and was
not chosen. The text-only engine now explicitly requests **empty roots** in both
thread and turn and requires the native thread response to contain exactly an
empty array. Unexpected, missing or malformed roots still hold before any turn.
The profile, no-network, empty environments/tools, canary, binary hash, fresh cwd,
ephemeral thread and no external instruction-source checks remain in force.
No file inputs or image capability are added. This is a stricter no-workspace
contract, not a permission relaxation to make the test pass.

The exact-empty no-auth native control matches all policy metadata and cleans
its thread/process/temp files; login/model-list/turn requests are zero. Clean
Node 20 focused SIWC+harness regression now passes **411/411**, zero fail/skip/
cancel. A new exact source CI is still required before another real model turn.
Companion Corely `d2beac8c29c0e68463f3f51d67ea8897ec816419` exact
[CI40348015374](https://github.com/moztechCEE/service-orchestrator/actions/runs/40348015374)
has passed. The separately approved DEV model-job grant is being implemented;
it does not complete producer/read-fence wiring or make New API a connected
personal upstream channel. Normal DEV, VM, production and existing data remain unchanged.

### Actual per-account generation and independent review (2026-10-26/27)

The empty-roots engine was frozen as `14dc1021f0ae04bf1550606d659b1a74c360ce01`.
Exact [CI40353251316](https://github.com/moztechCEE/new-api/actions/runs/40353251316)
passed on Node 20/22. Main independently reran all **411/411** offline tests,
zero fail/skip/cancel, then ran one fixed two-phase synthetic probe per account.
Each used a separate fresh managed process/home, normal official account
selection and **personal account**, not the company workspace. No existing
Codex/Luna auth cache or Platform API key was supplied.

| Native account receipt | Model | Generation | Separate-thread review |
| --- | --- | ---: | ---: |
| Info / managed ChatGPT / Pro | `gpt-6.1-sol` | 7,971 ms | 4,880 ms |
| Eason / managed ChatGPT / Pro | `gpt-6.1-sol` | 5,480 ms | 11,108 ms |

Both completed with schema-valid output, supported/answered independent review,
same-account checks and input/output usage receipts. Generator input/output
tokens were 5,793/30 and 5,791/30; reviewer input/output were 5,835/20 and
5,833/20, cached input zero. Both used the same verified official binary SHA
`0d5ac7aae20c4eda6242428d5e218c55ba96d8763fda2a271088ff37104b9d28`.
Their local sessions and temporary homes closed after testing. This cleanup is
not a claimed provider-side remote revocation.

These are actual managed-personal execution receipts without API fallback,
not just a model menu or login success. They are **not** exact plan-debit
attestation, a Corely-connected conversation, original-50 quality/latency
acceptance, live quota exhaustion/automatic failover, image support, manual
sending or learning proof. `exactPlanDebitAttested:false`,
`apiFallbackUsed:false`, `corelyConnected:false`, sending/learning false.
The earlier protocol and sandbox holds remain above and are not erased by
these successful probes. No cloud/VM/normal DEV/production changes occurred.

### Separate DEV model-job OAuth client — authorization only (2026-10-27)

`bin/codex-harness-model-job-client.mjs` implements the newly approved separate
`corely:dev-model-jobs` grant, not an expansion of the old three-capability
candidate client. It pins the exact isolated DEV issuer/resource, public client
`corely-local-model-jobs-dev` and literal loopback callback at port 47632. S256,
random state, exact issuer/code namespaces, one-use callback, no redirect
following, strict four-field/900-second token response and memory-only bearer
storage are enforced. No existing account credentials are read or imported.

The returned frozen object exposes only `receipt()` and `revoke()`: no bearer
accessor, resource read, job operation, provider call, customer send, approval or
learning ability. Its safe receipt explicitly says current server authority
`NOT_CHECKED` and job operations `NOT_IMPLEMENTED`; a connection is not personal
model execution, billing or whole-Corely proof. Expiry, invalid/backward clocks,
abort and failed revocation hold. Known grants in malformed bounded responses
are revoked; unknown token-exchange or cleanup outcomes stay explicitly
uncertain. Cleanup fanout, callback connections/attempts, body sizes and all
waits (including an uncooperative UI callback/fetch/body) are bounded.

Independent review identified a potential callback-response flush race before
release. The callback now settles only after response finish, followed by
graceful bounded listener shutdown; forced cleanup is not reported as success.
This was a source-level finding, not a reproduced live-browser failure. Offline
delayed-finish review and actual synthetic loopback tests pass.

Targeted client tests pass **90/90**; final clean Node20 SIWC+harness regression
passes **501/501**, zero failures/skips/cancels. Main independently reran all
501 with the external-network denial guard and matched the frozen file hashes.
All 14 workflow syntax checks
and diff check pass. Main separately paired the actual Corely
`PersonalModelJobOAuth` source with this client: fake current administrator,
direct in-process token/revoke calls and only the synthetic callback over
loopback. One PKCE exchange, narrow descriptor, principal acceptance, confirmed
revoke and subsequent principal rejection passed. No live Corely admin, cloud
grant, ChatGPT account/model, send, learning or API fallback was used.

Companion Corely authorization runtime
`0d44d507919d3e43f1777b3c066ea33d6e59a0c9` passed exact
[CI40356718251](https://github.com/moztechCEE/service-orchestrator/actions/runs/40356718251),
including ephemeral PostgreSQL authorization-snapshot and full integration
stability checks; local fresh **6,888/6,888** and forced build/types/lint pass.
The client is frozen/pushed as
**d406277d7aea198c186d9eb29aad261760c4f940**; exact
[CI40361803882](https://github.com/moztechCEE/new-api/actions/runs/40361803882)
was read back with matching head SHA and both Node20/22 jobs SUCCESS.
Neither authorization source is deployed. New API VM
channel/provider configuration remains unchanged. Model-job HTTP operations,
trusted DEV producers, server-owned synthetic read fences and normal
API/Worker/manual-final-review registration are still open.

This source/result checkpoint was queued to the authorized secondary shared
inbox as `3fb1a936-fb90-487d-8f41-27fd9bc8b8ae`. One receipt check is pending,
without read/ACK or native delivery; secondary remains paused. New cloud/IAM
scope must be separately confirmed, not inherited from old approvals.
