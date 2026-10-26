# Local Codex harness pilot

This is a **local, owner-operated, fixed synthetic probe** of the official Codex
agent, not an HTTP proxy, New API channel, automatic account pool or production
customer-service backend. No arbitrary prompts or real customer data are accepted.

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
