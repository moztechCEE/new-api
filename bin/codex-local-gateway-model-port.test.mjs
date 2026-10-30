import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { after, before, test } from 'node:test';
import { createCodexLocalGatewayModelTransports, createCodexLocalSourceAttestor, deriveCodexLocalAttestationKey } from './codex-local-gateway-model-port.mjs';
import { ModelContractError } from './corely-model-contract.mjs';

// Injected HTTP/SSE fixtures only: no credential, provider, DB, or listener.
const savedFetch = globalThis.fetch;
before(() => { globalThis.fetch = async () => { throw new Error('NETWORK_DISABLED_IN_TEST'); }; });
after(() => { globalThis.fetch = savedFetch; });
const URL = 'http://127.0.0.1:23157/v1/responses', MODEL = 'gpt-6.1-sol';
const TOKENS = { info: 'synthetic-info-gateway-token-00000001', eason: 'synthetic-eason-gateway-token-0000002' };
const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object'
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
const sha = value => createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');
function request(callId = 'local-call', extra = {}) {
  const content = { version: 1, callId, model: MODEL, workload: 'REPLY_LLM', purpose: 'reply_generation',
    scope: { tenantId: 'moztech', brandId: 'moztech-test', synthetic: true, jobId: 'local-job' },
    system: '合成事實🙂\r\n不可省略品質覆核。', user: '合成問題\r\n補充內容。', schemaSha256: null, ...extra };
  if (content.responseSchema) content.schemaSha256 = sha(content.responseSchema);
  return { ...content, inputSha256: sha(content) };
}
function completion(text = '合成回覆。', extra = {}) {
  return { id: 'synthetic-response', model: MODEL, status: 'completed',
    output: [{ type: 'message', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text }] }],
    usage: { input_tokens: 20, output_tokens: 7, total_tokens: 27, input_tokens_details: { cached_tokens: 3 } }, ...extra };
}
function sse(response = completion()) {
  return new Response(`data: ${JSON.stringify({ type: 'response.completed', response })}\n\n`,
    { headers: { 'content-type': 'text/event-stream' } });
}
const deferred = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; };
function harness(t, options = {}) {
  const owner = new AbortController(), calls = [], checks = []; let time = 1000;
  const proof = binding => ({ version: 1, accountAlias: binding.accountAlias, model: MODEL, authMode: 'managed_chatgpt',
    accountVerified: true, nativeChannelType: 57, localOnly: true, apiFallbackEnabled: false, freshLoginVerified: true,
    configurationRevision: 'a'.repeat(64), expiresAt: 300_000 });
  const instance = createCodexLocalGatewayModelTransports({ gatewayUrl: URL,
    accounts: { info: { gatewayToken: TOKENS.info }, eason: { gatewayToken: TOKENS.eason } },
    signal: owner.signal, now: () => time,
    attest: async context => { checks.push(context); return options.attest ? options.attest(context, proof(context.binding)) : proof(context.binding); },
    fetchImpl: async (url, init) => { calls.push({ url, init }); return options.fetch ? options.fetch(url, init) : sse(); },
    ...options.config });
  t.after(instance.close);
  return { instance, calls, checks, owner, setTime: value => { time = value; } };
}
const run = (state, input = request(), alias = 'info', signal = new AbortController().signal) => state.instance.ports[alias].generate(input, signal);

test('native local ports preserve full schema, prompt, hashes, usage, and per-account tokens without SIWC relabeling', async t => {
  const schema = { type: 'object', properties: { reply: { type: 'string', minLength: 2 } }, required: ['reply'], additionalProperties: false };
  const state = harness(t, { fetch: () => sse(completion('{"reply":"合成回覆"}')) });
  for (const alias of ['info', 'eason']) {
    const input = request(`call-${alias}`, { responseSchema: schema, reasoningEffort: 'low', verbosity: 'low',
      promptCache: { key: `support-${'b'.repeat(64)}`, userPrefixChars: 4 } });
    const result = await run(state, input, alias), wire = JSON.parse(state.calls.at(-1).init.body);
    assert.equal(result.authMode, 'managed_chatgpt'); assert.equal(result.accountAlias, alias); assert.equal(result.accountVerified, true);
    assert.equal(result.inputSha256, input.inputSha256); assert.equal(result.schemaSha256, sha(schema));
    assert.deepEqual(result.usage, { inputTokens: 20, outputTokens: 7, cachedInputTokens: 3 });
    assert.equal(wire.instructions, input.system); assert.deepEqual(wire.input, [{ role: 'user', content: input.user }]);
    assert.deepEqual(wire.text.format.schema, schema); assert.equal(wire.text.format.strict, true);
    assert.deepEqual(wire.reasoning, { effort: 'low' }); assert.equal(wire.text.verbosity, 'low');
    assert.equal(wire.store, false); assert.equal(wire.stream, true); assert.equal(wire.model, MODEL);
    assert.doesNotMatch(JSON.stringify(wire), /siwc|prompt_cache|cache_control|tools|synthetic-info-gateway/);
    assert.equal(state.calls.at(-1).url, URL); assert.equal(state.calls.at(-1).init.headers.Authorization, `Bearer ${TOKENS[alias]}`);
    assert.equal(state.calls.at(-1).init.redirect, 'error'); assert.equal(state.calls.at(-1).init.credentials, 'omit');
    assert.equal(state.calls.at(-1).init.cache, 'no-store');
    assert.equal(state.checks.at(-2).phase, 'before'); assert.equal(state.checks.at(-1).phase, 'after');
    assert.equal(state.checks.at(-2).handle, state.checks.at(-1).handle); assert.deepEqual(state.checks.at(-1).handle, {});
    assert.equal(Object.isFrozen(state.checks.at(-1).binding), true); assert.equal(Object.isFrozen(result), true);
  }
  assert.notEqual(state.checks[0].handle, state.checks[2].handle);
  assert.deepEqual(Object.keys(state.instance.ports), ['info', 'eason']);
  assert.deepEqual(state.instance.ports.info.capabilities, { text: true, structuredJson: true, images: false });
});

test('configuration denies nonliteral loopback, aliases, shared tokens and all paid API knobs', async t => {
  const cases = [
    ...['https://newapi-dev.corely.cc/v1/responses', 'http://localhost:23157/v1/responses', 'http://[::1]:23157/v1/responses',
      'http://127.1:23157/v1/responses', 'http://127.0.0.1:023157/v1/responses', 'http://127.0.0.1:80/v1/responses',
      'http://127.0.0.1:23157/v1/responses?alias=info', 'http://127.0.0.1:23157/v1/responses#x',
      'http://user@127.0.0.1:23157/v1/responses', 'http://127.0.0.1:23157/v1/chat/completions'].map(gatewayUrl => ({ gatewayUrl })),
    { accounts: { info: { gatewayToken: TOKENS.info }, eason: { gatewayToken: TOKENS.info } } },
    { accounts: { info: { gatewayToken: TOKENS.info }, other: { gatewayToken: TOKENS.eason } } },
    { apiKey: 'synthetic-not-accepted' }, { apiFallbackEnabled: true }, { attest: undefined },
  ];
  for (const config of cases) assert.throws(() => harness(t, { config }), { code: 'INVALID_CONFIGURATION' });
});

test('attestation requires fresh exact account/config/native-channel evidence; no fetch on missing admission', async t => {
  const variants = [{ accountAlias: 'eason' }, { authMode: 'siwc_plan' }, { accountVerified: false }, { nativeChannelType: 1 },
    { localOnly: false }, { apiFallbackEnabled: true }, { freshLoginVerified: false }, { model: 'other' },
    { expiresAt: 1000 }, { configurationRevision: 'unverified' }, { rawSecret: 'never-export' }];
  for (const change of variants) {
    const state = harness(t, { attest: (_context, proof) => ({ ...proof, ...change }) });
    await assert.rejects(run(state), { code: 'ATTESTATION_FAILED' }); assert.equal(state.calls.length, 0);
  }
});

test('revoke/change/expire after model work never releases the otherwise valid result', async t => {
  for (const mode of ['revoke', 'revision', 'expire']) {
    const state = harness(t, { attest: ({ phase }, proof) => phase === 'before' ? proof :
      mode === 'revoke' ? { ...proof, freshLoginVerified: false } : mode === 'revision'
        ? { ...proof, configurationRevision: 'b'.repeat(64) } : { ...proof, expiresAt: 1000 } });
    await assert.rejects(run(state), { code: mode === 'revision' ? 'ATTESTATION_CHANGED' : 'ATTESTATION_FAILED' });
    assert.equal(state.calls.length, 1);
  }
});

test('generic/fabricated HTTP quota is held without automatic Eason, API, or raw error content', async t => {
  for (const status of [400, 401, 403, 429, 500]) {
    const state = harness(t, { fetch: () => new Response('{"error":{"code":"usage_limit_reached","message":"secret-fixture"}}', { status }) });
    await assert.rejects(run(state), error => error.code === 'GATEWAY_HTTP_FAILURE' && !JSON.stringify(error).includes('secret-fixture'));
    assert.equal(state.calls.length, 1); assert.equal(state.checks.length, 2);
    assert.equal(state.checks[1].outcome, 'http_failure'); assert.equal(state.checks[1].binding.accountAlias, 'info');
  }
});

test('all malformed model inputs are held before attestation and do not lose request/schema binding', async t => {
  for (const input of [{ ...request('bad-hash'), inputSha256: 'a'.repeat(64) }, request('other-model', { model: 'other' }),
    request('other-brand', { scope: { tenantId: 'moztech', brandId: 'real-brand', synthetic: true, jobId: 'job' } }),
    request('real-customer', { scope: { tenantId: 'moztech', brandId: 'moztech-test', synthetic: false, jobId: 'job' } }),
    request('image', { image: { url: 'https://example.invalid' } }), request('too-large', { user: 'a'.repeat(8 * 1_048_576 + 1) })]) {
    const state = harness(t);
    await assert.rejects(run(state, input), { code: 'INVALID_REQUEST' }); assert.equal(state.calls.length, 0); assert.equal(state.checks.length, 0);
  }
});

test('SSE completion, exact model, safe bounded usage and full output schema are mandatory', async t => {
  const schema = { type: 'object', properties: { reply: { type: 'string' } }, required: ['reply'], additionalProperties: false };
  const cases = [completion('answer', { model: 'other' }), completion('answer', { status: 'incomplete' }),
    completion('answer', { usage: undefined }), completion('answer', { usage: { input_tokens: -1, output_tokens: 1, total_tokens: 0 } }),
    completion('answer', { usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2, input_tokens_details: { cached_tokens: 3 } } }),
    completion('answer', { usage: { input_tokens: 1, output_tokens: 1, total_tokens: 3 } }),
    completion('answer', { output: [{ type: 'function_call', name: 'send' }] })];
  for (const value of cases) {
    const state = harness(t, { fetch: () => sse(value) });
    await assert.rejects(run(state), { code: 'GATEWAY_RESPONSE_INVALID' }); assert.equal(state.calls.length, 1);
  }
  const state = harness(t, { fetch: () => sse(completion('{"reply":"ok","unapproved":true}')) });
  await assert.rejects(run(state, request('schema', { responseSchema: schema })), { code: 'INVALID_STRUCTURED_OUTPUT' });
});

test('redirect, content type, truncated/oversized stream cannot establish success', async t => {
  for (const fetch of [() => new Response('not SSE', { headers: { 'content-type': 'text/html' } }),
    () => new Response('data: {"type":"response.created","response":{"id":"only-created"}}\n\n', { headers: { 'content-type': 'text/event-stream' } }),
    () => new Response('a'.repeat(1_048_577), { headers: { 'content-type': 'text/event-stream' } }),
    () => { const response = sse(); Object.defineProperty(response, 'url', { value: 'https://example.invalid' }); return response; }]) {
    const state = harness(t, { fetch }); await assert.rejects(run(state), { code: 'GATEWAY_RESPONSE_INVALID' });
    assert.equal(state.calls.length, 1);
  }
});

test('per-alias replay and concurrent duplicate are denied; no retry after uncertain failure', async t => {
  const waiting = deferred(), entered = deferred();
  const state = harness(t, { fetch: () => { entered.resolve(); return waiting.promise; } });
  const first = run(state); await entered.promise;
  await assert.rejects(run(state), { code: 'GATEWAY_REPLAY_OR_CAPACITY' });
  await assert.rejects(run(state, request('concurrent')), { code: 'GATEWAY_REPLAY_OR_CAPACITY' });
  waiting.reject(new Error('private-provider-secret'));
  await assert.rejects(first, { code: 'GATEWAY_UNAVAILABLE' });
  await assert.rejects(run(state), { code: 'GATEWAY_REPLAY_OR_CAPACITY' }); assert.equal(state.calls.length, 1);
});

test('caller cancellation during attestation discards late admission without dispatch', async t => {
  const waiting = deferred(), entered = deferred(), abort = new AbortController();
  const state = harness(t, { attest: (_context, proof) => { entered.resolve(); return waiting.promise.then(() => proof); } });
  const pending = run(state, request(), 'info', abort.signal); await entered.promise; abort.abort(new Error('secret-abort-reason'));
  await assert.rejects(pending, { code: 'GATEWAY_ABORTED' }); waiting.resolve(); await Promise.resolve();
  assert.equal(state.calls.length, 0);
});

test('abort/owner-close during model wait discards late provider success and retained port references', async t => {
  for (const mode of ['abort', 'close', 'owner']) {
    const waiting = deferred(), entered = deferred(), abort = new AbortController();
    const state = harness(t, { fetch: () => { entered.resolve(); return waiting.promise; } });
    const pending = run(state, request(), 'info', abort.signal); await entered.promise;
    if (mode === 'abort') abort.abort('private-reason'); else if (mode === 'close') state.instance.close(); else state.owner.abort();
    await assert.rejects(pending, { code: mode === 'abort' ? 'GATEWAY_ABORTED' : 'GATEWAY_CLOSED' });
    waiting.resolve(sse()); await Promise.resolve(); assert.equal(state.checks.length, 1);
    if (mode !== 'abort') await assert.rejects(run(state, request('retained')), { code: 'GATEWAY_CLOSED' });
  }
});

test('cancellation while the final attestation waits cannot accept its late success', async t => {
  const waiting = deferred(), entered = deferred(), abort = new AbortController();
  const state = harness(t, { attest: ({ phase }, proof) => {
    if (phase === 'before') return proof;
    entered.resolve(); return waiting.promise.then(() => proof);
  } });
  const pending = run(state, request(), 'info', abort.signal); await entered.promise; abort.abort();
  await assert.rejects(pending, { code: 'GATEWAY_ABORTED' }); waiting.resolve(); await Promise.resolve();
  assert.equal(state.calls.length, 1); assert.equal(state.checks.length, 2);
  await assert.rejects(run(state), { code: 'GATEWAY_REPLAY_OR_CAPACITY' });
});

test('stream cancellation interrupts a provider that has not closed its body without dispatching a retry', async t => {
  const started = deferred(), abort = new AbortController(); let cancelled = 0;
  const state = harness(t, { fetch: () => new Response(new ReadableStream({
    start(controller) { controller.enqueue(new TextEncoder().encode('data: {"type":"response.created","response":{"id":"still-running"}}\n\n')); started.resolve(); },
    cancel() { cancelled++; },
  }), { headers: { 'content-type': 'text/event-stream' } }) });
  const pending = run(state, request(), 'info', abort.signal); await started.promise; abort.abort();
  await assert.rejects(pending, { code: 'GATEWAY_ABORTED' }); await Promise.resolve();
  assert.equal(state.calls.length, 1); assert.equal(state.checks.length, 1); assert.equal(cancelled, 1);
});

test('owner TTL and backwards clocks fail closed before dispatch or late acceptance', async t => {
  const expired = harness(t); expired.setTime(121_000);
  await assert.rejects(run(expired), { code: 'GATEWAY_EXPIRED' }); assert.equal(expired.calls.length, 0);
  const backwards = harness(t); backwards.setTime(999);
  await assert.rejects(run(backwards), { code: 'GATEWAY_EXPIRED' }); assert.equal(backwards.calls.length, 0);
  const late = harness(t, { fetch: () => { late.setTime(121_001); return sse(); } });
  await assert.rejects(run(late), error => ['GATEWAY_EXPIRED', 'GATEWAY_CLOSED'].includes(error.code)); assert.equal(late.calls.length, 1);
});

test('caller mutation after dispatch cannot change request text, schema, or attestation identity', async t => {
  const waiting = deferred(), entered = deferred(), input = request();
  const state = harness(t, { attest: async (_context, proof) => { entered.resolve(); await waiting.promise; return proof; } });
  const pending = run(state, input); await entered.promise;
  input.system = 'mutated'; input.scope.synthetic = false; input.model = 'other'; waiting.resolve();
  const result = await pending; assert.equal(result.model, MODEL);
  assert.equal(JSON.parse(state.calls[0].init.body).instructions, '合成事實🙂\r\n不可省略品質覆核。');
});

test('throwing proxy/getter/config, attestation and transport exceptions never expose raw values', async t => {
  const hostile = new Proxy({}, { getPrototypeOf() { throw new Error('private-credential'); }, ownKeys() { throw new Error('private-credential'); } });
  assert.throws(() => createCodexLocalGatewayModelTransports(hostile), { code: 'INVALID_CONFIGURATION' });
  const configured = Object.defineProperty({}, 'gatewayUrl', { enumerable: true, get() { throw new Error('private-credential'); } });
  assert.throws(() => createCodexLocalGatewayModelTransports(configured), { code: 'INVALID_CONFIGURATION' });
  const state = harness(t, { attest: () => hostile });
  await assert.rejects(run(state), { code: 'ATTESTATION_FAILED' });
  const throws = harness(t, { attest: () => { throw hostile; } });
  await assert.rejects(run(throws), { code: 'ATTESTATION_FAILED' });
  const provider = harness(t, { fetch: () => { throw hostile; } });
  await assert.rejects(run(provider), error => error.code === 'GATEWAY_UNAVAILABLE' && !JSON.stringify(error).includes('private-credential'));
});

test('expiry of the original admitted proof cannot be renewed after model work to accept its late result', async t => {
  const state = harness(t, { attest: ({ phase }, proof) => ({ ...proof, expiresAt: phase === 'before' ? 2000 : 3000 }),
    fetch: () => { state.setTime(2001); return sse(); } });
  await assert.rejects(run(state), { code: 'ATTESTATION_FAILED' }); assert.equal(state.calls.length, 1);
});

test('untrusted response accessors cannot escape the fixed-error boundary during cleanup', async t => {
  const state = harness(t, { fetch: () => Object.defineProperty({}, 'body', { get() { throw new Error('private-response-value'); } }) });
  await assert.rejects(run(state), error => ['GATEWAY_UNAVAILABLE', 'GATEWAY_RESPONSE_INVALID'].includes(error.code) &&
    !JSON.stringify(error).includes('private-response-value'));
});

test('out-of-range numeric loopback ports report fixed configuration errors instead of URL parser values', t => {
  assert.throws(() => harness(t, { config: { gatewayUrl: 'http://127.0.0.1:99999/v1/responses' } }), { code: 'INVALID_CONFIGURATION' });
});

test('foreign typed errors with a code getter cannot leak values from the catch boundary', async t => {
  const error = new ModelContractError('INVALID_OUTPUT');
  Object.defineProperty(error, 'code', { get() { throw new Error('private-code-value'); } });
  const state = harness(t, { fetch: () => { throw error; } });
  await assert.rejects(run(state), failure => failure.code === 'GATEWAY_UNAVAILABLE' && !JSON.stringify(failure).includes('private-code-value'));
});

const SOURCE_VERSION = 'new-api.local-codex-attest.v1';
const FRESH_TOKENS = { access_token: 'synthetic-access', id_token: 'synthetic-id', refresh_token: 'synthetic-refresh', account_id: 'synthetic-account' };
const SOURCE_KEY = 'c233d1039bd4e49f09a30672ebb6f0b73578c77e8ef9da0a2305b4c3bb63000f';
const SOURCE_ACCOUNTS = { info: { channelId: 71, group: 'synthetic-info', credentialProofKey64hex: SOURCE_KEY, freshLoginVerified: true },
  eason: { channelId: 72, group: 'synthetic-eason', credentialProofKey64hex: 'e'.repeat(64), freshLoginVerified: true } };
function signSourceProof(proof, key = SOURCE_KEY) {
  const mac = createHmac('sha256', Buffer.from(key, 'hex'));
  for (const part of [proof.version, proof.nonce, proof.phase, proof.call_id_hash, proof.input_sha256,
    proof.schema_sha256 ?? '-', proof.model, proof.group, `${proof.channel_id}`, proof.route_revision, `${proof.issued_at}`, `${proof.expires_at}`]) {
    const bytes = Buffer.from(part, 'utf8'), length = Buffer.alloc(4); length.writeUInt32BE(bytes.length); mac.update(length); mac.update(bytes);
  }
  return { ...proof, proof: mac.digest('hex') };
}
function sourceContext(phase = 'before', extra = {}) {
  return Object.freeze({ phase, handle: Object.freeze({}), outcome: phase === 'before' ? 'pending' : 'success',
    binding: Object.freeze({ accountAlias: 'info', model: MODEL, callId: 'source-call', inputSha256: 'b'.repeat(64), schemaSha256: null, gatewayUrl: URL }),
    signal: new AbortController().signal, ...extra });
}
function sourceHarness(t, options = {}) {
  const owner = new AbortController(), calls = []; let time = 10_000;
  const instance = createCodexLocalSourceAttestor({ accounts: SOURCE_ACCOUNTS, signal: owner.signal, now: () => time,
    requestAttestation: async context => {
      calls.push(context);
      const proof = signSourceProof({ version: SOURCE_VERSION, channel_id: context.channelId, model: MODEL,
        group: context.payload.group, ...context.payload, route_revision: 'd'.repeat(64), issued_at: time, expires_at: time + 120_000 },
      SOURCE_ACCOUNTS[context.accountAlias].credentialProofKey64hex);
      return options.respond ? options.respond(context, proof) : proof;
    }, ...options.config });
  t.after(instance.close);
  return { instance, calls, owner, setTime: value => { time = value; } };
}
const finishContext = before => Object.freeze({ ...before, phase: 'after', outcome: 'success' });

test('source attestor uses the Go four-field framing vector and rejects credential objects with executable or extra data', () => {
  assert.equal(deriveCodexLocalAttestationKey(FRESH_TOKENS), SOURCE_KEY);
  for (const value of [{ ...FRESH_TOKENS, refresh_token: '' }, { ...FRESH_TOKENS, access_token: 'x'.repeat(65_537) },
    { ...FRESH_TOKENS, email: 'must-not-be-read' }, new Proxy(FRESH_TOKENS, {}),
    Object.defineProperty({ ...FRESH_TOKENS }, 'id_token', { enumerable: true, get() { throw new Error('private-token'); } })]) {
    assert.throws(() => deriveCodexLocalAttestationKey(value), error => error.code === 'INVALID_CONFIGURATION' && !`${error}`.includes('private-token'));
  }
});

test('source RPC is nonce/phase/model/group/hash bound, prompt-free and compatible with native before/after contracts', async t => {
  const state = sourceHarness(t), before = sourceContext(), admitted = await state.instance.attest(before);
  const confirmed = await state.instance.attest(finishContext(before));
  assert.equal(admitted.configurationRevision, 'd'.repeat(64)); assert.equal(confirmed.configurationRevision, admitted.configurationRevision);
  assert.equal(admitted.authMode, 'managed_chatgpt'); assert.equal(admitted.localOnly, true); assert.equal(admitted.apiFallbackEnabled, false);
  assert.equal(admitted.nativeChannelType, 57); assert.equal(admitted.accountVerified, true); assert.equal(admitted.freshLoginVerified, true);
  assert.equal(admitted.expiresAt, 130_000); assert.equal(Object.isFrozen(admitted), true);
  assert.equal(state.calls.length, 2);
  assert.notEqual(state.calls[0].payload.nonce, state.calls[1].payload.nonce);
  for (const rpc of state.calls) {
    assert.deepEqual(Object.keys(rpc).sort(), ['accountAlias', 'channelId', 'payload', 'signal']);
    assert.equal(Object.isFrozen(rpc), true); assert.equal(Object.isFrozen(rpc.payload), true);
    assert.deepEqual(Object.keys(rpc.payload).sort(), ['call_id_hash', 'group', 'input_sha256', 'model', 'nonce', 'phase', 'schema_sha256']);
    assert.equal(rpc.payload.call_id_hash, createHash('sha256').update(before.binding.callId, 'utf8').digest('hex'));
    assert.equal(rpc.payload.input_sha256, before.binding.inputSha256); assert.equal(rpc.payload.schema_sha256, null);
    assert.equal(rpc.accountAlias, 'info'); assert.equal(rpc.channelId, 71); assert.equal(rpc.payload.group, 'synthetic-info');
    assert.doesNotMatch(JSON.stringify(rpc), /synthetic-access|synthetic-refresh|synthetic-account|credentialProofKey|gatewayToken|system|user|prompt|mfa|password/i);
  }
});

test('source proofs independently bind both account aliases and a non-null structured-output schema', async t => {
  const state = sourceHarness(t);
  for (const alias of ['info', 'eason']) {
    const before = sourceContext('before', { binding: Object.freeze({ ...sourceContext().binding, accountAlias: alias,
      callId: `schema-${alias}`, schemaSha256: 'f'.repeat(64) }) });
    const first = await state.instance.attest(before), last = await state.instance.attest(finishContext(before));
    assert.equal(first.accountAlias, alias); assert.equal(last.accountAlias, alias);
    for (const rpc of state.calls.slice(-2)) {
      assert.equal(rpc.channelId, SOURCE_ACCOUNTS[alias].channelId); assert.equal(rpc.payload.group, SOURCE_ACCOUNTS[alias].group);
      assert.equal(rpc.payload.schema_sha256, 'f'.repeat(64));
    }
  }
});

test('source verifier rejects signed scope changes, expired/future/long proofs and unknown/accessor/proxy response values', async t => {
  for (const changes of [{ channel_id: 72 }, { model: 'other-model' }, { group: 'other-brand' }, { nonce: 'e'.repeat(64) },
    { phase: 'after' }, { call_id_hash: 'e'.repeat(64) }, { input_sha256: 'e'.repeat(64) }, { schema_sha256: 'e'.repeat(64) },
    { issued_at: 4000 }, { issued_at: 16_000 }, { expires_at: 10_000 }, { expires_at: 130_001 }, { credential: 'never-export' },
    { proof: '0'.repeat(64) }]) {
    const state = sourceHarness(t, { respond: (_context, proof) => changes.proof ? { ...proof, ...changes } : signSourceProof({ ...proof, ...changes }) });
    await assert.rejects(state.instance.attest(sourceContext()), { code: 'ATTESTATION_FAILED' });
  }
  for (const transform of [value => new Proxy(value, {}), value => Object.defineProperty(value, 'proof', {
    enumerable: true, get() { throw new Error('private-proof'); } })]) {
    const state = sourceHarness(t, { respond: (_context, proof) => transform(proof) });
    await assert.rejects(state.instance.attest(sourceContext()), error => error.code === 'ATTESTATION_FAILED' && !`${error}`.includes('private-proof'));
  }
});

test('source credential rotation and route revision changes hold results instead of renewing accepted state', async t => {
  for (const mode of ['credential', 'route']) {
    const state = sourceHarness(t, { respond: (context, proof) => context.payload.phase === 'before' ? proof : mode === 'credential'
      ? signSourceProof(proof, 'f'.repeat(64)) : signSourceProof({ ...proof, route_revision: 'e'.repeat(64) }) });
    const before = sourceContext(); await state.instance.attest(before);
    await assert.rejects(state.instance.attest(finishContext(before)), { code: mode === 'route' ? 'ATTESTATION_CHANGED' : 'ATTESTATION_FAILED' });
  }
  let revision = 'd'.repeat(64);
  const state = sourceHarness(t, { respond: (_context, proof) => signSourceProof({ ...proof, route_revision: revision }) });
  await state.instance.attest(sourceContext()); revision = 'e'.repeat(64);
  await assert.rejects(state.instance.attest(sourceContext('before', { handle: Object.freeze({}), binding: Object.freeze({ ...sourceContext().binding, callId: 'another-call' }) })), { code: 'ATTESTATION_CHANGED' });
});

test('source handles are single before/single after, exact-binding and cannot renew original proof expiry', async t => {
  const state = sourceHarness(t), before = sourceContext();
  await assert.rejects(state.instance.attest(finishContext(before)), { code: 'ATTESTATION_FAILED' });
  const valid = sourceContext(); await state.instance.attest(valid);
  await assert.rejects(state.instance.attest(valid), { code: 'ATTESTATION_FAILED' });
  await assert.rejects(state.instance.attest(finishContext(Object.freeze({ ...valid, binding: Object.freeze({ ...valid.binding, inputSha256: 'e'.repeat(64) }) }))), { code: 'ATTESTATION_FAILED' });
  const fresh = sourceContext('before', { binding: Object.freeze({ ...valid.binding, callId: 'fresh-call' }) });
  await state.instance.attest(fresh); await state.instance.attest(finishContext(fresh));
  await assert.rejects(state.instance.attest(finishContext(fresh)), { code: 'ATTESTATION_FAILED' });
  const expires = sourceHarness(t, { respond: (_context, proof) => signSourceProof({ ...proof, expires_at: 10_001 }) });
  const admitted = sourceContext(); await expires.instance.attest(admitted); expires.setTime(10_001);
  await assert.rejects(expires.instance.attest(finishContext(admitted)), { code: 'ATTESTATION_FAILED' });
});

test('source cancellation/close discards late proof and exposes only fixed errors without MFA or HTTP side channels', async t => {
  for (const mode of ['caller', 'owner', 'close']) {
    const waiting = deferred(), entered = deferred(), caller = new AbortController();
    const state = sourceHarness(t, { respond: (_context, proof) => { entered.resolve(); return waiting.promise.then(() => proof); } });
    const pending = state.instance.attest(sourceContext('before', { signal: caller.signal })); await entered.promise;
    if (mode === 'caller') caller.abort('private-reason'); else if (mode === 'owner') state.owner.abort(); else state.instance.close();
    await assert.rejects(pending, error => ['GATEWAY_ABORTED', 'GATEWAY_CLOSED'].includes(error.code) && !`${error}`.includes('private-reason'));
    waiting.resolve(); await Promise.resolve();
    assert.equal(state.calls.length, 1);
  }
});

test('source attestor can guard complete native model dispatch with exactly two non-secret proof RPCs', async t => {
  const source = sourceHarness(t), state = harness(t, { config: { attest: source.instance.attest } });
  const result = await run(state, request('source-native-integration'));
  assert.equal(result.status, 'success'); assert.equal(source.calls.length, 2); assert.equal(state.calls.length, 1);
});

test('source proof has its own five-second RPC cap and discards a non-cooperative late answer', async t => {
  const timeout = new AbortController(), entered = deferred(), waiting = deferred();
  t.mock.method(AbortSignal, 'timeout', ms => { assert.equal(ms, 5000); return timeout.signal; });
  const state = sourceHarness(t, { respond: (_context, proof) => { entered.resolve(); return waiting.promise.then(() => proof); } });
  const context = sourceContext(), pending = state.instance.attest(context); await entered.promise; timeout.abort();
  await assert.rejects(pending, { code: 'ATTESTATION_FAILED' }); waiting.resolve(); await Promise.resolve();
  await assert.rejects(state.instance.attest(context), { code: 'ATTESTATION_FAILED' }); assert.equal(state.calls.length, 1);
});

test('source admission rejects unsupported MFA/API knobs, stale login markers, shared credentials and executable account configs', t => {
  let mfaCalls = 0;
  for (const config of [{ requestMFA: () => { mfaCalls++; } }, { apiFallbackEnabled: true },
    { accounts: { ...SOURCE_ACCOUNTS, info: { ...SOURCE_ACCOUNTS.info, freshLoginVerified: false } } },
    { accounts: { ...SOURCE_ACCOUNTS, eason: { ...SOURCE_ACCOUNTS.eason, channelId: 71 } } },
    { accounts: { ...SOURCE_ACCOUNTS, eason: { ...SOURCE_ACCOUNTS.eason, credentialProofKey64hex: SOURCE_KEY } } },
    { accounts: new Proxy(SOURCE_ACCOUNTS, {}) },
    { accounts: { ...SOURCE_ACCOUNTS, info: Object.defineProperty({ ...SOURCE_ACCOUNTS.info }, 'credentialProofKey64hex', {
      enumerable: true, get() { throw new Error('private-key'); } }) } }]) {
    assert.throws(() => sourceHarness(t, { config }), { code: 'INVALID_CONFIGURATION' });
  }
  assert.equal(mfaCalls, 0);
});

test('source monotonic owner expiry and an aborted before handle cannot be revived with another signal', async t => {
  const old = sourceHarness(t); old.setTime(9999);
  await assert.rejects(old.instance.attest(sourceContext()), { code: 'GATEWAY_EXPIRED' });
  const expired = sourceHarness(t); expired.setTime(130_000);
  await assert.rejects(expired.instance.attest(sourceContext()), error => ['GATEWAY_EXPIRED', 'GATEWAY_CLOSED'].includes(error.code));
  const state = sourceHarness(t), before = sourceContext(); await state.instance.attest(before);
  await assert.rejects(state.instance.attest(finishContext({ ...before, signal: new AbortController().signal })), { code: 'ATTESTATION_FAILED' });
  await assert.rejects(state.instance.attest(finishContext(before)), { code: 'ATTESTATION_FAILED' });
});

test('native source waits have separate phase caps and cannot spend or outlive the model-only sixty-second budget', async t => {
  const modelDeadlines = [], sourceDeadlines = [], preEntered = deferred(), preRelease = deferred(), postEntered = deferred(), postRelease = deferred();
  t.mock.method(AbortSignal, 'timeout', ms => {
    const deadline = new AbortController();
    if (ms === 60_000) modelDeadlines.push(deadline);
    else { assert.equal(ms, 5000); sourceDeadlines.push(deadline); }
    return deadline.signal;
  });
  const state = harness(t, { attest: ({ phase }, proof) => {
    if (phase === 'before') { preEntered.resolve(); return preRelease.promise.then(() => proof); }
    postEntered.resolve(); return postRelease.promise.then(() => proof);
  }, fetch: () => { state.setTime(64_000); return sse(); } });
  const observed = run(state).then(value => ({ value }), error => ({ error }));
  await preEntered.promise;
  assert.equal(modelDeadlines.length, 0, 'the model clock has not started while source authorization waits');
  assert.equal(sourceDeadlines.length, 1);
  state.setTime(5000); preRelease.resolve(); await postEntered.promise;
  assert.equal(modelDeadlines.length, 1); assert.equal(sourceDeadlines.length, 2);
  assert.equal(state.calls.length, 1);
  modelDeadlines[0].abort(); // Model completed at 59s; its 60s cap elapses during the independent post-check.
  await Promise.resolve(); assert.equal(state.checks.at(-1).signal.aborted, false);
  state.setTime(68_000); postRelease.resolve();
  const result = await observed; assert.equal(result.error, undefined); assert.equal(result.value.status, 'success');
  assert.equal(state.checks[0].signal, state.checks[1].signal, 'the source attestor retains one owner/caller lifetime across phases');
});

test('native model deadline still covers the entire unfinished SSE and never runs the after proof on timeout', async t => {
  let modelDeadline;
  t.mock.method(AbortSignal, 'timeout', ms => {
    const deadline = new AbortController(); if (ms === 60_000) modelDeadline = deadline;
    else assert.equal(ms, 5000);
    return deadline.signal;
  });
  const entered = deferred();
  const state = harness(t, { fetch: () => new Response(new ReadableStream({ start(controller) {
    controller.enqueue(new TextEncoder().encode('data: {"type":"response.created","response":{"id":"waiting"}}\n\n')); entered.resolve();
  } }), { headers: { 'content-type': 'text/event-stream' } }) });
  const pending = run(state); await entered.promise; modelDeadline.abort();
  await assert.rejects(pending, { code: 'GATEWAY_TIMEOUT' }); assert.equal(state.checks.length, 1);
});

test('native before and after source caps discard late attestations without weakening owner cancellation', async t => {
  for (const phase of ['before', 'after']) {
    const sourceDeadlines = [], entered = deferred(), release = deferred();
    const timeout = t.mock.method(AbortSignal, 'timeout', ms => {
      const deadline = new AbortController(); if (ms === 5000) sourceDeadlines.push(deadline);
      else assert.equal(ms, 60_000);
      return deadline.signal;
    });
    const state = harness(t, { attest: (context, proof) => {
      if (context.phase !== phase) return proof;
      entered.resolve(); return release.promise.then(() => proof);
    } });
    const pending = run(state); await entered.promise; sourceDeadlines.at(-1).abort();
    await assert.rejects(pending, { code: 'ATTESTATION_FAILED' }); release.resolve(); await Promise.resolve();
    assert.equal(state.calls.length, phase === 'before' ? 0 : 1); timeout.mock.restore();
  }
});
