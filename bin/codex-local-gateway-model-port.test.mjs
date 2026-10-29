import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { after, before, test } from 'node:test';
import { createCodexLocalGatewayModelTransports } from './codex-local-gateway-model-port.mjs';
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
