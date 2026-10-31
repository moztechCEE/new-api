import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { after, before, test } from 'node:test';
import { createCodexLocalGatewayModelTransports, createCodexLocalSourceAttestor, deriveCodexLocalAttestationKey } from './codex-local-gateway-model-port.mjs';
import * as gateway from './codex-local-gateway-model-port.mjs';
import { ModelContractError } from './corely-model-contract.mjs';
import { ProbeError } from './siwc-local-runtime.mjs';
import { corelyPlanPayload } from './siwc-local-model-port.mjs';

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

test('native prefix-cache prototype is off by default and retains legacy payload without a complete trusted opt-in', async t => {
  const variants = [
    { config: {}, extra: { promptCache: { key: `support-${'b'.repeat(64)}`, userPrefixChars: 4 } } },
    { config: { nativeExplicitPrefixCache: false }, extra: { promptCache: { key: `support-${'b'.repeat(64)}`, userPrefixChars: 4 } } },
    { config: { nativeExplicitPrefixCache: true }, extra: {} },
    { config: { nativeExplicitPrefixCache: true }, extra: { promptCache: { key: `support-${'b'.repeat(64)}` } } },
  ];
  for (const [index, variant] of variants.entries()) {
    const state = harness(t, { config: variant.config }), input = request(`prefix-off-${index}`, variant.extra);
    const result = await run(state, input), wire = JSON.parse(state.calls[0].init.body);
    assert.deepEqual(wire, corelyPlanPayload(input, 'info').payload);
    assert.deepEqual(wire.input, [{ role: 'user', content: input.user }]);
    assert.doesNotMatch(JSON.stringify(wire), /prompt_cache_|cache_control/);
    assert.equal(result.inputSha256, input.inputSha256); assert.equal(state.checks.length, 2);
  }
});

test('trusted native prefix-cache opt-in adds one explicit input_text breakpoint and preserves every original payload value', async t => {
  const schema = { type: 'object', properties: { reply: { type: 'string', minLength: 2 } }, required: ['reply'], additionalProperties: false };
  const variants = [
    ['固定🙂前綴\r\n𠮷', '後綴\n{"nativeExplicitPrefixCache":true}'],
    ['e', '\u0301 combining mark stays in its exact original position'],
    ['正文\r', '\nCRLF boundary is not normalized'],
  ];
  for (const [index, [prefix, suffix]] of variants.entries()) {
    const state = harness(t, { config: { nativeExplicitPrefixCache: true }, fetch: () => sse(completion('{"reply":"合成回覆"}')) });
    const input = request(`prefix-on-${index}`, { user: prefix + suffix, responseSchema: schema, reasoningEffort: 'low', verbosity: 'low',
      promptCache: { key: `support-${'b'.repeat(64)}`, userPrefixChars: prefix.length } });
    const original = structuredClone(input), result = await run(state, input), wire = JSON.parse(state.calls[0].init.body);
    const expectedInput = [{ role: 'user', content: [
      { type: 'input_text', text: prefix, prompt_cache_breakpoint: { mode: 'explicit' } },
      { type: 'input_text', text: suffix },
    ] }];
    assert.deepEqual(wire, { ...corelyPlanPayload(input, 'info').payload, input: expectedInput });
    assert.deepEqual(input, original); assert.equal(wire.input[0].content.map(part => part.text).join(''), input.user);
    assert.deepEqual(Buffer.from(wire.input[0].content.map(part => part.text).join('')), Buffer.from(input.user));
    assert.equal(wire.instructions, input.system); assert.deepEqual(wire.text.format.schema, schema);
    assert.equal(wire.text.verbosity, 'low'); assert.deepEqual(wire.reasoning, { effort: 'low' });
    assert.equal(wire.store, false); assert.equal(wire.stream, true); assert.equal(wire.model, MODEL);
    for (const field of ['prompt_cache_key', 'prompt_cache_options', 'prompt_cache_retention', 'cache_control', 'previous_response_id', 'metadata']) {
      assert.equal(Object.hasOwn(wire, field), false);
    }
    assert.equal(JSON.stringify(wire).match(/prompt_cache_breakpoint/g)?.length, 1);
    assert.equal(result.inputSha256, input.inputSha256); assert.equal(result.schemaSha256, input.schemaSha256);
    assert.deepEqual(result.usage, { inputTokens: 20, outputTokens: 7, cachedInputTokens: 3 });
    assert.deepEqual(state.checks.map(check => check.phase), ['before', 'after']);
    // The shared SIWC serializer remains conservative even for the same hint.
    assert.deepEqual(corelyPlanPayload(input, 'info').payload.input, [{ role: 'user', content: input.user }]);
  }
});

test('native prefix-cache admission accepts only own literal booleans and never a request or prompt flag', async t => {
  for (const value of ['true', 1, null, new Boolean(true), {}, []]) {
    assert.throws(() => harness(t, { config: { nativeExplicitPrefixCache: value } }), { code: 'INVALID_CONFIGURATION' });
  }
  let getters = 0;
  const accessor = Object.defineProperty({}, 'nativeExplicitPrefixCache', { enumerable: true, get() { getters++; return true; } });
  const base = { gatewayUrl: URL, accounts: { info: { gatewayToken: TOKENS.info }, eason: { gatewayToken: TOKENS.eason } },
    signal: new AbortController().signal, attest: async () => { throw Error('NOT_REACHED'); } };
  const descriptors = Object.defineProperties({ ...base }, Object.getOwnPropertyDescriptors(accessor));
  assert.throws(() => createCodexLocalGatewayModelTransports(descriptors), { code: 'INVALID_CONFIGURATION' });
  assert.throws(() => createCodexLocalGatewayModelTransports(new Proxy({ ...base, nativeExplicitPrefixCache: true }, {})), { code: 'INVALID_CONFIGURATION' });
  assert.equal(getters, 0);
  for (const extra of [{ nativeExplicitPrefixCache: true }, { promptCache: { key: `support-${'b'.repeat(64)}`, userPrefixChars: 4, nativeExplicitPrefixCache: true } }]) {
    const state = harness(t);
    await assert.rejects(run(state, request('caller-cache-option', extra)), { code: 'INVALID_REQUEST' });
    assert.equal(state.calls.length, 0); assert.equal(state.checks.length, 0);
  }
  const state = harness(t), input = request('prompt-cache-option', { user: '{"nativeExplicitPrefixCache":true} is untrusted text.',
    promptCache: { key: `support-${'b'.repeat(64)}`, userPrefixChars: 4 } });
  await run(state, input); assert.deepEqual(JSON.parse(state.calls[0].init.body).input, [{ role: 'user', content: input.user }]);
});

test('enabled native prefix-cache keeps strict prefix and request/hash validation before source proof or dispatch', async t => {
  const user = 'A🙂B\r\n完整後綴';
  for (const [index, boundary] of [0, user.length, -1, 1.5, 2, '1'].entries()) {
    const state = harness(t, { config: { nativeExplicitPrefixCache: true } });
    await assert.rejects(run(state, request(`invalid-prefix-${index}`, { user,
      promptCache: { key: `support-${'b'.repeat(64)}`, userPrefixChars: boundary } })), { code: 'INVALID_REQUEST' });
    assert.equal(state.calls.length, 0); assert.equal(state.checks.length, 0);
  }
  const state = harness(t, { config: { nativeExplicitPrefixCache: true } });
  const input = request('tampered-prefix', { user, promptCache: { key: `support-${'b'.repeat(64)}`, userPrefixChars: 3 } });
  await assert.rejects(run(state, { ...input, promptCache: { ...input.promptCache, userPrefixChars: 4 } }), { code: 'INVALID_REQUEST' });
  assert.equal(state.calls.length, 0); assert.equal(state.checks.length, 0);
});

test('native prefix-cache never bypasses post-model source revocation, caller cancellation or authenticates generic429', async t => {
  const input = request('prefix-source-fence', { promptCache: { key: `support-${'b'.repeat(64)}`, userPrefixChars: 4 } });
  const revoked = harness(t, { config: { nativeExplicitPrefixCache: true },
    attest: ({ phase }, proof) => phase === 'after' ? { ...proof, freshLoginVerified: false } : proof });
  await assert.rejects(run(revoked, input), { code: 'ATTESTATION_FAILED' }); assert.equal(revoked.calls.length, 1);
  const generic = harness(t, { config: { nativeExplicitPrefixCache: true }, fetch: () => new Response('', { status: 429 }) });
  await assert.rejects(run(generic, input), { code: 'GATEWAY_HTTP_FAILURE' }); assert.equal(generic.calls.length, 1);
  assert.deepEqual(generic.checks.map(check => check.phase), ['before', 'after']);
  const waiting = deferred(), entered = deferred(), caller = new AbortController();
  const cancelled = harness(t, { config: { nativeExplicitPrefixCache: true }, fetch: () => { entered.resolve(); return waiting.promise; } });
  const pending = run(cancelled, input, 'info', caller.signal); await entered.promise; caller.abort();
  await assert.rejects(pending, { code: 'GATEWAY_ABORTED' }); waiting.resolve(sse()); await Promise.resolve();
  assert.equal(cancelled.calls.length, 1); assert.deepEqual(cancelled.checks.map(check => check.phase), ['before']);
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

const QUOTA_HEADERS = ['X-New-Api-Local-Codex-Nonce', 'X-New-Api-Local-Codex-Call-Sha256',
  'X-New-Api-Local-Codex-Input-Sha256', 'X-New-Api-Local-Codex-Schema-Sha256'];
const QUOTA_RECEIPT_HEADER = 'X-New-Api-Local-Codex-Quota';
function quotaReceipt(headers, alias = 'info', changes = {}) {
  const values = { nonce: headers[QUOTA_HEADERS[0]], call: headers[QUOTA_HEADERS[1]], input: headers[QUOTA_HEADERS[2]],
    schema: headers[QUOTA_HEADERS[3]], url: 'https://chatgpt.com/backend-api/codex/responses', model: MODEL, group: SOURCE_ACCOUNTS[alias].group,
    channel: `${SOURCE_ACCOUNTS[alias].channelId}`, status: '429', kind: 'usage_limit_reached', attempt: '1',
    issued: '10000', expires: '130000', ...changes };
  const mac = createHmac('sha256', Buffer.from(SOURCE_ACCOUNTS[alias].credentialProofKey64hex, 'hex'));
  for (const part of ['new-api.local-codex-quota.v1', values.nonce, values.call, values.input, values.schema, values.url, values.model,
    values.group, values.channel, values.status, values.kind, values.attempt, values.issued, values.expires]) {
    const bytes = Buffer.from(part, 'utf8'), length = Buffer.alloc(4); length.writeUInt32BE(bytes.length); mac.update(length); mac.update(bytes);
  }
  return `v1.${values.issued}.${values.expires}.${mac.digest('hex')}`;
}
const quotaContext = context => Object.freeze({ handle: context.handle, binding: context.binding, signal: context.signal });

test('quota HMAC framing matches the shared literal Go producer vector including actual upstream URL', () => {
  const headers = { [QUOTA_HEADERS[0]]: 'a'.repeat(64), [QUOTA_HEADERS[1]]: 'b'.repeat(64),
    [QUOTA_HEADERS[2]]: 'c'.repeat(64), [QUOTA_HEADERS[3]]: '-' };
  assert.equal(quotaReceipt(headers), 'v1.10000.130000.d32bf1ca651b432953ce64c201a0e023f707d5e7dc7e2cdf4f6c607d7b8fa2c7');
});

test('source quota callbacks release only bound hashes and verify one post-source data-plane receipt without exposing keys', async t => {
  const state = sourceHarness(t), before = sourceContext();
  await assert.rejects(async () => state.instance.quotaRequest(quotaContext(before)), { code: 'ATTESTATION_FAILED' });
  await state.instance.attest(before);
  const headers = state.instance.quotaRequest(quotaContext(before));
  assert.equal(Object.isFrozen(headers), true); assert.deepEqual(Object.keys(headers).sort(), [...QUOTA_HEADERS].sort());
  assert.doesNotMatch(JSON.stringify(headers), /synthetic-access|synthetic-refresh|credentialProofKey|gatewayToken|synthetic-account/);
  assert.throws(() => state.instance.quotaRequest(quotaContext(before)), { code: 'ATTESTATION_FAILED' });
  const receipt = quotaReceipt(headers);
  assert.throws(() => state.instance.quotaVerify({ ...quotaContext(before), status: 429, receipt }), { code: 'ATTESTATION_FAILED' });
  await state.instance.attest(finishContext(before));
  assert.equal(state.instance.quotaVerify(Object.freeze({ ...quotaContext(before), status: 429, receipt })), true);
  assert.throws(() => state.instance.quotaVerify({ ...quotaContext(before), status: 429, receipt }), { code: 'ATTESTATION_FAILED' });
  assert.deepEqual(Object.keys(state.instance).sort(), ['attest', 'close', 'quotaRequest', 'quotaVerify']);
});

test('quota receipts bind every scope/hash/status/attempt and expire without accepting a forged or stale header', async t => {
  for (const change of [{ nonce: 'e'.repeat(64) }, { call: 'e'.repeat(64) }, { input: 'e'.repeat(64) }, { schema: 'e'.repeat(64) },
    { url: 'https://not-official.invalid/backend-api/codex/responses' }, { model: 'other' }, { group: 'other-brand' }, { channel: '72' }, { status: '401' }, { kind: 'rate_limit_error' }, { attempt: '2' },
    { issued: '4000' }, { issued: '16000' }, { expires: '10000' }, { expires: '130001' }]) {
    const state = sourceHarness(t), before = sourceContext(); await state.instance.attest(before);
    const headers = state.instance.quotaRequest(quotaContext(before)); await state.instance.attest(finishContext(before));
    assert.throws(() => state.instance.quotaVerify({ ...quotaContext(before), status: 429, receipt: quotaReceipt(headers, 'info', change) }), { code: 'ATTESTATION_FAILED' });
  }
  const state = sourceHarness(t), before = sourceContext(); await state.instance.attest(before);
  const headers = state.instance.quotaRequest(quotaContext(before)); await state.instance.attest(finishContext(before)); state.setTime(130000);
  assert.throws(() => state.instance.quotaVerify({ ...quotaContext(before), status: 429, receipt: quotaReceipt(headers) }), error => ['GATEWAY_EXPIRED', 'GATEWAY_CLOSED'].includes(error.code));
});

// These are deterministic fixtures signed for the documented Go error path,
// not evidence that Info/Eason has naturally exhausted its personal allowance.
test('native quota results require both source phases and a valid actual-route receipt; bare errors never authorize fallback', async t => {
  for (const alias of ['info', 'eason']) {
    const source = sourceHarness(t), state = harness(t, { config: { attest: source.instance.attest,
      quotaRequest: source.instance.quotaRequest, quotaVerify: source.instance.quotaVerify },
    fetch: (_url, init) => new Response('{"error":{"type":"usage_limit_reached","message":"private-provider-diagnostic"}}', {
      status: 429, headers: { [QUOTA_RECEIPT_HEADER]: quotaReceipt(init.headers, alias) },
    }) });
    const input = request(`quota-${alias}`), result = await run(state, input, alias);
    assert.equal(result.status, 'quota_exhausted'); assert.equal(result.authenticated, true); assert.equal(result.code, 'QUOTA_EXHAUSTED');
    assert.equal(result.accountAlias, alias); assert.equal(result.inputSha256, input.inputSha256);
    assert.equal(source.calls.length, 2); assert.equal(state.calls.length, 1);
    assert.doesNotMatch(JSON.stringify(result), /private-provider|synthetic-access|synthetic-refresh|receipt|nonce|proof/);
  }
  for (const receipt of [undefined, 'v1.10000.130000.' + '0'.repeat(64), 'untrusted', 'x'.repeat(1000)]) {
    const source = sourceHarness(t), state = harness(t, { config: { attest: source.instance.attest,
      quotaRequest: source.instance.quotaRequest, quotaVerify: source.instance.quotaVerify },
    fetch: () => new Response('{"error":{"type":"usage_limit_reached"}}', { status: 429,
      headers: receipt === undefined ? {} : { [QUOTA_RECEIPT_HEADER]: receipt } }) });
    await assert.rejects(run(state), error => ['GATEWAY_HTTP_FAILURE', 'ATTESTATION_FAILED'].includes(error.code));
    assert.equal(state.calls.length, 1); assert.equal(source.calls.length, 2);
  }
});

test('native prefix-cache preserves authenticated typed-quota source and original request/schema bindings in a deterministic fixture', async t => {
  const source = sourceHarness(t), input = request('quota-prefix-binding', {
    promptCache: { key: `support-${'b'.repeat(64)}`, userPrefixChars: 4 },
    responseSchema: { type: 'object', properties: { reply: { type: 'string' } }, required: ['reply'], additionalProperties: false },
  });
  const state = harness(t, { config: { nativeExplicitPrefixCache: true, attest: source.instance.attest,
    quotaRequest: source.instance.quotaRequest, quotaVerify: source.instance.quotaVerify },
    fetch: (_url, init) => new Response('', { status: 429, headers: { [QUOTA_RECEIPT_HEADER]: quotaReceipt(init.headers) } }) });
  const result = await run(state, input), wire = JSON.parse(state.calls[0].init.body);
  assert.equal(result.status, 'quota_exhausted'); assert.equal(result.authenticated, true); assert.equal(result.code, 'QUOTA_EXHAUSTED');
  assert.equal(result.inputSha256, input.inputSha256); assert.equal(result.schemaSha256, input.schemaSha256);
  assert.equal(wire.input[0].content[0].prompt_cache_breakpoint.mode, 'explicit');
  assert.equal(wire.input[0].content.map(part => part.text).join(''), input.user);
  assert.equal(state.calls.length, 1); assert.equal(source.calls.length, 2);
  // Fixture authenticity is only this test's HMAC contract, never a live
  // allowance exhaustion, debit, cache hit or automatic account-switch proof.
});

test('quota outcome cannot bypass revoked/changed source, caller abort, or a partial successful-status stream', async t => {
  for (const mode of ['revoke', 'changed', 'partial', 'abort']) {
    const caller = new AbortController();
    const source = sourceHarness(t, { respond: (context, proof) => context.payload.phase === 'after' && mode === 'revoke' ? { ...proof, proof: '0'.repeat(64) } :
      context.payload.phase === 'after' && mode === 'changed' ? signSourceProof({ ...proof, route_revision: 'e'.repeat(64) }) : proof });
    const state = harness(t, { config: { attest: source.instance.attest, quotaRequest: source.instance.quotaRequest,
      quotaVerify: source.instance.quotaVerify }, fetch: (_url, init) => {
      if (mode === 'abort') caller.abort();
      const headers = { [QUOTA_RECEIPT_HEADER]: quotaReceipt(init.headers) };
      return mode === 'partial' ? new Response('data: {"type":"response.created"}\n\n', { headers: { ...headers, 'content-type': 'text/event-stream' } }) :
        new Response('{"error":{"type":"usage_limit_reached"}}', { status: 429, headers });
    } });
    await assert.rejects(run(state, request(), 'info', caller.signal)); assert.equal(state.calls.length, 1);
  }
});

test('native historical-regression admission is explicit, fixed-corpus only and never inferred from wire scope', async t => {
  const scope = { tenantId: 'moztech', brandId: 'moztech-test', dataClass: 'historical_regression',
    corpusSha256: 'c895a50c382ef87751f00cca0899b1660a0f77eca7b5cb72a8fc139573aba5e3', jobId: 'historical-local-test' };
  const denied = harness(t);
  await assert.rejects(run(denied, request('historical-denied', { scope })), { code: 'INVALID_REQUEST' }); assert.equal(denied.calls.length, 0);
  const allowed = harness(t, { config: { allowHistoricalRegression: true } });
  const result = await run(allowed, request('historical-allowed', { scope })); assert.equal(result.status, 'success');
  for (const invalid of [{ ...scope, synthetic: true }, { ...scope, corpusSha256: 'f'.repeat(64) }, { ...scope, brandId: 'real-brand' }]) {
    await assert.rejects(run(allowed, request('historical-invalid', { scope: invalid })), { code: 'INVALID_REQUEST' });
  }
  assert.equal(allowed.calls.length, 1);
});

test('optional quota callbacks are paired, synchronous and cannot leak rejection causes or executable header values', async t => {
  assert.throws(() => harness(t, { config: { quotaRequest: () => ({}) } }), { code: 'INVALID_CONFIGURATION' });
  assert.throws(() => harness(t, { config: { quotaVerify: () => true } }), { code: 'INVALID_CONFIGURATION' });
  for (const mode of ['request-promise', 'verify-promise', 'getter']) {
    const source = sourceHarness(t), state = harness(t, { config: { attest: source.instance.attest,
      quotaRequest: mode === 'request-promise' ? () => Promise.reject(new Error('private-quota-secret')) : mode === 'getter' ?
        () => Object.defineProperty({}, QUOTA_HEADERS[0], { enumerable: true, get() { throw new Error('private-quota-secret'); } }) : source.instance.quotaRequest,
      quotaVerify: mode === 'verify-promise' ? () => Promise.reject(new Error('private-quota-secret')) : source.instance.quotaVerify },
    fetch: (_url, init) => new Response('not read', { status: 429, headers: { [QUOTA_RECEIPT_HEADER]: quotaReceipt(init.headers) } }) });
    await assert.rejects(run(state), error => error.code === 'ATTESTATION_FAILED' && !`${error}`.includes('private-quota-secret'));
    assert.equal(state.calls.length, mode === 'verify-promise' ? 1 : 0);
  }
});

test('stream failures retain only a fixed private class while public errors, validation and single-attempt routing stay unchanged', async t => {
  const frame = value => `data: ${JSON.stringify(value)}\n\n`;
  const stream = text => new Response(text, { headers: { 'content-type': 'text/event-stream' } });
  const cases = [
    ['missing terminal', () => stream(frame({ type: 'response.created', response: { id: 'created-only' } })), 'TERMINAL_MISSING'],
    ['failed terminal', () => stream(frame({ type: 'response.failed', response: { error: { message: 'PRIVATE_STREAM_VALUE' } } })), 'TERMINAL_NOT_COMPLETED'],
    ['nontext output', () => sse(completion('', { output: [{ type: 'function_call', name: 'PRIVATE_STREAM_VALUE' }] })), 'NON_TEXT_OUTPUT'],
    ['missing usage', () => sse(completion('safe text', { usage: undefined })), 'USAGE_INVALID'],
    ['invalid usage', () => sse(completion('safe text', { usage: { input_tokens: 1, output_tokens: 2, total_tokens: 2 } })), 'USAGE_INVALID'],
    ['interrupted stream', () => new Response(new ReadableStream({ start(controller) {
      controller.error(new Error('PRIVATE_STREAM_VALUE'));
    } }), { headers: { 'content-type': 'text/event-stream' } }), 'STREAM_INTERRUPTED'],
    ['invalid UTF8', () => stream(new Uint8Array([0xff])), 'STREAM_INTERRUPTED'],
    ['invalid event', () => stream('data: {PRIVATE_STREAM_VALUE}\n\n'), 'STREAM_EVENT_INVALID'],
    ['invalid completion', () => sse(completion('safe text', { model: 'PRIVATE_STREAM_VALUE' })), 'COMPLETION_INVALID'],
    ['mismatched output', () => stream(frame({ type: 'response.output_text.delta', delta: 'PRIVATE_STREAM_VALUE' }) +
      frame({ type: 'response.completed', response: completion('different text') })), 'OUTPUT_MISMATCH'],
    ['stream limit', () => stream('x'.repeat(1_048_577)), 'STREAM_LIMIT'],
    ['output limit', () => stream(frame({ type: 'response.output_text.delta', delta: 'x'.repeat(65_537) })), 'STREAM_LIMIT'],
  ];
  for (const [name, response, responseFailureClass] of cases) await t.test(name, async child => {
    const state = harness(child, { fetch: response });
    await assert.rejects(run(state), error => {
      assert.equal(error.code, 'GATEWAY_RESPONSE_INVALID');
      const diagnostic = gateway.codexLocalGatewayResponseDiagnostic(error);
      assert.deepEqual(diagnostic, { responseFailureClass }); assert.equal(Object.isFrozen(diagnostic), true);
      assert.doesNotMatch(JSON.stringify({ error, diagnostic }), /PRIVATE_STREAM_VALUE|input_tokens|output_tokens|total_tokens|cause|body/);
      return true;
    });
    assert.equal(state.calls.length, 1); assert.equal(state.checks.length, 1);
    assert.equal(state.checks[0].binding.accountAlias, 'info');
  });
});

test('response diagnostics do not inspect foreign error getters or proxies and cannot be mutated through an error', async t => {
  let getters = 0;
  const getter = Object.create(ProbeError.prototype);
  Object.defineProperty(getter, 'code', { get() { getters++; throw new Error('PRIVATE_STREAM_VALUE'); } });
  const proxy = new Proxy(new ProbeError('INVALID_USAGE_RECEIPT'), {
    get() { getters++; throw new Error('PRIVATE_STREAM_VALUE'); },
    getOwnPropertyDescriptor() { getters++; throw new Error('PRIVATE_STREAM_VALUE'); },
    getPrototypeOf() { getters++; throw new Error('PRIVATE_STREAM_VALUE'); },
  });
  const revoked = Proxy.revocable(new ProbeError('INVALID_USAGE_RECEIPT'), {}); revoked.revoke();
  for (const [error, expectedCode, expected] of [[getter, 'GATEWAY_RESPONSE_INVALID', { responseFailureClass: 'UNKNOWN' }],
    [Object.assign(Object.create(ProbeError.prototype), { code: 'INVALID_USAGE_RECEIPT' }), 'GATEWAY_RESPONSE_INVALID', { responseFailureClass: 'UNKNOWN' }],
    [proxy, 'GATEWAY_UNAVAILABLE', undefined], [revoked.proxy, 'GATEWAY_UNAVAILABLE', undefined],
    [{ code: 'INVALID_USAGE_RECEIPT' }, 'GATEWAY_UNAVAILABLE', undefined]]) {
    const state = harness(t, { fetch: () => { throw error; } });
    await assert.rejects(run(state), failure => {
      assert.equal(failure.code, expectedCode);
      const before = gateway.codexLocalGatewayResponseDiagnostic(failure); assert.deepEqual(before, expected);
      Object.defineProperty(failure, 'responseFailureClass', { value: 'PRIVATE_STREAM_VALUE' });
      Object.defineProperty(failure, 'code', { get() { getters++; throw new Error('PRIVATE_STREAM_VALUE'); } });
      assert.equal(gateway.codexLocalGatewayResponseDiagnostic(failure), before);
      return true;
    });
    assert.equal(state.calls.length, 1);
  }
  assert.equal(getters, 0);
  assert.equal(gateway.codexLocalGatewayResponseDiagnostic(new ProbeError('INVALID_USAGE_RECEIPT')), undefined);
  assert.equal(gateway.codexLocalGatewayResponseDiagnostic(revoked.proxy), undefined);
  assert.equal(gateway.codexLocalGatewayResponseDiagnostic(
    new gateway.CodexLocalGatewayError('GATEWAY_RESPONSE_INVALID', 'TERMINAL_MISSING')), undefined);
});

test('source admission failures never borrow a stream parser classification', async t => {
  for (const phase of ['before', 'after']) await t.test(phase, async child => {
    const state = harness(child, { attest: (context, proof) => {
      if (context.phase === phase) throw new ProbeError('INVALID_USAGE_RECEIPT');
      return proof;
    } });
    await assert.rejects(run(state), error => {
      assert.equal(error.code, 'ATTESTATION_FAILED');
      assert.equal(gateway.codexLocalGatewayResponseDiagnostic(error), undefined); return true;
    });
    assert.equal(state.calls.length, phase === 'before' ? 0 : 1);
  });
});

test('owner cancellation and model timeout keep priority over a simultaneous stream failure classification', async t => {
  for (const mode of ['caller', 'owner', 'timeout']) await t.test(mode, async child => {
    const caller = new AbortController(); let deadline;
    child.mock.method(AbortSignal, 'timeout', milliseconds => {
      const controller = new AbortController(); if (milliseconds === 60_000) deadline = controller;
      return controller.signal;
    });
    const state = harness(child, { fetch: () => {
      if (mode === 'caller') caller.abort(); else if (mode === 'owner') state.owner.abort(); else deadline.abort();
      return new Response(new ReadableStream({ start(controller) { controller.error(new Error('PRIVATE_STREAM_VALUE')); } }),
        { headers: { 'content-type': 'text/event-stream' } });
    } });
    await assert.rejects(run(state, request(), 'info', caller.signal), error => {
      assert.equal(error.code, mode === 'caller' ? 'GATEWAY_ABORTED' : mode === 'owner' ? 'GATEWAY_CLOSED' : 'GATEWAY_TIMEOUT');
      assert.equal(gateway.codexLocalGatewayResponseDiagnostic(error), undefined); return true;
    });
    assert.equal(state.calls.length, 1);
  });
});
