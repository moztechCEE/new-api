import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { spawnSync } from 'node:child_process';
import { after, before, test } from 'node:test';
import { createCodexLocalGatewayModelTransports, createCodexLocalSourceAttestor, deriveCodexLocalAttestationKey } from './codex-local-gateway-model-port.mjs';
import * as gateway from './codex-local-gateway-model-port.mjs';
import { ModelContractError, snapshotModelRequest, snapshotModelResult } from './corely-model-contract.mjs';
import { ProbeError, consumePlanTextStream, isSettledPlanOutputFailure } from './siwc-local-runtime.mjs';
import { corelyPlanPayload, runCorelyPlanRequest } from './siwc-local-model-port.mjs';

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
const flush = async () => { for (let index = 0; index < 30; index++) await Promise.resolve(); };
function providerWorkAttempt(events, signal = new AbortController().signal) {
  let output, completed = false;
  const attempt = Object.freeze({ async run(operation) {
    assert.equal(this, attempt, 'the original opaque attempt is not cloned');
    events.push('work-start');
    try { output = await operation(signal); completed = true; return output; }
    finally { events.push('work-end'); }
  } });
  return { attempt, output: () => output, completed: () => completed };
}
const runProviderWork = (state, attempt, input = request(), signal = new AbortController().signal) =>
  state.instance.ports.info.generateWithProviderWork(input, signal, attempt);
function providerFailureHarness(t, options = {}) {
  return harness(t, { ...options, config: { dispatchProviderOperation: context => context.operation(context.signal),
    allowProviderFailureFallback: true, ...options.config } });
}

test('provider failures require a trusted own opt-in, preserve legacy errors and never accept request admission flags', async t => {
  for (const config of [{ allowProviderFailureFallback: true }, { allowProviderFailureFallback: 'true' }]) {
    assert.throws(() => harness(t, { config }), { code: 'INVALID_CONFIGURATION' });
  }
  let reads = 0;
  const getterConfig = { gatewayUrl: URL, accounts: { info: { gatewayToken: TOKENS.info }, eason: { gatewayToken: TOKENS.eason } },
    signal: new AbortController().signal, attest() {} };
  Object.defineProperty(getterConfig, 'allowProviderFailureFallback', { enumerable: true, get() { reads++; throw Error('PRIVATE_GETTER'); } });
  assert.throws(() => createCodexLocalGatewayModelTransports(getterConfig), { code: 'INVALID_CONFIGURATION' });
  assert.equal(reads, 0);
  for (const status of [401, 429, 504]) {
    const state = providerFailureHarness(t, { fetch: () => new Response('PRIVATE_HTTP_BODY', { status }) });
    await assert.rejects(run(state), { code: 'GATEWAY_HTTP_FAILURE' });
  }
  const state = providerFailureHarness(t);
  for (const input of [request('untrusted-flag', { allowProviderFailureFallback: true }),
    request('other-scope', { scope: { tenantId: 'other', brandId: 'other', synthetic: true, jobId: 'job' } })]) {
    await assert.rejects(runProviderWork(state, providerWorkAttempt([]).attempt, input), { code: 'INVALID_REQUEST' });
  }
  assert.equal(state.calls.length, 0); assert.equal(state.checks.length, 0);
});
test('completed HTTP provider failures are fixed bound receipts, not success, usage or quota claims', async t => {
  for (const [status, reason] of [[401, 'AUTHENTICATION'], [403, 'AUTHENTICATION'], [429, 'RATE_LIMIT'],
    [408, 'TIMEOUT'], [504, 'TIMEOUT'], [400, 'UPSTREAM'], [500, 'UPSTREAM']]) {
    const work = providerWorkAttempt([]), input = request('provider-http-'+status), state = providerFailureHarness(t, {
      fetch: () => new Response('PRIVATE_HTTP_BODY', { status }) });
    const result = await runProviderWork(state, work.attempt, input);
    assert.equal(result.status, 'provider_failure'); assert.equal(result.reason, reason);
    assert.equal(result.code, 'PROVIDER_UNAVAILABLE'); assert.equal(result.operationSettled, true);
    for (const key of ['callId', 'inputSha256', 'schemaSha256']) assert.equal(result[key], input[key]);
    assert.equal(result.accountAlias, 'info'); assert.equal(result.authMode, 'managed_chatgpt');
    assert.equal(work.completed(), true); assert.deepEqual(work.output(), {});
    assert.equal(Object.isFrozen(result), true); assert.equal(state.calls.length, 1);
    assert.deepEqual(state.checks.map(value => value.phase), ['before', 'after']);
    for (const key of ['text', 'usage', 'authenticated', 'completionStatus']) assert.equal(Object.hasOwn(result, key), false);
    assert.doesNotMatch(JSON.stringify(result), /PRIVATE_HTTP_BODY|receipt|nonce|proof|Bearer/);
  }
});
test('only a settled branded physical network rejection can become a provider failure', async t => {
  const real = gateway.createCodexLocalProviderNetworkFailure(); let reads = 0;
  assert.equal(gateway.isCodexLocalProviderNetworkFailure(real), true);
  for (const foreign of [null, false, {}, { ...real }, new Proxy({}, { get() { reads++; throw Error('PRIVATE_PROXY'); } }),
    Object.defineProperty({}, 'code', { get() { reads++; throw Error('PRIVATE_GETTER'); } })]) {
    assert.equal(gateway.isCodexLocalProviderNetworkFailure(foreign), false);
  }
  assert.equal(reads, 0);
  for (const branded of [true, false]) {
    const work = providerWorkAttempt([]), entered = deferred(), release = deferred(), state = providerFailureHarness(t, {
      fetch: () => { entered.resolve(); return release.promise; } });
    const pending = runProviderWork(state, work.attempt); await entered.promise;
    assert.equal(work.completed(), false); assert.deepEqual(state.checks.map(value => value.phase), ['before']);
    release.reject(branded ? gateway.createCodexLocalProviderNetworkFailure() : Error('PRIVATE_RAW_TRANSPORT_ERROR'));
    if (branded) assert.equal((await pending).reason, 'NETWORK');
    else await assert.rejects(pending, { code: 'GATEWAY_UNAVAILABLE' });
    assert.equal(work.completed(), branded); assert.equal(state.calls.length, 1);
    assert.deepEqual(state.checks.map(value => value.phase), branded ? ['before', 'after'] : ['before']);
  }
});
test('provider-failure receipts wait for the full after-proof and source validation', async t => {
  const reached = deferred(), release = deferred(), work = providerWorkAttempt([]), state = providerFailureHarness(t, {
    fetch: () => new Response('', { status: 401 }), attest: async (context, proof) => {
      if (context.phase === 'after') { reached.resolve(); await release.promise; } return proof;
    } });
  let settled = false; const pending = runProviderWork(state, work.attempt).finally(() => { settled = true; });
  await reached.promise; assert.equal(work.completed(), true); assert.equal(settled, false);
  release.resolve(); assert.equal((await pending).reason, 'AUTHENTICATION');
  for (const mode of ['revision', 'revoked', 'expired']) {
    const held = providerFailureHarness(t, { fetch: () => new Response('', { status: 401 }), attest: (context, proof) =>
      context.phase === 'before' ? proof : mode === 'revision' ? { ...proof, configurationRevision: 'b'.repeat(64) } :
        mode === 'revoked' ? { ...proof, freshLoginVerified: false } : { ...proof, expiresAt: 1000 } });
    await assert.rejects(runProviderWork(held, providerWorkAttempt([]).attempt), {
      code: mode === 'revision' ? 'ATTESTATION_CHANGED' : 'ATTESTATION_FAILED' });
  }
});
test('provider failures cannot outlive caller cancellation or classify an unfinished stream as settled', async t => {
  for (const stage of ['fetch', 'after']) {
    const entered = deferred(), release = deferred(), caller = new AbortController(), state = providerFailureHarness(t, {
      fetch: () => stage === 'fetch' ? (entered.resolve(), release.promise) : new Response('', { status: 401 }),
      attest: async (context, proof) => { if (stage === 'after' && context.phase === 'after') { entered.resolve(); await release.promise; } return proof; },
    });
    const pending = runProviderWork(state, providerWorkAttempt([]).attempt, request('failure-abort-'+stage), caller.signal);
    await entered.promise; caller.abort(false);
    await assert.rejects(pending, error => ['GATEWAY_ABORTED', 'GATEWAY_CLOSED'].includes(error.code));
    if (stage === 'fetch') release.reject(gateway.createCodexLocalProviderNetworkFailure()); else release.resolve();
    await flush(); assert.equal(state.calls.length, 1);
  }
  let deadline, stream;
  t.mock.method(AbortSignal, 'timeout', ms => { const c = new AbortController(); if (ms === 60000) deadline = c; return c.signal; });
  const work = providerWorkAttempt([]), state = providerFailureHarness(t, { fetch: () => new Response(new ReadableStream({
    start(controller) { stream = controller; },
  }), { headers: { 'content-type': 'text/event-stream' } }) });
  const pending = runProviderWork(state, work.attempt); await flush(); deadline.abort();
  await assert.rejects(pending, { code: 'GATEWAY_TIMEOUT' }); assert.equal(work.completed(), false);
  assert.deepEqual(state.checks.map(value => value.phase), ['before']);
  stream.enqueue(new TextEncoder().encode('data: {"type":"response.created","response":{"id":"late"}}\n\n')); await flush();
});
test('source and dispatch throws or a wrapper with unfinished physical work never become provider receipts', async t => {
  for (const stage of ['before', 'dispatch']) {
    const state = providerFailureHarness(t, { attest: stage === 'before' ? () => { throw gateway.createCodexLocalProviderNetworkFailure(); } : undefined,
      config: stage === 'dispatch' ? { dispatchProviderOperation: () => { throw gateway.createCodexLocalProviderNetworkFailure(); } } : {} });
    await assert.rejects(runProviderWork(state, providerWorkAttempt([]).attempt), { code: stage === 'before' ? 'ATTESTATION_FAILED' : 'GATEWAY_UNAVAILABLE' });
    assert.equal(state.calls.length, 0);
  }
  const entered = deferred(), release = deferred(), state = providerFailureHarness(t, {
    fetch: () => { entered.resolve(); return release.promise; }, config: { dispatchProviderOperation: async context => {
      void context.operation(context.signal); await entered.promise; return {};
    } } });
  await assert.rejects(runProviderWork(state, providerWorkAttempt([]).attempt), { code: 'GATEWAY_CLOSED' });
  release.reject(gateway.createCodexLocalProviderNetworkFailure()); await flush();
  assert.deepEqual(state.checks.map(value => value.phase), ['before']);
});
test('full EOF with valid usage may report empty or schema-invalid output without publishing that usage', async t => {
  for (const mode of ['empty', 'whitespace', 'schema']) {
    const input = request('failure-output-'+mode, mode === 'schema' ? { responseSchema: { type: 'object',
      additionalProperties: false, required: ['ok'], properties: { ok: { type: 'boolean' } } } } : {});
    const state = providerFailureHarness(t, { fetch: () => sse(completion(mode === 'empty' ? '' : mode === 'whitespace' ? '  ' : '{"ok":"wrong"}')) });
    const result = await runProviderWork(state, providerWorkAttempt([]).attempt, input);
    assert.equal(result.status, 'provider_failure'); assert.equal(result.reason, 'INVALID_OUTPUT');
    assert.equal(Object.hasOwn(result, 'usage'), false); assert.equal(Object.hasOwn(result, 'text'), false);
    assert.deepEqual(state.checks.map(value => value.phase), ['before', 'after']);
  }
  for (const usage of [undefined, { input_tokens: 1, output_tokens: -1, total_tokens: 0 },
    { input_tokens: 1, output_tokens: 1, total_tokens: 3 },
    { input_tokens: 1, output_tokens: 1, total_tokens: 2, input_tokens_details: { cached_tokens: 2 } },
    { input_tokens: Number.MAX_SAFE_INTEGER + 1, output_tokens: 0, total_tokens: Number.MAX_SAFE_INTEGER + 1 }]) {
    const state = providerFailureHarness(t, { fetch: () => sse(completion('', { usage })) });
    await assert.rejects(runProviderWork(state, providerWorkAttempt([]).attempt), { code: 'GATEWAY_RESPONSE_INVALID' });
    assert.deepEqual(state.checks.map(value => value.phase), ['before']);
  }
  const inconsistent = providerFailureHarness(t, { fetch: () => new Response(
    'data: {"type":"response.output_text.delta","delta":"different"}\n\n'+
      `data: ${JSON.stringify({ type: 'response.completed', response: completion('final') })}\n\n`,
    { headers: { 'content-type': 'text/event-stream' } }) });
  await assert.rejects(runProviderWork(inconsistent, providerWorkAttempt([]).attempt), { code: 'GATEWAY_RESPONSE_INVALID' });
});
test('failure receipt contract is strict opt-in and parser failure brands cannot be forged by options or error fields', async () => {
  const input = request('bound-provider-failure'), receipt = { accountAlias: 'info', authMode: 'managed_chatgpt', accountVerified: true,
    model: MODEL, callId: input.callId, inputSha256: input.inputSha256, schemaSha256: input.schemaSha256,
    status: 'provider_failure', code: 'PROVIDER_UNAVAILABLE', reason: 'NETWORK', operationSettled: true };
  const option = { allowProviderFailureFallback: true };
  assert.equal(snapshotModelResult(receipt, input, 'info', 'managed_chatgpt', option).reason, 'NETWORK');
  for (const value of [undefined, { allowProviderFailureFallback: false }, true, new Proxy(option, {}), Object.create(option),
    { ...option, extra: true }, Object.defineProperty({}, 'allowProviderFailureFallback', { enumerable: true, get() { throw Error('PRIVATE_GETTER'); } })]) {
    assert.throws(() => snapshotModelResult(receipt, input, 'info', 'managed_chatgpt', value), { code: 'INVALID_RECEIPT' });
  }
  for (const change of [{ accountAlias: 'eason' }, { callId: 'other' }, { inputSha256: 'a'.repeat(64) }, { schemaSha256: 'b'.repeat(64) },
    { code: 'QUOTA_EXHAUSTED' }, { reason: 'unknown' }, { operationSettled: false }, { text: 'PRIVATE_TEXT' }, { usage: {} }, { authenticated: true }]) {
    assert.throws(() => snapshotModelResult({ ...receipt, ...change }, input, 'info', 'managed_chatgpt', option), { code: 'INVALID_RECEIPT' });
  }
  assert.throws(() => snapshotModelResult({ ...receipt, authMode: 'siwc_plan' }, input, 'info', 'siwc_plan', option), { code: 'INVALID_RECEIPT' });
  for (const options of [true, {}, new Proxy({ classifySettledOutputFailure: true }, {}),
    Object.create({ classifySettledOutputFailure: true }), { classifySettledOutputFailure: 'true' }]) {
    await assert.rejects(consumePlanTextStream(sse(completion('')).body, new AbortController().signal, undefined, options), { code: 'INVALID_STREAM_OPTIONS' });
  }
  let caught; try { await consumePlanTextStream(sse(completion('')).body, new AbortController().signal, undefined,
    { classifySettledOutputFailure: true }); } catch (error) { caught = error; }
  assert.equal(isSettledPlanOutputFailure(caught), true); assert.equal(isSettledPlanOutputFailure({ code: caught.code }), false);
});

test('provider-work method is constructor-capability-only and legacy generate never invokes it', async t => {
  const legacy = harness(t);
  assert.equal(Object.hasOwn(legacy.instance.ports.info, 'generateWithProviderWork'), false);
  for (const value of [true, {}, new Proxy(() => {}, {})]) {
    assert.throws(() => harness(t, { config: { dispatchProviderOperation: value } }), { code: 'INVALID_CONFIGURATION' });
  }
  let dispatches = 0;
  const configured = harness(t, { config: { dispatchProviderOperation: () => { dispatches++; throw Error('NOT_USED_BY_LEGACY'); } } });
  const old = await run(configured);
  assert.equal(dispatches, 0); assert.equal(old.status, 'success');
  assert.deepEqual(old.usage, { inputTokens: 20, outputTokens: 7, cachedInputTokens: 3 });
});
test('provider-work operation includes exact full schema, validated usage and result before after-proof', async t => {
  const events = [], work = providerWorkAttempt(events), input = request('provider-work-schema', {
    responseSchema: { type: 'object', additionalProperties: false, required: ['ok'], properties: { ok: { type: 'boolean' } } },
    reasoningEffort: 'low' });
  const state = harness(t, { attest: (context, proof) => { events.push(context.phase); return proof; },
    fetch: (_url, init) => { events.push('fetch'); assert.deepEqual(JSON.parse(init.body), corelyPlanPayload(input, 'info').payload);
      return sse(completion('{"ok":true}')); }, config: { dispatchProviderOperation: context => {
      assert.deepEqual(Object.keys(context).sort(), ['accountAlias', 'operation', 'request', 'signal']);
      assert.equal(Object.isFrozen(context), true); assert.equal(Object.isFrozen(context.request), true);
      assert.equal(context.accountAlias, 'info'); assert.equal(context.request.inputSha256, input.inputSha256);
      events.push('source-dispatch-guard'); return context.operation(context.signal);
    } } });
  const result = await runProviderWork(state, work.attempt, input);
  assert.strictEqual(result, work.output()); assert.equal(work.completed(), true);
  assert.deepEqual(events, ['before', 'source-dispatch-guard', 'work-start', 'fetch', 'work-end', 'after']);
  assert.deepEqual(result.usage, { inputTokens: 20, outputTokens: 7, cachedInputTokens: 3 });
  await assert.rejects(run(state, input), { code: 'GATEWAY_REPLAY_OR_CAPACITY' });
});
test('a completed SSE event or headers alone cannot end provider-work before EOF and final validation', async t => {
  const events = [], work = providerWorkAttempt(events); let stream;
  const state = harness(t, { fetch: () => new Response(new ReadableStream({ start(value) { stream = value; } }),
    { headers: { 'content-type': 'text/event-stream' } }),
    config: { dispatchProviderOperation: context => context.operation(context.signal) } });
  let settled = false;
  const pending = runProviderWork(state, work.attempt).finally(() => { settled = true; });
  await flush(); assert.equal(settled, false); assert.equal(work.completed(), false);
  stream.enqueue(new TextEncoder().encode(`data: ${JSON.stringify({ type: 'response.completed', response: completion() })}\n\n`));
  await flush(); assert.equal(settled, false); assert.equal(work.completed(), false);
  assert.deepEqual(state.checks.map(value => value.phase), ['before']);
  stream.close(); assert.equal((await pending).status, 'success');
  assert.equal(work.completed(), true); assert.deepEqual(state.checks.map(value => value.phase), ['before', 'after']);
});
test('Native sixty-second clock starts after the source dispatch guard, not while that guard waits', async t => {
  const deadlines = [];
  t.mock.method(AbortSignal, 'timeout', ms => { const c = new AbortController(); deadlines.push({ ms, controller: c }); return c.signal; });
  const guard = deferred(), reached = deferred(), events = [], work = providerWorkAttempt(events);
  const state = harness(t, { config: { dispatchProviderOperation: async context => {
    reached.resolve(); await guard.promise; return context.operation(context.signal);
  } } });
  const pending = runProviderWork(state, work.attempt); await reached.promise;
  assert.equal(deadlines.filter(value => value.ms === 60_000).length, 0); assert.deepEqual(events, []);
  state.setTime(70_000); guard.resolve(); assert.equal((await pending).status, 'success');
  assert.equal(deadlines.filter(value => value.ms === 60_000).length, 1);
  assert.equal(deadlines.filter(value => value.ms === 5_000).length, 2);
});
test('the unchanged absolute owner expiry rejects a late guard without borrowing a provider operation', async t => {
  const guard = deferred(), reached = deferred(), events = [], work = providerWorkAttempt(events);
  const state = harness(t, { config: { dispatchProviderOperation: async context => {
    reached.resolve(); await guard.promise; return context.operation(context.signal);
  } } });
  const pending = runProviderWork(state, work.attempt); await reached.promise;
  state.setTime(121_000); guard.resolve();
  await assert.rejects(pending, error => ['GATEWAY_EXPIRED', 'GATEWAY_CLOSED'].includes(error.code));
  assert.deepEqual(events, []); assert.equal(state.calls.length, 0);
});
test('provider-work Native timeout covers a hanging full stream and rejects its late completion', async t => {
  let deadline, stream, cancelled = false;
  t.mock.method(AbortSignal, 'timeout', ms => { const c = new AbortController(); if (ms === 60_000) deadline = c; return c.signal; });
  const events = [], work = providerWorkAttempt(events), state = harness(t, {
    fetch: () => new Response(new ReadableStream({ start(value) { stream = value; }, cancel() { cancelled = true; } }),
      { headers: { 'content-type': 'text/event-stream' } }),
    config: { dispatchProviderOperation: context => context.operation(context.signal) } });
  const pending = runProviderWork(state, work.attempt); await flush(); assert.ok(deadline); assert.ok(stream);
  deadline.abort(); await assert.rejects(pending, { code: 'GATEWAY_TIMEOUT' }); await flush();
  assert.equal(work.completed(), false);
  // A public timeout is not proof an uncooperative body has settled. Release
  // its pending read, then observe the real iterator cleanup separately.
  stream.enqueue(new TextEncoder().encode('data: {"type":"response.created","response":{"id":"late"}}\n\n'));
  await flush(); assert.equal(cancelled, true);
  assert.deepEqual(state.checks.map(value => value.phase), ['before']);
});
test('completed provider-work does not lend its model deadline to the bounded after-proof', async t => {
  let deadline; const after = deferred(), reached = deferred(), events = [], work = providerWorkAttempt(events);
  t.mock.method(AbortSignal, 'timeout', ms => { const c = new AbortController(); if (ms === 60_000) deadline = c; return c.signal; });
  const state = harness(t, { attest: async (context, proof) => {
    if (context.phase === 'after') { reached.resolve(); await after.promise; } return proof;
  }, config: { dispatchProviderOperation: context => context.operation(context.signal) } });
  const pending = runProviderWork(state, work.attempt); await reached.promise;
  assert.equal(work.completed(), true); deadline.abort(); after.resolve();
  assert.equal((await pending).status, 'success');
});
test('provider-work keeps schema and usage validation inside the operation without changing quantities', async t => {
  for (const mode of ['schema', 'usage']) await t.test(mode, async child => {
    const events = [], work = providerWorkAttempt(events), input = request('provider-validation-'+mode, mode === 'schema' ? {
      responseSchema: { type: 'object', additionalProperties: false, required: ['ok'], properties: { ok: { type: 'boolean' } } },
    } : {});
    const state = harness(child, { fetch: () => sse(mode === 'schema' ? completion('{"ok":"wrong"}') : completion('text', {
      usage: { input_tokens: 20, output_tokens: -1, total_tokens: 19 },
    })), config: { dispatchProviderOperation: context => context.operation(context.signal) } });
    await assert.rejects(runProviderWork(state, work.attempt, input), { code: mode === 'schema' ? 'INVALID_STRUCTURED_OUTPUT' : 'GATEWAY_RESPONSE_INVALID' });
    assert.equal(work.completed(), false); assert.deepEqual(state.checks.map(value => value.phase), ['before']);
  });
});
test('a wrapper cannot omit, clone or run the provider operation twice and adopt a fabricated result', async t => {
  for (const mode of ['omit', 'clone', 'twice', 'fake-attempt']) await t.test(mode, async child => {
    const events = [], work = providerWorkAttempt(events);
    const state = harness(child, { config: { dispatchProviderOperation: async context => {
      if (mode === 'omit') return {};
      const value = await context.operation(context.signal);
      if (mode === 'clone') return { ...value };
      if (mode === 'twice') try { await context.operation(context.signal); } catch { /* swallowed by hostile fixture */ }
      return value;
    } } });
    const attempt = mode === 'fake-attempt' ? Object.freeze({ run: async () => ({}) }) : work.attempt;
    await assert.rejects(runProviderWork(state, attempt), { code: 'GATEWAY_UNAVAILABLE' });
    assert.equal(state.calls.length, ['omit', 'fake-attempt'].includes(mode) ? 0 : 1);
    assert.deepEqual(state.checks.map(value => value.phase), ['before']);
  });
});
test('provider-work validates an opaque attempt without invoking getters or copying its authority', async t => {
  let reads = 0; const state = harness(t, { config: { dispatchProviderOperation: context => context.operation(context.signal) } });
  const getter = Object.defineProperty({}, 'run', { enumerable: true, get() { reads++; return () => {}; } });
  for (const attempt of [null, {}, getter, Object.create({ run() {} }), new Proxy({ run() {} }, {}), { run: new Proxy(() => {}, {}) }]) {
    await assert.rejects(runProviderWork(state, attempt), { code: 'INVALID_REQUEST' });
  }
  assert.equal(reads, 0); assert.equal(state.calls.length, 0); assert.equal(state.checks.length, 0);
});
test('caller cancellation during a source guard stops before either provider clock or physical request', async t => {
  const reached = deferred(), guard = deferred(), caller = new AbortController(), events = [], work = providerWorkAttempt(events);
  const state = harness(t, { config: { dispatchProviderOperation: async context => { reached.resolve(); await guard.promise; return context.operation(context.signal); } } });
  const pending = runProviderWork(state, work.attempt, request(), caller.signal); await reached.promise;
  caller.abort(false); await assert.rejects(pending, { code: 'GATEWAY_ABORTED' }); guard.resolve(); await flush();
  assert.deepEqual(events, []); assert.equal(state.calls.length, 0);
});
test('a wrapper returning before its model operation settles closes the owner and cannot publish late output', async t => {
  for (const mode of ['return', 'throw']) await t.test(mode, async child => {
    const fetched = deferred(), release = deferred(), events = [], work = providerWorkAttempt(events);
    const state = harness(child, { fetch: () => { fetched.resolve(); return release.promise; },
      config: { dispatchProviderOperation: async context => {
        void context.operation(context.signal); await fetched.promise;
        if (mode === 'throw') throw new Error('PRIVATE_WRAPPER_FAILURE');
        return {};
      } } });
    await assert.rejects(runProviderWork(state, work.attempt), { code: 'GATEWAY_CLOSED' });
    await assert.rejects(runProviderWork(state, providerWorkAttempt([]).attempt, request('second')), { code: 'GATEWAY_CLOSED' });
    release.resolve(sse()); await flush();
    assert.equal(work.completed(), false); assert.equal(state.calls.length, 1);
    assert.deepEqual(state.checks.map(value => value.phase), ['before']);
  });
});

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

test('native session-affinity is default-OFF and preserves exact payload bytes without complete metadata', async t => {
  for (const [index, variant] of [
    { config: {}, extra: { promptCache: { key: `support-${'b'.repeat(64)}`, userPrefixChars: 4 } } },
    { config: { nativeSessionAffinity: false }, extra: { promptCache: { key: `support-${'b'.repeat(64)}`, userPrefixChars: 4 } } },
    { config: { nativeSessionAffinity: true }, extra: {} },
    { config: { nativeSessionAffinity: true }, extra: { promptCache: { key: `support-${'b'.repeat(64)}` } } },
  ].entries()) {
    const state = harness(t, { config: variant.config }), input = request(`affinity-default-${index}`, variant.extra);
    const result = await run(state, input), init = state.calls[0].init;
    assert.equal(init.body, JSON.stringify(corelyPlanPayload(input, 'info').payload));
    assert.equal(init.headers['session-id'], undefined); assert.equal(init.headers['thread-id'], undefined);
    assert.equal(init.headers['x-codex-turn-state'], undefined); assert.equal(result.inputSha256, input.inputSha256);
    assert.deepEqual(state.checks.map(check => check.phase), ['before', 'after']);
  }
});

// Independent synthetic vector: this cache-only identifier is never an auth/session grant.
function expectedAffinity(input, alias, token = TOKENS[alias]) {
  const hmac = createHmac('sha256', token);
  for (const value of ['new-api.local-codex-cache-affinity.v1', alias, input.scope.tenantId, input.scope.brandId,
    input.model, input.workload, input.purpose, input.reasoningEffort ?? '-', input.verbosity ?? '-', input.promptCache.key,
    createHash('sha256').update(input.system, 'utf8').digest('hex'), input.schemaSha256 ?? '-',
    createHash('sha256').update(input.user.slice(0, input.promptCache.userPrefixChars), 'utf8').digest('hex')]) {
    const bytes = Buffer.from(value, 'utf8'), size = Buffer.alloc(4); size.writeUInt32BE(bytes.length);
    hmac.update(size); hmac.update(bytes);
  }
  return hmac.digest('hex');
}

test('native session-affinity is stable across owners/calls and suffixes while body, output and source contracts stay exact', async t => {
  const prefix = '固定清潔說明🙂\r\n保留品質覆核。';
  for (const messagePrefix of [false, true]) {
    const ids = [];
    for (let index = 0; index < 2; index++) {
      const input = request(`affinity-stable-${messagePrefix}-${index}`, { user: prefix + `合成問題${index}。`,
        scope: { tenantId: 'moztech', brandId: 'moztech-test', synthetic: true, jobId: `new-job-${index}` },
        promptCache: { key: `support-${'b'.repeat(64)}`, userPrefixChars: prefix.length } });
      const state = harness(t, { config: { nativeSessionAffinity: true, nativeMessagePrefixCache: messagePrefix } });
      const result = await run(state, input), init = state.calls[0].init, expected = corelyPlanPayload(input, 'info').payload;
      const expectedBody = messagePrefix ? { ...expected, input: [
        { role: 'user', content: prefix }, { role: 'user', content: input.user.slice(prefix.length) },
      ] } : expected;
      assert.equal(init.body, JSON.stringify(expectedBody)); assert.equal(init.headers['session-id'], expectedAffinity(input, 'info'));
      assert.match(init.headers['session-id'], /^[a-f0-9]{64}$/); ids.push(init.headers['session-id']);
      assert.doesNotMatch(init.headers['session-id'], /moztech|info|eason|synthetic|support/);
      assert.deepEqual(Object.keys(result).sort(), ['accountAlias', 'accountVerified', 'authMode', 'callId', 'completionStatus',
        'inputSha256', 'model', 'schemaSha256', 'status', 'text', 'usage'].sort());
      assert.equal(result.inputSha256, input.inputSha256); assert.equal(result.text, '合成回覆。');
      assert.deepEqual(state.checks.map(check => check.phase), ['before', 'after']);
      assert.equal(init.headers['thread-id'], undefined); assert.equal(init.headers['x-codex-turn-state'], undefined);
    }
    assert.equal(ids[0], ids[1]);
  }
});

test('native session-affinity namespaces exact material/system/schema/key/account and rotates with the existing short-lived token', async t => {
  const prefix = '共同規範🙂\r\n', base = { user: prefix + '合成問題。',
    promptCache: { key: `support-${'b'.repeat(64)}`, userPrefixChars: prefix.length } };
  const baseline = request('affinity-namespace-base', base), ids = [];
  for (const [index, variant] of [
    {}, { system: baseline.system + '另一份規則。' },
    { user: '替換規範🙂\r\n合成問題。' },
    { responseSchema: { type: 'object', properties: { reply: { type: 'string' } }, required: ['reply'], additionalProperties: false } },
    { promptCache: { ...base.promptCache, key: `support-${'c'.repeat(64)}` } },
    { purpose: 'reply_repair' }, { reasoningEffort: 'low', verbosity: 'low' },
  ].entries()) {
    const input = request(`affinity-namespace-${index}`, { ...base, ...variant });
    const state = harness(t, { config: { nativeSessionAffinity: true }, fetch: () => sse(completion(input.responseSchema ? '{"reply":"合成回覆。"}' : '合成回覆。')) });
    await run(state, input); const id = state.calls[0].init.headers['session-id'];
    assert.equal(id, expectedAffinity(input, 'info')); ids.push(id);
  }
  assert.equal(new Set(ids).size, ids.length);
  const otherAccount = harness(t, { config: { nativeSessionAffinity: true } }); await run(otherAccount, baseline, 'eason');
  assert.equal(otherAccount.calls[0].init.headers['session-id'], expectedAffinity(baseline, 'eason'));
  assert.notEqual(otherAccount.calls[0].init.headers['session-id'], ids[0]);
  const token = 'synthetic-rotated-info-gateway-token-000003';
  const rotated = harness(t, { config: { nativeSessionAffinity: true,
    accounts: { info: { gatewayToken: token }, eason: { gatewayToken: TOKENS.eason } } } });
  await run(rotated, baseline); assert.equal(rotated.calls[0].init.headers['session-id'], expectedAffinity(baseline, 'info', token));
  assert.notEqual(rotated.calls[0].init.headers['session-id'], ids[0]);
  // The expected vector binds both scope fields; the actual gateway still rejects other brands before any proof/dispatch.
  for (const scope of [{ ...baseline.scope, tenantId: 'other-tenant' }, { ...baseline.scope, brandId: 'other-brand' }]) {
    assert.notEqual(expectedAffinity({ ...baseline, scope }, 'info'), ids[0]);
    const state = harness(t, { config: { nativeSessionAffinity: true } });
    await assert.rejects(run(state, request('affinity-foreign-scope', { ...base, scope })), { code: 'INVALID_REQUEST' });
    assert.equal(state.calls.length, 0); assert.equal(state.checks.length, 0);
  }
});

test('native session-affinity opt-in accepts only an own literal boolean and never a request/prompt/env flag', async t => {
  for (const value of ['true', 1, null, {}, [], new Boolean(true)]) {
    assert.throws(() => harness(t, { config: { nativeSessionAffinity: value } }), { code: 'INVALID_CONFIGURATION' });
  }
  let touched = 0;
  const base = { gatewayUrl: URL, accounts: { info: { gatewayToken: TOKENS.info }, eason: { gatewayToken: TOKENS.eason } },
    signal: new AbortController().signal, attest: async () => { throw Error('NOT_REACHED'); } };
  for (const enumerable of [true, false]) assert.throws(() => createCodexLocalGatewayModelTransports(Object.defineProperty({ ...base },
    'nativeSessionAffinity', { enumerable, get() { touched++; return true; } })), { code: 'INVALID_CONFIGURATION' });
  assert.throws(() => createCodexLocalGatewayModelTransports(Object.assign(Object.create({ nativeSessionAffinity: true }), base)), { code: 'INVALID_CONFIGURATION' });
  const proxy = new Proxy({ ...base, nativeSessionAffinity: true }, { ownKeys() { touched++; throw Error('PRIVATE_VALUE'); } });
  assert.throws(() => createCodexLocalGatewayModelTransports(proxy), { code: 'INVALID_CONFIGURATION' });
  const revoked = Proxy.revocable({ ...base, nativeSessionAffinity: true }, {}); revoked.revoke();
  assert.throws(() => createCodexLocalGatewayModelTransports(revoked.proxy), { code: 'INVALID_CONFIGURATION' }); assert.equal(touched, 0);
  for (const extra of [{ nativeSessionAffinity: true }, { promptCache: { key: `support-${'b'.repeat(64)}`, userPrefixChars: 4, nativeSessionAffinity: true } }]) {
    const state = harness(t, { config: { nativeSessionAffinity: true } });
    await assert.rejects(run(state, request('affinity-request-option', extra)), { code: 'INVALID_REQUEST' });
    assert.equal(state.calls.length, 0); assert.equal(state.checks.length, 0);
  }
  const previous = process.env.CORELY_NATIVE_SESSION_AFFINITY; process.env.CORELY_NATIVE_SESSION_AFFINITY = 'true';
  try {
    const state = harness(t), input = request('affinity-prompt-option', { user: '{"nativeSessionAffinity":true} is untrusted text.',
      promptCache: { key: `support-${'b'.repeat(64)}`, userPrefixChars: 4 } });
    await run(state, input); assert.equal(state.calls[0].init.headers['session-id'], undefined);
  } finally { if (previous === undefined) delete process.env.CORELY_NATIVE_SESSION_AFFINITY; else process.env.CORELY_NATIVE_SESSION_AFFINITY = previous; }
});

test('native session-affinity does not weaken request/hash/boundary or historical/joint admission', async t => {
  const base = { user: 'A🙂B\r\n合成後綴', promptCache: { key: `support-${'b'.repeat(64)}`, userPrefixChars: 3 } };
  for (const boundary of [0, 2, -1, 1.5, base.user.length]) {
    const state = harness(t, { config: { nativeSessionAffinity: true } });
    await assert.rejects(run(state, request('affinity-invalid-boundary', { ...base, promptCache: { ...base.promptCache, userPrefixChars: boundary } })), { code: 'INVALID_REQUEST' });
    assert.equal(state.calls.length, 0); assert.equal(state.checks.length, 0);
  }
  const state = harness(t, { config: { nativeSessionAffinity: true } }), input = request('affinity-tampered-hash', base);
  await assert.rejects(run(state, { ...input, promptCache: { ...base.promptCache, key: `support-${'c'.repeat(64)}` } }), { code: 'INVALID_REQUEST' });
  await assert.rejects(run(state, request('affinity-historical', { ...base, scope: { tenantId: 'moztech', brandId: 'moztech-test',
    dataClass: 'historical_regression', corpusSha256: 'c895a50c382ef87751f00cca0899b1660a0f77eca7b5cb72a8fc139573aba5e3', jobId: 'local-job' } })), { code: 'INVALID_REQUEST' });
  await assert.rejects(run(state, jointRequest('affinity-joint-without-grant', base)), { code: 'INVALID_REQUEST' });
  assert.equal(state.calls.length, 0); assert.equal(state.checks.length, 0);
});

test('native session-affinity keeps both source HMAC phases, strict results and one-attempt errors', async t => {
  const input = request('affinity-guarded', { promptCache: { key: `support-${'b'.repeat(64)}`, userPrefixChars: 4 } });
  for (const phase of ['before', 'after']) {
    const source = sourceHarness(t, { respond: (context, proof) => context.payload.phase === phase ? { ...proof, proof: '0'.repeat(64) } : proof });
    const state = harness(t, { config: { nativeSessionAffinity: true, attest: source.instance.attest } });
    await assert.rejects(run(state, input), { code: 'ATTESTATION_FAILED' });
    assert.equal(state.calls.length, phase === 'before' ? 0 : 1); assert.equal(source.calls.length, phase === 'before' ? 1 : 2);
  }
  for (const status of [400, 429]) {
    const state = harness(t, { config: { nativeSessionAffinity: true }, fetch: () => new Response('', { status }) });
    await assert.rejects(run(state, input), { code: 'GATEWAY_HTTP_FAILURE' }); assert.equal(state.calls.length, 1);
    assert.deepEqual(state.checks.map(check => check.phase), ['before', 'after']);
  }
  const schema = { type: 'object', properties: { reply: { type: 'string' } }, required: ['reply'], additionalProperties: false };
  const invalid = harness(t, { config: { nativeSessionAffinity: true }, fetch: () => sse(completion('{"reply":"合成","extra":true}')) });
  await assert.rejects(run(invalid, request('affinity-invalid-output', { promptCache: input.promptCache, responseSchema: schema })), { code: 'INVALID_STRUCTURED_OUTPUT' });
  assert.equal(invalid.calls.length, 1);
});

test('native session-affinity retains cancellation, late-result discard, immutable binding and replay boundaries', async t => {
  const waiting = deferred(), entered = deferred(), caller = new AbortController();
  const state = harness(t, { config: { nativeSessionAffinity: true }, fetch: () => { entered.resolve(); return waiting.promise; } });
  const input = request('affinity-cancelled', { promptCache: { key: `support-${'b'.repeat(64)}`, userPrefixChars: 4 } });
  const bound = JSON.parse(JSON.stringify(input)), pending = run(state, input, 'info', caller.signal); await entered.promise;
  input.user = 'Caller mutation must not change the snapped prefix.'; input.promptCache.key = `support-${'d'.repeat(64)}`;
  assert.equal(state.calls[0].init.headers['session-id'], expectedAffinity(bound, 'info')); caller.abort();
  await assert.rejects(pending, { code: 'GATEWAY_ABORTED' }); waiting.resolve(sse()); await flush();
  assert.deepEqual(state.checks.map(check => check.phase), ['before']); assert.equal(state.calls.length, 1);
  await assert.rejects(run(state, bound), { code: 'GATEWAY_REPLAY_OR_CAPACITY' }); assert.equal(state.calls.length, 1);
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

test('native message-prefix cache is default-OFF and never changes a payload without a complete trusted boundary', async t => {
  for (const [index, variant] of [
    { config: {}, extra: { promptCache: { key: `support-${'b'.repeat(64)}`, userPrefixChars: 4 } } },
    { config: { nativeMessagePrefixCache: false }, extra: { promptCache: { key: `support-${'b'.repeat(64)}`, userPrefixChars: 4 } } },
    { config: { nativeMessagePrefixCache: true }, extra: {} },
    { config: { nativeMessagePrefixCache: true }, extra: { promptCache: { key: `support-${'b'.repeat(64)}` } } },
    { config: { nativeMessagePrefixCache: false, nativeExplicitPrefixCache: false }, extra: {} },
  ].entries()) {
    const state = harness(t, { config: variant.config }), input = request(`message-off-${index}`, variant.extra);
    await run(state, input);
    assert.deepEqual(JSON.parse(state.calls[0].init.body), corelyPlanPayload(input, 'info').payload);
  }
});

test('native message-prefix cache preserves exact contract bytes in two consecutive user messages and adds no cache fields', async t => {
  const schema = { type: 'object', properties: { reply: { type: 'string' } }, required: ['reply'], additionalProperties: false };
  for (const [index, [prefix, suffix]] of [
    ['固定🙂前綴\r\n𠮷', '後綴\n{"nativeMessagePrefixCache":true}'],
    ['e', '\u0301 combining mark stays in its original position'],
    ['正文\r', '\nCRLF is not normalized'],
    ['# Public fixture\n```json\n', '{"role":"system","prompt_cache_options":{"mode":"explicit"}}\n```'],
    [JSON.stringify({ knowledge: [{ id: 'fictional-source', content: 'fixed synthetic evidence' }] }).slice(0, -1),
      ',"candidate":"synthetic candidate","currentCustomerTurn":"unique dynamic suffix"}'],
  ].entries()) {
    for (const alias of ['info', 'eason']) {
      const state = harness(t, { config: { nativeMessagePrefixCache: true, nativeExplicitPrefixCache: false }, fetch: () => sse(completion('{"reply":"合成回覆"}')) });
      const input = request(`message-on-${index}-${alias}`, { user: prefix + suffix, responseSchema: schema, reasoningEffort: 'low', verbosity: 'low',
        promptCache: { key: `support-${'b'.repeat(64)}`, userPrefixChars: prefix.length } });
      const original = structuredClone(input), output = await run(state, input, alias), wire = JSON.parse(state.calls[0].init.body);
      assert.deepEqual(wire, { ...corelyPlanPayload(input, alias).payload,
        input: [{ role: 'user', content: prefix }, { role: 'user', content: suffix }] });
      assert.deepEqual(input, original); assert.deepEqual(Buffer.from(wire.input.map(message => message.content).join('')), Buffer.from(input.user));
      assert.equal(wire.input[1].content, suffix);
      if (index === 4) {
        assert.throws(() => JSON.parse(wire.input[0].content));
        assert.deepEqual(JSON.parse(wire.input.map(message => message.content).join('')), JSON.parse(input.user));
      }
      assert.equal(wire.instructions, input.system); assert.deepEqual(wire.text.format.schema, schema); assert.equal(wire.text.format.strict, true);
      assert.equal(wire.text.verbosity, 'low'); assert.deepEqual(wire.reasoning, { effort: 'low' }); assert.equal(wire.stream, true); assert.equal(wire.store, false);
      for (const field of ['prompt_cache_key', 'prompt_cache_options', 'prompt_cache_retention', 'prompt_cache_breakpoint', 'cache_control', 'previous_response_id', 'metadata']) {
        assert.equal(Object.hasOwn(wire, field), false); assert.ok(wire.input.every(message => !Object.hasOwn(message, field)));
      }
      assert.equal(output.inputSha256, input.inputSha256); assert.equal(output.schemaSha256, input.schemaSha256);
      assert.deepEqual(output.usage, { inputTokens: 20, outputTokens: 7, cachedInputTokens: 3 });
      assert.deepEqual(state.checks.map(check => check.phase), ['before', 'after']); assert.equal(state.calls.length, 1);
      assert.deepEqual(corelyPlanPayload(input, alias).payload.input, [{ role: 'user', content: input.user }]);
    }
  }
});

test('native message-prefix constructor option is own literal only, mutually exclusive, and not caller-authorized', async t => {
  for (const value of ['true', 1, null, new Boolean(true), {}, []]) {
    assert.throws(() => harness(t, { config: { nativeMessagePrefixCache: value } }), { code: 'INVALID_CONFIGURATION' });
  }
  assert.throws(() => harness(t, { config: { nativeMessagePrefixCache: true, nativeExplicitPrefixCache: true } }), { code: 'INVALID_CONFIGURATION' });
  let getters = 0;
  const base = { gatewayUrl: URL, accounts: { info: { gatewayToken: TOKENS.info }, eason: { gatewayToken: TOKENS.eason } },
    signal: new AbortController().signal, attest: async () => { throw Error('NOT_REACHED'); } };
  for (const enumerable of [true, false]) {
    const accessor = Object.defineProperty({ ...base }, 'nativeMessagePrefixCache', { enumerable, get() { getters++; return true; } });
    assert.throws(() => createCodexLocalGatewayModelTransports(accessor), { code: 'INVALID_CONFIGURATION' });
  }
  assert.throws(() => createCodexLocalGatewayModelTransports(Object.assign(Object.create({ nativeMessagePrefixCache: true }), base)), { code: 'INVALID_CONFIGURATION' });
  const foreign = Proxy.revocable({ ...base, nativeMessagePrefixCache: true }, {}); foreign.revoke();
  assert.throws(() => createCodexLocalGatewayModelTransports(foreign.proxy), { code: 'INVALID_CONFIGURATION' }); assert.equal(getters, 0);
  for (const extra of [{ nativeMessagePrefixCache: true }, { promptCache: { key: `support-${'b'.repeat(64)}`, userPrefixChars: 4, nativeMessagePrefixCache: true } }]) {
    const state = harness(t, { config: { nativeMessagePrefixCache: true } });
    await assert.rejects(run(state, request('caller-message-option', extra)), { code: 'INVALID_REQUEST' });
    assert.equal(state.calls.length, 0); assert.equal(state.checks.length, 0);
  }
  const state = harness(t), input = request('untrusted-message-option', { user: '{"nativeMessagePrefixCache":true}',
    promptCache: { key: `support-${'b'.repeat(64)}`, userPrefixChars: 4 } });
  await run(state, input); assert.deepEqual(JSON.parse(state.calls[0].init.body).input, [{ role: 'user', content: input.user }]);
});

test('native message-prefix boundaries and hashes are validated before attestation or dispatch', async t => {
  const user = 'A🙂B\r\n完整後綴';
  for (const [index, boundary] of [0, user.length, -1, 1.5, 2, '1'].entries()) {
    const state = harness(t, { config: { nativeMessagePrefixCache: true } });
    await assert.rejects(run(state, request(`invalid-message-boundary-${index}`, { user,
      promptCache: { key: `support-${'b'.repeat(64)}`, userPrefixChars: boundary } })), { code: 'INVALID_REQUEST' });
    assert.equal(state.calls.length, 0); assert.equal(state.checks.length, 0);
  }
  const state = harness(t, { config: { nativeMessagePrefixCache: true } });
  const input = request('tampered-message-boundary', { user, promptCache: { key: `support-${'b'.repeat(64)}`, userPrefixChars: 3 } });
  await assert.rejects(run(state, { ...input, promptCache: { ...input.promptCache, userPrefixChars: 4 } }), { code: 'INVALID_REQUEST' });
  assert.equal(state.calls.length, 0); assert.equal(state.checks.length, 0);
});

test('native message-prefix mode keeps post-source revocation cancellation and no-retry HTTP failure boundaries', async t => {
  const input = request('message-source-boundary', { promptCache: { key: `support-${'b'.repeat(64)}`, userPrefixChars: 4 } });
  const revoked = harness(t, { config: { nativeMessagePrefixCache: true },
    attest: ({ phase }, proof) => phase === 'after' ? { ...proof, freshLoginVerified: false } : proof });
  await assert.rejects(run(revoked, input), { code: 'ATTESTATION_FAILED' }); assert.equal(revoked.calls.length, 1);
  for (const status of [400, 429]) {
    const failed = harness(t, { config: { nativeMessagePrefixCache: true }, fetch: () => new Response('', { status }) });
    await assert.rejects(run(failed, input), { code: 'GATEWAY_HTTP_FAILURE' }); assert.equal(failed.calls.length, 1);
    assert.deepEqual(failed.checks.map(check => check.phase), ['before', 'after']);
  }
  const waiting = deferred(), entered = deferred(), caller = new AbortController();
  const cancelled = harness(t, { config: { nativeMessagePrefixCache: true }, fetch: () => { entered.resolve(); return waiting.promise; } });
  const pending = run(cancelled, input, 'info', caller.signal); await entered.promise; caller.abort();
  await assert.rejects(pending, { code: 'GATEWAY_ABORTED' }); waiting.resolve(sse()); await Promise.resolve();
  assert.equal(cancelled.calls.length, 1); assert.deepEqual(cancelled.checks.map(check => check.phase), ['before']);
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
  const state = harness(t, { config: { diagnostics: true }, attest: ({ phase }, proof) => {
    if (phase === 'before') return proof;
    entered.resolve(); return waiting.promise.then(() => proof);
  } });
  const pending = run(state, request(), 'info', abort.signal); await entered.promise; abort.abort();
  await assert.rejects(pending, { code: 'GATEWAY_ABORTED' }); waiting.resolve(); await Promise.resolve();
  assert.equal(state.calls.length, 1); assert.equal(state.checks.length, 2);
  const [timing] = gateway.codexLocalGatewayTimingSnapshot(state.instance).records;
  assert.equal(timing.status, 'FAILED'); assert.equal(timing.abortPhase, 'AFTER_PROOF'); assert.equal(timing.sourceAfterMs, null);
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
  const state = harness(t, { config: { diagnostics: true }, attest: ({ phase }, proof) => {
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
  assert.equal(gateway.codexLocalGatewayTimingSnapshot(state.instance).records[0].abortOffsetMs, null,
    'an elapsed completed-model deadline during after-proof is not an owner cancellation');
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

test('provider failure opt-in never replaces authenticated quota verification or promotes a forged quota header', async t => {
  for (const mode of ['valid', 'forged', 'bare']) {
    const source = sourceHarness(t), state = providerFailureHarness(t, { config: {
      attest: source.instance.attest, quotaRequest: source.instance.quotaRequest, quotaVerify: source.instance.quotaVerify },
      fetch: (_url, init) => new Response('{"error":{"code":"usage_limit_reached"}}', { status: 429,
        headers: mode === 'bare' ? {} : { [QUOTA_RECEIPT_HEADER]: mode === 'valid' ? quotaReceipt(init.headers) : 'v1.10000.130000.'+'0'.repeat(64) } }) });
    if (mode === 'forged') await assert.rejects(runProviderWork(state, providerWorkAttempt([]).attempt), { code: 'ATTESTATION_FAILED' });
    else {
      const result = await runProviderWork(state, providerWorkAttempt([]).attempt);
      assert.equal(result.status, mode === 'valid' ? 'quota_exhausted' : 'provider_failure');
      if (mode === 'valid') assert.equal(result.authenticated, true); else assert.equal(result.reason, 'RATE_LIMIT');
    }
    assert.equal(state.calls.length, 1); assert.equal(source.calls.length, 2);
  }
});

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
    const source = sourceHarness(t), state = harness(t, { config: { diagnostics: true, attest: source.instance.attest,
      quotaRequest: source.instance.quotaRequest, quotaVerify: source.instance.quotaVerify },
    fetch: (_url, init) => new Response('{"error":{"type":"usage_limit_reached","message":"private-provider-diagnostic"}}', {
      status: 429, headers: { [QUOTA_RECEIPT_HEADER]: quotaReceipt(init.headers, alias) },
    }) });
    const input = request(`quota-${alias}`), result = await run(state, input, alias);
    assert.equal(result.status, 'quota_exhausted'); assert.equal(result.authenticated, true); assert.equal(result.code, 'QUOTA_EXHAUSTED');
    assert.equal(result.accountAlias, alias); assert.equal(result.inputSha256, input.inputSha256);
    assert.equal(source.calls.length, 2); assert.equal(state.calls.length, 1);
    const [timing] = gateway.codexLocalGatewayTimingSnapshot(state.instance).records;
    assert.equal(timing.status, 'QUOTA_EXHAUSTED'); assert.equal(timing.terminalOffsetMs, null);
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

test('provider-work keeps HTTP quota opaque until the unchanged after-proof and actual-route HMAC verification', async t => {
  for (const alias of ['info', 'eason']) {
    const events = [], work = providerWorkAttempt(events), source = sourceHarness(t, { respond: (context, proof) => {
      events.push('source-'+context.payload.phase); return proof;
    } });
    const state = harness(t, { config: { attest: source.instance.attest, quotaRequest: source.instance.quotaRequest,
      quotaVerify: context => { events.push('quota-verify'); return source.instance.quotaVerify(context); },
      dispatchProviderOperation: context => context.operation(context.signal) },
      fetch: (_url, init) => new Response('PRIVATE_HTTP_BODY', { status: 429,
        headers: { [QUOTA_RECEIPT_HEADER]: quotaReceipt(init.headers, alias) } }) });
    const result = await state.instance.ports[alias].generateWithProviderWork(request('provider-quota-'+alias),
      new AbortController().signal, work.attempt);
    assert.equal(work.completed(), true); assert.deepEqual(work.output(), {});
    assert.notStrictEqual(result, work.output()); assert.equal(result.status, 'quota_exhausted');
    assert.equal(result.authenticated, true); assert.equal(result.accountAlias, alias);
    assert.deepEqual(events, ['source-before', 'work-start', 'work-end', 'source-after', 'quota-verify']);
    assert.equal(state.calls.length, 1); assert.doesNotMatch(JSON.stringify(result), /PRIVATE_HTTP_BODY|receipt|nonce/);
  }
  for (const mode of ['bare', 'forged', 'changed-source']) {
    let verifications = 0; const work = providerWorkAttempt([]), source = sourceHarness(t, { respond: (context, proof) =>
      mode === 'changed-source' && context.payload.phase === 'after' ? signSourceProof({ ...proof, route_revision: 'e'.repeat(64) }) : proof });
    const state = harness(t, { config: { attest: source.instance.attest, quotaRequest: source.instance.quotaRequest,
      quotaVerify: context => { verifications++; return source.instance.quotaVerify(context); },
      dispatchProviderOperation: context => context.operation(context.signal) },
      fetch: (_url, init) => new Response('', { status: 429, headers: mode === 'bare' ? {} : {
        [QUOTA_RECEIPT_HEADER]: mode === 'forged' ? 'v1.10000.130000.'+'0'.repeat(64) : quotaReceipt(init.headers),
      } }) });
    await assert.rejects(runProviderWork(state, work.attempt), { code: mode === 'bare' ? 'GATEWAY_HTTP_FAILURE' : 'ATTESTATION_FAILED' });
    assert.equal(state.calls.length, 1); assert.equal(source.calls.length, 2);
    assert.equal(verifications, mode === 'forged' ? 1 : 0);
  }
});

test('provider-work still requires its bounded after-proof and source revision after complete validated work', async t => {
  for (const mode of ['after-timeout', 'changed', 'revoked']) {
    const reached = deferred(), release = deferred(), work = providerWorkAttempt([]); let sourceDeadline;
    const timeout = t.mock.method(AbortSignal, 'timeout', ms => {
      const c = new AbortController(); if (ms === 5000) sourceDeadline = c; return c.signal;
    });
    const state = harness(t, { attest: async (context, proof) => {
      if (context.phase !== 'after') return proof;
      if (mode === 'after-timeout') { reached.resolve(); await release.promise; }
      return mode === 'changed' ? { ...proof, configurationRevision: 'b'.repeat(64) } :
        mode === 'revoked' ? { ...proof, freshLoginVerified: false } : proof;
    }, config: { dispatchProviderOperation: context => context.operation(context.signal) } });
    const pending = runProviderWork(state, work.attempt);
    if (mode === 'after-timeout') { await reached.promise; sourceDeadline.abort(); }
    await assert.rejects(pending, { code: mode === 'changed' ? 'ATTESTATION_CHANGED' : 'ATTESTATION_FAILED' });
    assert.equal(work.completed(), true); assert.equal(state.calls.length, 1);
    release.resolve(); await flush(); timeout.mock.restore();
  }
});

test('native prefix-cache and session-affinity preserve authenticated typed-quota source and original request/schema bindings in a deterministic fixture', async t => {
  for (const option of ['nativeExplicitPrefixCache', 'nativeMessagePrefixCache', 'nativeSessionAffinity']) {
    const source = sourceHarness(t), input = request(`quota-prefix-${option}`, {
      promptCache: { key: `support-${'b'.repeat(64)}`, userPrefixChars: 4 },
      responseSchema: { type: 'object', properties: { reply: { type: 'string' } }, required: ['reply'], additionalProperties: false },
    });
    const state = harness(t, { config: { [option]: true, attest: source.instance.attest,
      quotaRequest: source.instance.quotaRequest, quotaVerify: source.instance.quotaVerify },
      fetch: (_url, init) => new Response('', { status: 429, headers: { [QUOTA_RECEIPT_HEADER]: quotaReceipt(init.headers) } }) });
    const result = await run(state, input), wire = JSON.parse(state.calls[0].init.body);
    assert.equal(result.status, 'quota_exhausted'); assert.equal(result.authenticated, true); assert.equal(result.code, 'QUOTA_EXHAUSTED');
    assert.equal(result.inputSha256, input.inputSha256); assert.equal(result.schemaSha256, input.schemaSha256);
    if (option === 'nativeExplicitPrefixCache') {
      assert.equal(wire.input[0].content[0].prompt_cache_breakpoint.mode, 'explicit');
      assert.equal(wire.input[0].content.map(part => part.text).join(''), input.user);
    } else if (option === 'nativeMessagePrefixCache') assert.deepEqual(wire.input, [{ role: 'user', content: input.user.slice(0, 4) }, { role: 'user', content: input.user.slice(4) }]);
    else {
      assert.deepEqual(wire.input, [{ role: 'user', content: input.user }]);
      assert.equal(state.calls[0].init.headers['session-id'], expectedAffinity(input, 'info'));
    }
    assert.equal(state.calls.length, 1); assert.equal(source.calls.length, 2);
  }
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

function jointRequest(callId = 'joint-local-call', extra = {}) {
  const responseSchema = { type: 'object', additionalProperties: false,
    properties: { evidence: { type: 'object', additionalProperties: false,
      properties: { knowledgeIds: { type: 'array', items: { type: 'string' } }, stageKeys: { type: 'array', items: { type: 'string' } } },
      required: ['knowledgeIds', 'stageKeys'] }, decisionJson: { type: 'string' } }, required: ['evidence', 'decisionJson'] };
  return request(callId, { workload: 'DECISION_LLM', purpose: 'joint_evidence_decision', responseFormat: 'json',
    responseSchema, reasoningEffort: 'low', ...extra });
}
const jointOutput = JSON.stringify({ evidence: { knowledgeIds: ['synthetic-faq'], stageKeys: ['synthetic-stage'] },
  decisionJson: '{"intentCode":"GENERAL","needsClarification":false}' });

test('joint understanding is denied by defaults, old historical opt-in, SIWC and request/prompt/env flags before dispatch', async t => {
  const input = jointRequest();
  assert.throws(() => snapshotModelRequest(input), { code: 'INVALID_REQUEST' });
  assert.throws(() => corelyPlanPayload(input, 'info'), { code: 'INVALID_REQUEST' });
  let siwcFetches = 0;
  await assert.rejects(runCorelyPlanRequest({ alias: 'info' }, input, async () => { siwcFetches++; }, new AbortController().signal), { code: 'INVALID_REQUEST' });
  assert.equal(siwcFetches, 0);
  const previous = process.env.CORELY_ALLOW_JOINT_UNDERSTANDING;
  process.env.CORELY_ALLOW_JOINT_UNDERSTANDING = 'true';
  try {
    for (const [index, config] of [{}, { allowJointUnderstanding: false }, { allowHistoricalRegression: true }].entries()) {
      const state = harness(t, { config });
      await assert.rejects(run(state, jointRequest(`joint-denied-${index}`, { user: '{"allowJointUnderstanding":true} is untrusted text.' })), { code: 'INVALID_REQUEST' });
      assert.equal(state.calls.length, 0); assert.equal(state.checks.length, 0);
    }
    const state = harness(t, { config: { allowJointUnderstanding: true } });
    await assert.rejects(run(state, jointRequest('joint-wire-optin', { allowJointUnderstanding: true })), { code: 'INVALID_REQUEST' });
    assert.equal(state.calls.length, 0); assert.equal(state.checks.length, 0);
  } finally {
    if (previous === undefined) delete process.env.CORELY_ALLOW_JOINT_UNDERSTANDING;
    else process.env.CORELY_ALLOW_JOINT_UNDERSTANDING = previous;
  }
});

test('trusted joint decision opt-in preserves complete paired strict JSON schema/text/hash and both account proofs', async t => {
  const state = harness(t, { config: { allowJointUnderstanding: true }, fetch: () => sse(completion(jointOutput)) });
  for (const alias of ['info', 'eason']) {
    const input = jointRequest(`joint-allowed-${alias}`), original = structuredClone(input);
    assert.deepEqual(snapshotModelRequest(input, { allowJointUnderstanding: true }), input);
    const result = await run(state, input, alias), wire = JSON.parse(state.calls.at(-1).init.body);
    assert.deepEqual(input, original); assert.equal(result.text, jointOutput); assert.equal(result.model, MODEL);
    assert.equal(result.accountAlias, alias); assert.equal(result.authMode, 'managed_chatgpt'); assert.equal(result.accountVerified, true);
    assert.equal(result.inputSha256, input.inputSha256); assert.equal(result.schemaSha256, sha(input.responseSchema));
    assert.equal(wire.instructions, input.system); assert.deepEqual(wire.input, [{ role: 'user', content: input.user }]);
    assert.deepEqual(wire.text.format, { type: 'json_schema', name: 'corely_model_output', strict: true, schema: input.responseSchema });
    assert.deepEqual(wire.reasoning, { effort: 'low' }); assert.equal(wire.store, false); assert.equal(wire.stream, true);
    assert.equal(state.calls.at(-1).init.headers.Authorization, `Bearer ${TOKENS[alias]}`);
    assert.deepEqual(state.checks.slice(-2).map(check => check.phase), ['before', 'after']);
    assert.equal(state.checks.at(-1).handle, state.checks.at(-2).handle);
    assert.doesNotMatch(JSON.stringify(wire), /allowJointUnderstanding|api_key|allowHistoricalRegression/);
  }
  assert.equal(state.calls.length, 2);
});

test('joint purpose remains DECISION-only with a supported JSON schema and the original exact hashes', async t => {
  const state = harness(t, { config: { allowJointUnderstanding: true } });
  const variants = [
    ...['REPLY_LLM', 'WEB_CHAT_VISION', 'MEDIA_IMAGE_ANALYSIS'].map(workload => ({ workload })),
    { responseFormat: undefined }, { responseSchema: undefined },
    { responseSchema: { type: 'object', additionalProperties: true, properties: {}, required: [] } },
  ];
  for (const [index, extra] of variants.entries()) {
    // Omitted fields are absent wire values, not nested undefined placeholders.
    const input = jointRequest(`joint-invalid-contract-${index}`, extra);
    for (const key of ['responseFormat', 'responseSchema']) if (input[key] === undefined) delete input[key];
    input.schemaSha256 = input.responseSchema ? sha(input.responseSchema) : null;
    input.inputSha256 = sha(Object.fromEntries(Object.entries(input).filter(([key]) => key !== 'inputSha256')));
    await assert.rejects(run(state, input), { code: 'INVALID_REQUEST' });
  }
  const input = jointRequest('joint-hash-tamper'); input.user += ' unbound change';
  await assert.rejects(run(state, input), { code: 'INVALID_REQUEST' });
  assert.equal(state.calls.length, 0); assert.equal(state.checks.length, 0);
});

test('historical joint work requires both independent trusted opt-ins and the unchanged exact corpus/scope', async t => {
  const scope = { tenantId: 'moztech', brandId: 'moztech-test', dataClass: 'historical_regression',
    corpusSha256: 'c895a50c382ef87751f00cca0899b1660a0f77eca7b5cb72a8fc139573aba5e3', jobId: 'historical-joint-test' };
  for (const config of [{ allowJointUnderstanding: true }, { allowHistoricalRegression: true }]) {
    const state = harness(t, { config });
    await assert.rejects(run(state, jointRequest('joint-historical-denied', { scope })), { code: 'INVALID_REQUEST' });
    assert.equal(state.calls.length, 0); assert.equal(state.checks.length, 0);
  }
  const state = harness(t, { config: { allowJointUnderstanding: true, allowHistoricalRegression: true }, fetch: () => sse(completion(jointOutput)) });
  assert.equal((await run(state, jointRequest('joint-historical-allowed', { scope }))).status, 'success');
  for (const [index, invalid] of [{ ...scope, corpusSha256: 'f'.repeat(64) }, { ...scope, brandId: 'real-brand' }, { ...scope, synthetic: true }].entries()) {
    await assert.rejects(run(state, jointRequest(`joint-historical-invalid-${index}`, { scope: invalid })), { code: 'INVALID_REQUEST' });
  }
  assert.equal(state.calls.length, 1); assert.equal(state.checks.length, 2);
});

test('joint bootstrap option accepts only owned literal flags and never executes accessors/proxies', t => {
  const input = jointRequest(); let getters = 0, proxyTraps = 0;
  for (const value of ['true', 1, null, new Boolean(true), {}, []]) {
    assert.throws(() => harness(t, { config: { allowJointUnderstanding: value } }), { code: 'INVALID_CONFIGURATION' });
    assert.throws(() => snapshotModelRequest(input, { allowJointUnderstanding: value }), { code: 'INVALID_REQUEST' });
  }
  assert.throws(() => snapshotModelRequest(input, { allowJointUnderstanding: false }), { code: 'INVALID_REQUEST' });
  const base = { gatewayUrl: URL, accounts: { info: { gatewayToken: TOKENS.info }, eason: { gatewayToken: TOKENS.eason } },
    signal: new AbortController().signal, attest: async () => { throw Error('NOT_REACHED'); } };
  for (const enumerable of [true, false]) {
    const options = Object.defineProperty({}, 'allowJointUnderstanding', { enumerable, get() { getters++; return true; } });
    assert.throws(() => snapshotModelRequest(input, options), { code: 'INVALID_REQUEST' });
    assert.throws(() => createCodexLocalGatewayModelTransports(Object.defineProperties({ ...base }, Object.getOwnPropertyDescriptors(options))), { code: 'INVALID_CONFIGURATION' });
  }
  const proxy = new Proxy({ allowJointUnderstanding: true }, { ownKeys(target) { proxyTraps++; return Reflect.ownKeys(target); } });
  assert.throws(() => snapshotModelRequest(input, proxy), { code: 'INVALID_REQUEST' });
  assert.throws(() => createCodexLocalGatewayModelTransports(new Proxy({ ...base, allowJointUnderstanding: true }, {})), { code: 'INVALID_CONFIGURATION' });
  assert.throws(() => snapshotModelRequest(input, { allowJointUnderstanding: true, permitRealCustomers: true }), { code: 'INVALID_REQUEST' });
  assert.equal(getters, 0); assert.equal(proxyTraps, 0);
});

test('prototype flags cannot supply either independent joint or historical bootstrap opt-in', t => {
  const jointDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, 'allowJointUnderstanding');
  const historicalDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, 'allowHistoricalRegression');
  Object.defineProperty(Object.prototype, 'allowJointUnderstanding', { configurable: true, value: true });
  Object.defineProperty(Object.prototype, 'allowHistoricalRegression', { configurable: true, value: true });
  try {
    assert.throws(() => snapshotModelRequest(jointRequest('prototype-joint')), { code: 'INVALID_REQUEST' });
    assert.throws(() => snapshotModelRequest(jointRequest('prototype-joint-options'), {}), { code: 'INVALID_REQUEST' });
    assert.throws(() => snapshotModelRequest(jointRequest('prototype-historical', { scope: {
      tenantId: 'moztech', brandId: 'moztech-test', dataClass: 'historical_regression',
      corpusSha256: 'c895a50c382ef87751f00cca0899b1660a0f77eca7b5cb72a8fc139573aba5e3', jobId: 'prototype-test',
    } }), { allowJointUnderstanding: true }), { code: 'SCOPE_NOT_ADMITTED' });
    assert.doesNotThrow(() => harness(t));
  } finally {
    if (jointDescriptor) Object.defineProperty(Object.prototype, 'allowJointUnderstanding', jointDescriptor);
    else delete Object.prototype.allowJointUnderstanding;
    if (historicalDescriptor) Object.defineProperty(Object.prototype, 'allowHistoricalRegression', historicalDescriptor);
    else delete Object.prototype.allowHistoricalRegression;
  }
});

test('joint opt-in does not bypass structured output, source revocation, HTTP/quota errors or replay', async t => {
  const input = jointRequest('joint-boundaries');
  const revoked = harness(t, { config: { allowJointUnderstanding: true }, fetch: () => sse(completion(jointOutput)),
    attest: ({ phase }, proof) => phase === 'after' ? { ...proof, freshLoginVerified: false } : proof });
  await assert.rejects(run(revoked, input), { code: 'ATTESTATION_FAILED' }); assert.equal(revoked.calls.length, 1);
  const invalid = harness(t, { config: { allowJointUnderstanding: true }, fetch: () => sse(completion('{"evidence":{},"decisionJson":7}')) });
  await assert.rejects(run(invalid, input), { code: 'INVALID_STRUCTURED_OUTPUT' }); assert.equal(invalid.calls.length, 1);
  const quota = harness(t, { config: { allowJointUnderstanding: true }, fetch: () => new Response('', { status: 429 }) });
  await assert.rejects(run(quota, input), { code: 'GATEWAY_HTTP_FAILURE' });
  assert.equal(quota.calls.length, 1); assert.deepEqual(quota.checks.map(check => check.phase), ['before', 'after']);
  await assert.rejects(run(quota, input), { code: 'GATEWAY_REPLAY_OR_CAPACITY' }); assert.equal(quota.calls.length, 1);
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
    const state = harness(child, { config: { diagnostics: true }, fetch: response });
    await assert.rejects(run(state), error => {
      assert.equal(error.code, 'GATEWAY_RESPONSE_INVALID');
      const diagnostic = gateway.codexLocalGatewayResponseDiagnostic(error);
      assert.deepEqual(diagnostic, { responseFailureClass }); assert.equal(Object.isFrozen(diagnostic), true);
      assert.doesNotMatch(JSON.stringify({ error, diagnostic }), /PRIVATE_STREAM_VALUE|input_tokens|output_tokens|total_tokens|cause|body/);
      return true;
    });
    assert.equal(state.calls.length, 1); assert.equal(state.checks.length, 1);
    assert.equal(state.checks[0].binding.accountAlias, 'info');
    assert.equal(gateway.codexLocalGatewayTimingSnapshot(state.instance).records[0].status, 'FAILED');
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

test('stage timing requires an own literal trusted opt-in and never changes owner/request/result contracts', async t => {
  const previous = process.env.CORELY_LOCAL_MODEL_DIAGNOSTICS;
  process.env.CORELY_LOCAL_MODEL_DIAGNOSTICS = 'true';
  try {
    for (const diagnostics of [undefined, false]) {
      const state = harness(t, { config: { diagnostics } });
      const result = await run(state);
      assert.deepEqual(gateway.codexLocalGatewayTimingSnapshot(state.instance), { records: [], droppedCount: 0 });
      assert.deepEqual(Object.keys(state.instance).sort(), ['close', 'ports']);
      assert.deepEqual(result.usage, { inputTokens: 20, outputTokens: 7, cachedInputTokens: 3 });
    }
  } finally { if (previous === undefined) delete process.env.CORELY_LOCAL_MODEL_DIAGNOSTICS; else process.env.CORELY_LOCAL_MODEL_DIAGNOSTICS = previous; }
  for (const value of ['true', 1, null, new Boolean(true), {}, []]) {
    assert.throws(() => harness(t, { config: { diagnostics: value } }), { code: 'INVALID_CONFIGURATION' });
  }
  let touched = 0;
  const base = { gatewayUrl: URL, accounts: { info: { gatewayToken: TOKENS.info }, eason: { gatewayToken: TOKENS.eason } },
    attest: async () => { throw Error('NOT_REACHED'); }, signal: new AbortController().signal };
  for (const bad of [Object.defineProperty({ ...base }, 'diagnostics', { enumerable: true, get() { touched++; return true; } }),
    Object.assign(Object.create({ diagnostics: true }), base), new Proxy({ ...base, diagnostics: true }, {})]) {
    assert.throws(() => createCodexLocalGatewayModelTransports(bad), { code: 'INVALID_CONFIGURATION' });
  }
  const state = harness(t, { config: { diagnostics: true } });
  await assert.rejects(run(state, request('caller-diagnostics', { diagnostics: true })), { code: 'INVALID_REQUEST' });
  assert.deepEqual(gateway.codexLocalGatewayTimingSnapshot(state.instance), { records: [], droppedCount: 0 });
  assert.equal(state.calls.length, 0); assert.equal(state.checks.length, 0); assert.equal(touched, 0);
  const foreign = new Proxy({}, { get() { touched++; throw Error('PRIVATE_INPUT'); } });
  assert.deepEqual(gateway.codexLocalGatewayTimingSnapshot(foreign), { records: [], droppedCount: 0 }); assert.equal(touched, 0);
});

test('numeric stages separate source proof, fetch headers, first text, terminal, stream end and final source check', async t => {
  let time = 100, controller;
  t.mock.method(performance, 'now', () => time);
  const frame = value => new TextEncoder().encode(`data: ${JSON.stringify(value)}\n\n`);
  const state = harness(t, { config: { diagnostics: true },
    attest: ({ phase }, proof) => { time += phase === 'before' ? 10 : 7; return proof; },
    fetch: () => { time += 20; return new Response(new ReadableStream({ start(value) { controller = value; } }),
      { headers: { 'content-type': 'text/event-stream' } }); } });
  const input = request('PRIVATE_CALL_IDENTIFIER', { user: 'PRIVATE_INPUT', system: 'PRIVATE_SYSTEM' });
  const pending = run(state, input); await flush();
  const empty = gateway.codexLocalGatewayTimingSnapshot(state.instance); assert.deepEqual(empty, { records: [], droppedCount: 0 });
  time = 160; controller.enqueue(frame({ type: 'response.output_text.delta', delta: 'PRIVATE_' })); await flush();
  time = 200; controller.enqueue(frame({ type: 'response.output_text.delta', delta: 'OUTPUT' })); await flush();
  time = 250; controller.enqueue(frame({ type: 'response.completed', response: completion('PRIVATE_OUTPUT') })); await flush();
  time = 253; controller.close(); const result = await pending;
  const snapshot = gateway.codexLocalGatewayTimingSnapshot(state.instance);
  assert.deepEqual(snapshot, { droppedCount: 0, records: [{ attempt: 1, account: 'info', purpose: 'reply_generation', status: 'SUCCESS', clockStatus: 'OBSERVED',
    totalMs: 160, sourceBeforeMs: 10, dispatchOffsetMs: 10, dispatchToHeadersMs: 20,
    headersToFirstTextMs: 30, firstTextToTerminalMs: 90, terminalToStreamEndMs: 3,
    headersToValidatedFinalOnlyTextMs: null, firstTextKind: 'DELTA', terminalOffsetMs: 150, streamEndOffsetMs: 153,
    sourceAfterMs: 7, abortOffsetMs: null, abortPhase: null }] });
  assert.equal(result.text, 'PRIVATE_OUTPUT'); assert.equal(result.inputSha256, input.inputSha256);
  assert.deepEqual(Object.keys(result).sort(), ['accountAlias', 'accountVerified', 'authMode', 'callId', 'completionStatus',
    'inputSha256', 'model', 'schemaSha256', 'status', 'text', 'usage']);
  assert.deepEqual(Object.keys(state.instance).sort(), ['close', 'ports']);
  assert.deepEqual(state.checks.map(x => x.phase), ['before', 'after']); assert.equal(state.calls.length, 1);
  assert.deepEqual(JSON.parse(state.calls[0].init.body), corelyPlanPayload(input, 'info').payload);
  assert.equal(Object.isFrozen(snapshot), true); assert.equal(Object.isFrozen(snapshot.records), true); assert.equal(Object.isFrozen(snapshot.records[0]), true);
  assert.throws(() => { snapshot.records[0].status = 'SUCCESS_OVERRIDE'; }, TypeError);
  assert.deepEqual(empty, { records: [], droppedCount: 0 }, 'a previously returned snapshot cannot grow');
  assert.doesNotMatch(JSON.stringify(snapshot), /PRIVATE_|token|Authorization|gateway|schema|input|response|callId|cause/);
  state.instance.close(); assert.deepEqual(gateway.codexLocalGatewayTimingSnapshot(state.instance), snapshot);
});

test('final-only text and a seen terminal remain observations, never early acceptance of invalid usage or structured output', async t => {
  for (const mode of ['valid', 'missing-usage', 'invalid-output']) await t.test(mode, async child => {
    let time = 0;
    child.mock.method(performance, 'now', () => time++);
    const state = harness(child, { config: { diagnostics: true }, fetch: () => sse(completion('PRIVATE_OUTPUT',
      mode === 'missing-usage' ? { usage: undefined } : {})) });
    const input = request(`final-only-${mode}`, mode === 'invalid-output' ? { responseFormat: 'json' } : {});
    if (mode === 'valid') assert.equal((await run(state, input, 'eason')).status, 'success');
    else await assert.rejects(run(state, input, 'eason'), { code: mode === 'missing-usage' ? 'GATEWAY_RESPONSE_INVALID' : 'INVALID_STRUCTURED_OUTPUT' });
    const [row] = gateway.codexLocalGatewayTimingSnapshot(state.instance).records;
    assert.equal(row.status, mode === 'valid' ? 'SUCCESS' : 'FAILED'); assert.equal(row.account, 'eason');
    assert.equal(row.firstTextKind, 'FINAL_ONLY_VALIDATED'); assert.equal(row.headersToFirstTextMs, null);
    assert.equal(row.firstTextToTerminalMs, null); assert.ok(row.terminalOffsetMs <= row.streamEndOffsetMs);
    assert.ok(row.headersToValidatedFinalOnlyTextMs >= 0);
    assert.equal(state.calls.length, 1); assert.equal(state.checks.length, mode === 'valid' ? 2 : 1);
  });
});

test('diagnostic observer failure cannot swallow a parser error or change a completed receipt', async () => {
  const expected = await consumePlanTextStream(sse().body, new AbortController().signal);
  for (const asyncFailure of [false, true]) {
    const phases = [];
    const result = await consumePlanTextStream(sse().body, new AbortController().signal, (...args) => {
      assert.equal(args.length, 1); phases.push(args[0]);
      if (asyncFailure) return Promise.reject(new Error('PRIVATE_OBSERVER_FAILURE'));
      throw new Error('PRIVATE_OBSERVER_FAILURE');
    });
    assert.deepEqual(result, expected);
    assert.deepEqual(phases, ['terminal', 'stream_end', 'final_text_only']);
    await assert.rejects(consumePlanTextStream(new Response('data: {PRIVATE_STREAM_VALUE}\n\n').body,
      new AbortController().signal, () => { throw Error('PRIVATE_OBSERVER_FAILURE'); }), { code: 'INVALID_STREAM_EVENT' });
  }
});

test('cross-realm observer rejection is absorbed without reading its own then/catch accessors or replacing a parser error', () => {
  // Isolate intentional rejected-Promise fixtures so Node's test runner never
  // mistakes the regression's unhandled events for provider/parser failures.
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import { runInNewContext } from 'node:vm';
    import { consumePlanTextStream, MODEL } from ${JSON.stringify(new globalThis.URL('./siwc-local-runtime.mjs', import.meta.url).href)};
    let unhandled = 0, getters = 0, observed = 0, originalParserError = false;
    process.on('unhandledRejection', () => { unhandled++; });
    const completed = { type: 'response.completed', response: { id: 'synthetic', status: 'completed', model: MODEL,
      output: [{ type: 'message', content: [{ type: 'output_text', text: 'PRIVATE_TEXT' }] }],
      usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2 } } };
    const body = () => new Response('data: ' + JSON.stringify(completed) + '\\n\\n').body;
    const observer = () => {
      observed++;
      const rejected = runInNewContext('Promise.reject(new Error("PRIVATE_OBSERVER"))');
      for (const key of ['then', 'catch']) Object.defineProperty(rejected, key, { get() { getters++; throw Error('PRIVATE_GETTER'); } });
      return rejected;
    };
    await consumePlanTextStream(body(), new AbortController().signal, observer);
    const invalid = 'data: ' + JSON.stringify(completed) + '\\n\\ndata: {PRIVATE_INVALID}\\n\\n';
    try { await consumePlanTextStream(new Response(invalid).body, new AbortController().signal, observer); }
    catch (error) { originalParserError = error.code === 'INVALID_STREAM_EVENT'; }
    await new Promise(resolve => setImmediate(resolve));
    console.log(JSON.stringify({ unhandled, getters, observed, originalParserError }));
  `], { encoding: 'utf8', env: { PATH: process.env.PATH, HOME: '/private/tmp' }, timeout: 5000 });
  assert.equal(child.status, 0);
  const receipt = JSON.parse(child.stdout.trim());
  assert.ok(receipt.observed >= 3); assert.equal(receipt.unhandled, 0); assert.equal(receipt.getters, 0);
  assert.equal(receipt.originalParserError, true); assert.doesNotMatch(child.stdout + child.stderr, /PRIVATE_/);
});

test('timing preserves caller/owner/model cancellation and immutable snapshots after a noncooperative late fetch', async t => {
  for (const mode of ['caller', 'owner', 'model']) await t.test(mode, async child => {
    let time = 100, modelDeadline;
    child.mock.method(performance, 'now', () => time);
    child.mock.method(AbortSignal, 'timeout', ms => { const deadline = new AbortController();
      if (ms === 60000) modelDeadline = deadline; else assert.equal(ms, 5000); return deadline.signal; });
    const entered = deferred(), release = deferred(), caller = new AbortController();
    const state = harness(child, { config: { diagnostics: true }, fetch: () => { entered.resolve(); return release.promise; } });
    const pending = run(state, request(`late-timing-${mode}`), 'info', caller.signal); await entered.promise;
    time = 160;
    if (mode === 'caller') caller.abort('PRIVATE_ABORT_REASON'); else if (mode === 'owner') state.owner.abort('PRIVATE_ABORT_REASON'); else modelDeadline.abort('PRIVATE_ABORT_REASON');
    await assert.rejects(pending, { code: mode === 'caller' ? 'GATEWAY_ABORTED' : mode === 'owner' ? 'GATEWAY_CLOSED' : 'GATEWAY_TIMEOUT' });
    const before = gateway.codexLocalGatewayTimingSnapshot(state.instance); assert.equal(before.records.length, 1);
    assert.equal(before.records[0].status, 'FAILED'); assert.equal(before.records[0].abortOffsetMs, 60); assert.equal(before.records[0].abortPhase, 'DISPATCH');
    assert.equal(before.records[0].dispatchToHeadersMs, null); assert.equal(before.records[0].terminalOffsetMs, null);
    time = 999; release.resolve(sse(completion('PRIVATE_LATE_OUTPUT'))); await flush();
    assert.deepEqual(gateway.codexLocalGatewayTimingSnapshot(state.instance), before);
    assert.equal(state.calls.length, 1); assert.equal(state.checks.length, 1);
    assert.doesNotMatch(JSON.stringify(before), /PRIVATE_|reason|inputSha|callId|gatewayToken/);
  });
});

test('invalid diagnostic clock is not an authority clock and cannot change model acceptance', async t => {
  t.mock.method(performance, 'now', () => { throw Error('PRIVATE_DIAGNOSTIC_CLOCK_FAILURE'); });
  const state = harness(t, { config: { diagnostics: true } });
  assert.equal((await run(state)).status, 'success');
  const [row] = gateway.codexLocalGatewayTimingSnapshot(state.instance).records;
  assert.equal(row.clockStatus, 'UNAVAILABLE'); assert.equal(row.totalMs, null); assert.equal(row.status, 'SUCCESS');
  assert.equal(state.calls.length, 1); assert.equal(state.checks.length, 2);
});

test('cancellation after first text or a terminal event cannot publish or later amend an observed receipt', async t => {
  for (const terminalSeen of [false, true]) await t.test(String(terminalSeen), async child => {
    let time = 100, stream;
    child.mock.method(performance, 'now', () => time);
    const caller = new AbortController(), encode = event => new TextEncoder().encode(`data: ${JSON.stringify(event)}\n\n`);
    const state = harness(child, { config: { diagnostics: true }, fetch: () => new Response(new ReadableStream({
      start(controller) { stream = controller; }, cancel() {},
    }), { headers: { 'content-type': 'text/event-stream' } }) });
    const pending = run(state, request(`stream-timing-${terminalSeen}`), 'info', caller.signal); await flush();
    time = 150; stream.enqueue(encode({ type: 'response.output_text.delta', delta: 'PRIVATE_STREAM_TEXT' })); await flush();
    if (terminalSeen) { time = 160; stream.enqueue(encode({ type: 'response.completed', response: completion('PRIVATE_STREAM_TEXT') })); await flush(); }
    time = 170; caller.abort('PRIVATE_REASON'); await assert.rejects(pending, { code: 'GATEWAY_ABORTED' });
    const snapshot = gateway.codexLocalGatewayTimingSnapshot(state.instance), [row] = snapshot.records;
    assert.equal(row.status, 'FAILED'); assert.equal(row.firstTextKind, 'DELTA');
    assert.equal(row.abortPhase, 'STREAM'); assert.equal(row.abortOffsetMs, 70);
    assert.equal(row.terminalOffsetMs, terminalSeen ? 60 : null); assert.equal(row.streamEndOffsetMs, null);
    time = 1000; await flush();
    assert.deepEqual(gateway.codexLocalGatewayTimingSnapshot(state.instance), snapshot);
    assert.equal(state.checks.length, 1); assert.equal(state.calls.length, 1);
    assert.doesNotMatch(JSON.stringify(snapshot), /PRIVATE_|reason|text|body/);
  });
});

test('bounded timing history reports dropped observations without changing subsequent model admission or results', async t => {
  const state = harness(t, { config: { diagnostics: true } });
  for (let index = 0; index < 34; index++) assert.equal((await run(state, request(`bounded-stage-${index}`))).status, 'success');
  const snapshot = gateway.codexLocalGatewayTimingSnapshot(state.instance);
  assert.equal(snapshot.records.length, 32); assert.equal(snapshot.droppedCount, 2);
  assert.equal(snapshot.records[0].attempt, 1); assert.equal(snapshot.records.at(-1).attempt, 32);
  assert.equal(state.calls.length, 34); assert.equal(state.checks.length, 68);
});
