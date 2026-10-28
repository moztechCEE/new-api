import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { Readable } from 'node:stream';
import { after, before, test } from 'node:test';
import { createSiwcGatewayModelTransports } from './siwc-gateway-model-port.mjs';
import { runCorelyPlanRequest } from './siwc-local-model-port.mjs';
import { MODEL, ProbeError } from './siwc-local-runtime.mjs';

// Only injected synthetic Gateway/session fixtures run. No provider, credentials,
// database, actual VM or customer is read by this suite.
const savedFetch = globalThis.fetch;
before(() => { globalThis.fetch = async () => { throw new Error('NETWORK_DISABLED_IN_TEST'); }; });
after(() => { globalThis.fetch = savedFetch; });
const GATEWAY = 'https://newapi-dev.corely.cc/v1/responses';
const GATEWAY_KEY = 'synthetic-gateway-service-token-00000001';
const BRIDGE_KEY = 'synthetic-bridge-service-token-00000002';
const SHA = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object'
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;

function requestFixture(callId = 'gateway-fixture-call', overrides = {}) {
  const content = { version: 1, callId, model: MODEL, workload: 'REPLY_LLM', purpose: 'reply_generation',
    scope: { tenantId: 'moztech', brandId: 'moztech-test', synthetic: true, jobId: 'gateway-fixture-job' },
    system: 'Synthetic facts only.', user: 'Synthetic customer question.', schemaSha256: null, ...overrides };
  if (content.responseSchema) content.schemaSha256 = SHA(canonical(content.responseSchema));
  return { ...content, inputSha256: SHA(canonical(content)) };
}

function resultFixture(request, alias = 'info', overrides = {}) {
  return { accountAlias: alias, authMode: 'siwc_plan', accountVerified: true, model: MODEL, callId: request.callId,
    inputSha256: request.inputSha256, schemaSha256: request.schemaSha256, status: 'success', completionStatus: 'completed',
    text: 'Synthetic support answer.', usage: { inputTokens: 23, outputTokens: 7, cachedInputTokens: 3 }, ...overrides };
}

async function bridgeCall(handleRequest, body, { headers = {}, remoteAddress = '127.0.0.1', method = 'POST',
  url = '/v1/responses', rawHeaders, chunks, onReady } = {}) {
  const req = Readable.from(chunks ?? [Buffer.from(body)]);
  req.method = method; req.url = url; req.socket = { remoteAddress };
  req.headers = { authorization: `Bearer ${BRIDGE_KEY}`, 'content-type': 'application/json', ...headers };
  req.rawHeaders = rawHeaders ?? Object.entries(req.headers).flat();
  const res = new EventEmitter(); res.writableEnded = false; res.destroyed = false;
  res.writeHead = (status, value) => { res.status = status; res.headers = value; };
  res.end = value => { res.body = value ?? ''; res.writableEnded = true; res.emit('finish'); };
  const handling = handleRequest(req, res);
  if (onReady) await onReady(req, res);
  await handling;
  return { req, res, response: new Response(res.body, { status: res.status, headers: res.headers }) };
}

function harness(t, { generate, gateway, options = {} } = {}) {
  const lifetime = new AbortController(), calls = [], requests = [], diagnostics = [];
  let instance;
  instance = createSiwcGatewayModelTransports({ sessions: { generate: async (alias, request, signal) => {
    calls.push({ alias, request, signal });
    return generate ? generate(alias, request, signal) : resultFixture(request, alias);
  } }, gatewayUrl: GATEWAY, gatewayToken: GATEWAY_KEY, bridgeSecret: BRIDGE_KEY, signal: lifetime.signal,
  fetchImpl: async (url, init) => {
    requests.push({ url, init });
    assert.equal(url, options.gatewayUrl ?? GATEWAY);
    assert.equal(init.headers.Authorization, `Bearer ${GATEWAY_KEY}`);
    assert.equal(init.redirect, 'error'); assert.equal(init.credentials, 'omit');
    return gateway ? gateway(instance, init, calls) : (await bridgeCall(instance.handleRequest, init.body)).response;
  }, onDiagnostic: event => diagnostics.push(event), ...options });
  t.after(() => instance.close());
  return { instance, calls, requests, diagnostics, lifetime };
}

test('Gateway and private bridge retain strict structured facts, identity, usage and single-attempt receipt', async t => {
  const schema = { type: 'object', properties: { reply: { type: 'string' } }, required: ['reply'], additionalProperties: false };
  const request = requestFixture('structured-gateway-fixture', { responseSchema: schema, verbosity: 'low', reasoningEffort: 'low' });
  const state = harness(t, { generate: (alias, original) => resultFixture(original, alias, { text: '{"reply":"Synthetic answer"}' }) });
  const result = await state.instance.ports.info.generate(request, new AbortController().signal);
  assert.equal(result.text, '{"reply":"Synthetic answer"}');
  assert.deepEqual(result.usage, { inputTokens: 23, outputTokens: 7, cachedInputTokens: 3 });
  assert.equal(result.accountAlias, 'info'); assert.equal(result.authMode, 'siwc_plan');
  assert.equal(state.calls.length, 1); assert.equal(state.requests.length, 1);
  assert.deepEqual(state.calls[0].request, canonical(request));
  assert.equal(Object.hasOwn(state.calls[0].request, 'metadata'), false);
  const wire = JSON.parse(state.requests[0].init.body);
  assert.match(wire.metadata.corely_siwc_nonce, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(wire.text.format.strict, true); assert.deepEqual(wire.text.format.schema, schema);
  assert.equal(wire.model, MODEL); assert.equal(wire.stream, true); assert.equal(wire.store, false);
  assert.deepEqual(Object.keys(state.instance.ports).sort(), ['eason', 'info']);
  assert.equal(JSON.stringify(result).includes(BRIDGE_KEY), false);
  await assert.rejects(state.instance.ports.info.generate(request, new AbortController().signal), { code: 'GATEWAY_REPLAY_OR_CAPACITY' });
});

test('bound hints cross the Gateway while both accounts send the complete conservative SIWC profile without its nonce', async t => {
  const providerCalls = [], prefix = '固定合成事實🙂\r\n', user = prefix + '本輪合成問題。\r\n補充內容。';
  const system = '完整合成規範\r\n不可省略獨立覆核🙂';
  const state = harness(t, { generate: (alias, original, signal) => runCorelyPlanRequest({ alias,
    planScopeGranted: true, accountMatchesExpected: true, accessToken: `synthetic-${alias}-access`, expiresAt: Date.now() + 300_000 },
  original, async (url, init) => {
    assert.equal(init.headers.Authorization, `Bearer synthetic-${alias}-access`);
    if (url.endsWith('/models')) return Response.json({ models: [{ slug: MODEL, visibility: 'list' }] });
    assert.equal(url, 'https://api.openai.com/v1/responses');
    const payload = JSON.parse(init.body); providerCalls.push({ alias, payload });
    assert.equal(payload.instructions, system); assert.deepEqual(payload.input, [{ role: 'user', content: user }]);
    assert.equal(Object.hasOwn(payload, 'metadata'), false); assert.doesNotMatch(JSON.stringify(payload), /prompt_cache_|cache_control|corely_siwc_nonce/);
    return new Response(`data: ${JSON.stringify({ type: 'response.completed', response: {
      id: `synthetic-${alias}-response`, status: 'completed', model: MODEL,
      output: [{ type: 'message', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text: '合成客服答案🙂' }] }],
      usage: { input_tokens: 23, output_tokens: 7, total_tokens: 30, input_tokens_details: { cached_tokens: 3 } },
    } })}\n\n`, { headers: { 'Content-Type': 'text/event-stream' } });
  }, signal) });
  const options = { system, user, promptCache: { key: `support-${'b'.repeat(64)}`, userPrefixChars: prefix.length } };
  for (const alias of ['info', 'eason']) {
    const request = requestFixture(`prefix-${alias}`, options);
    const result = await state.instance.ports[alias].generate(request, new AbortController().signal);
    assert.equal(result.status, 'success'); assert.equal(result.accountAlias, alias); assert.equal(result.inputSha256, request.inputSha256);
    assert.deepEqual(state.calls.at(-1).request.promptCache, options.promptCache);
    assert.equal(state.calls.at(-1).request.user, user); assert.equal(Object.hasOwn(state.calls.at(-1).request, 'metadata'), false);
    const wire = JSON.parse(state.requests.at(-1).init.body);
    assert.match(wire.metadata.corely_siwc_nonce, /^[A-Za-z0-9_-]{43}$/);
    assert.equal(wire.instructions, system); assert.deepEqual(wire.input, [{ role: 'user', content: user }]);
    assert.doesNotMatch(JSON.stringify(wire), /prompt_cache_|cache_control/);
  }
  assert.equal(state.calls.length, 2); assert.equal(providerCalls.length, 2);
  assert.deepEqual(providerCalls.map(call => call.alias), ['info', 'eason']);
  assert.deepEqual(providerCalls[0].payload, providerCalls[1].payload);
});

test('only bound authenticated quota receipt returns quota; generic/fabricated Gateway429 never does', async t => {
  await t.test('authenticated receipt', async t => {
    const state = harness(t, { generate: (alias, request) => ({ accountAlias: alias, authMode: 'siwc_plan', accountVerified: true,
      model: MODEL, callId: request.callId, inputSha256: request.inputSha256, schemaSha256: request.schemaSha256,
      status: 'quota_exhausted', code: 'QUOTA_EXHAUSTED', authenticated: true }) });
    const result = await state.instance.ports.info.generate(requestFixture(), new AbortController().signal);
    assert.equal(result.status, 'quota_exhausted'); assert.equal(result.authenticated, true);
    assert.equal(state.calls.length, 1); assert.equal(state.calls[0].alias, 'info');
  });
  await t.test('unbound error and no implicit Eason/API', async t => {
    const state = harness(t, { gateway: () => new Response(JSON.stringify({ error: { code: 'subscription_sharing_usage_limit_exceeded' } }),
      { status: 429, headers: { 'content-type': 'application/json' } }) });
    await assert.rejects(state.instance.ports.info.generate(requestFixture(), new AbortController().signal), { code: 'GATEWAY_RESPONSE_INVALID' });
    assert.equal(state.calls.length, 0); assert.equal(state.requests.length, 1);
  });
});

test('service audience, browser exclusion, path, private peer and HTTP framing are enforced before inference', async t => {
  const state = harness(t);
  const cases = [
    { headers: { authorization: `Bearer ${GATEWAY_KEY}` } }, { headers: { authorization: `Bearer ${BRIDGE_KEY} extra` } },
    { headers: { origin: 'https://example.invalid' } }, { headers: { cookie: 'fixture=value' } },
    { headers: { 'sec-fetch-site': 'same-origin' } }, { headers: { 'user-agent': 'Mozilla/5.0' } },
    { headers: { 'x-forwarded-for': '127.0.0.1' } }, { remoteAddress: '203.0.113.5' },
    { method: 'GET' }, { url: '/v1/responses?alias=eason' }, { url: '/other' },
    { headers: { 'content-type': 'text/plain' } },
    { headers: { 'content-length': '2', 'transfer-encoding': 'chunked' } },
    { rawHeaders: ['authorization', `Bearer ${BRIDGE_KEY}`, 'Authorization', `Bearer ${BRIDGE_KEY}`] },
  ];
  for (const options of cases) assert.equal((await bridgeCall(state.instance.handleRequest, '{}', options)).res.status, 403);
  assert.equal(state.calls.length, 0);
});

test('payload tampering, duplicate JSON keys and unsolicited metadata cannot start SIWC', async t => {
  for (const mutate of [wire => ({ ...wire, model: 'different-model' }),
    wire => ({ ...wire, input: [{ role: 'user', content: 'Modified synthetic input' }] }),
    wire => ({ ...wire, metadata: { ...wire.metadata, accountAlias: 'eason' } }),
    wire => ({ ...wire, store: true })]) {
    await t.test('changed complete original payload', async t => {
      const state = harness(t, { gateway: async (instance, init) => (await bridgeCall(instance.handleRequest,
        JSON.stringify(mutate(JSON.parse(init.body))))).response });
      await assert.rejects(state.instance.ports.info.generate(requestFixture(), new AbortController().signal));
      assert.equal(state.calls.length, 0);
    });
  }
  await t.test('duplicate member', async t => {
    const state = harness(t, { gateway: async (instance, init) => (await bridgeCall(instance.handleRequest,
      init.body.replace('{', '{"model":"different-model",'))).response });
    await assert.rejects(state.instance.ports.info.generate(requestFixture(), new AbortController().signal));
    assert.equal(state.calls.length, 0);
  });
});

test('bridge diagnostics distinguish nonce admission from byte-only payload changes without logging actual values', async t => {
  const variants = [
    ['GATEWAY_NONCE_INVALID', body => JSON.stringify({ ...JSON.parse(body), metadata: {} })],
    ['GATEWAY_NONCE_UNBOUND', body => JSON.stringify({ ...JSON.parse(body), metadata: { corely_siwc_nonce: 'x'.repeat(43) } })],
    ['GATEWAY_PAYLOAD_MISMATCH', body => JSON.stringify(JSON.parse(body), null, 2)],
  ];
  for (const [reason, mutate] of variants) await t.test(reason, async t => {
    const state = harness(t, { gateway: async (instance, init) => {
      const { res, response } = await bridgeCall(instance.handleRequest, mutate(init.body));
      assert.equal(res.status, 409);
      assert.equal(res.body, '{"error":{"type":"corely_siwc_error","code":"bridge_request_held","message":"Corely SIWC request held"}}');
      return response;
    } });
    await assert.rejects(state.instance.ports.info.generate(requestFixture(), new AbortController().signal), { code: 'GATEWAY_RESPONSE_INVALID' });
    assert.deepEqual(state.diagnostics, [
      { stage: 'BRIDGE_INVOCATION', reason, httpStatus: 409, consumed: false },
      { stage: 'GATEWAY_RESPONSE', reason: 'GATEWAY_RESPONSE_INVALID', httpStatus: 409, consumed: false },
    ]);
    assert.equal(state.diagnostics.every(Object.isFrozen), true);
    assert.equal(state.calls.length, 0); assert.equal(state.requests.length, 1);
    const serialized = JSON.stringify(state.diagnostics);
    for (const actual of [GATEWAY_KEY, BRIDGE_KEY, 'Synthetic customer question.', 'Synthetic facts only.', 'x'.repeat(43)]) {
      assert.equal(serialized.includes(actual), false);
    }
  });
});

test('fixed bridge failure enums locate model/catalog, inference and output failures while every uncertain call stays single-attempt', async t => {
  const schema = { type: 'object', properties: { reply: { type: 'string' } }, required: ['reply'], additionalProperties: false };
  let codeGetterReads = 0;
  const provider = mode => (alias, request, signal) => runCorelyPlanRequest({ alias, accessToken: 'PRIVATE_SYNTHETIC_PROVIDER_TOKEN',
    expiresAt: Date.now() + 3_600_000, planScopeGranted: true, accountMatchesExpected: true }, request, async url => {
    if (url === 'https://api.openai.com/v1/models') return new Response(JSON.stringify({ models: mode === 'missing_model' ? [] : [{ slug: MODEL, visibility: 'list' }] }),
      { status: mode === 'catalog_http' ? 403 : 200, headers: { 'content-type': 'application/json' } });
    assert.equal(url, 'https://api.openai.com/v1/responses');
    if (mode === 'provider_http') return new Response('{"error":{"message":"PRIVATE_PROVIDER_ERROR"}}',
      { status: 400, headers: { 'content-type': 'application/json' } });
    const completed = { type: 'response.completed', response: { id: 'synthetic_provider_response', model: MODEL, status: 'completed',
      output: [{ type: 'message', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text: '{"unexpected":true}' }] }],
      usage: { input_tokens: 23, output_tokens: 7, total_tokens: 30 } } };
    return new Response(`event: response.completed\ndata: ${JSON.stringify(completed)}\n\n`, { status: 200, headers: { 'content-type': 'text/event-stream' } });
  }, signal);
  const variants = [
    ['catalog model absent', provider('missing_model'), 'BRIDGE_SESSION', 'EXACT_MODEL_NOT_AVAILABLE', 409],
    ['catalog HTTP', provider('catalog_http'), 'BRIDGE_SESSION', 'UPSTREAM_HTTP_ERROR', 403],
    ['inference HTTP', provider('provider_http'), 'BRIDGE_SESSION', 'INFERENCE_HTTP_ERROR', 400],
    ['provider output validation', provider('invalid_output'), 'BRIDGE_SESSION', 'INVALID_STRUCTURED_OUTPUT', 409],
    ['bound receipt output validation', (alias, request) => resultFixture(request, alias, { text: '{"unexpected":true}' }), 'BRIDGE_RESULT', 'INVALID_STRUCTURED_OUTPUT', 409],
    ['unknown secret-bearing error', () => { throw Object.assign(new Error('PRIVATE_PROVIDER_BODY_AND_TOKEN'),
      { code: 'PRIVATE_SECRET_CODE', diagnostic: { httpStatus: 401, errorCode: 'PRIVATE_TOKEN' }, cause: 'PRIVATE_INPUT' }); }, 'BRIDGE_SESSION', 'UNKNOWN_ERROR', 409],
    ['unknown error getter', () => { const error = new Error('PRIVATE_GETTER_MESSAGE');
      Object.defineProperty(error, 'code', { get() { codeGetterReads++; throw new Error('PRIVATE_GETTER_VALUE'); } }); throw error;
    }, 'BRIDGE_SESSION', 'UNKNOWN_ERROR', 409],
  ];
  for (const [name, generate, stage, reason, httpStatus] of variants) await t.test(name, async t => {
    const state = harness(t, { generate });
    const request = requestFixture('diagnostic-failure-call', { responseSchema: schema });
    await assert.rejects(state.instance.ports.info.generate(request, new AbortController().signal), { code: 'GATEWAY_CALL_ABORTED' });
    assert.deepEqual(state.diagnostics, [
      { stage, reason, httpStatus, consumed: true, ...(name === 'inference HTTP'
        ? { providerErrorTypeClass: 'MISSING', providerParamClass: 'MISSING' } : {}) },
      { stage: 'GATEWAY_FETCH', reason: 'GATEWAY_CALL_ABORTED', httpStatus: null, consumed: true },
    ]);
    assert.equal(codeGetterReads, 0);
    assert.equal(state.calls.length, 1); assert.equal(state.calls[0].alias, 'info'); assert.equal(state.requests.length, 1);
    await assert.rejects(state.instance.ports.info.generate(request, new AbortController().signal), { code: 'GATEWAY_REPLAY_OR_CAPACITY' });
    assert.equal(state.calls.length, 1); assert.equal(state.requests.length, 1); assert.equal(state.diagnostics.length, 2);
    assert.doesNotMatch(JSON.stringify(state.diagnostics), /PRIVATE|Synthetic|@|Bearer|nonce|\.cc/);
  });
});

test('only branded fixed inference classes cross the Gateway audit boundary; diagnostic getters and proxies cannot forge them', async t => {
  let reads = 0;
  const classes = { providerErrorTypeClass: 'INVALID_REQUEST', providerParamClass: 'CACHE_OPTIONS' };
  const trusted = () => {
    const error = new ProbeError('INFERENCE_HTTP_400', classes);
    Object.defineProperty(error, 'diagnostic', { get() { reads++; throw new Error('PRIVATE_GETTER'); } });
    return error;
  };
  for (const [name, create, expectedClasses] of [
    ['original trusted snapshot', trusted, classes],
    ['foreign diagnostic getter', () => Object.defineProperty(Object.assign(new Error('PRIVATE_MESSAGE'), { code: 'INFERENCE_HTTP_400' }),
      'diagnostic', { get() { reads++; throw new Error('PRIVATE_FOREIGN_GETTER'); } }), {}],
    ['foreign fixed-looking data', () => Object.assign(new Error('PRIVATE_MESSAGE'), { code: 'INFERENCE_HTTP_400', diagnostic: classes }), {}],
    ['proxy of trusted error', () => new Proxy(trusted(), { get() { reads++; throw new Error('PRIVATE_PROXY_GETTER'); } }), {}],
    ['non-inference trusted error', () => new ProbeError('UPSTREAM_HTTP_403', classes), {}],
  ]) await t.test(name, async t => {
    const state = harness(t, { generate: () => { throw create(); } });
    const request = requestFixture('fixed-class-boundary');
    await assert.rejects(state.instance.ports.info.generate(request, new AbortController().signal), { code: 'GATEWAY_CALL_ABORTED' });
    assert.deepEqual(state.diagnostics[0], { stage: 'BRIDGE_SESSION', reason: name === 'non-inference trusted error'
      ? 'UPSTREAM_HTTP_ERROR' : 'INFERENCE_HTTP_ERROR', httpStatus: name === 'non-inference trusted error' ? 403 : 400,
    consumed: true, ...expectedClasses });
    assert.deepEqual(state.diagnostics[1], { stage: 'GATEWAY_FETCH', reason: 'GATEWAY_CALL_ABORTED', httpStatus: null, consumed: true });
    assert.equal(state.calls.length, 1); assert.equal(state.requests.length, 1);
    assert.equal(reads, 0); assert.doesNotMatch(JSON.stringify(state.diagnostics), /PRIVATE|prompt_cache|Bearer/);
    await assert.rejects(state.instance.ports.info.generate(request, new AbortController().signal), { code: 'GATEWAY_REPLAY_OR_CAPACITY' });
    assert.equal(state.calls.length, 1); assert.equal(state.requests.length, 1);
  });
});

test('provider type and parameter classes never become quota authority or trigger another account', async t => {
  for (const [name, status, error, exhausted] of [
    ['quota-looking type and parameter only', 400, { type: 'subscription_sharing_usage_limit_exceeded',
      param: 'subscription_sharing_usage_limit_exceeded' }, false],
    ['ordinary rate limit', 429, { type: 'rate_limit_error', param: 'reasoning.effort', code: 'rate_limit_exceeded' }, false],
    ['exact authenticated quota code retained', 429, { type: 'invalid_request_error', param: 'prompt_cache_key',
      code: 'subscription_sharing_usage_limit_exceeded' }, true],
  ]) await t.test(name, async t => {
    let catalogCalls = 0, providerCalls = 0;
    const state = harness(t, { generate: (alias, request, signal) => runCorelyPlanRequest({ alias,
      accessToken: 'PRIVATE_SYNTHETIC_PROVIDER_TOKEN', expiresAt: Date.now() + 3_600_000,
      planScopeGranted: true, accountMatchesExpected: true }, request, async url => {
      if (url === 'https://api.openai.com/v1/models') {
        catalogCalls++; return Response.json({ models: [{ slug: MODEL, visibility: 'list' }] });
      }
      providerCalls++; assert.equal(url, 'https://api.openai.com/v1/responses');
      return Response.json({ error: { ...error, message: 'PRIVATE_PROVIDER_ERROR' } }, { status });
    }, signal) });
    if (exhausted) {
      const result = await state.instance.ports.info.generate(requestFixture(), new AbortController().signal);
      assert.equal(result.status, 'quota_exhausted'); assert.equal(result.authenticated, true);
      assert.equal(state.diagnostics.length, 0);
    } else {
      await assert.rejects(state.instance.ports.info.generate(requestFixture(), new AbortController().signal), { code: 'GATEWAY_CALL_ABORTED' });
      assert.equal(state.diagnostics[0].reason, 'INFERENCE_HTTP_ERROR');
      assert.equal(state.diagnostics[0].providerErrorTypeClass, status === 400 ? 'OTHER' : 'RATE_LIMIT');
      assert.equal(state.diagnostics[0].providerParamClass, status === 400 ? 'OTHER' : 'REASONING');
    }
    assert.equal(catalogCalls, 1); assert.equal(providerCalls, 1);
    assert.equal(state.calls.length, 1); assert.equal(state.requests.length, 1); assert.equal(state.calls[0].alias, 'info');
    assert.doesNotMatch(JSON.stringify(state.diagnostics), /PRIVATE|subscription_sharing|rate_limit_error|reasoning\.effort/);
  });
});

test('throwing, rejecting or pending diagnostic observers cannot relax a bridge hold or rerun inference', async t => {
  for (const mode of ['throw', 'reject', 'pending']) await t.test(mode, async t => {
    const events = [];
    const state = harness(t, { generate: () => { throw new ProbeError('EXACT_MODEL_NOT_AVAILABLE'); },
      options: { onDiagnostic: event => {
        events.push(event);
        if (mode === 'throw') throw new Error('PRIVATE_OBSERVER_ERROR');
        if (mode === 'reject') return Promise.reject(new Error('PRIVATE_OBSERVER_ERROR'));
        return new Promise(() => {});
      } } });
    const request = requestFixture();
    await assert.rejects(state.instance.ports.info.generate(request, new AbortController().signal), { code: 'GATEWAY_CALL_ABORTED' });
    await assert.rejects(state.instance.ports.info.generate(request, new AbortController().signal), { code: 'GATEWAY_REPLAY_OR_CAPACITY' });
    assert.equal(state.calls.length, 1); assert.equal(state.requests.length, 1); assert.equal(events.length, 2);
    assert.deepEqual(events[0], { stage: 'BRIDGE_SESSION', reason: 'EXACT_MODEL_NOT_AVAILABLE', httpStatus: 409, consumed: true });
  });
});

test('concurrent/repeated bridge replay invokes sessions exactly once without canceling the owner', async t => {
  let complete;
  const outcome = new Promise(resolve => { complete = resolve; });
  const state = harness(t, { generate: async (alias, request) => { await outcome; return resultFixture(request, alias); },
    gateway: async (instance, init, calls) => {
      const first = bridgeCall(instance.handleRequest, init.body);
      while (calls.length === 0) await new Promise(resolve => setImmediate(resolve));
      const replay = await bridgeCall(instance.handleRequest, init.body);
      assert.equal(replay.res.status, 409); assert.equal(calls[0].signal.aborted, false);
      complete();
      const original = await first;
      assert.equal((await bridgeCall(instance.handleRequest, init.body)).res.status, 409);
      return original.response;
    } });
  assert.equal((await state.instance.ports.info.generate(requestFixture(), new AbortController().signal)).status, 'success');
  assert.equal(state.calls.length, 1);
});

test('Gateway text/model/usage/response identity tampering and missing terminal all fail closed', async t => {
  const edits = [body => body.replace('Synthetic support answer.', 'Altered support answer.'),
    body => body.replace(MODEL, 'another-model'), body => body.replace('"output_tokens":7', '"output_tokens":8'),
    body => body.replace('resp_corely_', 'resp_changed_'), body => body.replace('response.completed', 'response.in_progress').replace('response.completed', 'response.in_progress')];
  for (const edit of edits) await t.test('modified Gateway envelope', async t => {
    const state = harness(t, { gateway: async (instance, init) => {
      const { res } = await bridgeCall(instance.handleRequest, init.body);
      return new Response(edit(res.body), { status: 200, headers: res.headers });
    } });
    await assert.rejects(state.instance.ports.info.generate(requestFixture(), new AbortController().signal));
    assert.equal(state.calls.length, 1); assert.equal(state.requests.length, 1);
  });
});

test('invalid internal receipt/schema, upstream failure, and unsafe usage do not emit successful Gateway output', async t => {
  const variants = [result => ({ ...result, accountAlias: 'eason' }), result => ({ ...result, model: 'different-model' }),
    result => ({ ...result, inputSha256: '0'.repeat(64) }), result => ({ ...result, accountVerified: false }),
    result => ({ ...result, usage: { inputTokens: Number.MAX_SAFE_INTEGER, outputTokens: 1, cachedInputTokens: 0 } })];
  for (const modify of variants) await t.test('invalid bound receipt', async t => {
    const state = harness(t, { generate: (alias, request) => modify(resultFixture(request, alias)) });
    await assert.rejects(state.instance.ports.info.generate(requestFixture(), new AbortController().signal));
    assert.equal(state.calls.length, 1);
  });
  await t.test('upstream uncertainty does not retry', async t => {
    const state = harness(t, { generate: () => { throw new Error('SYNTHETIC_PROVIDER_TIMEOUT'); } });
    await assert.rejects(state.instance.ports.info.generate(requestFixture(), new AbortController().signal));
    assert.equal(state.calls.length, 1); assert.equal(state.requests.length, 1);
  });
});

test('caller cancellation and close fence ignored late session output and cannot replay a model call', async t => {
  let release;
  const delayed = new Promise(resolve => { release = resolve; });
  const state = harness(t, { generate: async (alias, request) => { await delayed; return resultFixture(request, alias); } });
  const caller = new AbortController(), request = requestFixture();
  const running = state.instance.ports.info.generate(request, caller.signal);
  while (state.calls.length === 0) await new Promise(resolve => setImmediate(resolve));
  caller.abort();
  await assert.rejects(running, { code: 'GATEWAY_CALL_ABORTED' });
  assert.equal(state.calls[0].signal.aborted, true);
  release();
  await assert.rejects(state.instance.ports.info.generate(request, new AbortController().signal), { code: 'GATEWAY_REPLAY_OR_CAPACITY' });
  state.instance.close();
  await assert.rejects(state.instance.ports.eason.generate(requestFixture('closed-call'), new AbortController().signal), { code: 'GATEWAY_CALL_ABORTED' });
  assert.equal((await bridgeCall(state.instance.handleRequest, state.requests[0].init.body)).res.status, 403);
  assert.equal(state.calls.length, 1);
});

test('bridge disconnect and factory close propagate cancellation to the only active session operation', async t => {
  for (const mode of ['bridge_disconnect', 'factory_close']) await t.test(mode, async t => {
    let release;
    const delayed = new Promise(resolve => { release = resolve; });
    const state = harness(t, { generate: async (alias, request) => { await delayed; return resultFixture(request, alias); },
      gateway: async (instance, init, calls) => (await bridgeCall(instance.handleRequest, init.body, { onReady: async (_req, res) => {
        while (calls.length === 0) await new Promise(resolve => setImmediate(resolve));
        if (mode === 'bridge_disconnect') res.emit('close');
        else instance.close();
      } })).response });
    await assert.rejects(state.instance.ports.info.generate(requestFixture(), new AbortController().signal));
    assert.equal(state.calls.length, 1); assert.equal(state.calls[0].signal.aborted, true);
    release();
  });
});

test('body framing bounds, malformed JSON, and unknown nonce fail without touching a session', async t => {
  const state = harness(t);
  const variants = [
    ['{}', { headers: { 'content-length': '83886100' } }],
    ['{}', { headers: { 'content-length': '3' } }],
    ['{}', { headers: { 'content-length': '-1' } }],
    ['{', {}], ['{}', {}],
    [JSON.stringify({ metadata: { corely_siwc_nonce: 'x'.repeat(43) } }), {}],
    ['{}', { chunks: [Buffer.from([0xff, 0xff])] }],
    ['{}', { chunks: [Buffer.alloc(8 * 1024 * 1024 + 4097)] }],
  ];
  for (const [body, options] of variants) {
    const { res } = await bridgeCall(state.instance.handleRequest, body, options);
    assert.equal(res.status, 409);
    assert.equal(res.body.includes(GATEWAY_KEY), false); assert.equal(res.body.includes(BRIDGE_KEY), false);
  }
  assert.equal(state.calls.length, 0);
});

test('scope/hash admission and invalid structured output cannot bypass the preexisting model contract', async t => {
  const state = harness(t);
  for (const request of [requestFixture('wrong-brand', { scope: { tenantId: 'moztech', brandId: 'another-brand', synthetic: true, jobId: 'fixture' } }),
    { ...requestFixture('tampered-hash'), user: 'Changed without a matching input digest' }]) {
    await assert.rejects(state.instance.ports.info.generate(request, new AbortController().signal));
  }
  assert.equal(state.requests.length, 0); assert.equal(state.calls.length, 0);
  const invalid = harness(t, { generate: (alias, request) => resultFixture(request, alias, { text: '{"unexpected":true}' }) });
  const schema = { type: 'object', properties: { reply: { type: 'string' } }, required: ['reply'], additionalProperties: false };
  await assert.rejects(invalid.instance.ports.info.generate(requestFixture('invalid-structured-output', { responseSchema: schema }), new AbortController().signal));
  assert.equal(invalid.calls.length, 1);
});

test('request TTL and capacity are bounded without retrying an uncertain request', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const state = harness(t, { gateway: () => new Promise(() => {}) });
  const pending = [];
  for (let i = 0; i < 32; i++) pending.push(state.instance.ports.info.generate(requestFixture(`capacity-${i}`), new AbortController().signal));
  await assert.rejects(state.instance.ports.info.generate(requestFixture('over-capacity'), new AbortController().signal), { code: 'GATEWAY_REPLAY_OR_CAPACITY' });
  const settled = Promise.allSettled(pending);
  t.mock.timers.tick(60_000);
  const results = await settled;
  assert.equal(results.every(result => result.status === 'rejected' && result.reason.code === 'GATEWAY_CALL_ABORTED'), true);
  assert.equal(state.calls.length, 0);
});

test('configuration only permits fixed DEV HTTPS/explicit loopback endpoint and separate service secrets', async t => {
  for (const gatewayUrl of ['https://api.openai.com/v1/responses', 'https://other.example.invalid/v1/responses',
    'http://newapi-dev.corely.cc/v1/responses', 'http://localhost:3000/v1/responses', 'http://127.0.0.1:80/v1/responses',
    'https://newapi-dev.corely.cc/v1/responses?x=y', 'https://newapi-dev.corely.cc/other']) {
    assert.throws(() => harness(t, { options: { gatewayUrl } }), { code: 'GATEWAY_OPTIONS_INVALID' });
  }
  assert.throws(() => harness(t, { options: { bridgeSecret: GATEWAY_KEY } }), { code: 'GATEWAY_OPTIONS_INVALID' });
  assert.throws(() => harness(t, { options: { gatewayToken: 'short' } }), { code: 'GATEWAY_OPTIONS_INVALID' });
  const local = harness(t, { options: { gatewayUrl: 'http://127.0.0.1:31337/v1/responses' } });
  assert.equal((await local.instance.ports.eason.generate(requestFixture(), new AbortController().signal)).accountAlias, 'eason');
  assert.equal(local.calls[0].alias, 'eason');
});
