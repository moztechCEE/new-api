import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { Readable } from 'node:stream';
import { after, before, test } from 'node:test';
import { createSiwcGatewayModelTransports } from './siwc-gateway-model-port.mjs';
import { MODEL } from './siwc-local-runtime.mjs';

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
  const lifetime = new AbortController(), calls = [], requests = [];
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
  }, ...options });
  t.after(() => instance.close());
  return { instance, calls, requests, lifetime };
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

test('prefix hints cross the Gateway without losing bytes or leaking its nonce to SIWC; accounts keep separate cache keys', async t => {
  const state = harness(t), user = 'Stable synthetic facts.\nCurrent synthetic request.';
  const options = { user, promptCache: { key: `support-${'b'.repeat(64)}`, userPrefixChars: 'Stable synthetic facts.'.length } };
  for (const alias of ['info', 'eason']) {
    const request = requestFixture(`prefix-${alias}`, options);
    const result = await state.instance.ports[alias].generate(request, new AbortController().signal);
    assert.equal(result.status, 'success'); assert.equal(result.accountAlias, alias);
    assert.deepEqual(state.calls.at(-1).request.promptCache, options.promptCache);
    assert.equal(state.calls.at(-1).request.user, user); assert.equal(Object.hasOwn(state.calls.at(-1).request, 'metadata'), false);
    const wire = JSON.parse(state.requests.at(-1).init.body);
    assert.equal(wire.input[0].role, 'developer');
    assert.equal(wire.input[1].content.map(block => block.text).join(''), user);
    assert.deepEqual(wire.input[1].content[0].prompt_cache_breakpoint, { mode: 'explicit' });
    assert.equal(Object.hasOwn(wire, 'prompt_cache_retention'), false);
  }
  assert.notEqual(JSON.parse(state.requests[0].init.body).prompt_cache_key, JSON.parse(state.requests[1].init.body).prompt_cache_key);
  assert.equal(state.calls.length, 2);
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
