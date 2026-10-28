import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { chmod, link, lstat, mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { after, before, test } from 'node:test';
import { ISSUER, RESOURCE, MODEL, PROBE_OUTPUT, SCOPES, ProbeError, digest } from './siwc-local-runtime.mjs';
import { openSessionStore, persistValidatedAuthorization, retainIssuedRegistration, writeEnrollment, importEnrollment,
  forgetTransferredEnrollment, createPersistentPlanSessions, SESSION_ACCOUNTS } from './siwc-local-sessions.mjs';
import { startPersistentEnrollment, assertIsolatedSessionEnvironment, parseSessionCommand } from './siwc-local-vm.mjs';
import { corelyPlanPayload, createSiwcModelTransports, createTransientSiwcModelPort, runCorelyPlanRequest } from './siwc-local-model-port.mjs';

// Only fake identities/credentials and injected provider responses are used.
const nativeFetch = globalThis.fetch;
before(() => { globalThis.fetch = async () => { throw new Error('NETWORK_DISABLED_IN_TEST'); }; });
after(() => { globalThis.fetch = nativeFetch; });
const NOW = Math.floor(Date.now() / 1000) * 1000;
const NONCE = 'synthetic-enrollment-nonce';
const keys = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...keys.publicKey.export({ format: 'jwk' }), kid: 'synthetic', alg: 'RS256', use: 'sig' };
const JWKS = { keys: [jwk] };
const code = expected => error => error instanceof ProbeError && error.code === expected;

function fixtureToken(alias = 'info', { claims = {}, token = {}, nonce = NONCE } = {}) {
  const payload = { iss: ISSUER, sub: `synthetic-${alias}`, aud: `fixture_${alias}`, nonce,
    iat: NOW / 1000 - 10, exp: NOW / 1000 + 3600, email: SESSION_ACCOUNTS[alias], email_verified: true, ...claims };
  const content = [Buffer.from(JSON.stringify({ alg: 'RS256', kid: jwk.kid })).toString('base64url'),
    Buffer.from(JSON.stringify(payload)).toString('base64url')].join('.');
  return { id_token: `${content}.${sign('RSA-SHA256', Buffer.from(content), keys.privateKey).toString('base64url')}`,
    access_token: `synthetic-${alias}-access`, refresh_token: `synthetic-${alias}-refresh`,
    expires_in: 300, token_type: 'Bearer', scope: SCOPES, ...token };
}
async function stores(t) {
  const parent = await mkdtemp(join(tmpdir(), 'new-api-session-fixture-'));
  t.after(() => rm(parent, { recursive: true, force: true }));
  return { parent, local: await openSessionStore(join(parent, 'enrollment'), { runtime: 'enrollment' }),
    vm: await openSessionStore(join(parent, 'vm')) };
}
async function enroll(store, alias = 'info', options) {
  return persistValidatedAuthorization(store, alias, { token: fixtureToken(alias, options), jwks: JWKS,
    clientId: `fixture_${alias}`, nonce: options?.nonce ?? NONCE }, NOW);
}
async function transferred(t, aliases = ['info']) {
  const fixture = await stores(t);
  for (const alias of aliases) {
    await enroll(fixture.local, alias);
    const transfer = await writeEnrollment(fixture.local, alias, fixture.vm.host.hostId);
    const bundle = JSON.parse(await readFile(transfer.file, 'utf8'));
    await importEnrollment(fixture.vm, alias, bundle, JWKS, NOW + 1000);
  }
  return fixture;
}
const catalog = () => Response.json({ models: [{ slug: MODEL, visibility: 'list' }] });
function completion() {
  return new Response(Buffer.from(`data: ${JSON.stringify({ type: 'response.completed', response: {
    id: 'synthetic-response', status: 'completed', model: MODEL,
    output: [{ type: 'message', content: [{ type: 'output_text', text: PROBE_OUTPUT }] }],
    usage: { input_tokens: 17, output_tokens: 11, total_tokens: 28 },
  } })}\n\n`), { headers: { 'Content-Type': 'text/event-stream' } });
}

function modelRequest({ callId = 'synthetic-model-call', inputSha256: _inputHash, schemaSha256: _schemaHash, ...changes } = {}) {
  const sort = value => value && typeof value === 'object' ? Array.isArray(value) ? value.map(sort)
    : Object.fromEntries(Object.keys(value).sort().map(key => [key, sort(value[key])])) : value;
  const draft = { version: 1, callId, model: MODEL, workload: 'REPLY_LLM', purpose: 'reply_generation',
    scope: { tenantId: 'moztech', brandId: 'moztech-test', synthetic: true, jobId: 'synthetic-model-job' },
    system: 'Synthetic brand facts only. Preserve quality review.', user: 'Synthetic customer question.', ...changes };
  const content = { ...draft, schemaSha256: draft.responseSchema ? digest(JSON.stringify(sort(draft.responseSchema))) : null };
  return { ...content, inputSha256: digest(JSON.stringify(sort(content))) };
}
function modelCompletion(text, { usage = { input_tokens: 21, output_tokens: 8, total_tokens: 29,
  input_tokens_details: { cached_tokens: 5 } }, output, ...changes } = {}) {
  return new Response(Buffer.from(`data: ${JSON.stringify({ type: 'response.completed', response: {
    id: 'synthetic-corely-response', status: 'completed', model: MODEL,
    output: output ?? [{ type: 'message', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text }] }],
    usage, ...changes,
  } })}\n\n`), { headers: { 'Content-Type': 'text/event-stream' } });
}

test('SIWC maps the entire bounded Corely contract to public Responses without paid-API-only fields', async t => {
  const schema = { type: 'object', properties: { answer: { type: 'string', minLength: 1 } }, required: ['answer'], additionalProperties: false };
  const input = modelRequest({ responseSchema: schema, responseFormat: 'json', reasoningEffort: 'low', verbosity: 'low' });
  const { request, payload } = corelyPlanPayload(input);
  assert.equal(request.inputSha256, input.inputSha256);
  assert.deepEqual(payload, { model: MODEL, instructions: input.system, input: [{ role: 'user', content: input.user }], store: false, stream: true,
    reasoning: { effort: 'low' }, text: { format: { type: 'json_schema', name: 'corely_model_output', strict: true, schema }, verbosity: 'low' } });
  assert.equal(Object.isFrozen(request.responseSchema.properties.answer), true);
  input.responseSchema.properties.answer.minLength = 999;
  assert.equal(payload.text.format.schema.properties.answer.minLength, 1);
  assert.deepEqual(corelyPlanPayload(modelRequest({ responseFormat: 'json' })).payload.text, { format: { type: 'json_object' } });
  for (const [name, bad, expected] of [
    ['real customer scope', modelRequest({ scope: { tenantId: 'moztech', brandId: 'moztech-test', synthetic: false, jobId: 'x' } }), 'SCOPE_NOT_ADMITTED'],
    ['cross brand', modelRequest({ scope: { tenantId: 'moztech', brandId: 'other', synthetic: true, jobId: 'x' } }), 'SCOPE_NOT_ADMITTED'],
    ['wrong model', modelRequest({ model: 'gpt-6-astra' }), 'INVALID_REQUEST'],
    ['image not yet verified', modelRequest({ image: { mime: 'image/png', base64: 'c3ludGhldGlj' } }), 'UNSUPPORTED_CAPABILITY'],
    ['unbound content', { ...modelRequest(), user: 'changed' }, 'INPUT_MISMATCH'],
    ['unsupported schema', modelRequest({ responseSchema: { type: 'object', properties: {}, required: [], additionalProperties: true } }), 'UNSUPPORTED_CAPABILITY'],
    ['API field injection', modelRequest({ temperature: 0 }), 'INVALID_REQUEST'],
  ]) await t.test(name, () => assert.throws(() => corelyPlanPayload(bad), { code: expected }));
});

test('SIWC preserves complete prompt variants and bound hints without optional API cache fields', async () => {
  const prefix = '品牌事實\r\n完整產品目錄🙂\n', system = '完整系統規則\r\n獨立覆核不可省略。';
  const original = modelRequest({ system, user: prefix + '本輪顧客問題一。', promptCache: {
    key: `support-${'a'.repeat(64)}`, userPrefixChars: prefix.length }, reasoningEffort: 'low', verbosity: 'low' });
  const { request, payload } = corelyPlanPayload(original, 'info');
  assert.deepEqual(Buffer.from(payload.instructions), Buffer.from(system));
  assert.deepEqual(payload.input, [{ role: 'user', content: original.user }]);
  assert.deepEqual(Buffer.from(payload.input[0].content), Buffer.from(original.user));
  assert.equal(request.inputSha256, original.inputSha256);
  assert.equal(payload.store, false); assert.equal(payload.stream, true);
  assert.deepEqual(payload.reasoning, { effort: 'low' }); assert.equal(payload.text.verbosity, 'low');
  for (const name of ['metadata', 'prompt_cache_options', 'prompt_cache_key', 'prompt_cache_retention', 'cache_control', 'previous_response_id', 'background']) assert.equal(Object.hasOwn(payload, name), false);
  assert.doesNotMatch(JSON.stringify(payload), /prompt_cache_breakpoint/);
  assert.deepEqual(corelyPlanPayload(original, 'eason').payload, payload);
  const changedQuestion = modelRequest({ ...original, user: prefix + '本輪顧客問題二。' });
  for (const changes of [{ user: changedQuestion.user }, { system: system + '新增規則' }, { user: '不同事實🙂\n' + original.user },
    { purpose: 'semantic_reply_review' }, { responseSchema: { type: 'object', properties: {}, required: [], additionalProperties: false } }]) {
    const variant = modelRequest({ ...original, ...changes }), projected = corelyPlanPayload(variant, 'info');
    assert.notEqual(projected.request.inputSha256, request.inputSha256);
    assert.equal(projected.payload.instructions, variant.system); assert.equal(projected.payload.input[0].content, variant.user);
    if (variant.responseSchema) assert.deepEqual(projected.payload.text.format.schema, variant.responseSchema);
  }
  const noBoundary = corelyPlanPayload(modelRequest({ ...original, promptCache: { key: original.promptCache.key } }), 'info');
  assert.deepEqual(noBoundary.payload, payload); assert.notEqual(noBoundary.request.inputSha256, request.inputSha256);
  assert.equal(Object.isFrozen(request.promptCache), true);
  assert.throws(() => corelyPlanPayload(changedQuestion), code('MODEL_PORT_INVALID'));
  original.promptCache.key = `support-${'b'.repeat(64)}`;
  assert.equal(request.promptCache.key, `support-${'a'.repeat(64)}`);
});

test('SIWC rejects invalid, falsy, Unicode-split and unbound prefix hints without dropping metadata', async t => {
  for (const promptCache of [false, null, [], {}, { key: 'customer-id' }, { key: `support-${'a'.repeat(64)}`, extra: true },
    ...[0, false, -1, 1.5, '1', 2, 4].map(userPrefixChars => ({ key: `support-${'a'.repeat(64)}`, userPrefixChars }))]) {
    await t.test(JSON.stringify(promptCache), () => assert.throws(() => corelyPlanPayload(modelRequest({ user: 'a🙂b', promptCache }), 'info'), { code: 'INVALID_REQUEST' }));
  }
  const request = modelRequest({ promptCache: { key: `support-${'a'.repeat(64)}` } });
  assert.throws(() => corelyPlanPayload({ ...request, promptCache: false }, 'info'), { code: 'INVALID_REQUEST' });
  assert.throws(() => corelyPlanPayload({ ...request, promptCache: { key: `support-${'b'.repeat(64)}` } }, 'info'), { code: 'INPUT_MISMATCH' });
});

test('personal Responses keeps the conservative profile and never retries a synthetic invalid request', async () => {
  const session = { alias: 'info', planScopeGranted: true, accountMatchesExpected: true,
    accessToken: 'synthetic-access', expiresAt: Date.now() + 300_000 };
  const input = modelRequest({ promptCache: { key: `support-${'a'.repeat(64)}`, userPrefixChars: 9 } });
  let catalogCalls = 0, modelCalls = 0;
  await assert.rejects(runCorelyPlanRequest(session, input, async (url, init) => {
    assert.equal(init.headers.Authorization, 'Bearer synthetic-access');
    if (url.endsWith('/models')) { catalogCalls++; return catalog(); }
    modelCalls++;
    const payload = JSON.parse(init.body);
    assert.deepEqual(payload.input, [{ role: 'user', content: input.user }]); assert.equal(payload.instructions, input.system);
    assert.doesNotMatch(JSON.stringify(payload), /prompt_cache_|cache_control/);
    return Response.json({ error: { type: 'invalid_request_error', code: 'synthetic_invalid_request',
      param: 'synthetic_parameter' } }, { status: 400 });
  }, new AbortController().signal), code('INFERENCE_HTTP_400'));
  assert.equal(catalogCalls, 1); assert.equal(modelCalls, 1);
});

test('persistent SIWC ports preserve all four purposes and independent review for Info and Eason with exact bound receipts', async t => {
  const { vm } = await transferred(t, ['info', 'eason']);
  const seen = [], purposes = ['semantic_evidence_selection', 'support_decision', 'reply_generation', 'semantic_reply_review'];
  const schema = { type: 'object', properties: { approved: { type: 'boolean' } }, required: ['approved'], additionalProperties: false };
  let expected;
  const sessions = createPersistentPlanSessions(vm, { now: () => NOW + 2000, fetchImpl: async (url, init) => {
    assert.equal(init.headers.Authorization, `Bearer synthetic-${expected.alias}-access`);
    if (url === `${RESOURCE}/models`) return catalog();
    assert.equal(url, `${RESOURCE}/responses`); assert.equal(init.credentials, 'omit'); assert.equal(init.redirect, 'error');
    const payload = JSON.parse(init.body); seen.push(payload);
    assert.deepEqual(payload, { model: MODEL, instructions: expected.input.system,
      input: [{ role: 'user', content: expected.input.user }], store: false, stream: true, reasoning: { effort: 'low' },
      text: { verbosity: 'low', ...(expected.input.responseSchema
        ? { format: { type: 'json_schema', name: 'corely_model_output', strict: true, schema } } : {}) } });
    assert.doesNotMatch(JSON.stringify(payload), /prompt_cache_|cache_control|metadata/);
    return modelCompletion(expected.input.responseSchema ? '{"approved":true}' : 'Synthetic grounded answer.');
  } });
  const ports = createSiwcModelTransports(sessions);
  assert.equal(ports.info.authMode, 'siwc_plan');
  assert.equal(ports.info.capabilities.images, false);
  const receipts = [];
  let lastInput;
  for (const alias of ['info', 'eason']) for (const purpose of purposes) {
    const prefix = '完整合成品牌事實🙂\r\n', user = prefix + `當前合成問題：${purpose}\r\n不能忽略補充內容。`;
    const input = modelRequest({ callId: `synthetic-${alias}-${purpose}`, purpose,
      workload: ['semantic_evidence_selection', 'support_decision'].includes(purpose) ? 'DECISION_LLM' : 'REPLY_LLM',
      system: purpose === 'semantic_reply_review' ? 'Independent quality review.\r\n事實與問題必須一致🙂' : `Synthetic ${purpose}.\r\n完整系統規則🙂`,
      user, promptCache: { key: `support-${'a'.repeat(64)}`, userPrefixChars: prefix.length }, reasoningEffort: 'low', verbosity: 'low',
      ...(['semantic_evidence_selection', 'semantic_reply_review'].includes(purpose) ? { responseSchema: schema } : {}) });
    expected = { alias, input: structuredClone(input) }; lastInput = structuredClone(input);
    const pending = ports[alias].generate(input, new AbortController().signal);
    input.user = 'Mutated after starting; must not be sent.';
    const result = await pending; receipts.push(result);
    assert.deepEqual(result, { accountAlias: alias, authMode: 'siwc_plan', accountVerified: true, model: MODEL,
      callId: expected.input.callId, inputSha256: expected.input.inputSha256, schemaSha256: expected.input.schemaSha256,
      status: 'success', completionStatus: 'completed', text: expected.input.responseSchema ? '{"approved":true}' : 'Synthetic grounded answer.',
      usage: { inputTokens: 21, outputTokens: 8, cachedInputTokens: 5 } });
  }
  assert.equal(new Set(receipts.map(receipt => receipt.callId)).size, 8); assert.equal(seen.length, 8);
  assert.equal(seen.filter(payload => payload.instructions.startsWith('Independent quality review.')).length, 2);
  assert.equal(seen.every(payload => payload.store === false && payload.stream === true && !payload.tools && !payload.previous_response_id), true);
  await assert.rejects(ports.eason.generate(lastInput, new AbortController().signal), code('MODEL_CALL_REPLAY_OR_CAPACITY'));
  assert.equal(seen.length, 8);
});

test('only official authenticated plan exhaustion becomes a Corely SIWC quota receipt', async t => {
  const { vm } = await transferred(t);
  for (const [name, status, errorCode, quota] of [
    ['known exhausted plan', 429, 'subscription_sharing_usage_limit_exceeded', true],
    ['ordinary throttle', 429, 'rate_limit_exceeded', false],
    ['unavailable plan', 503, 'subscription_sharing_usage_unavailable', false],
    ['session revoked', 401, 'chatpass_v2_invalid_authorization_context', false],
    ['unsupported model capability', 400, 'subscription_sharing_unsupported_capability', false],
  ]) await t.test(name, async () => {
    const calls = [];
    const sessions = createPersistentPlanSessions(vm, { now: () => NOW + 2000, fetchImpl: async (url, init) => {
      calls.push(url); assert.equal(init.headers.Authorization, 'Bearer synthetic-info-access');
      return url.endsWith('/models') ? catalog() : Response.json({ error: { code: errorCode, message: 'private-provider-detail' } }, { status });
    } });
    const request = modelRequest();
    if (quota) {
      const result = await sessions.generate('info', request, new AbortController().signal);
      assert.deepEqual(result, { accountAlias: 'info', authMode: 'siwc_plan', accountVerified: true, model: MODEL,
        callId: request.callId, inputSha256: request.inputSha256, schemaSha256: null,
        status: 'quota_exhausted', code: 'QUOTA_EXHAUSTED', authenticated: true });
    } else await assert.rejects(sessions.generate('info', request, new AbortController().signal), error =>
      error instanceof ProbeError && !JSON.stringify(error).includes('private-provider-detail'));
    assert.deepEqual(calls, [`${RESOURCE}/models`, `${RESOURCE}/responses`]);
  });
});

test('SIWC rejects partial, refused, tool, wrong-model, unmetered and invalid structured completions', async t => {
  const { vm } = await transferred(t);
  for (const [name, make, expected] of [
    ['incomplete', () => modelCompletion('{}', { status: 'incomplete' }), 'INVALID_COMPLETION'],
    ['wrong model', () => modelCompletion('{}', { model: 'gpt-6-astra' }), 'INVALID_COMPLETION'],
    ['unmetered', () => modelCompletion('{}', { usage: null }), 'INVALID_USAGE_RECEIPT'],
    ['cache usage overflow', () => modelCompletion('{}', { usage: { input_tokens: 2, output_tokens: 2, total_tokens: 4, input_tokens_details: { cached_tokens: 3 } } }), 'INVALID_USAGE_RECEIPT'],
    ['refused', () => modelCompletion('', { output: [{ type: 'message', content: [{ type: 'refusal', refusal: 'synthetic' }] }] }), 'NON_TEXT_OUTPUT_REJECTED'],
    ['tool call', () => modelCompletion('', { output: [{ type: 'function_call', name: 'send_message', arguments: '{}' }] }), 'NON_TEXT_OUTPUT_REJECTED'],
    ['invalid schema output', () => modelCompletion('{"approved":"yes"}'), 'INVALID_STRUCTURED_OUTPUT'],
    ['extra output field', () => modelCompletion('{"approved":true,"extra":1}'), 'INVALID_STRUCTURED_OUTPUT'],
    ['provider redirect', () => ({ redirected: true, url: 'https://other.invalid' }), 'INFERENCE_RESPONSE_INVALID'],
  ]) await t.test(name, async () => {
    const sessions = createPersistentPlanSessions(vm, { now: () => NOW + 2000,
      fetchImpl: async url => url.endsWith('/models') ? catalog() : make() });
    const request = modelRequest({ purpose: 'semantic_reply_review', responseSchema: { type: 'object',
      properties: { approved: { type: 'boolean' } }, required: ['approved'], additionalProperties: false } });
    await assert.rejects(sessions.generate('info', request, new AbortController().signal), code(expected));
    assert.equal((await vm.read('info')).state, 'active');
  });
});

test('cancelled and uncertain model work is not repeated or converted into quota fallback', async t => {
  const { vm } = await transferred(t);
  const aborted = new AbortController(); aborted.abort(); let count = 0;
  const early = createPersistentPlanSessions(vm, { now: () => NOW + 2000, fetchImpl: async () => { count++; throw new Error('not reached'); } });
  assert.throws(() => early.generate('info', modelRequest(), aborted.signal), code('SESSION_OPERATION_ABORTED'));
  assert.equal(count, 0);
  let reached, finish;
  const started = new Promise(resolve => { reached = resolve; });
  const response = new Promise(resolve => { finish = resolve; });
  const controller = new AbortController();
  const sessions = createPersistentPlanSessions(vm, { now: () => NOW + 2000, fetchImpl: async url => {
    count++; if (url.endsWith('/models')) return catalog(); reached(); return response;
  } });
  const request = modelRequest();
  const operation = sessions.generate('info', request, controller.signal);
  await started; controller.abort();
  await assert.rejects(operation, code('SESSION_OPERATION_ABORTED'));
  await assert.rejects(sessions.generate('info', request, new AbortController().signal), code('MODEL_CALL_REPLAY_OR_CAPACITY'));
  finish(modelCompletion('Late answer must not be returned.'));
  assert.equal(count, 2); assert.equal((await vm.read('info')).state, 'active');
});

test('ephemeral owner-login port retains no token getter and stops on its OAuth lifetime', async () => {
  const lifetime = new AbortController(), signal = new AbortController();
  const session = { alias: 'info', planScopeGranted: true, accountMatchesExpected: true,
    accessToken: 'synthetic-owner-access', expiresAt: Date.now() + 300_000 };
  let calls = 0;
  const port = createTransientSiwcModelPort(session, async (url, init) => {
    calls++; assert.equal(init.headers.Authorization, 'Bearer synthetic-owner-access');
    return url.endsWith('/models') ? catalog() : modelCompletion('Synthetic answer.');
  }, lifetime.signal);
  assert.deepEqual(Object.keys(port).sort(), ['authMode', 'capabilities', 'generate']);
  session.accessToken = 'changed-owner-token';
  const request = modelRequest();
  assert.equal((await port.generate(request, signal.signal)).authMode, 'siwc_plan');
  await assert.rejects(port.generate(request, signal.signal), code('MODEL_CALL_REPLAY_OR_CAPACITY'));
  lifetime.abort();
  await assert.rejects(port.generate(modelRequest({ callId: 'after-owner-logout' }), signal.signal), code('SESSION_OPERATION_ABORTED'));
  assert.equal(calls, 2);
});

test('ending normal owner login cancels uncertain in-flight model work without a retry', async () => {
  const lifetime = new AbortController(), signal = new AbortController();
  let reached, release, calls = 0;
  const started = new Promise(resolve => { reached = resolve; });
  const delayed = new Promise(resolve => { release = resolve; });
  const port = createTransientSiwcModelPort({ alias: 'info', planScopeGranted: true, accountMatchesExpected: true,
    accessToken: 'synthetic-owner-access', expiresAt: Date.now() + 300_000 }, async url => {
    calls++; if (url.endsWith('/models')) return catalog(); reached(); return delayed;
  }, lifetime.signal);
  const request = modelRequest(), pending = port.generate(request, signal.signal);
  await started; lifetime.abort();
  await assert.rejects(pending, code('SESSION_OPERATION_ABORTED'));
  release(modelCompletion('Late synthetic answer.'));
  await assert.rejects(port.generate(modelRequest({ callId: 'after-abort' }), signal.signal), code('SESSION_OPERATION_ABORTED'));
  assert.equal(calls, 2);
});

test('model port rejects missing expiry and invalid bearer shape before any provider request', async () => {
  let calls = 0;
  const session = { alias: 'info', planScopeGranted: true, accountMatchesExpected: true,
    accessToken: 'synthetic-access', expiresAt: Date.now() + 300_000 };
  for (const changes of [{ expiresAt: undefined }, { expiresAt: Number.NaN }, { expiresAt: Date.now() - 1 },
    { accessToken: 'synthetic\ninvalid' }]) {
    await assert.rejects(runCorelyPlanRequest({ ...session, ...changes }, modelRequest(), async () => { calls++; },
      new AbortController().signal), code('SESSION_NOT_ELIGIBLE'));
  }
  assert.equal(calls, 0);
});

test('separate protected runtime hosts survive restart without reading any native auth cache', async t => {
  const { local, vm, parent } = await stores(t);
  assert.notEqual(local.host.hostId, vm.host.hostId);
  assert.equal((await openSessionStore(vm.root)).host.hostId, vm.host.hostId);
  assert.equal((await lstat(vm.root)).mode & 0o777, 0o700);
  assert.equal((await lstat(join(vm.root, 'host.json'))).mode & 0o777, 0o600);
  assert.deepEqual(await readdir(vm.root), ['host.json']);
  assert.deepEqual((await createPersistentPlanSessions(vm).status()).accounts.map(a => a.state), ['not_connected', 'not_connected']);
  await assert.rejects(openSessionStore(vm.root, { runtime: 'enrollment' }), code('HOST_RECORD_INVALID'));
  await assert.rejects(vm.read('../enrollment/host'), code('ACCOUNT_NOT_ADMITTED'));
  await assert.rejects(openSessionStore('relative/path'), code('SESSION_STORAGE_PATH_INVALID'));
  // Root-level mount points must retain their whole basename (/state in the
  // real container smoke). /tmp already exists and must fail its privacy check,
  // not be misresolved to /mp and fail while creating an unrelated directory.
  await assert.rejects(openSessionStore('/tmp'), code('SESSION_STORAGE_NOT_PRIVATE'));
  await symlink(vm.root, join(parent, 'linked'));
  await assert.rejects(openSessionStore(join(parent, 'linked')), code('SESSION_STORAGE_NOT_PRIVATE'));
  await chmod(vm.root, 0o750);
  await assert.rejects(openSessionStore(vm.root), code('SESSION_STORAGE_NOT_PRIVATE'));
});

test('protected import validates identity and binds the VM host without overwriting other registrations', async t => {
  const { local, vm } = await stores(t);
  await assert.rejects(enroll(local, 'info', { token: { scope: `${SCOPES} administrative.write` } }), code('PLAN_SCOPE_NOT_ADMITTED'));
  assert.equal(await local.read('info'), undefined);
  const receipt = await enroll(local);
  assert.equal(receipt.identityVerified, true); assert.equal(receipt.apiFallbackEnabled, false);
  assert.doesNotMatch(JSON.stringify(receipt), /synthetic-info-(?:access|refresh)|idToken|nonce/);
  const transfer = await writeEnrollment(local, 'info', vm.host.hostId);
  assert.equal((await lstat(transfer.file)).mode & 0o777, 0o600);
  const bundle = JSON.parse(await readFile(transfer.file, 'utf8'));
  for (const [name, mutate, expected] of [
    ['wrong VM', b => { b.targetVm = 'production'; }, 'ENROLLMENT_NOT_ADMITTED'],
    ['wrong destination', b => { b.targetHostId = local.host.hostId; }, 'ENROLLMENT_NOT_ADMITTED'],
    ['native auth shape', b => { b.auth_mode = 'chatgpt'; }, 'ENROLLMENT_NOT_ADMITTED'],
    ['account mix-up', b => { b.record.alias = 'eason'; }, 'SESSION_RECORD_INVALID'],
    ['modified signed identity', b => { b.record.subjectHash = '0'.repeat(64); }, 'ACCOUNT_NOT_EXPECTED'],
    ['wrong issuer', b => { b.record.issuer = 'https://evil.invalid'; }, 'SESSION_RECORD_INVALID'],
    ['missing plan grant', b => { b.record.scopes = ['openid']; }, 'SESSION_RECORD_INVALID'],
  ]) await t.test(name, async () => {
    const bad = structuredClone(bundle); mutate(bad);
    await assert.rejects(importEnrollment(vm, 'info', bad, JWKS, NOW + 1000), code(expected));
    assert.equal(await vm.read('info'), undefined);
  });
  const result = await importEnrollment(vm, 'info', bundle, JWKS, NOW + 1000);
  assert.equal(result.importedEnrollmentSha256, digest(JSON.stringify(bundle)));
  const record = await vm.read('info');
  assert.equal(record.hostId, vm.host.hostId); assert.equal(record.authorizationHostId, local.host.hostId);
  assert.equal(record.clientId, 'fixture_info'); assert.equal(record.email, 'info@moztech.cc');
  assert.equal((await lstat(join(vm.root, 'info.json'))).mode & 0o777, 0o600);
  await assert.rejects(importEnrollment(vm, 'info', bundle, JWKS, NOW + 1000), code('EXISTING_SESSION_MUST_DISCONNECT'));
  await assert.rejects(forgetTransferredEnrollment(local, 'info', '0'.repeat(64)), code('ENROLLMENT_NOT_ADMITTED'));
  const forgotten = await forgetTransferredEnrollment(local, 'info', result.importedEnrollmentSha256);
  assert.equal(forgotten.localCredentialsRemoved, true); assert.equal(forgotten.remoteSessionRevoked, false);
  assert.equal((await local.read('info')).state, 'disconnected');
  assert.deepEqual((await readdir(local.root)).sort(), ['host.json', 'info.json']);
  assert.doesNotMatch(await readFile(join(local.root, 'info.json'), 'utf8'), /accessToken|refreshToken|idToken|nonce/);
  assert.equal((await vm.read('info')).state, 'active');
  await createPersistentPlanSessions(vm, { now: () => NOW + 2000,
    fetchImpl: async () => new Response(null, { status: 200 }) }).disconnect('info');
  await assert.rejects(importEnrollment(vm, 'info', bundle, JWKS, NOW + 3000), code('ENROLLMENT_REPLAY_REJECTED'));
});

test('restart uses only Info plan credentials for the fixed proof and exposes no reusable tokens', async t => {
  const { vm } = await transferred(t, ['info', 'eason']);
  const calls = [];
  const sessions = createPersistentPlanSessions(await openSessionStore(vm.root), { now: () => NOW + 2000,
    fetchImpl: async (url, init) => {
      calls.push(url); assert.equal(init.headers.Authorization, 'Bearer synthetic-info-access');
      assert.equal(init.redirect, 'error');
      if (url === `${RESOURCE}/models`) return catalog();
      assert.equal(url, `${RESOURCE}/responses`);
      assert.deepEqual(JSON.parse(init.body), { model: MODEL, input: [{ role: 'user', content: 'Reply with exactly: Corely local plan probe OK.' }], store: false, stream: true });
      return completion();
    } });
  const result = await sessions.probeInAccountOrder();
  assert.equal(result.completed, true); assert.equal(result.alias, 'info'); assert.equal(result.apiKeyFallbackUsed, false);
  assert.equal(result.authorizationSource, 'APP_OWNED_SIWC'); assert.equal(result.newApiRelayTested, false);
  assert.equal(result.corelyRelayTested, false); assert.equal(result.exactDebitAmountVerified, false);
  assert.deepEqual(calls, [`${RESOURCE}/models`, `${RESOURCE}/responses`]);
  assert.doesNotMatch(JSON.stringify({ result, status: await sessions.status() }), /synthetic-(?:info|eason)-(?:access|refresh)|idToken|nonce/);
});

test('only an authenticated exact plan-exhaustion code can select Eason; never generic errors or API', async t => {
  const { vm } = await transferred(t, ['info', 'eason']);
  for (const [name, status, errorCode, easonAllowed] of [
    ['plan exhausted', 429, 'subscription_sharing_usage_limit_exceeded', true],
    ['generic rate limit', 429, 'rate_limit_exceeded', false],
    ['unavailable plan', 503, 'subscription_sharing_usage_unavailable', false],
    ['invalid session', 401, 'chatpass_v2_invalid_authorization_context', false],
    ['unsupported capability', 400, 'subscription_sharing_unsupported_capability', false],
  ]) await t.test(name, async () => {
    const used = [];
    const sessions = createPersistentPlanSessions(vm, { now: () => NOW + 2000, fetchImpl: async (url, init) => {
      if (url.endsWith('/models')) return catalog();
      used.push(init.headers.Authorization);
      if (init.headers.Authorization.includes('info')) return Response.json({ error: { code: errorCode, message: 'synthetic-private-do-not-log' } }, { status });
      return completion();
    } });
    if (easonAllowed) { assert.equal((await sessions.probeInAccountOrder()).alias, 'eason'); assert.equal(used.length, 2); }
    else { await assert.rejects(sessions.probeInAccountOrder()); assert.equal(used.length, 1); }
  });
});

test('rotating refresh is serialized, atomically persisted, uses the issued client and omits scope', async t => {
  const { vm } = await transferred(t);
  let calls = 0, release, entered;
  const waiting = new Promise(resolve => { entered = resolve; });
  const proceed = new Promise(resolve => { release = resolve; });
  const sessions = createPersistentPlanSessions(vm, { now: () => NOW + 250000, fetchImpl: async (url, init) => {
    assert.equal(url, `${ISSUER}/api/accounts/oauth/token`); calls++;
    assert.deepEqual(Object.fromEntries(init.body), { grant_type: 'refresh_token', client_id: 'fixture_info',
      refresh_token: 'synthetic-info-refresh', resource: RESOURCE });
    assert.equal(init.credentials, 'omit'); assert.equal(init.redirect, 'error');
    entered(); await proceed;
    return Response.json({ access_token: 'synthetic-rotated-access', refresh_token: 'synthetic-rotated-refresh', token_type: 'Bearer', expires_in: 3600 });
  } });
  const first = sessions.maintain(); await waiting;
  assert.equal((await vm.read('info')).state, 'refresh_pending');
  const otherProcess = createPersistentPlanSessions(await openSessionStore(vm.root));
  await assert.rejects(otherProcess.probe('info'), code('SESSION_BUSY_OR_LOCKED'));
  const second = sessions.maintain(); release();
  await Promise.all([first, second]);
  assert.equal(calls, 1);
  const saved = await vm.read('info');
  assert.equal(saved.state, 'active'); assert.equal(saved.accessToken, 'synthetic-rotated-access');
  assert.equal(saved.refreshToken, 'synthetic-rotated-refresh'); assert.equal(saved.expiresAt, NOW + 3850000);
  assert.equal((await readdir(vm.root)).some(name => name.endsWith('.tmp') || name.endsWith('.lock')), false);
  const restarted = createPersistentPlanSessions(await openSessionStore(vm.root), { now: () => NOW + 251000,
    fetchImpl: () => { throw new Error('Refresh must not repeat.'); } });
  assert.equal((await restarted.maintain()).accounts[0].state, 'active');
});

test('uncertain refreshes, scope expansion and identity changes hold durably without replay or fallback', async t => {
  for (const [name, result, expected] of [
    ['network ambiguity', () => { throw new Error('synthetic-private-network-details'); }, 'REFRESH_OUTCOME_UNCERTAIN'],
    ['provider 503', () => Response.json({ error: 'temporarily_unavailable' }, { status: 503 }), 'REFRESH_OUTCOME_UNCERTAIN'],
    ['invalid JSON', () => new Response('{', { headers: { 'content-type': 'application/json' } }), 'REFRESH_OUTCOME_UNCERTAIN'],
    ['scope escalation', () => Response.json({ ...fixtureToken(), scope: `${SCOPES} administrative.write` }), 'REFRESH_SCOPE_INVALID'],
    ['lost plan scope', () => Response.json({ ...fixtureToken(), scope: 'openid email' }), 'REFRESH_SCOPE_INVALID'],
    ['changed identity', () => Response.json(fixtureToken('info', { claims: { sub: 'different-subject' } })), 'REFRESH_IDENTITY_INVALID'],
  ]) await t.test(name, async t => {
    const { vm } = await transferred(t); let calls = 0;
    const sessions = createPersistentPlanSessions(vm, { now: () => NOW + 250000, fetchImpl: async url => {
      calls++; return url.endsWith('/jwks.json') ? Response.json(JWKS) : result();
    } });
    const receipt = await sessions.maintain(); assert.equal(receipt.accounts[0].code, expected);
    const afterFirst = calls;
    assert.equal((await vm.read('info')).state, 'refresh_pending');
    await assert.rejects(createPersistentPlanSessions(await openSessionStore(vm.root), { now: () => NOW + 251000,
      fetchImpl: () => { throw new Error('Must not replay old refresh.'); } }).probe('info'), code('REFRESH_OUTCOME_UNCERTAIN'));
    assert.equal(calls, afterFirst); assert.doesNotMatch(JSON.stringify(receipt), /synthetic-private/);
  });
});

test('definitive invalid_grant removes tokens but retains registration, and never activates Eason', async t => {
  const { vm } = await transferred(t, ['info', 'eason']); let calls = 0;
  const sessions = createPersistentPlanSessions(vm, { now: () => NOW + 250000, fetchImpl: async () => {
    calls++; return Response.json({ error: 'invalid_grant' }, { status: 400 });
  } });
  await assert.rejects(sessions.probeInAccountOrder(), code('SESSION_REAUTH_REQUIRED'));
  assert.equal(calls, 1);
  const record = await vm.read('info'); assert.equal(record.state, 'reauth_required'); assert.equal(record.clientId, 'fixture_info');
  assert.doesNotMatch(JSON.stringify(record), /accessToken|refreshToken|idToken|nonce/);
  assert.equal((await vm.read('eason')).state, 'active');
});

test('optional refresh ID token is checked against the same client and identity; missing nonce and refresh token are valid', async t => {
  const { vm } = await transferred(t); const old = await vm.read('info');
  const response = fixtureToken('info', { claims: { nonce: undefined }, token: { refresh_token: undefined, scope: undefined, expires_in: 3600 } });
  const sessions = createPersistentPlanSessions(vm, { now: () => NOW + 250000, fetchImpl: async url =>
    Response.json(url.endsWith('/jwks.json') ? JWKS : response) });
  assert.equal((await sessions.maintain()).accounts[0].state, 'active');
  const record = await vm.read('info'); assert.equal(record.refreshToken, old.refreshToken);
  assert.equal(record.idToken, response.id_token); assert.deepEqual(record.scopes, old.scopes);
});

test('a replacement refresh token remains revocable if identity validation or final persistence fails', async t => {
  for (const reason of ['identity', 'persistence']) await t.test(reason, async t => {
    const { vm } = await transferred(t); let revoked = 0;
    const store = reason === 'persistence' ? { ...vm, write: async (alias, record) => {
      if (record.state === 'active' && record.refreshToken === 'synthetic-new-renewal-handle') throw new ProbeError('SESSION_STORAGE_WRITE_FAILED');
      return vm.write(alias, record);
    } } : vm;
    const fetchImpl = async (url, init) => {
      if (url.endsWith('/jwks.json')) return Response.json(JWKS);
      if (url.endsWith('/revoke')) {
        revoked++; assert.equal(init.body.get('token'), 'synthetic-new-renewal-handle'); return new Response(null, { status: 200 });
      }
      return Response.json(fixtureToken('info', { claims: reason === 'identity' ? { sub: 'changed' } : {},
        token: { refresh_token: 'synthetic-new-renewal-handle', expires_in: 3600 } }));
    };
    const sessions = createPersistentPlanSessions(store, { now: () => NOW + 250000, fetchImpl });
    assert.equal((await sessions.maintain()).accounts[0].state, 'held');
    const pending = await vm.read('info'); assert.equal(pending.state, 'refresh_pending');
    assert.equal(pending.refreshToken, 'synthetic-new-renewal-handle');
    await assert.rejects(sessions.probe('info'), code('REFRESH_OUTCOME_UNCERTAIN'));
    assert.equal((await sessions.disconnect('info')).remoteRevocationConfirmed, true); assert.equal(revoked, 1);
  });
});

test('weak files, hardlinks, symlinks, stale locks and clock rollback cannot supply a usable session', async t => {
  const { vm, parent } = await transferred(t);
  const path = join(vm.root, 'info.json'), contents = await readFile(path);
  await chmod(path, 0o640); await assert.rejects(vm.read('info'), code('SESSION_STORAGE_NOT_PRIVATE')); await chmod(path, 0o600);
  await link(path, join(parent, 'hardlink')); await assert.rejects(vm.read('info'), code('SESSION_STORAGE_NOT_PRIVATE')); await rm(join(parent, 'hardlink'));
  await rm(path); await writeFile(join(parent, 'external'), contents, { mode: 0o600 }); await symlink(join(parent, 'external'), path);
  await assert.rejects(vm.read('info'), code('SESSION_STORAGE_INVALID')); await rm(path); await writeFile(path, contents, { mode: 0o600 });
  await writeFile(join(vm.root, 'info.lock'), 'synthetic-interrupted-lease', { mode: 0o600 });
  const sessions = createPersistentPlanSessions(vm, { now: () => NOW + 2000 });
  await assert.rejects(sessions.probe('info'), code('SESSION_BUSY_OR_LOCKED')); await rm(join(vm.root, 'info.lock'));
  await assert.rejects(createPersistentPlanSessions(vm, { now: () => NOW }).probe('info'), code('SESSION_CLOCK_INVALID'));
  await assert.rejects(sessions.probe('info', AbortSignal.abort('synthetic-private-reason')), code('SESSION_OPERATION_ABORTED'));
});

test('disconnect revokes only the chosen account, clears local secrets and truthfully reports failed remote revocation', async t => {
  const { vm } = await transferred(t, ['info', 'eason']); let calls = 0;
  const sessions = createPersistentPlanSessions(vm, { now: () => NOW + 2000, fetchImpl: async (url, init) => {
    assert.equal(url, `${ISSUER}/api/accounts/oauth/revoke`); calls++;
    assert.equal(init.body.get('client_id'), 'fixture_info'); assert.equal(init.body.get('token'), 'synthetic-info-refresh');
    return new Response(null, { status: 200 });
  } });
  assert.equal((await sessions.disconnect('info')).remoteRevocationConfirmed, true); assert.equal(calls, 1);
  assert.equal((await vm.read('info')).state, 'disconnected'); assert.equal((await vm.read('eason')).state, 'active');
  const failed = createPersistentPlanSessions(vm, { now: () => NOW + 2000, fetchImpl: async () => Response.json({ error: 'invalid_request' }, { status: 400 }) });
  const receipt = await failed.disconnect('eason'); assert.equal(receipt.remoteRevocationConfirmed, false);
  assert.equal(receipt.disconnectInChatGptSettingsIfUnconfirmed, true); assert.equal((await vm.read('eason')).state, 'disconnected');
});

test('normal OAuth persists only the app-owned expected identity and creates a protected handoff, without inference', async t => {
  const { local, vm } = await stores(t); let authUrl, tokenCalls = 0, modelCalls = 0;
  const enrollment = await startPersistentEnrollment({ store: local, alias: 'info', targetHostId: vm.host.hostId,
    fetchImpl: async (url, init) => {
      if (url.endsWith('/openid-configuration')) return Response.json({ issuer: ISSUER, jwks_uri: `${ISSUER}/.well-known/jwks.json`,
        authorization_endpoint: `${ISSUER}/api/accounts/authorize`, token_endpoint: `${ISSUER}/api/accounts/oauth/token`,
        revocation_endpoint: `${ISSUER}/api/accounts/oauth/revoke` });
      if (url.endsWith('/jwks.json')) return Response.json(JWKS);
      if (url.endsWith('/token')) {
        tokenCalls++; assert.equal(init.body.get('client_id'), 'fixture_info');
        assert.equal(init.body.get('redirect_uri'), `${enrollment.localUrl}/auth/callback`);
        return Response.json(fixtureToken('info', { nonce: authUrl.searchParams.get('nonce') }));
      }
      modelCalls++; throw new Error('No model or revocation is allowed after successful persistent enrollment.');
    } });
  t.after(() => enrollment.close());
  const start = await nativeFetch(enrollment.localUrl, { redirect: 'manual' }); authUrl = new URL(start.headers.get('location'));
  assert.equal(authUrl.searchParams.get('agent_name_hint'), 'New API DEV Personal Plan');
  assert.equal(authUrl.searchParams.get('ext_agent_host_id'), local.host.hostId);
  const callback = new URL('/auth/callback', enrollment.localUrl);
  callback.search = new URLSearchParams({ client_id: 'fixture_info', code: 'synthetic-code', state: authUrl.searchParams.get('state') });
  const csrf = new URL(callback); csrf.searchParams.set('state', 'bad');
  assert.equal((await nativeFetch(csrf, { redirect: 'manual' })).status, 400);
  assert.equal((await nativeFetch(callback, { redirect: 'manual' })).status, 303);
  const receipt = await enrollment.completion;
  assert.equal(receipt.identityVerified, true); assert.equal(receipt.modelExecuted, false); assert.equal(modelCalls, 0); assert.equal(tokenCalls, 1);
  assert.equal((await nativeFetch(callback, { redirect: 'manual' })).status, 409);
  assert.doesNotMatch(JSON.stringify(receipt), /synthetic-info-(?:access|refresh)|idToken|nonce/);
  assert.equal((await local.read('info')).state, 'active'); assert.equal(await vm.read('info'), undefined);
});

test('wrong OAuth account is revoked instead of persisted or substituted into the Info registration', async t => {
  const { local, vm } = await stores(t); let authUrl, revoked = 0;
  const enrollment = await startPersistentEnrollment({ store: local, alias: 'info', targetHostId: vm.host.hostId,
    fetchImpl: async (url, init) => {
      if (url.endsWith('/openid-configuration')) return Response.json({ issuer: ISSUER, jwks_uri: `${ISSUER}/.well-known/jwks.json`,
        authorization_endpoint: `${ISSUER}/api/accounts/authorize`, token_endpoint: `${ISSUER}/api/accounts/oauth/token`,
        revocation_endpoint: `${ISSUER}/api/accounts/oauth/revoke` });
      if (url.endsWith('/jwks.json')) return Response.json(JWKS);
      if (url.endsWith('/token')) return Response.json(fixtureToken('eason', { claims: { aud: 'fixture_info' }, nonce: authUrl.searchParams.get('nonce') }));
      assert.equal(url, `${ISSUER}/api/accounts/oauth/revoke`); revoked++;
      assert.equal(init.body.get('client_id'), 'fixture_info'); assert.equal(init.body.get('token'), 'synthetic-eason-refresh');
      return new Response(null, { status: 200 });
    } });
  t.after(() => enrollment.close());
  const start = await nativeFetch(enrollment.localUrl, { redirect: 'manual' }); authUrl = new URL(start.headers.get('location'));
  const callback = new URL('/auth/callback', enrollment.localUrl);
  callback.search = new URLSearchParams({ client_id: 'fixture_info', code: 'synthetic-code', state: authUrl.searchParams.get('state') });
  await nativeFetch(callback, { redirect: 'manual' });
  await assert.rejects(enrollment.completion, code('ACCOUNT_NOT_EXPECTED')); assert.equal(revoked, 1);
  const record = await local.read('info'); assert.equal(record.state, 'disconnected'); assert.equal(record.subjectHash, undefined);
  assert.doesNotMatch(JSON.stringify(record), /accessToken|refreshToken|idToken|nonce/);
  assert.equal((await readdir(local.root)).some(file => file.endsWith('.transfer.json')), false);
  assert.equal(await vm.read('info'), undefined); assert.equal(await local.read('eason'), undefined);
});

test('operator commands never inherit API/proxy/native-auth configuration or accept customer/model arguments', async t => {
  for (const env of [{ OPENAI_API_KEY: 'synthetic' }, { NODE_OPTIONS: '' }, { HTTPS_PROXY: '' }, { CODEX_HOME: '/synthetic' },
    { NODE_DEBUG: 'undici' }, { SSLKEYLOGFILE: '/synthetic/keylog' }, { SSL_CERT_FILE: '/synthetic/ca' },
    Object.create({ OPENAI_BASE_URL: 'https://example.invalid' })]) assert.throws(() => assertIsolatedSessionEnvironment(env), code('SESSION_ENVIRONMENT_NOT_ISOLATED'));
  assert.doesNotThrow(() => assertIsolatedSessionEnvironment({ PATH: '/usr/bin', HOME: '/synthetic' }));
  assert.equal(parseSessionCommand(['probe', '--state-dir', '/synthetic']).command, 'probe');
  for (const args of [[], ['probe', '--state-dir', '/synthetic', '--account', 'eason'],
    ['authorize', '--state-dir', '/synthetic', '--account', 'unknown', '--target-host-id', 'fixture'],
    ['status', '--state-dir', '/synthetic', '--state-dir', '/other'],
    ['probe', '--state-dir', '/synthetic', '--prompt', 'customer-data'], ['probe', '--state-dir', '/synthetic', '--model', 'other']]) {
    assert.throws(() => parseSessionCommand(args), code('SESSION_COMMAND_INVALID'));
  }
  const { parent } = await stores(t), path = join(parent, 'must-not-exist');
  const child = spawnSync(process.execPath, ['bin/siwc-local-vm.mjs', 'init-vm', '--state-dir', path],
    { cwd: new URL('..', import.meta.url), env: { PATH: process.env.PATH, OPENAI_API_KEY: 'synthetic-not-printed' }, encoding: 'utf8' });
  assert.equal(child.status, 1); assert.match(child.stdout, /SESSION_ENVIRONMENT_NOT_ISOLATED/); assert.doesNotMatch(child.stdout, /synthetic-not-printed/);
  await assert.rejects(lstat(path), { code: 'ENOENT' });
});
