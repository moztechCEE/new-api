import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { chmod, link, lstat, mkdtemp, mkdir, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { Readable } from 'node:stream';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  ISSUER, RESOURCE, MODEL, PROBE_INPUT, PROBE_OUTPUT, SCOPES, ProbeError,
  createAttempt, consumeCallback, validateSession, publicJson, selectExactModel,
  syntheticRequest, consumeProbeStream, runSyntheticProbe, inferenceFailureDiagnostic, digest,
} from './siwc-local-runtime.mjs';
import { loadRegistration, saveRegistration } from './siwc-local-pilot.mjs';

// All HTTP responses, tokens and identities below are synthetic. The global
// network guard catches accidental requests outside an explicitly injected mock.
const originalFetch = globalThis.fetch;
before(() => { globalThis.fetch = async () => { throw new Error('NETWORK_DISABLED_IN_TEST'); }; });
after(() => { globalThis.fetch = originalFetch; });

const NOW = 1_800_000_000_000;
const HOST = 'urn:uuid:01234567-89ab-4def-8123-456789abcdef';
const CALLBACK = 'http://127.0.0.1:43123/auth/callback';
const EMAIL = 'fixture@example.invalid';
const CLIENT = 'fixture_client';
const NONCE = 'synthetic-nonce';
const keyPair = generateKeyPairSync('rsa', { modulusLength: 2048 });
const otherKeyPair = generateKeyPairSync('rsa', { modulusLength: 2048 });
const signingJwk = { ...keyPair.publicKey.export({ format: 'jwk' }), kid: 'fixture-key', alg: 'RS256', use: 'sig' };
const JWKS = { keys: [signingJwk] };

function tokenFixture({ claims = {}, header = {}, token = {}, privateKey = keyPair.privateKey } = {}) {
  const payload = {
    iss: ISSUER, sub: 'synthetic-subject', aud: CLIENT, nonce: NONCE,
    iat: NOW / 1000 - 10, exp: NOW / 1000 + 300,
    email: EMAIL, email_verified: true, ...claims,
  };
  const encodedHeader = Buffer.from(JSON.stringify({ alg: 'RS256', kid: signingJwk.kid, ...header })).toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signed = `${encodedHeader}.${encodedPayload}`;
  return {
    id_token: `${signed}.${sign('RSA-SHA256', Buffer.from(signed), privateKey).toString('base64url')}`,
    access_token: 'synthetic-access-token', refresh_token: 'synthetic-refresh-token',
    token_type: 'Bearer', expires_in: 300, scope: SCOPES, ...token,
  };
}

function callbackFor(attempt, params = {}) {
  const url = new URL(attempt.redirectUri);
  url.search = new URLSearchParams({ state: attempt.state, code: 'synthetic-code', client_id: CLIENT, ...params });
  return url.href;
}

function completedEvent(overrides = {}) {
  return { type: 'response.completed', response: {
    id: 'resp_synthetic_fixture', status: 'completed', model: MODEL,
    output: [{ type: 'message', content: [{ type: 'output_text', text: PROBE_OUTPUT }] }],
    ...overrides,
  } };
}

function eventFrame(event, newline = '\n') {
  return `data: ${JSON.stringify(event)}${newline}${newline}`;
}

function streamBody(events, suffix = '') {
  return Readable.from([Buffer.from(events.map(event => eventFrame(event)).join('') + suffix)]);
}

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

function eligibleSession() {
  return { accessToken: 'synthetic-access-token', expiresAt: Date.now() + 60_000,
    planScopeGranted: true, accountMatchesExpected: true };
}

test('authorization attempt binds loopback, PKCE, state, nonce and requested plan scopes', () => {
  const attempt = createAttempt(HOST, CALLBACK, NOW);
  const second = createAttempt(HOST, CALLBACK, NOW);
  const url = new URL(attempt.url);
  assert.equal(url.origin, ISSUER);
  assert.equal(url.pathname, '/api/accounts/authorize');
  assert.equal(url.searchParams.get('client_id'), 'dynamic_agent_client');
  assert.equal(url.searchParams.get('ext_agent_host_id'), HOST);
  assert.equal(url.searchParams.get('redirect_uri'), CALLBACK);
  assert.equal(url.searchParams.get('scope'), SCOPES);
  assert.equal(url.searchParams.get('resource'), RESOURCE);
  assert.equal(url.searchParams.get('response_type'), 'code');
  assert.equal(url.searchParams.get('state'), attempt.state);
  assert.equal(url.searchParams.get('nonce'), attempt.nonce);
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(url.searchParams.get('code_challenge'), createHash('sha256').update(attempt.verifier).digest('base64url'));
  assert.match(attempt.verifier, /^[A-Za-z0-9_-]{43,128}$/);
  assert.notEqual(attempt.state, second.state);
  assert.notEqual(attempt.nonce, second.nonce);
  assert.notEqual(attempt.verifier, second.verifier);
  assert.equal(attempt.expiresAt, NOW + 600_000);
  assert.equal(attempt.used, false);
});

test('authorization rejects non-loopback or ambiguous callback targets', async t => {
  for (const callback of [
    'https://127.0.0.1:43123/auth/callback', 'http://localhost:43123/auth/callback',
    'http://127.0.0.1/auth/callback', 'http://127.0.0.1:43123/other',
    `${CALLBACK}?x=1`, `${CALLBACK}#fragment`, 'http://user@127.0.0.1:43123/auth/callback',
  ]) await t.test(callback, () => assert.throws(() => createAttempt(HOST, callback, NOW), { code: 'INVALID_CALLBACK' }));
  assert.throws(() => createAttempt('not-a-host-id', CALLBACK, NOW), { code: 'INVALID_HOST_ID' });
});

test('callback yields the issued client and PKCE form exactly once', () => {
  const attempt = createAttempt(HOST, CALLBACK, NOW);
  const raw = callbackFor(attempt, { iss: ISSUER });
  const { clientId, form } = consumeCallback(raw, attempt, NOW + 1);
  assert.equal(clientId, CLIENT);
  assert.deepEqual(Object.fromEntries(form), {
    grant_type: 'authorization_code', client_id: CLIENT, code: 'synthetic-code',
    code_verifier: attempt.verifier, redirect_uri: CALLBACK, resource: RESOURCE,
  });
  assert.equal(attempt.used, true);
  assert.throws(() => consumeCallback(raw, attempt, NOW + 2), { code: 'CALLBACK_ALREADY_CONSUMED' });
});

test('callback rejects CSRF, expiry, duplicate parameters, mix-up and incomplete registration', async t => {
  const cases = [
    ['wrong state', a => callbackFor(a, { state: 'wrong-state' }), NOW, 'INVALID_STATE'],
    ['expired', a => callbackFor(a), NOW + 600_000, 'CALLBACK_EXPIRED'],
    ['origin mix-up', a => callbackFor(a).replace('127.0.0.1', 'example.invalid'), NOW, 'INVALID_CALLBACK'],
    ['path mix-up', a => callbackFor(a).replace('/auth/callback', '/other'), NOW, 'INVALID_CALLBACK'],
    ['fragment', a => `${callbackFor(a)}#fragment`, NOW, 'INVALID_CALLBACK'],
    ['duplicate state', a => `${callbackFor(a)}&state=${a.state}`, NOW, 'DUPLICATE_CALLBACK_PARAMETER'],
    ['duplicate code', a => `${callbackFor(a)}&code=second`, NOW, 'DUPLICATE_CALLBACK_PARAMETER'],
    ['issuer mix-up', a => callbackFor(a, { iss: 'https://example.invalid' }), NOW, 'INVALID_ISSUER'],
    ['registration client not issued', a => callbackFor(a, { client_id: 'dynamic_agent_client' }), NOW, 'REGISTRATION_INCOMPLETE'],
    ['missing client', a => callbackFor(a, { client_id: '' }), NOW, 'REGISTRATION_INCOMPLETE'],
    ['missing code', a => callbackFor(a, { code: '' }), NOW, 'REGISTRATION_INCOMPLETE'],
    ['code newline', a => callbackFor(a, { code: 'bad\ncode' }), NOW, 'REGISTRATION_INCOMPLETE'],
    ['bounded code', a => callbackFor(a, { code: 'x'.repeat(8193) }), NOW, 'REGISTRATION_INCOMPLETE'],
    ['bounded callback', a => `${callbackFor(a)}&extra=${'x'.repeat(32769)}`, NOW, 'INVALID_CALLBACK'],
  ];
  for (const [name, buildUrl, now, code] of cases) await t.test(name, () => {
    const attempt = createAttempt(HOST, CALLBACK, NOW);
    assert.throws(() => consumeCallback(buildUrl(attempt), attempt, now), { code });
  });
});

test('authorization denial consumes the valid attempt and cannot be replayed', () => {
  const attempt = createAttempt(HOST, CALLBACK, NOW);
  assert.throws(() => consumeCallback(callbackFor(attempt, { error: 'access_denied' }), attempt, NOW), { code: 'AUTHORIZATION_NOT_GRANTED' });
  assert.throws(() => consumeCallback(callbackFor(attempt), attempt, NOW), { code: 'CALLBACK_ALREADY_CONSUMED' });
});

test('returning authorization reuses the issued registration and binds callback to it', () => {
  const attempt = createAttempt(HOST, CALLBACK, NOW, { clientId: CLIENT });
  const url = new URL(attempt.url);
  assert.equal(url.searchParams.get('client_id'), CLIENT);
  assert.equal(url.searchParams.has('agent_name_hint'), false);
  const callback = new URL(callbackFor(attempt));
  callback.searchParams.delete('client_id');
  const result = consumeCallback(callback.href, attempt, NOW);
  assert.equal(result.clientId, CLIENT);
  assert.equal(result.form.get('client_id'), CLIENT);
  assert.equal(result.form.get('code_verifier'), attempt.verifier);
  assert.throws(() => consumeCallback(callback.href, attempt, NOW), { code: 'CALLBACK_ALREADY_CONSUMED' });
  const matching = createAttempt(HOST, CALLBACK, NOW, { clientId: CLIENT });
  assert.equal(consumeCallback(callbackFor(matching), matching, NOW).clientId, CLIENT);
  const mismatched = createAttempt(HOST, CALLBACK, NOW, { clientId: CLIENT });
  assert.throws(() => consumeCallback(callbackFor(mismatched, { client_id: 'other_client' }), mismatched, NOW),
    { code: 'REGISTRATION_MISMATCH' });
  assert.equal(mismatched.used, true);
  for (const clientId of ['', 'dynamic_agent_client', 'invalid client', 'x'.repeat(257)]) {
    assert.throws(() => createAttempt(HOST, CALLBACK, NOW, { clientId }), { code: 'INVALID_REGISTRATION' });
  }
});

test('real RS256 ID token establishes only the expected scoped synthetic session', () => {
  const result = validateSession(tokenFixture(), JWKS, CLIENT, NONCE, EMAIL.toUpperCase(), NOW);
  assert.deepEqual(result, {
    accessToken: 'synthetic-access-token', refreshToken: 'synthetic-refresh-token',
    expiresAt: NOW + 300_000, clientId: CLIENT, subjectHash: digest('synthetic-subject'),
    planScopeGranted: true, accountMatchesExpected: true,
  });
  assert.equal('id_token' in result, false);
  assert.equal('email' in result, false);
  assert.equal('sub' in result, false);
  assert.equal(validateSession(tokenFixture({ claims: { aud: [CLIENT, 'another'], azp: CLIENT } }), JWKS, CLIENT, NONCE, EMAIL, NOW).clientId, CLIENT);
});

test('returning session binds the validated subject as well as verified email', () => {
  const expected = digest('synthetic-subject');
  assert.equal(validateSession(tokenFixture(), JWKS, CLIENT, NONCE, EMAIL, NOW, expected).subjectHash, expected);
  assert.throws(() => validateSession(tokenFixture({ claims: { sub: 'other-subject' } }),
    JWKS, CLIENT, NONCE, EMAIL, NOW, expected), { code: 'ACCOUNT_NOT_EXPECTED' });
  assert.throws(() => validateSession(tokenFixture(), JWKS, CLIENT, NONCE, EMAIL, NOW, digest('other-subject')),
    { code: 'ACCOUNT_NOT_EXPECTED' });
});

test('token validation rejects signature/header substitution and unexpected signing keys', async t => {
  const signed = tokenFixture();
  const parts = signed.id_token.split('.');
  const tampered = `${parts[0]}.${Buffer.from(JSON.stringify({ sub: 'tampered' })).toString('base64url')}.${parts[2]}`;
  const cases = [
    ['bad signature', tokenFixture({ privateKey: otherKeyPair.privateKey }), JWKS, 'INVALID_ID_TOKEN_SIGNATURE'],
    ['tampered payload', { ...signed, id_token: tampered }, JWKS, 'INVALID_ID_TOKEN_SIGNATURE'],
    ['unsigned algorithm', tokenFixture({ header: { alg: 'none' } }), JWKS, 'INVALID_ID_TOKEN_HEADER'],
    ['remote key URL', tokenFixture({ header: { jku: 'https://example.invalid/jwks' } }), JWKS, 'INVALID_ID_TOKEN_HEADER'],
    ['certificate URL', tokenFixture({ header: { x5u: 'https://example.invalid/cert' } }), JWKS, 'INVALID_ID_TOKEN_HEADER'],
    ['critical header', tokenFixture({ header: { crit: ['unknown'] } }), JWKS, 'INVALID_ID_TOKEN_HEADER'],
    ['unknown key', tokenFixture({ header: { kid: 'absent' } }), JWKS, 'UNKNOWN_SIGNING_KEY'],
    ['duplicate key', signed, { keys: [signingJwk, signingJwk] }, 'UNKNOWN_SIGNING_KEY'],
    ['key wrong use', signed, { keys: [{ ...signingJwk, use: 'enc' }] }, 'UNKNOWN_SIGNING_KEY'],
    ['malformed token', { ...signed, id_token: 'not.a.valid.jwt' }, JWKS, 'INVALID_ID_TOKEN'],
  ];
  for (const [name, token, jwks, code] of cases) await t.test(name, () => {
    assert.throws(() => validateSession(token, jwks, CLIENT, NONCE, EMAIL, NOW), { code });
  });
});

test('token validation rejects issuer, nonce, time, audience, identity and scope failures', async t => {
  const cases = [
    ['issuer', { claims: { iss: 'https://example.invalid' } }, 'INVALID_ID_TOKEN_CLAIMS'],
    ['nonce', { claims: { nonce: 'wrong' } }, 'INVALID_ID_TOKEN_CLAIMS'],
    ['subject', { claims: { sub: '' } }, 'INVALID_ID_TOKEN_CLAIMS'],
    ['expiry', { claims: { exp: NOW / 1000 } }, 'INVALID_ID_TOKEN_CLAIMS'],
    ['future issued', { claims: { iat: NOW / 1000 + 61 } }, 'INVALID_ID_TOKEN_CLAIMS'],
    ['future not before', { claims: { nbf: NOW / 1000 + 61 } }, 'INVALID_ID_TOKEN_CLAIMS'],
    ['wrong audience', { claims: { aud: 'other_client' } }, 'INVALID_AUDIENCE'],
    ['multiple audience without azp', { claims: { aud: [CLIENT, 'other'] } }, 'INVALID_AUDIENCE'],
    ['wrong authorized party', { claims: { azp: 'other' } }, 'INVALID_AUDIENCE'],
    ['wrong email', { claims: { email: 'other@example.invalid' } }, 'ACCOUNT_NOT_EXPECTED'],
    ['email not verified', { claims: { email_verified: false } }, 'ACCOUNT_NOT_EXPECTED'],
    ['plan scope absent', { token: { scope: 'openid resource.invoke' } }, 'PLAN_USAGE_NOT_GRANTED'],
    ['resource scope absent', { token: { scope: 'openid chatgpt.tokens.use.direct' } }, 'PLAN_USAGE_NOT_GRANTED'],
    ['wrong bearer type', { token: { token_type: 'Basic' } }, 'INVALID_TOKEN_RESPONSE'],
    ['missing access token', { token: { access_token: '' } }, 'INVALID_TOKEN_RESPONSE'],
    ['invalid lifetime', { token: { expires_in: 0 } }, 'INVALID_TOKEN_RESPONSE'],
    ['bounded lifetime', { token: { expires_in: 86401 } }, 'INVALID_TOKEN_RESPONSE'],
    ['bounded token', { token: { access_token: 'x'.repeat(65537) } }, 'INVALID_TOKEN_RESPONSE'],
  ];
  for (const [name, input, code] of cases) await t.test(name, () => {
    assert.throws(() => validateSession(tokenFixture(input), JWKS, CLIENT, NONCE, EMAIL, NOW), { code });
  });
});

test('model selection requires an exact visible catalog slug and never aliases another model', () => {
  assert.equal(selectExactModel({ models: [{ slug: 'gpt-6-astra', visibility: 'list' }, { slug: MODEL, visibility: 'list' }] }), MODEL);
  for (const catalog of [
    { data: [{ id: MODEL }] }, { models: [{ slug: `${MODEL}-alias`, visibility: 'list' }] },
    { models: [{ slug: MODEL, visibility: 'hidden' }] }, { models: [] }, null,
  ]) assert.throws(() => selectExactModel(catalog), { code: 'EXACT_MODEL_NOT_AVAILABLE' });
});

test('synthetic request contains no customer data, storage, API fallback or model substitution', () => {
  assert.deepEqual(syntheticRequest(), {
    model: MODEL, input: [{ role: 'user', content: PROBE_INPUT }], store: false, stream: true,
  });
});

test('SSE accepts chunked CRLF data only after a completed exact-model response', async () => {
  const raw = `: keep-alive\r\n\r\n${eventFrame({ type: 'response.output_text.delta', delta: PROBE_OUTPUT.slice(0, 12) }, '\r\n')}${eventFrame({ type: 'response.output_text.delta', delta: PROBE_OUTPUT.slice(12) }, '\r\n')}${eventFrame(completedEvent(), '\r\n')}data: [DONE]\r\n\r\n`;
  const bytes = Buffer.from(raw);
  const result = await consumeProbeStream(Readable.from([bytes.subarray(0, 17), bytes.subarray(17, 53), bytes.subarray(53)]));
  assert.deepEqual(result, { completed: true, model: MODEL,
    responseIdHash: digest('resp_synthetic_fixture'), outputHash: digest(PROBE_OUTPUT) });
  assert.equal('responseId' in result, false);
  assert.equal('text' in result, false);
});

test('SSE fails closed on errors, missing completion, mismatch, interruption and bounds', async t => {
  const cases = [
    ['error', () => streamBody([{ type: 'error', error: { message: 'synthetic' } }]), 'INFERENCE_NOT_COMPLETED'],
    ['failed', () => streamBody([{ type: 'response.failed' }]), 'INFERENCE_NOT_COMPLETED'],
    ['incomplete', () => streamBody([{ type: 'response.incomplete' }]), 'INFERENCE_NOT_COMPLETED'],
    ['truncated before completion', () => streamBody([{ type: 'response.output_text.delta', delta: PROBE_OUTPUT }]), 'MISSING_COMPLETED_EVENT'],
    ['done without completion', () => streamBody([], 'data: [DONE]\n\n'), 'MISSING_COMPLETED_EVENT'],
    ['invalid JSON', () => streamBody([], 'data: {not-json}\n\n'), 'INVALID_STREAM_EVENT'],
    ['wrong model', () => streamBody([completedEvent({ model: 'gpt-6-astra' })]), 'INVALID_COMPLETION'],
    ['wrong status', () => streamBody([completedEvent({ status: 'in_progress' })]), 'INVALID_COMPLETION'],
    ['missing response id', () => streamBody([completedEvent({ id: '' })]), 'INVALID_COMPLETION'],
    ['duplicate completion', () => streamBody([completedEvent(), completedEvent()]), 'INVALID_COMPLETION'],
    ['delta after completion', () => streamBody([completedEvent(), { type: 'response.output_text.delta', delta: 'late' }]), 'INVALID_STREAM_EVENT'],
    ['delta mismatch', () => streamBody([{ type: 'response.output_text.delta', delta: 'wrong' }, completedEvent()]), 'SYNTHETIC_OUTPUT_MISMATCH'],
    ['wrong final text', () => streamBody([completedEvent({ output: [{ type: 'message', content: [{ type: 'output_text', text: 'wrong' }] }] })]), 'SYNTHETIC_OUTPUT_MISMATCH'],
    ['output bound', () => streamBody([{ type: 'response.output_text.delta', delta: 'x'.repeat(65537) }]), 'OUTPUT_TOO_LARGE'],
    ['stream bound', () => Readable.from([Buffer.alloc(1_048_577, 32)]), 'STREAM_TOO_LARGE'],
    ['invalid UTF8', () => Readable.from([Buffer.from([0xff])]), 'STREAM_INTERRUPTED'],
    ['transport interruption', () => Readable.from((async function* () { yield Buffer.from('data: '); throw new Error('synthetic disconnect'); })()), 'STREAM_INTERRUPTED'],
  ];
  for (const [name, body, code] of cases) await t.test(name, async () => {
    await assert.rejects(consumeProbeStream(body()), { code });
  });
});

test('publicJson pins an exact official endpoint and refuses redirects without following them', async () => {
  let calls = 0;
  const fetchMock = async (url, init) => {
    calls++;
    assert.equal(url, `${RESOURCE}/models`);
    assert.equal(init.redirect, 'error');
    assert.ok(init.signal instanceof AbortSignal);
    return jsonResponse({ models: [] });
  };
  assert.deepEqual(await publicJson(`${RESOURCE}/models`, { redirect: 'follow' }, fetchMock), { models: [] });
  assert.equal(calls, 1);
  for (const url of [
    'https://example.invalid/models', `${RESOURCE}/models?account=other`, `${RESOURCE}/responses`,
    'http://api.openai.com/v1/models', 'https://api.openai.com.evil.invalid/v1/models',
    `${ISSUER}/api/accounts/oauth/token/`,
  ]) await assert.rejects(publicJson(url, {}, fetchMock), { code: 'ENDPOINT_NOT_ALLOWED' });
  assert.equal(calls, 1);
  await assert.rejects(publicJson(`${RESOURCE}/models`, {}, async () => new Response('', {
    status: 302, headers: { location: 'https://example.invalid' },
  })), { code: 'UPSTREAM_HTTP_302' });
});

test('publicJson bounds and validates response bodies and sanitizes transport failures', async t => {
  const cases = [
    ['HTTP failure', () => jsonResponse({ error: 'synthetic' }, 401), 'UPSTREAM_HTTP_401'],
    ['wrong content type', () => new Response('{}', { headers: { 'content-type': 'text/html' } }), 'INVALID_UPSTREAM_CONTENT_TYPE'],
    ['malformed JSON', () => new Response('{', { headers: { 'content-type': 'application/json' } }), 'INVALID_UPSTREAM_RESPONSE'],
    ['response too large', () => new Response('x'.repeat(1_048_577), { headers: { 'content-type': 'application/json' } }), 'UPSTREAM_RESPONSE_TOO_LARGE'],
  ];
  for (const [name, response, code] of cases) await t.test(name, async () => {
    await assert.rejects(publicJson(`${RESOURCE}/models`, {}, async () => response()), { code });
  });
  await assert.rejects(publicJson(`${RESOURCE}/models`, {}, async () => { throw new Error('private synthetic diagnostic'); }),
    { code: 'UPSTREAM_REQUEST_FAILED', message: 'UPSTREAM_REQUEST_FAILED' });
  assert.deepEqual(await publicJson(`${ISSUER}/api/accounts/oauth/revoke`, {}, async () => new Response(null, { status: 200 })), {});
  await assert.rejects(publicJson(`${ISSUER}/api/accounts/oauth/revoke`, {}, async () => new Response(null, { status: 204 })),
    { code: 'REVOCATION_NOT_CONFIRMED' });
  await assert.rejects(publicJson(`${ISSUER}/api/accounts/oauth/revoke`, {}, async () => jsonResponse({ success: true })),
    { code: 'REVOCATION_NOT_CONFIRMED' });
});

test('synthetic probe calls only models and Responses using the authorized plan session', async () => {
  const calls = [];
  const session = eligibleSession();
  const result = await runSyntheticProbe(session, async (url, init) => {
    calls.push(url);
    assert.equal(init.headers.Authorization, `Bearer ${session.accessToken}`);
    assert.equal(init.redirect, 'error');
    if (url === `${RESOURCE}/models`) return jsonResponse({ models: [{ slug: MODEL, visibility: 'list' }] });
    assert.equal(url, `${RESOURCE}/responses`);
    assert.equal(init.method, 'POST');
    assert.equal(init.headers.Accept, 'text/event-stream');
    assert.deepEqual(JSON.parse(init.body), syntheticRequest());
    return new Response(streamBody([completedEvent()]), { headers: { 'content-type': 'text/event-stream' } });
  });
  assert.deepEqual(calls, [`${RESOURCE}/models`, `${RESOURCE}/responses`]);
  assert.equal(result.completed, true);
  assert.equal(result.model, MODEL);
});

test('ineligible sessions and unavailable exact model cause no inference or fallback', async t => {
  for (const session of [null, { ...eligibleSession(), planScopeGranted: false },
    { ...eligibleSession(), accountMatchesExpected: false }, { ...eligibleSession(), expiresAt: 0 }]) {
    let calls = 0;
    await assert.rejects(runSyntheticProbe(session, async () => { calls++; throw new Error('must not fetch'); }), { code: 'SESSION_NOT_ELIGIBLE' });
    assert.equal(calls, 0);
  }
  await t.test('missing exact model', async () => {
    const calls = [];
    await assert.rejects(runSyntheticProbe(eligibleSession(), async url => {
      calls.push(url);
      return jsonResponse({ models: [{ slug: 'gpt-6-astra', visibility: 'list' }] });
    }), { code: 'EXACT_MODEL_NOT_AVAILABLE' });
    assert.deepEqual(calls, [`${RESOURCE}/models`]);
  });
});

test('synthetic inference failure never retries, rotates accounts or falls back to an API key', async t => {
  for (const status of [401, 403, 429, 503]) await t.test(`HTTP ${status}`, async () => {
    const calls = [];
    await assert.rejects(runSyntheticProbe(eligibleSession(), async url => {
      calls.push(url);
      if (url === `${RESOURCE}/models`) return jsonResponse({ models: [{ slug: MODEL, visibility: 'list' }] });
      return jsonResponse({ error: 'synthetic failure' }, status);
    }), { code: `INFERENCE_HTTP_${status}` });
    assert.deepEqual(calls, [`${RESOURCE}/models`, `${RESOURCE}/responses`]);
  });
  await t.test('wrong stream content type', async () => {
    let calls = 0;
    await assert.rejects(runSyntheticProbe(eligibleSession(), async () => ++calls === 1
      ? jsonResponse({ models: [{ slug: MODEL, visibility: 'list' }] }) : jsonResponse({ text: PROBE_OUTPUT })),
    { code: 'INVALID_STREAM_CONTENT_TYPE' });
    assert.equal(calls, 2);
  });
  await t.test('transport failure is safe and terminal', async () => {
    let calls = 0;
    await assert.rejects(runSyntheticProbe(eligibleSession(), async () => {
      if (++calls === 1) return jsonResponse({ models: [{ slug: MODEL, visibility: 'list' }] });
      throw new Error('private synthetic diagnostic');
    }), { code: 'INFERENCE_REQUEST_FAILED', message: 'INFERENCE_REQUEST_FAILED' });
    assert.equal(calls, 2);
  });
});

test('typed probe errors expose only stable error codes', () => {
  const error = new ProbeError('SYNTHETIC_FAILURE');
  assert.equal(error.code, 'SYNTHETIC_FAILURE');
  assert.equal(error.message, 'SYNTHETIC_FAILURE');
  assert.equal(error instanceof Error, true);
});

test('synthetic probe accepts case-insensitive exact SSE MIME with charset, never stream-like suffixes', async t => {
  for (const mime of ['TEXT/EVENT-STREAM', 'Text/Event-Stream; Charset=UTF-8']) await t.test(mime, async () => {
    const calls = [];
    const result = await runSyntheticProbe(eligibleSession(), async (url, init) => {
      calls.push(url);
      if (url === `${RESOURCE}/models`) return jsonResponse({ models: [{ slug: MODEL, visibility: 'list' }] });
      assert.equal(init.headers.Accept, 'text/event-stream');
      return new Response(streamBody([completedEvent()]), { headers: { 'content-type': mime } });
    });
    assert.equal(result.completed, true);
    assert.deepEqual(calls, [`${RESOURCE}/models`, `${RESOURCE}/responses`]);
  });
  await t.test('streamx is not SSE', async () => {
    const calls = [];
    await assert.rejects(runSyntheticProbe(eligibleSession(), async url => {
      calls.push(url);
      if (url === `${RESOURCE}/models`) return jsonResponse({ models: [{ slug: MODEL, visibility: 'list' }] });
      return new Response(streamBody([completedEvent()]), { headers: { 'content-type': 'text/event-streamx' } });
    }), error => {
      assert.equal(error.code, 'INVALID_STREAM_CONTENT_TYPE');
      assert.deepEqual(error.diagnostic, { httpStatus: 200, contentTypeClass: 'OTHER',
        catalogModelVerified: true, bodyShape: 'NOT_PARSED' });
      return true;
    });
    assert.deepEqual(calls, [`${RESOURCE}/models`, `${RESOURCE}/responses`]);
  });
});

test('successful HTTP without SSE is never inference completion or a reason to use another account', async t => {
  const cases = [
    ['JSON response object', () => jsonResponse({ object: 'response', status: 'completed',
      output: completedEvent().response.output }), 200, 'JSON', 'RESPONSE_OBJECT', 'completed'],
    ['JSON detail', () => jsonResponse({ detail: 'synthetic-private-detail' }), 200, 'JSON', 'DETAIL_OBJECT'],
    ['HTML', () => new Response('<h1>synthetic-private-html</h1>', { headers: { 'content-type': 'text/html; charset=utf-8' } }), 200, 'HTML', 'NOT_PARSED'],
    ['missing MIME', () => new Response(Buffer.from('synthetic-private-body')), 200, 'MISSING', 'NOT_PARSED'],
    ['no content 204', () => new Response(null, { status: 204 }), 204, 'MISSING', 'NOT_PARSED'],
  ];
  for (const [name, response, status, contentTypeClass, bodyShape, responseStatus] of cases) await t.test(name, async () => {
    const calls = [];
    await assert.rejects(runSyntheticProbe(eligibleSession(), async url => {
      calls.push(url);
      if (url === `${RESOURCE}/models`) return jsonResponse({ models: [{ slug: MODEL, visibility: 'list' }] });
      return response();
    }), error => {
      assert.equal(error.code, 'INVALID_STREAM_CONTENT_TYPE');
      assert.deepEqual(error.diagnostic, { httpStatus: status, contentTypeClass, catalogModelVerified: true,
        bodyShape, ...(responseStatus ? { responseStatus } : {}) });
      assert.equal(JSON.stringify(error).includes('synthetic-private'), false);
      return true;
    });
    assert.deepEqual(calls, [`${RESOURCE}/models`, `${RESOURCE}/responses`]);
  });
});

test('inference diagnostic exposes only bounded structural classes and known provider codes', async t => {
  const codes = [
    'subscription_sharing_user_not_eligible', 'subscription_sharing_usage_limit_exceeded',
    'subscription_sharing_usage_unavailable', 'subscription_sharing_unsupported_capability',
    'subscription_sharing_route_not_supported', 'subscription_sharing_invalid_user',
    'chatpass_v2_scope_not_authorized', 'chatpass_v2_invalid_authorization_context',
    'subscription_sharing_user_unavailable',
  ];
  for (const code of codes) await t.test(code, async () => {
    const diagnostic = await inferenceFailureDiagnostic(jsonResponse({ error: { code,
      message: 'SYNTHETIC_SECRET_DO_NOT_EMIT', detail: 'synthetic-access-token' } }, 403));
    assert.deepEqual(diagnostic, { httpStatus: 403, contentTypeClass: 'JSON',
      catalogModelVerified: true, bodyShape: 'ERROR_OBJECT', errorCode: code });
  });
  for (const [body, shape] of [[{ error: { code: 'unknown-private-code', message: 'SYNTHETIC_SECRET_DO_NOT_EMIT' } }, 'ERROR_OBJECT'],
    [{ detail: { access_token: 'SYNTHETIC_SECRET_DO_NOT_EMIT' } }, 'DETAIL_OBJECT'],
    [[{ message: 'SYNTHETIC_SECRET_DO_NOT_EMIT' }], 'ARRAY'], ['SYNTHETIC_SECRET_DO_NOT_EMIT', 'SCALAR'],
    [null, 'SCALAR'], [{ arbitrary: 'SYNTHETIC_SECRET_DO_NOT_EMIT' }, 'OTHER_OBJECT']]) {
    const diagnostic = await inferenceFailureDiagnostic(jsonResponse(body));
    assert.equal(diagnostic.bodyShape, shape);
    assert.equal('errorCode' in diagnostic, false);
    assert.equal(JSON.stringify(diagnostic).includes('SYNTHETIC_SECRET_DO_NOT_EMIT'), false);
    assert.equal(JSON.stringify(diagnostic).includes('unknown-private-code'), false);
  }
  for (const status of ['completed', 'in_progress', 'failed', 'incomplete', 'queued']) {
    assert.equal((await inferenceFailureDiagnostic(jsonResponse({ object: 'response', status }))).responseStatus, status);
  }
  assert.equal('responseStatus' in await inferenceFailureDiagnostic(jsonResponse({ object: 'response', status: 'private-unknown-status' })), false);
});

test('inference diagnostic hashes request IDs and never returns raw headers', async () => {
  const requestId = 'req_synthetic_private_request_id';
  const response = jsonResponse({ detail: 'synthetic-private-detail' });
  response.headers.set('x-request-id', requestId);
  response.headers.set('authorization', 'Bearer SYNTHETIC_SECRET_DO_NOT_EMIT');
  const diagnostic = await inferenceFailureDiagnostic(response);
  assert.equal(diagnostic.requestIdHash, digest(requestId));
  assert.equal('requestId' in diagnostic, false);
  assert.equal('headers' in diagnostic, false);
  assert.equal(JSON.stringify(diagnostic).includes(requestId), false);
  assert.equal(JSON.stringify(diagnostic).includes('SYNTHETIC_SECRET_DO_NOT_EMIT'), false);
  const excessive = jsonResponse({});
  excessive.headers.set('x-request-id', 'x'.repeat(1025));
  assert.equal('requestIdHash' in await inferenceFailureDiagnostic(excessive), false);
});

test('inference diagnostic enforces 16 KiB JSON bound and cancels over-limit bodies', async () => {
  const payload = JSON.stringify({ detail: 'synthetic-private-detail' });
  const atLimit = `${payload}${' '.repeat(16384 - Buffer.byteLength(payload))}`;
  assert.equal((await inferenceFailureDiagnostic(new Response(atLimit, {
    headers: { 'content-type': 'Application/JSON; charset=UTF-8' },
  }))).bodyShape, 'DETAIL_OBJECT');
  let canceled = false;
  const body = new ReadableStream({
    start(controller) { controller.enqueue(new Uint8Array(16385)); },
    cancel() { canceled = true; },
  });
  const result = await inferenceFailureDiagnostic(new Response(body, { headers: { 'content-type': 'application/json' } }));
  assert.equal(result.bodyShape, 'OVER_LIMIT');
  assert.equal(canceled, true);
});

test('inference diagnostic terminates unreadable, interrupted or stalled bodies without private errors', { timeout: 2000 }, async () => {
  for (const bytes of [Buffer.from('{not-json'), Buffer.from([0xff])]) {
    assert.equal((await inferenceFailureDiagnostic(new Response(bytes, {
      headers: { 'content-type': 'application/json' },
    }))).bodyShape, 'UNREADABLE');
  }
  const interrupted = new ReadableStream({
    start(controller) { controller.error(new Error('SYNTHETIC_SECRET_DO_NOT_EMIT')); },
  });
  assert.equal((await inferenceFailureDiagnostic(new Response(interrupted, {
    headers: { 'content-type': 'application/json' },
  }))).bodyShape, 'UNREADABLE');
  let canceled = false;
  const stalled = new ReadableStream({ cancel() { canceled = true; } });
  const diagnostic = await inferenceFailureDiagnostic(new Response(stalled, {
    headers: { 'content-type': 'application/json' },
  }), 5);
  assert.equal(diagnostic.bodyShape, 'UNREADABLE');
  assert.equal(canceled, true);
  assert.equal(JSON.stringify(diagnostic).includes('SYNTHETIC_SECRET_DO_NOT_EMIT'), false);
});

test('ProbeError accepts only safe diagnostic fields and rejects untrusted constructor extras', () => {
  const diagnostic = { httpStatus: 403, contentTypeClass: 'JSON', bodyShape: 'ERROR_OBJECT',
    catalogModelVerified: true, errorCode: 'subscription_sharing_user_not_eligible', responseStatus: 'failed',
    requestIdHash: digest('synthetic-request'),
    message: 'SYNTHETIC_SECRET_DO_NOT_EMIT', detail: 'SYNTHETIC_SECRET_DO_NOT_EMIT',
    token: 'SYNTHETIC_SECRET_DO_NOT_EMIT', requestId: 'req_private', headers: { authorization: 'private' } };
  const error = new ProbeError('INFERENCE_HTTP_403', diagnostic);
  assert.deepEqual(error.diagnostic, { httpStatus: 403, contentTypeClass: 'JSON', bodyShape: 'ERROR_OBJECT',
    catalogModelVerified: true, errorCode: 'subscription_sharing_user_not_eligible', responseStatus: 'failed',
    requestIdHash: digest('synthetic-request') });
  assert.equal(Object.isFrozen(error.diagnostic), true);
  assert.equal(error.message, 'INFERENCE_HTTP_403');
  assert.equal(JSON.stringify(error).includes('SYNTHETIC_SECRET_DO_NOT_EMIT'), false);
  assert.deepEqual(new ProbeError('INVALID_STREAM_CONTENT_TYPE', {
    httpStatus: 600, contentTypeClass: 'application/json', bodyShape: 'raw-private-body',
    catalogModelVerified: false, errorCode: 'unknown-private-code', responseStatus: 'private-status',
    requestIdHash: 'raw-id', arbitrary: 'SYNTHETIC_SECRET_DO_NOT_EMIT',
  }).diagnostic, {});
});

test('malicious diagnostic messages and token-shaped detail never appear on child stdout or JSON', () => {
  const runtimeUrl = new URL('./siwc-local-runtime.mjs', import.meta.url).href;
  const source = `import { inferenceFailureDiagnostic, ProbeError } from ${JSON.stringify(runtimeUrl)};
    globalThis.fetch = async () => { throw new Error('NETWORK_DISABLED'); };
    const secret = 'SYNTHETIC_SECRET_DO_NOT_EMIT';
    const response = new Response(JSON.stringify({ detail: { access_token: secret },
      error: { code: 'unknown-private-code', message: secret, detail: secret } }),
      { status: 200, headers: { 'content-type': 'application/json', 'x-request-id': secret } });
    const diagnostic = await inferenceFailureDiagnostic(response);
    process.stdout.write(JSON.stringify(new ProbeError('INVALID_STREAM_CONTENT_TYPE', {
      ...diagnostic, message: secret, detail: secret, access_token: secret })));
  `;
  const child = spawnSync(process.execPath, ['--input-type=module', '--eval', source], {
    env: { PATH: '/usr/bin:/bin', LANG: 'C' }, encoding: 'utf8', timeout: 5000,
  });
  assert.equal(child.error, undefined);
  assert.equal(child.status, 0);
  assert.equal(child.stderr, '');
  assert.equal(child.stdout.includes('SYNTHETIC_SECRET_DO_NOT_EMIT'), false);
  assert.equal(child.stdout.includes('unknown-private-code'), false);
  const result = JSON.parse(child.stdout);
  assert.equal(result.code, 'INVALID_STREAM_CONTENT_TYPE');
  assert.equal(result.diagnostic.bodyShape, 'ERROR_OBJECT');
  assert.match(result.diagnostic.requestIdHash, /^[0-9a-f]{64}$/);
});

test('private registration storage atomically preserves only non-secret mappings and stable host identity', async t => {
  const root = await mkdtemp(join(tmpdir(), 'siwc-storage-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const path = join(root, 'outer', 'pilot', 'host.json');
  const initial = await loadRegistration(path);
  assert.match(initial.hostId, /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  assert.deepEqual(Object.keys(initial), ['hostId']);
  assert.equal((await lstat(dirname(path))).mode & 0o777, 0o700);
  assert.equal((await lstat(path)).mode & 0o777, 0o600);
  assert.deepEqual(await loadRegistration(path), initial);
  const before = await lstat(path);
  const mapping = { ...initial, clientId: CLIENT, subjectHash: digest('synthetic-subject') };
  await saveRegistration({ ...mapping,
    accessToken: 'synthetic-secret-must-not-persist', refresh_token: 'synthetic-refresh-must-not-persist',
    id_token: 'synthetic-id-must-not-persist', password: 'synthetic-password-must-not-persist',
    expectedEmail: EMAIL, arbitrary: { nested: true },
  }, path);
  const after = await lstat(path);
  assert.notEqual(after.ino, before.ino, 'save must replace the file atomically, not rewrite its original inode');
  assert.equal(after.mode & 0o777, 0o600);
  assert.equal(after.nlink, 1);
  const storedText = await readFile(path, 'utf8');
  assert.deepEqual(JSON.parse(storedText), mapping);
  assert.equal(storedText.includes('must-not-persist'), false);
  assert.equal(storedText.includes(EMAIL), false);
  assert.deepEqual(await loadRegistration(path), mapping);
  assert.deepEqual(await readdir(dirname(path)), ['host.json'], 'atomic save must not leave temporary files');
  await saveRegistration(mapping, path);
  assert.deepEqual(await loadRegistration(path), mapping);
});

test('registration loader rejects symlink, hardlink and overly broad storage permissions', async t => {
  const cases = [
    ['symlink parent', async (root, path) => {
      const target = join(root, 'target');
      await mkdir(target, { mode: 0o700 });
      await symlink(target, dirname(path));
    }, 'HOST_STORAGE_NOT_PRIVATE'],
    ['symlink file', async (root, path) => {
      await mkdir(dirname(path), { mode: 0o700 });
      const target = join(root, 'target.json');
      await writeFile(target, JSON.stringify({ hostId: HOST }), { mode: 0o600 });
      await symlink(target, path);
    }, 'HOST_STORAGE_INVALID'],
    ['hardlinked file', async (root, path) => {
      await mkdir(dirname(path), { mode: 0o700 });
      const target = join(root, 'target.json');
      await writeFile(target, JSON.stringify({ hostId: HOST }), { mode: 0o600 });
      await link(target, path);
    }, 'HOST_STORAGE_NOT_PRIVATE'],
    ['group writable outer directory', async (_root, path) => {
      await chmod(dirname(dirname(path)), 0o770);
    }, 'HOST_STORAGE_NOT_PRIVATE'],
    ['public parent directory', async (_root, path) => {
      await mkdir(dirname(path), { mode: 0o700 });
      await chmod(dirname(path), 0o755);
    }, 'HOST_STORAGE_NOT_PRIVATE'],
    ['public registration file', async (_root, path) => {
      await mkdir(dirname(path), { mode: 0o700 });
      await writeFile(path, JSON.stringify({ hostId: HOST }), { mode: 0o600 });
      await chmod(path, 0o644);
    }, 'HOST_STORAGE_NOT_PRIVATE'],
  ];
  for (const [name, prepare, code] of cases) await t.test(name, async st => {
    const root = await mkdtemp(join(tmpdir(), 'siwc-storage-test-'));
    st.after(() => rm(root, { recursive: true, force: true }));
    const path = join(root, 'outer', 'pilot', 'host.json');
    await mkdir(dirname(dirname(path)), { mode: 0o700 });
    await prepare(root, path);
    await assert.rejects(loadRegistration(path), { code });
  });
});

test('registration loader rejects malformed, oversized or secret-bearing stored records', async t => {
  const cases = [
    ['malformed JSON', '{', 'HOST_STORAGE_INVALID'],
    ['unknown secret field', JSON.stringify({ hostId: HOST, access_token: 'synthetic-token' }), 'HOST_STORAGE_INVALID'],
    ['invalid host', JSON.stringify({ hostId: 'urn:uuid:------------------------------------' }), 'HOST_STORAGE_INVALID'],
    ['unissued client', JSON.stringify({ hostId: HOST, clientId: 'dynamic_agent_client' }), 'HOST_STORAGE_INVALID'],
    ['subject without client', JSON.stringify({ hostId: HOST, subjectHash: digest('synthetic-subject') }), 'HOST_STORAGE_INVALID'],
    ['invalid subject hash', JSON.stringify({ hostId: HOST, clientId: CLIENT, subjectHash: 'bad-hash' }), 'HOST_STORAGE_INVALID'],
    ['oversized record', 'x'.repeat(4097), 'HOST_STORAGE_NOT_PRIVATE'],
  ];
  for (const [name, text, code] of cases) await t.test(name, async st => {
    const root = await mkdtemp(join(tmpdir(), 'siwc-storage-test-'));
    st.after(() => rm(root, { recursive: true, force: true }));
    const path = join(root, 'outer', 'pilot', 'host.json');
    await mkdir(dirname(dirname(path)), { mode: 0o700 });
    await mkdir(dirname(path), { mode: 0o700 });
    await writeFile(path, text, { mode: 0o600 });
    await assert.rejects(loadRegistration(path), { code });
  });
});

test('failed atomic save preserves the previous record and cleans its temporary file', async t => {
  const root = await mkdtemp(join(tmpdir(), 'siwc-storage-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const path = join(root, 'outer', 'pilot', 'host.json');
  const initial = await loadRegistration(path);
  const invalid = { hostId: { circular: null } };
  invalid.hostId.circular = invalid.hostId;
  await assert.rejects(saveRegistration(invalid, path), { code: 'HOST_STORAGE_UNAVAILABLE' });
  assert.deepEqual(await loadRegistration(path), initial);
  assert.deepEqual(await readdir(dirname(path)), ['host.json']);
});

test('CLI without explicit authorization performs no network, bind or storage initialization', async t => {
  const root = await mkdtemp(join(tmpdir(), 'siwc-cli-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const pilotPath = fileURLToPath(new URL('./siwc-local-pilot.mjs', import.meta.url));
  const defaultStorage = fileURLToPath(new URL('../.local-tests/siwc-personal-pilot/host.json', import.meta.url));
  const storageBefore = await lstat(defaultStorage).catch(error => {
    if (error.code !== 'ENOENT') throw error;
    return null;
  });
  const guard = `import { Server } from 'node:net';
    globalThis.fetch = async () => { process.stderr.write('UNEXPECTED_NETWORK'); throw new Error('NETWORK_DISABLED'); };
    Server.prototype.listen = function () { process.stderr.write('UNEXPECTED_LISTEN'); throw new Error('LISTEN_DISABLED'); };`;
  const child = spawnSync(process.execPath, ['--import', `data:text/javascript,${encodeURIComponent(guard)}`, pilotPath], {
    cwd: root, env: { HOME: root, TMPDIR: root, LANG: 'C' }, encoding: 'utf8', timeout: 5_000,
  });
  assert.equal(child.error, undefined);
  assert.equal(child.status, 0);
  assert.equal(child.stderr, '');
  const output = JSON.parse(child.stdout);
  assert.equal(output.status, 'NOT_STARTED');
  assert.equal(output.noCloud, true);
  assert.equal(output.noApiKeyFallback, true);
  assert.equal(output.credentialsPersisted, false);
  const storageAfter = await lstat(defaultStorage).catch(error => {
    if (error.code !== 'ENOENT') throw error;
    return null;
  });
  assert.deepEqual(storageAfter && { ino: storageAfter.ino, mtimeMs: storageAfter.mtimeMs, size: storageAfter.size },
    storageBefore && { ino: storageBefore.ino, mtimeMs: storageBefore.mtimeMs, size: storageBefore.size });
  assert.deepEqual(await readdir(root), []);
});
