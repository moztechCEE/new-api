import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer, request } from 'node:http';
import { after, before, test } from 'node:test';
import { CORELY_MODEL_JOB_RESOURCE as RESOURCE, CORELY_MODEL_JOB_ISSUER as ISSUER, CORELY_MODEL_JOB_SCOPE as SCOPE,
  CORELY_MODEL_JOB_CLIENT_ID as CLIENT, CORELY_MODEL_JOB_REDIRECT as REDIRECT, ModelJobClientError,
  validateModelJobCallback, connectCorelyModelJobs } from './codex-harness-model-job-client.mjs';

const TOKEN = `models_access_${'t'.repeat(43)}`, CODE = `models_code_${'c'.repeat(43)}`, STATE = 's'.repeat(43);
const realFetch = globalThis.fetch;
before(() => { globalThis.fetch = () => { throw new Error('ALL_EXTERNAL_NETWORK_DISABLED'); }; });
after(() => { globalThis.fetch = realFetch; });
const validToken = () => ({ access_token: TOKEN, token_type: 'Bearer', expires_in: 900, scope: SCOPE });
const isCode = code => error => error instanceof ModelJobClientError && error.code === code && error.message === code && !error.cause;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function callbackUrl(auth, mutate) {
  const authorization = new URL(auth), url = new URL(REDIRECT);
  url.searchParams.set('state', authorization.searchParams.get('state'));
  url.searchParams.set('iss', ISSUER); url.searchParams.set('code', CODE);
  mutate?.(url); return url;
}

function loopback(url, { method = 'GET', path, headers = {}, rawHeaders } = {}) {
  assert.equal(new URL(url).origin, 'http://127.0.0.1:47632');
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port: 47632, method, path: path ?? new URL(url).pathname + new URL(url).search,
      headers: rawHeaders ?? { Host: '127.0.0.1:47632', Connection: 'close', ...headers }, agent: false }, res => {
      const chunks = []; res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString() }));
      res.on('error', reject);
    });
    req.setTimeout(2000, () => req.destroy(new Error('SYNTHETIC_LOOPBACK_TIMEOUT'))); req.on('error', reject); req.end();
  });
}

async function portReusable() {
  const server = createServer();
  try { await new Promise((resolve, reject) => { server.once('error', reject); server.listen(47632, '127.0.0.1', resolve); }); }
  finally { if (server.listening) await new Promise(resolve => server.close(resolve)); }
}

function fakeFetch({ tokenResponse, revokeResponse, tokenThrow, revokeThrow } = {}) {
  const calls = [];
  const fetchImpl = async (url, options) => {
    assert.ok([`${ISSUER}/token`, `${ISSUER}/revoke`].includes(url), 'no resource, model, provider or arbitrary request');
    assert.equal(options.method, 'POST'); assert.equal(options.redirect, 'error'); assert.equal(options.credentials, 'omit');
    assert.equal(options.cache, 'no-store'); assert.ok(options.signal instanceof AbortSignal);
    assert.equal(options.headers['Content-Type'], 'application/x-www-form-urlencoded');
    assert.equal(options.headers.Authorization, undefined);
    const form = new URLSearchParams(options.body); calls.push({ url, form, options });
    if (url.endsWith('/token')) {
      if (tokenThrow) throw tokenThrow;
      return typeof tokenResponse === 'function' ? tokenResponse(options) : tokenResponse ?? Response.json(validToken());
    }
    if (revokeThrow) throw revokeThrow;
    return typeof revokeResponse === 'function' ? revokeResponse(options) : revokeResponse ?? new Response(null, { status: 200 });
  };
  return { fetchImpl, calls };
}

async function authorize(auth) { assert.equal((await loopback(callbackUrl(auth))).status, 200); }

test('callback requires the separate model-job client, exact loopback, state, issuer and prefixed code', async t => {
  const base = new URL(REDIRECT); base.searchParams.set('state', STATE); base.searchParams.set('iss', ISSUER); base.searchParams.set('code', CODE);
  assert.equal(validateModelJobCallback(base.href, STATE), CODE);
  const changes = [
    ['foreign issuer', url => url.searchParams.set('iss', `${RESOURCE}/local/oauth`)],
    ['missing issuer', url => url.searchParams.delete('iss')], ['wrong state', url => url.searchParams.set('state', 'x'.repeat(43))],
    ['missing state', url => url.searchParams.delete('state')], ['duplicated state', url => url.searchParams.append('state', STATE)],
    ['unprefixed code', url => url.searchParams.set('code', 'c'.repeat(43))], ['other grant code', url => url.searchParams.set('code', `local_code_${'c'.repeat(43)}`)],
    ['missing code', url => url.searchParams.delete('code')], ['extra code', url => url.searchParams.append('code', CODE)],
    ['extra token', url => url.searchParams.set('access_token', TOKEN)], ['code plus error', url => url.searchParams.set('error', 'access_denied')],
    ['other error', url => { url.searchParams.delete('code'); url.searchParams.set('error', 'private'); }],
    ['localhost', url => { url.hostname = 'localhost'; }], ['foreign port', url => { url.port = '47631'; }],
    ['path prefix', url => { url.pathname += '/extra'; }], ['fragment', url => { url.hash = 'fragment'; }],
    ['userinfo', url => { url.username = 'synthetic'; }], ['https loopback', url => { url.protocol = 'https:'; }],
  ];
  for (const [label, mutate] of changes) await t.test(label, () => { const url = new URL(base); mutate(url); assert.throws(() => validateModelJobCallback(url.href, STATE), isCode('INVALID_CALLBACK')); });
  for (const raw of [null, [], '/corely/model-jobs/callback', base.href.replace('/corely/', '/%63orely/'),
    base.href.replace('/corely/', '/unused/../corely/'), base.href.replace('state=', 'state=\n'), `${base.href}&broken=%`, 'x'.repeat(4097)]) {
    assert.throws(() => validateModelJobCallback(raw, STATE), isCode('INVALID_CALLBACK'));
  }
  const denied = new URL(base); denied.searchParams.delete('code'); denied.searchParams.set('error', 'access_denied');
  assert.throws(() => validateModelJobCallback(denied.href, STATE), isCode('AUTHORIZATION_DENIED'));
});

test('normal OAuth proves only a bounded Corely grant; bearer, code and verifier never leave closure', async () => {
  const transport = fakeFetch(); let authorization;
  const session = await connectCorelyModelJobs({ fetchImpl: transport.fetchImpl, onAuthorize: async auth => { authorization = new URL(auth); await authorize(auth); } });
  try {
    assert.equal(authorization.origin + authorization.pathname, `${ISSUER}/authorize`);
    assert.deepEqual([...authorization.searchParams.keys()].sort(), ['client_id', 'code_challenge', 'code_challenge_method', 'redirect_uri', 'resource', 'response_type', 'scope', 'state']);
    assert.equal(authorization.searchParams.get('client_id'), CLIENT); assert.equal(authorization.searchParams.get('scope'), SCOPE);
    assert.equal(authorization.searchParams.get('redirect_uri'), REDIRECT); assert.equal(authorization.searchParams.get('resource'), RESOURCE);
    assert.equal(authorization.searchParams.get('response_type'), 'code'); assert.equal(authorization.searchParams.get('code_challenge_method'), 'S256');
    assert.match(authorization.searchParams.get('state'), /^[A-Za-z0-9_-]{43}$/);
    const form = transport.calls[0].form;
    assert.deepEqual([...form.keys()].sort(), ['client_id', 'code', 'code_verifier', 'grant_type', 'redirect_uri', 'resource']);
    assert.equal(form.get('code'), CODE); assert.equal(form.get('client_id'), CLIENT); assert.equal(form.get('resource'), RESOURCE);
    assert.equal(form.get('grant_type'), 'authorization_code'); assert.equal(form.get('redirect_uri'), REDIRECT);
    assert.equal(createHash('sha256').update(form.get('code_verifier')).digest('base64url'), authorization.searchParams.get('code_challenge'));
    assert.notEqual(form.get('code_verifier'), authorization.searchParams.get('state'));
    assert.deepEqual(Object.keys(session).sort(), ['receipt', 'revoke']); assert.ok(Object.isFrozen(session));
    const receipt = session.receipt(); assert.ok(Object.isFrozen(receipt));
    assert.equal(receipt.status, 'CORELY_MODEL_JOB_GRANT_CONNECTED'); assert.equal(receipt.currentServerAuthority, 'NOT_CHECKED');
    assert.equal(receipt.syntheticOnly, true); assert.equal(receipt.jobOperations, 'NOT_IMPLEMENTED');
    for (const field of ['customerDataAccessed', 'modelExecuted', 'apiFallbackUsed', 'sendingPerformed', 'learningPerformed']) assert.equal(receipt[field], false);
    assert.ok(!JSON.stringify(session).includes(TOKEN)); assert.ok(!JSON.stringify(receipt).includes(CODE));
    assert.ok(!JSON.stringify(receipt).includes(form.get('code_verifier')));
    await portReusable();
  } finally { assert.deepEqual(await session.revoke(), { status: 'CORELY_MODEL_JOB_GRANT_REVOKED', revocationConfirmed: true }); }
  assert.throws(() => session.receipt(), isCode('GRANT_CLOSED'));
  await session.revoke(); assert.equal(transport.calls.length, 2);
  assert.deepEqual([...transport.calls[1].form.entries()], [['token', TOKEN], ['token_type_hint', 'access_token'], ['client_id', CLIENT]]);
});

test('callbacks are single use and all HTTP responses exclude secret echo and caching', async () => {
  const transport = fakeFetch();
  const session = await connectCorelyModelJobs({ fetchImpl: transport.fetchImpl, onAuthorize: async auth => {
    const url = callbackUrl(auth), result = await loopback(url);
    assert.equal(result.status, 200); assert.equal(result.headers['cache-control'], 'no-store');
    assert.equal(result.headers['referrer-policy'], 'no-referrer'); assert.equal(result.headers['x-content-type-options'], 'nosniff');
    assert.ok(!result.text.includes(CODE)); assert.ok(!result.text.includes(new URL(auth).searchParams.get('state')));
    assert.equal((await loopback(url)).status, 410);
  } });
  await session.revoke(); await portReusable();
});

test('wrong Host, method, raw path, absolute target, duplicate Host and body cannot consume a valid callback', async t => {
  for (const [label, options] of [
    ['Host alias', { headers: { Host: 'localhost:47632' } }], ['foreign Host', { headers: { Host: 'attacker.invalid' } }],
    ['method', { method: 'POST' }], ['wrong path', { path: '/other' }], ['encoded path', { path: '/%63orely/model-jobs/callback?x=y' }],
    ['absolute target', { path: `${REDIRECT}?x=y` }], ['GET body', { headers: { 'Content-Length': '1' } }],
    ['duplicate Host', { rawHeaders: ['Host', '127.0.0.1:47632', 'Host', 'attacker.invalid'] }],
  ]) await t.test(label, async () => {
    const transport = fakeFetch();
    const session = await connectCorelyModelJobs({ fetchImpl: transport.fetchImpl, onAuthorize: async auth => {
      const response = await loopback(callbackUrl(auth), options); assert.equal(response.status, 400); await authorize(auth);
    } });
    await session.revoke(); await portReusable();
  });
});

test('eight invalid callbacks, explicit denial and raw authorization failure clean listener without a token exchange', async t => {
  for (const [label, onAuthorize, code] of [
    ['bounded attempts', async auth => { for (let i = 0; i < 8; i++) assert.equal((await loopback(callbackUrl(auth, url => url.searchParams.set('state', 'x'.repeat(43))))).status, 400); }, 'INVALID_CALLBACK'],
    ['deny', async auth => { assert.equal((await loopback(callbackUrl(auth, url => { url.searchParams.delete('code'); url.searchParams.set('error', 'access_denied'); }))).status, 403); }, 'AUTHORIZATION_DENIED'],
    ['callback throws private value', async () => { throw new Error('synthetic-private-input'); }, 'AUTHORIZATION_FAILED'],
  ]) await t.test(label, async () => {
    const transport = fakeFetch(); await assert.rejects(connectCorelyModelJobs({ fetchImpl: transport.fetchImpl, onAuthorize }), isCode(code));
    assert.equal(transport.calls.length, 0); await portReusable();
  });
});

test('pending callback and hung onAuthorize are bounded independently of callback arrival', async t => {
  for (const [label, onAuthorize] of [
    ['no callback', async () => {}], ['hung owner callback', async () => new Promise(() => {})],
    ['valid response but hung owner callback', async auth => { await authorize(auth); return new Promise(() => {}); }],
  ]) await t.test(label, async () => {
    const transport = fakeFetch(), started = performance.now();
    await assert.rejects(connectCorelyModelJobs({ fetchImpl: transport.fetchImpl, onAuthorize, timeoutMs: 100 }), isCode('AUTHORIZATION_TIMEOUT'));
    assert.ok(performance.now() - started < 2000); assert.equal(transport.calls.length, 0); await portReusable();
  });
});

test('abort before start or while waiting does not exchange and closes the exact loopback listener', async t => {
  await t.test('before start', async () => {
    const signal = AbortSignal.abort(new Error('synthetic-private-abort'));
    await assert.rejects(connectCorelyModelJobs({ signal, onAuthorize: () => assert.fail('no UI'), fetchImpl: () => assert.fail('no HTTPS') }), isCode('ABORTED'));
    await portReusable();
  });
  await t.test('during callback wait', async () => {
    const controller = new AbortController(), transport = fakeFetch();
    await assert.rejects(connectCorelyModelJobs({ signal: controller.signal, fetchImpl: transport.fetchImpl, onAuthorize: async () => { controller.abort('synthetic-private-abort'); } }), isCode('ABORTED'));
    assert.equal(transport.calls.length, 0); await portReusable();
  });
  await t.test('during listen setup', async () => {
    const controller = new AbortController(), promise = connectCorelyModelJobs({ signal: controller.signal, onAuthorize: () => assert.fail('no UI') });
    controller.abort(); await assert.rejects(promise, isCode('ABORTED')); await sleep(5); await portReusable();
  });
});

test('loopback address collision does not open authorization or exchange a token', async () => {
  const blocker = createServer(); await new Promise(resolve => blocker.listen(47632, '127.0.0.1', resolve));
  try {
    await assert.rejects(connectCorelyModelJobs({ onAuthorize: () => assert.fail('no UI'), fetchImpl: () => assert.fail('no HTTPS') }), isCode('LOOPBACK_UNAVAILABLE'));
  } finally { await new Promise(resolve => blocker.close(resolve)); }
  await portReusable();
});

test('strict four-key token response rejects changed scope/lifetime/type/shape and revokes every captured usable grant', async t => {
  const cases = [
    ['extra field', { ...validToken(), refresh_token: 'forbidden' }], ['wrong scope', { ...validToken(), scope: 'corely:dev-work-candidates' }],
    ['lifetime string', { ...validToken(), expires_in: '900' }], ['expanded lifetime', { ...validToken(), expires_in: 901 }],
    ['shorter unexpected lifetime', { ...validToken(), expires_in: 899 }], ['token type', { ...validToken(), token_type: 'bearer' }],
    ['missing scope', { access_token: TOKEN, token_type: 'Bearer', expires_in: 900 }], ['array', [validToken()]],
    ['duplicate field', `${JSON.stringify(validToken()).slice(0, -1)},"scope":"${SCOPE}"}`],
    ['escaped duplicate key', `${JSON.stringify(validToken()).slice(0, -1)},"scop\\u0065":"${SCOPE}"}`],
    ['escaped key', JSON.stringify(validToken()).replace('access_token', '\\u0061ccess_token')],
    ['malformed after usable token', `{"access_token":"${TOKEN}",`],
    ['wrong content type', () => new Response(JSON.stringify(validToken()), { status: 200, headers: { 'Content-Type': 'text/plain' } })],
    ['non-200', () => Response.json(validToken(), { status: 400 })],
    ['body overflow', () => new Response(`${JSON.stringify(validToken())}${' '.repeat(16384)}`, { headers: { 'Content-Type': 'application/json' } })],
  ];
  for (const [label, value] of cases) await t.test(label, async () => {
    const tokenResponse = typeof value === 'function' ? value : typeof value === 'string' ? new Response(value, { headers: { 'Content-Type': 'application/json' } }) : Response.json(value);
    const transport = fakeFetch({ tokenResponse });
    await assert.rejects(connectCorelyModelJobs({ fetchImpl: transport.fetchImpl, onAuthorize: authorize }), isCode('TOKEN_RESPONSE_INVALID'));
    assert.equal(transport.calls.filter(row => row.url.endsWith('/revoke')).length, 1);
    assert.equal(transport.calls.at(-1).form.get('token'), TOKEN); await portReusable();
  });
});

test('wrong token format, null response, redirects and invalid UTF8 never produce a session', async t => {
  for (const [label, tokenResponse] of [
    ['old token', Response.json({ ...validToken(), access_token: 't'.repeat(43) })], ['null', Response.json(null)],
    ['redirect', new Response(null, { status: 302, headers: { Location: 'https://attacker.invalid' } })],
    ['invalid UTF8', new Response(new Uint8Array([0xff]), { headers: { 'Content-Type': 'application/json' } })],
  ]) await t.test(label, async () => {
    const transport = fakeFetch({ tokenResponse }); await assert.rejects(connectCorelyModelJobs({ fetchImpl: transport.fetchImpl, onAuthorize: authorize }), isCode('TOKEN_RESPONSE_INVALID'));
    assert.equal(transport.calls.length, 1); await portReusable();
  });
});

test('network exceptions and uncooperative hung token fetch or body are bounded unknown exchanges, never a no-grant assertion', async t => {
  for (const [label, config] of [
    ['exception', { tokenThrow: new Error('synthetic-private-network-input') }],
    ['hung fetch', { tokenResponse: () => new Promise(() => {}) }],
    ['hung body', { tokenResponse: () => new Response(new ReadableStream({ start() {} }), { headers: { 'Content-Type': 'application/json' } }) }],
  ]) await t.test(label, async () => {
    const transport = fakeFetch(config), started = performance.now();
    await assert.rejects(connectCorelyModelJobs({ fetchImpl: transport.fetchImpl, onAuthorize: authorize, requestTimeoutMs: 100 }), isCode('TOKEN_EXCHANGE_UNCERTAIN'));
    assert.ok(performance.now() - started < 2000); assert.equal(transport.calls.length, 1); await portReusable();
  });
});

test('a captured grant in a partial hung token body is revoked before the uncertain exchange is reported', async () => {
  let canceled = false;
  const transport = fakeFetch({ tokenResponse: () => new Response(new ReadableStream({
    start(controller) { controller.enqueue(new TextEncoder().encode(`{"access_token":"${TOKEN}",`)); }, cancel() { canceled = true; },
  }), { headers: { 'Content-Type': 'application/json' } }) });
  await assert.rejects(connectCorelyModelJobs({ fetchImpl: transport.fetchImpl, onAuthorize: authorize, requestTimeoutMs: 100 }), isCode('TOKEN_EXCHANGE_UNCERTAIN'));
  assert.equal(transport.calls.length, 2); assert.equal(canceled, true); await portReusable();
});

test('cleanup fanout is capped at server capacity and excess usable tokens remain explicitly unconfirmed', async () => {
  const tokens = Array.from({ length: 33 }, (_value, index) => `models_access_${String(index).padStart(43, 'a')}`);
  const transport = fakeFetch({ tokenResponse: Response.json({ ...validToken(), access_token: tokens[0], extra: tokens }) });
  await assert.rejects(connectCorelyModelJobs({ fetchImpl: transport.fetchImpl, onAuthorize: authorize }), isCode('REVOKE_UNCONFIRMED'));
  assert.equal(transport.calls.filter(row => row.url.endsWith('/revoke')).length, 32); await portReusable();
});

test('malformed-response grant revocation failure overrides protocol failure without leaking secret values', async () => {
  const transport = fakeFetch({ tokenResponse: Response.json({ ...validToken(), scope: 'wrong' }), revokeThrow: new Error(`synthetic-private-${TOKEN}`) });
  await assert.rejects(connectCorelyModelJobs({ fetchImpl: transport.fetchImpl, onAuthorize: authorize }), isCode('REVOKE_UNCONFIRMED'));
  await portReusable();
});

test('revocation is serialized, retryable after failure and never falsely marks a closed grant usable', async () => {
  let revokeCount = 0;
  const transport = fakeFetch({ revokeResponse: async () => { revokeCount++; if (revokeCount === 1) throw new Error('synthetic-private'); await sleep(10); return new Response(null, { status: 200 }); } });
  const session = await connectCorelyModelJobs({ fetchImpl: transport.fetchImpl, onAuthorize: authorize });
  await assert.rejects(session.revoke(), isCode('REVOKE_UNCONFIRMED'));
  assert.throws(() => session.receipt(), isCode('REVOKE_UNCONFIRMED'));
  const results = await Promise.all([session.revoke(), session.revoke(), session.revoke()]); assert.equal(results.length, 3);
  assert.equal(revokeCount, 2); assert.throws(() => session.receipt(), isCode('GRANT_CLOSED'));
  await portReusable();
});

test('revocation response status, body, redirect and hangs remain unconfirmed, including a hung body', async t => {
  for (const [label, revokeResponse] of [
    ['status', () => new Response(null, { status: 500 })], ['redirect', () => new Response(null, { status: 302 })],
    ['unexpected body', () => Response.json({ ok: true })], ['hung fetch', () => new Promise(() => {})],
    ['hung body', () => new Response(new ReadableStream({ start() {} }), { status: 200 })],
  ]) await t.test(label, async () => {
    const transport = fakeFetch({ revokeResponse });
    const session = await connectCorelyModelJobs({ fetchImpl: transport.fetchImpl, onAuthorize: authorize, requestTimeoutMs: 100 });
    const started = performance.now(); await assert.rejects(session.revoke(), isCode('REVOKE_UNCONFIRMED'));
    assert.ok(performance.now() - started < 2000); assert.throws(() => session.receipt(), isCode('REVOKE_UNCONFIRMED')); await portReusable();
  });
});

test('abort after connection immediately holds grant and performs only its own bounded revocation', async () => {
  const controller = new AbortController(), transport = fakeFetch();
  const session = await connectCorelyModelJobs({ signal: controller.signal, fetchImpl: transport.fetchImpl, onAuthorize: authorize });
  controller.abort(); assert.throws(() => session.receipt(), isCode('GRANT_CLOSED'));
  await session.revoke(); assert.equal(transport.calls.length, 2); await portReusable();
});

test('abort during token exchange is unknown and cannot leave an authorization listener running', async () => {
  const controller = new AbortController(); let seenSignal;
  const transport = fakeFetch({ tokenResponse: options => { seenSignal = options.signal; controller.abort(); return new Promise(() => {}); } });
  await assert.rejects(connectCorelyModelJobs({ signal: controller.signal, fetchImpl: transport.fetchImpl, onAuthorize: authorize }), isCode('TOKEN_EXCHANGE_UNCERTAIN'));
  assert.equal(seenSignal.aborted, true); await portReusable();
});

test('expiry, bad clock values, clock exceptions and rollback never produce a connected receipt', async t => {
  await t.test('expiry', async () => {
    let clock = 1_000; const transport = fakeFetch(), session = await connectCorelyModelJobs({ now: () => clock, fetchImpl: transport.fetchImpl, onAuthorize: authorize });
    clock += 900_000; assert.throws(() => session.receipt(), isCode('GRANT_EXPIRED')); await session.revoke();
  });
  for (const [label, invalid] of [['NaN', NaN], ['Infinity', Infinity], ['unsafe', Number.MAX_SAFE_INTEGER + 1], ['negative', -1], ['string', '1000'], ['rollback', 999], ['throws', undefined]]) {
    await t.test(label, async () => {
      let clock = 1_000, broken = false; const transport = fakeFetch();
      const session = await connectCorelyModelJobs({ now: () => { if (broken && invalid === undefined) throw new Error('synthetic-private-clock'); return broken ? invalid : clock; }, fetchImpl: transport.fetchImpl, onAuthorize: authorize });
      broken = true; assert.throws(() => session.receipt(), isCode('INVALID_OPTIONS')); await session.revoke();
    });
  }
  await portReusable();
});

test('unsafe constructor options and arbitrary credential/provider inputs fail before UI, listener or network', async () => {
  for (const options of [null, [], { onAuthorize: null }, { onAuthorize() {}, endpoint: 'https://attacker.invalid' },
    { onAuthorize() {}, access_token: TOKEN }, { onAuthorize() {}, scope: 'other' }, { onAuthorize() {}, timeoutMs: Infinity },
    { onAuthorize() {}, timeoutMs: 9 }, { onAuthorize() {}, requestTimeoutMs: 30001 }, { onAuthorize() {}, signal: {} },
    { onAuthorize() {}, now: () => NaN }, { onAuthorize() {}, now: () => { throw new Error('synthetic-private-clock'); } }]) {
    await assert.rejects(connectCorelyModelJobs(options), isCode('INVALID_OPTIONS'));
  }
  assert.equal(new ModelJobClientError('private value').code, 'INVALID_OPTIONS'); await portReusable();
});
