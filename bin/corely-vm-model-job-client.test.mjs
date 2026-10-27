import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync, verify } from 'node:crypto';
import { after, before, test } from 'node:test';
import { connectCorelyVmModelJobs, VmModelJobClientError, CORELY_VM_MODEL_JOB_RESOURCE as RESOURCE,
  CORELY_VM_MODEL_JOB_ISSUER as ISSUER, CORELY_VM_MODEL_JOB_SCOPE as SCOPE,
  CORELY_VM_MODEL_JOB_CLIENT_ID as CLIENT, CORELY_VM_HOST_ID_HASH as HOST,
  CORELY_VM_VERIFICATION_URI as VERIFICATION } from './corely-vm-model-job-client.mjs';

const TOKEN = `vm_models_access_${'t'.repeat(43)}`, DEVICE = `vm_models_device_${'d'.repeat(43)}`;
const REQUEST = `vm_models_${'r'.repeat(43)}`;
const realFetch = globalThis.fetch;
before(() => { globalThis.fetch = () => { throw new Error('ALL_EXTERNAL_NETWORK_DISABLED'); }; });
after(() => { globalThis.fetch = realFetch; });
const isCode = code => error => error instanceof VmModelJobClientError && error.code === code && error.message === code && !error.cause;
const canonical = value => value && typeof value === 'object' ? Array.isArray(value) ? value.map(canonical)
  : Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
const hash = value => createHash('sha256').update(value).digest('base64url');

function fixture(change = {}) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' });
  const thumbprint = hash(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: jwk.x }));
  let clock = 1_800_000_000_000, consented = false, completeCount = 0;
  const grantExpiry = clock + 86_400_000, calls = [], waits = [], proofs = new Set();
  const content = { version: 1, callId: 'synthetic-vm-model-call', workload: 'REPLY_LLM', purpose: 'reply_generation', model: 'gpt-6.1-sol',
    scope: { tenantId: 'moztech', brandId: 'moztech-test', synthetic: true, jobId: 'server-synthetic-job' },
    system: 'Synthetic facts only.', user: 'Synthetic current question.', schemaSha256: null };
  const request = { ...content, inputSha256: createHash('sha256').update(JSON.stringify(canonical(content))).digest('hex') };
  const lease = { leaseId: '63388770-cd07-4b5b-a53b-f73ee875a548', accountAlias: 'info', expiresAt: clock + 50_000, request };
  const result = { status: 'success', completionStatus: 'completed', accountAlias: 'info', authMode: 'siwc_plan', accountVerified: true,
    model: request.model, callId: request.callId, inputSha256: request.inputSha256, schemaSha256: null,
    text: 'Synthetic generated answer.', usage: { inputTokens: 10, outputTokens: 4, cachedInputTokens: 1 } };
  const status = () => ({ status: 'SYNTHETIC_VM_MODEL_TRANSPORT', scope: SCOPE, tenantId: 'moztech', brandId: 'moztech-test',
    authMode: 'siwc_plan', syntheticOnly: true, enrolled: true, producerConnected: false, apiFallbackEnabled: false,
    sendingCapability: false, learningCapability: false, vmHostIdHash: HOST, keyThumbprint: thumbprint, expiresAt: grantExpiry });
  const assertProof = (raw, url, method, accessToken) => {
    assert.equal(typeof raw, 'string'); const [h, p, s] = raw.split('.');
    const header = JSON.parse(Buffer.from(h, 'base64url')), payload = JSON.parse(Buffer.from(p, 'base64url'));
    assert.deepEqual(header, { typ: 'dpop+jwt', alg: 'EdDSA', jwk });
    assert.equal(verify(null, Buffer.from(`${h}.${p}`), createPublicKey({ key: header.jwk, format: 'jwk' }), Buffer.from(s, 'base64url')), true);
    assert.deepEqual(Object.keys(payload).sort(), ['htm', 'htu', 'iat', 'jti', ...(accessToken ? ['ath'] : [])].sort());
    assert.equal(payload.htu, url); assert.equal(payload.htm, method); assert.ok(Math.abs(payload.iat - clock / 1000) <= 30);
    assert.match(payload.jti, /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);
    assert.equal(proofs.has(payload.jti), false); proofs.add(payload.jti);
    if (accessToken) assert.equal(payload.ath, hash(accessToken));
  };
  const options = { privateKey, expectedKeyThumbprint: thumbprint, now: () => clock,
    sleep: async ms => { waits.push(ms); clock += ms; },
    onAuthorize: async value => {
      assert.deepEqual(Object.keys(value).sort(), ['verificationUri', 'verificationUriComplete', 'userCode', 'expiresIn', 'interval', 'scope', 'vmHostIdHash', 'keyThumbprint'].sort());
      assert.equal(value.verificationUriComplete, `${VERIFICATION}?requestId=${REQUEST}`);
      assert.doesNotMatch(JSON.stringify(value), /vm_models_device_|vm_models_access_|PRIVATE KEY/); consented = true;
      await change.onAuthorize?.(value);
    },
    fetchImpl: async (url, init) => {
      calls.push({ url, method: init.method });
      assert.equal(init.redirect, 'error'); assert.equal(init.credentials, 'omit'); assert.equal(init.cache, 'no-store');
      assert.ok(init.signal instanceof AbortSignal); assert.equal(init.headers.Accept, 'application/json');
      if (url === `${ISSUER}/device_authorization`) {
        assert.equal(init.method, 'POST'); assert.equal(init.headers.Authorization, undefined); assertProof(init.headers.DPoP, url, 'POST');
        assert.deepEqual(JSON.parse(init.body), { client_id: CLIENT, scope: SCOPE, resource: RESOURCE, vm_host_id_hash: HOST, jwk });
        const value = { device_code: DEVICE, user_code: 'ABCD-0123', verification_uri: VERIFICATION,
          verification_uri_complete: `${VERIFICATION}?requestId=${REQUEST}`, expires_in: 300, interval: 5 };
        return change.device?.(value) ?? Response.json(value);
      }
      if (url === `${ISSUER}/token`) {
        assert.equal(consented, true); assert.equal(init.method, 'POST'); assert.equal(init.headers.Authorization, undefined);
        assertProof(init.headers.DPoP, url, 'POST');
        assert.deepEqual(JSON.parse(init.body), { grant_type: 'urn:ietf:params:oauth:grant-type:device_code', client_id: CLIENT, resource: RESOURCE, device_code: DEVICE });
        const value = { access_token: TOKEN, token_type: 'DPoP', expires_in: Math.floor((grantExpiry - clock) / 1000), scope: SCOPE };
        return change.token?.(value, init) ?? Response.json(value);
      }
      assert.ok(['status', 'enroll', 'claim', 'complete'].some(operation => url === `${RESOURCE}/${operation}`), 'no arbitrary URL, customer, provider, API, or producer call');
      const op = url.slice(RESOURCE.length + 1);
      assert.equal(init.headers.Authorization, `DPoP ${TOKEN}`); assertProof(init.headers.DPoP, url, init.method, TOKEN);
      if (change.resource) return change.resource(op, init, status());
      if (op === 'status') { assert.equal(init.method, 'GET'); assert.equal(init.body, undefined); return Response.json(status()); }
      assert.equal(init.method, 'POST'); const body = JSON.parse(init.body);
      if (op === 'enroll') {
        assert.deepEqual(body, {}); return Response.json({ enrolled: true, authMode: 'siwc_plan', expiresAt: grantExpiry,
          syntheticOnly: true, apiFallbackEnabled: false, sendingCapability: false, learningCapability: false,
          vmHostIdHash: HOST, keyThumbprint: thumbprint });
      }
      if (op === 'claim') { assert.deepEqual(body, { accountAlias: 'info' }); return Response.json({ lease, authMode: 'siwc_plan' }); }
      assert.equal(op, 'complete'); assert.equal(body.leaseId, lease.leaseId); assert.equal(body.result.text, result.text); completeCount++;
      return Response.json({ accepted: true, replayed: false, callId: request.callId,
        resultSha256: createHash('sha256').update(JSON.stringify(body.result)).digest('hex') });
    } };
  return { options, calls, waits, lease, result, thumbprint, publicKey, status, assertProof,
    advance: ms => { clock += ms; }, completed: () => completeCount };
}

test('offline device + sender-constrained grant completes only one bound synthetic lease without exposing credentials', async () => {
  const f = fixture(), client = await connectCorelyVmModelJobs(f.options);
  assert.deepEqual(Object.keys(client).sort(), ['receipt', 'modelStatus', 'enrollModels', 'claimModel', 'completeModel', 'close'].sort());
  const receipt = client.receipt(); assert.equal(receipt.apiFallbackEnabled, false); assert.equal(receipt.keyThumbprint, f.thumbprint);
  assert.doesNotMatch(JSON.stringify(receipt), /vm_models_access_|vm_models_device_|Synthetic generated|PRIVATE KEY/);
  assert.equal((await client.modelStatus()).producerConnected, false); assert.equal((await client.enrollModels()).enrolled, true);
  const lease = await client.claimModel('info'); assert.equal(lease.request.inputSha256, f.lease.request.inputSha256);
  assert.equal((await client.completeModel(lease.leaseId, f.result)).accepted, true);
  await assert.rejects(client.completeModel(lease.leaseId, f.result), isCode('MODEL_JOB_NOT_CURRENT')); assert.equal(f.completed(), 1);
  assert.deepEqual(f.waits, [5000]); assert.equal(f.calls.filter(call => call.url.endsWith('/token')).length, 1);
  assert.equal(client.close().remoteRevocation, 'NOT_PERFORMED'); await assert.rejects(client.modelStatus(), isCode('GRANT_CLOSED'));
});

test('authorization_pending and slow_down are the only pollable token outcomes and produce fresh DPoP proofs', async () => {
  let polls = 0;
  const f = fixture({ token: value => ++polls < 3
    ? Response.json({ error: polls === 1 ? 'authorization_pending' : 'slow_down' }, { status: 400 }) : Response.json(value) });
  const client = await connectCorelyVmModelJobs(f.options); assert.deepEqual(f.waits, [5000, 5000, 10000]);
  assert.equal(polls, 3); client.close();
});

test('fixed issuer, URL, scope and pre-verified Ed25519 key cannot be changed by callers', async t => {
  for (const field of ['issuer', 'resource', 'scope', 'url', 'apiKey', 'token', 'vmHostIdHash']) {
    await t.test(field, async () => { const f = fixture(); await assert.rejects(connectCorelyVmModelJobs({ ...f.options, [field]: 'untrusted' }), isCode('INVALID_OPTIONS')); assert.equal(f.calls.length, 0); });
  }
  for (const change of [{ expectedKeyThumbprint: 'x'.repeat(43) }, { privateKey: generateKeyPairSync('ed25519').publicKey },
    { privateKey: generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey }]) {
    const f = fixture(); await assert.rejects(connectCorelyVmModelJobs({ ...f.options, ...change }), isCode('INVALID_KEY')); assert.equal(f.calls.length, 0);
  }
});

test('device response must bind the fixed verification URL and exact five-minute transaction', async t => {
  for (const change of [{ verification_uri: 'https://attacker.invalid/' }, { verification_uri_complete: `${VERIFICATION}?requestId=${REQUEST}&next=https://attacker.invalid` },
    { device_code: 'wrong' }, { expires_in: 301 }, { interval: 1 }, { scope: SCOPE }]) {
    await t.test(JSON.stringify(Object.keys(change)), async () => {
      const f = fixture({ device: value => Response.json({ ...value, ...change }) });
      await assert.rejects(connectCorelyVmModelJobs(f.options), isCode('DEVICE_RESPONSE_INVALID')); assert.equal(f.calls.length, 1);
    });
  }
});

test('token response cannot add refresh/API credentials, extend 24 hours, change scope, or downgrade DPoP', async t => {
  for (const change of [{ token_type: 'Bearer' }, { scope: 'corely:dev-model-jobs' }, { expires_in: 86401 }, { expires_in: 0 },
    { refresh_token: 'not-accepted' }, { access_token: 'models_access_old-profile' }]) {
    await t.test(JSON.stringify(Object.keys(change)), async () => {
      const f = fixture({ token: value => Response.json({ ...value, ...change }) });
      await assert.rejects(connectCorelyVmModelJobs(f.options), isCode('TOKEN_RESPONSE_INVALID'));
      assert.equal(f.calls.filter(call => call.url.endsWith('/token')).length, 1);
    });
  }
  const duplicate = fixture({ token: value => new Response(JSON.stringify(value).replace('"token_type":"DPoP"', '"token_type":"Bearer","token_type":"DPoP"'), { headers: { 'content-type': 'application/json' } }) });
  await assert.rejects(connectCorelyVmModelJobs(duplicate.options), isCode('TOKEN_RESPONSE_INVALID'));
});

test('wrong response issuer URL, signature refusal, denied and expired device outcomes do not retry exchanges', async t => {
  for (const response of [() => { const res = Response.json({}); Object.defineProperty(res, 'url', { value: 'https://wrong-issuer.invalid/token' }); return res; },
    () => Response.json({ error: 'invalid_dpop_proof' }, { status: 400 }),
    () => Response.json({ error: 'access_denied' }, { status: 400 }), () => Response.json({ error: 'expired_token' }, { status: 400 })]) {
    await t.test(String(response), async () => {
      const f = fixture({ token: response }); await assert.rejects(connectCorelyVmModelJobs(f.options), error =>
        ['TOKEN_RESPONSE_INVALID', 'AUTHORIZATION_DENIED', 'AUTHORIZATION_TIMEOUT'].includes(error.code));
      assert.equal(f.calls.filter(call => call.url.endsWith('/token')).length, 1);
    });
  }
});

test('uncertain token exchange never polls again even if transport ignores cancellation', async () => {
  const f = fixture({ token: () => new Promise(() => {}) });
  await assert.rejects(connectCorelyVmModelJobs({ ...f.options, requestTimeoutMs: 10 }), isCode('TOKEN_EXCHANGE_UNCERTAIN'));
  assert.equal(f.calls.filter(call => call.url.endsWith('/token')).length, 1);
});

test('expired authorization, expired grant, cancellation and dishonest polling clocks fail closed', async () => {
  const f = fixture({ onAuthorize: () => f.advance(300_001) });
  await assert.rejects(connectCorelyVmModelJobs(f.options), isCode('AUTHORIZATION_TIMEOUT')); assert.equal(f.calls.length, 1);
  const dishonest = fixture(); await assert.rejects(connectCorelyVmModelJobs({ ...dishonest.options, sleep: async () => {} }), isCode('INVALID_OPTIONS'));
  assert.equal(dishonest.calls.length, 1);
  const expired = fixture(), client = await connectCorelyVmModelJobs(expired.options); expired.advance(86_400_000);
  await assert.rejects(client.modelStatus(), isCode('GRANT_EXPIRED')); assert.equal(expired.calls.length, 2);
  const controller = new AbortController(), cancelled = fixture({ onAuthorize: () => controller.abort() });
  await assert.rejects(connectCorelyVmModelJobs({ ...cancelled.options, signal: controller.signal }), isCode('ABORTED')); assert.equal(cancelled.calls.length, 1);
});

test('resource status must retain fixed host/key, synthetic boundary, API-off and no producer assertion', async t => {
  for (const change of [{ vmHostIdHash: '0'.repeat(64) }, { keyThumbprint: 'x'.repeat(43) }, { producerConnected: true },
    { apiFallbackEnabled: true }, { syntheticOnly: false }, { learningCapability: true }, { sendingCapability: true }, { scope: 'other' }]) {
    await t.test(JSON.stringify(Object.keys(change)), async () => {
      const f = fixture({ resource: (_op, _init, status) => Response.json({ ...status, ...change }) }), client = await connectCorelyVmModelJobs(f.options);
      try { await assert.rejects(client.modelStatus(), isCode('RESOURCE_RESPONSE_INVALID')); } finally { client.close(); }
    });
  }
});

test('bounded response bodies and uncertain resource operations cannot be retried into duplicate work', async () => {
  const oversized = fixture({ device: () => new Response('x'.repeat(16_385), { headers: { 'content-type': 'application/json' } }) });
  await assert.rejects(connectCorelyVmModelJobs(oversized.options), isCode('DEVICE_RESPONSE_INVALID'));
  const f = fixture({ resource: () => new Promise(() => {}) }), client = await connectCorelyVmModelJobs({ ...f.options, requestTimeoutMs: 10 });
  await assert.rejects(client.modelStatus(), isCode('RESOURCE_REQUEST_UNCERTAIN'));
  await assert.rejects(client.claimModel('info'), isCode('RESOURCE_REQUEST_UNCERTAIN'));
  assert.equal(f.calls.filter(call => call.url.startsWith(RESOURCE) && !call.url.startsWith(ISSUER)).length, 1); client.close();
});
