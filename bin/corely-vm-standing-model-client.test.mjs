import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync, randomUUID, verify } from 'node:crypto';
import { test } from 'node:test';
import { CORELY_VM_HOST_ID_HASH, CORELY_VM_MODEL_JOB_RESOURCE, CORELY_VM_MODEL_JOB_SCOPE,
  CORELY_VM_VERIFICATION_URI } from './corely-vm-model-job-client.mjs';
import { CORELY_VM_STANDING_MODEL_ISSUER as ISSUER, CORELY_VM_STANDING_MODEL_SCOPE as SCOPE,
  openCorelyVmStandingModelAuthority as open } from './corely-vm-standing-model-client.mjs';

const START = 1_800_000_000_000, INITIAL_PARENT_EXPIRY = START + 86_400_000 * 30;
const id = (prefix, digit) => `${prefix}_${digit.repeat(42)}A`;
const hash = (value, encoding = 'base64url') => createHash('sha256').update(value).digest(encoding);
const isError = code => error => error.code === code && error.message === code;
const canon = value => Array.isArray(value) ? value.map(canon) : value && typeof value === 'object'
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canon(value[key])])) : value;
const json = (value, status = 200, more = {}) => new Response(typeof value === 'string' ? value : JSON.stringify(value), {
  status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...more },
});

function fixture(options = {}) {
  const pair = generateKeyPairSync('ed25519'), jwk = pair.publicKey.export({ format: 'jwk' });
  const thumb = hash(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x }));
  const state = { now: START, mono: 0, generation: 1, parentGeneration: 1, parentId: id('vm_models_standing_model_parent', 'P'),
    parentExpiresAt: INITIAL_PARENT_EXPIRY, child: null, childExpiresAt: null, enrolled: false, phase1Token: false, prepared: false,
    terminal: false, previousDenialStrong: true, intercept: null };
  const events = [], unique = new Set();
  const request = canon({ version: 1, callId: 'synthetic-standing-call', model: 'gpt-6.1-sol', workload: 'REPLY_LLM', purpose: 'semantic_reply_review',
    scope: { tenantId: 'moztech', brandId: 'moztech-test', synthetic: true, jobId: 'synthetic-job' }, system: 'Synthetic rules', user: 'Synthetic question', schemaSha256: null });
  request.inputSha256 = hash(JSON.stringify(request), 'hex');
  const result = { accountAlias: 'eason', authMode: 'siwc_plan', accountVerified: true, model: request.model, callId: request.callId,
    inputSha256: request.inputSha256, schemaSha256: request.schemaSha256, status: 'success', completionStatus: 'completed', text: 'Synthetic review',
    usage: { inputTokens: 3, outputTokens: 1, cachedInputTokens: 0 } };
  const baseModel = () => ({ authMode: 'siwc_plan', syntheticOnly: true, apiFallbackEnabled: false, sendingCapability: false,
    learningCapability: false, vmHostIdHash: CORELY_VM_HOST_ID_HASH, keyThumbprint: thumb, expiresAt: state.parentExpiresAt });
  const payload = () => ({ status: 'CORELY_VM_STANDING_MODEL_AUTHORITY_ACTIVE', generation: state.generation, parentId: state.parentId,
    parentGeneration: state.parentGeneration, standingExpiresAt: state.parentExpiresAt, childExpiresAt: state.childExpiresAt,
    maxChildSeconds: 120, keyThumbprint: thumb, vmHostIdHash: CORELY_VM_HOST_ID_HASH, scope: SCOPE,
    syntheticOnly: true, apiFallbackEnabled: false, noPaidCredits: true });
  const phase = url => (url.startsWith(`${ISSUER}/`) ? 'authority:' : 'model:') + url.split('/').at(-1);
  const fetchImpl = async (url, init) => {
    assert.ok(url.startsWith(`${ISSUER}/`) || new Set(['status', 'enroll', 'claim', 'complete', 'fail']).has(url.split('/').at(-1)) &&
      url === `${CORELY_VM_MODEL_JOB_RESOURCE}/${url.split('/').at(-1)}`);
    assert.equal(init.redirect, 'error'); assert.equal(init.credentials, 'omit'); assert.equal(init.cache, 'no-store');
    const body = init.body === undefined ? undefined : JSON.parse(init.body);
    const token = init.headers.Authorization?.slice(5), [a, b, c] = init.headers.DPoP.split('.');
    const header = JSON.parse(Buffer.from(a, 'base64url')), claims = JSON.parse(Buffer.from(b, 'base64url'));
    assert.equal(header.typ, 'dpop+jwt'); assert.equal(header.alg, 'EdDSA'); assert.deepEqual(header.jwk, { kty: jwk.kty, crv: jwk.crv, x: jwk.x });
    assert.equal(verify(null, Buffer.from(`${a}.${b}`), createPublicKey({ key: header.jwk, format: 'jwk' }), Buffer.from(c, 'base64url')), true);
    assert.equal(claims.scope, SCOPE); assert.equal(claims.htu, url); assert.equal(claims.htm, init.method); assert.equal(claims.iat, Math.floor(state.now / 1000));
    assert.ok(!unique.has(claims.jti)); unique.add(claims.jti);
    if (token) assert.equal(claims.ath, hash(token)); else assert.equal(Object.hasOwn(claims, 'ath'), false);
    if (phase(url) === 'authority:renew') assert.equal(claims.generation, body.generation);
    else assert.equal(Object.hasOwn(claims, 'generation'), false);
    events.push(phase(url));
    const override = state.intercept?.(phase(url), { body, token, payload: payload() }); if (override) return override;
    if (phase(url) === 'authority:prepare') {
      const requestId = id('vm_standing_model', 'R'); state.prepared = true;
      assert.deepEqual(body, {});
      return json({ status: 'CORELY_VM_STANDING_MODEL_CONSENT_REQUIRED', requestId,
        verification_uri_complete: `${CORELY_VM_VERIFICATION_URI}?requestId=${requestId}`, requestExpiresAt: START + 300_000, standingExpiresAt: state.parentExpiresAt });
    }
    if (phase(url) === 'authority:status') return state.terminal ? json({ error: 'execution_terminal' }, 409) : json(payload());
    if (phase(url) === 'authority:renew') {
      assert.equal(body.generation, state.generation); state.generation++;
      state.child = id(state.phase1Token ? 'vm_models_standing_access' : 'vm_models_standing_model_access', String(state.generation));
      state.childExpiresAt = Math.min(state.now + 120_000, state.parentExpiresAt);
      return json({ access_token: state.child, token_type: 'DPoP', expires_in: Math.floor((state.childExpiresAt - state.now) / 1000), scope: SCOPE });
    }
    if (phase(url) === 'authority:child-status') return token === state.child ? json({ status: 'CORELY_VM_STANDING_MODEL_CHILD_VALID',
      expiresAt: state.childExpiresAt, syntheticOnly: true, apiFallbackEnabled: false }) : json({ error: 'invalid_token' }, 401,
      state.previousDenialStrong ? { 'www-authenticate': 'DPoP error="invalid_token"' } : {});
    assert.equal(token, state.child);
    if (phase(url) === 'model:status') return json({ ...baseModel(), status: 'SYNTHETIC_VM_MODEL_TRANSPORT_V2', contractVersion: 2,
      scope: CORELY_VM_MODEL_JOB_SCOPE, tenantId: 'moztech', brandId: 'moztech-test', authorityProfile: 'standing-model',
      enrolled: state.enrolled, producerConnected: state.enrolled });
    if (phase(url) === 'model:enroll') { assert.deepEqual(body, {}); state.enrolled = true; return json({ ...baseModel(), enrolled: true }); }
    if (phase(url) === 'model:claim') return json({ authMode: 'siwc_plan', lease: { leaseId: randomUUID(), accountAlias: body.accountAlias,
      expiresAt: state.now + 20_000, request } });
    if (phase(url) === 'model:complete') return json({ accepted: true, replayed: false, callId: request.callId, resultSha256: hash(JSON.stringify(body.result), 'hex') });
    if (phase(url) === 'model:fail') return json({ held: true, reason: 'EXECUTION_UNAVAILABLE' });
    assert.fail('unexpected route');
  };
  const clientOptions = { enabled: true, privateKey: pair.privateKey, expectedKeyThumbprint: thumb, fetchImpl,
    now: () => state.now, monotonicNow: () => state.mono, ...options };
  const tick = ms => { state.now += ms; state.mono += ms; };
  return { client: open(clientOptions), state, events, request, result, clientOptions, tick, payload };
}

test('explicit standing model opt-in and separate dispatch opt-in never alter old clients', async () => {
  const f = fixture();
  assert.throws(() => open({ ...f.clientOptions, enabled: false }), isError('STANDING_MODEL_DISABLED'));
  assert.throws(() => open({ ...f.clientOptions, expectedKeyThumbprint: 'wrong' }), isError('STANDING_MODEL_KEY_INVALID'));
  assert.deepEqual(f.events, []);
  assert.equal((await f.client.prepare()).status, 'CORELY_VM_STANDING_MODEL_CONSENT_REQUIRED');
  const receipt = await f.client.renew();
  assert.equal(receipt.generation, 2); assert.equal(receipt.parentGeneration, 1);
  assert.equal(receipt.childExpiresAt, START + 120_000);
  assert.equal(receipt.standingExpiresAt, INITIAL_PARENT_EXPIRY);
  assert.equal(Object.hasOwn(receipt, 'access_token'), false);
  assert.equal((await f.client.modelStatus()).authorityProfile, 'standing-model');
  const count = f.events.length;
  for (const call of [() => f.client.enrollModels(), () => f.client.claimModel('info'), () => f.client.completeModel('x', {}), () => f.client.failModel('x')]) {
    await assert.rejects(call(), isError('STANDING_MODEL_DISPATCH_DISABLED'));
  }
  assert.equal(f.events.length, count);
});

test('successor verification preserves parent identity and requires fresh unexpired predecessor denial', async () => {
  const f = fixture(), first = await f.client.renew();
  f.tick(20_000);
  const next = await f.client.renew();
  assert.equal(next.generation, 3);
  assert.equal(next.parentId, first.parentId);
  assert.equal(next.parentGeneration, first.parentGeneration);
  assert.equal(next.standingExpiresAt, first.standingExpiresAt);
  assert.equal(next.predecessorDenialVerified, true);
  assert.deepEqual(f.events.slice(-5), ['authority:status', 'authority:renew', 'authority:status', 'authority:child-status', 'authority:child-status']);
  assert.equal((await f.client.childStatus()).expiresAt, next.childExpiresAt);
  const bad = fixture(); await bad.client.renew(); bad.state.previousDenialStrong = false;
  await assert.rejects(bad.client.renew(), isError('STANDING_MODEL_RECOVERY_REQUIRED'));
  await assert.rejects(bad.client.renew(), isError('STANDING_MODEL_CLOSED'));
  assert.equal(bad.events.filter(x => x === 'authority:renew').length, 2);
});

test('phase-1 prefix, changed parent and duplicated JSON fail closed before any model route', async () => {
  const f = fixture(); f.state.phase1Token = true;
  await assert.rejects(f.client.renew(), isError('STANDING_MODEL_RECOVERY_REQUIRED'));
  assert.deepEqual(f.events, ['authority:status', 'authority:renew']);
  const parent = fixture(); await parent.client.renew(); parent.state.parentId = id('vm_models_standing_model_parent', 'X');
  await assert.rejects(parent.client.renew(), isError('STANDING_MODEL_HELD'));
  assert.equal(parent.events.filter(x => x === 'authority:renew').length, 1);
  const duplicate = fixture();
  duplicate.state.intercept = (_phase, { payload }) => json(`{"gen\\u0065ration":1,${JSON.stringify(payload).slice(1)}`);
  await assert.rejects(duplicate.client.status(), isError('STANDING_MODEL_HELD'));
  const terminal = fixture(); terminal.state.terminal = true;
  await assert.rejects(terminal.client.status(), isError('STANDING_MODEL_EXECUTION_TERMINAL'));
  await assert.rejects(terminal.client.prepare(), isError('STANDING_MODEL_CLOSED'));
});

test('opted-in model lease binds same child, parent expiry, synthetic request and result hash', async () => {
  const f = fixture({ enableModelDispatch: true }); await f.client.renew();
  const enrollment = await f.client.enrollModels();
  assert.equal(enrollment.expiresAt, INITIAL_PARENT_EXPIRY);
  const lease = await f.client.claimModel('eason');
  assert.equal(lease.accountAlias, 'eason');
  assert.equal(lease.request.purpose, 'semantic_reply_review');
  await assert.rejects(f.client.renew(), isError('STANDING_MODEL_BUSY'));
  const receipt = await f.client.completeModel(lease.leaseId, f.result);
  assert.equal(receipt.callId, lease.request.callId);
  assert.equal(receipt.resultSha256, hash(JSON.stringify(canon(f.result)), 'hex'));
  await assert.rejects(f.client.completeModel(lease.leaseId, f.result), isError('STANDING_MODEL_LEASE_NOT_CURRENT'));
  const renewed = await f.client.renew(); assert.equal(renewed.predecessorDenialVerified, true);
  assert.equal((await f.client.modelStatus()).enrolled, true);
  const rejected = await f.client.claimModel('info');
  assert.deepEqual(await f.client.failModel(rejected.leaseId), { held: true, reason: 'EXECUTION_UNAVAILABLE' });
  await assert.rejects(f.client.claimModel('info'), isError('STANDING_MODEL_CLOSED'));
});

test('invalid legacy model profile, child expiry and lost result never retry or advance', async () => {
  const f = fixture(); await f.client.renew();
  f.state.intercept = route => route === 'model:status' ? json({ status: 'SYNTHETIC_VM_MODEL_TRANSPORT_V2', contractVersion: 2 }) : null;
  await assert.rejects(f.client.modelStatus(), isError('STANDING_MODEL_HELD'));
  const expiry = fixture({ enableModelDispatch: true }); await expiry.client.renew(); await expiry.client.enrollModels();
  expiry.tick(120_000); await assert.rejects(expiry.client.claimModel('info'), isError('STANDING_MODEL_HELD'));
  assert.ok(!expiry.events.includes('model:claim'));
  const lost = fixture({ enableModelDispatch: true }); await lost.client.renew(); await lost.client.enrollModels();
  const lease = await lost.client.claimModel('eason');
  lost.state.intercept = route => { if (route === 'model:complete') throw new Error('secret transport detail'); return null; };
  await assert.rejects(lost.client.completeModel(lease.leaseId, lost.result), isError('STANDING_MODEL_HELD'));
  await assert.rejects(lost.client.completeModel(lease.leaseId, lost.result), isError('STANDING_MODEL_CLOSED'));
  assert.equal(lost.events.filter(x => x === 'model:complete').length, 1);
});
