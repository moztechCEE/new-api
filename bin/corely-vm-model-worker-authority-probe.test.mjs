import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, verify } from 'node:crypto';
import { spawn } from 'node:child_process';
import { chmod, mkdtemp, readFile, readdir, realpath, rm, symlink, rename, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { PassThrough, Writable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { connectCorelyVmModelJobs, CORELY_VM_MODEL_JOB_ISSUER as ISSUER, CORELY_VM_MODEL_JOB_SCOPE as SCOPE,
  CORELY_VM_MODEL_JOB_RESOURCE as RESOURCE, CORELY_VM_VERIFICATION_URI as CONSENT, CORELY_VM_HOST_ID_HASH as HOST,
} from './corely-vm-model-job-client.mjs';
import { runCorelyVmAuthorityProbe } from './corely-vm-model-worker-authority-probe.mjs';

// Public deterministic CI material. No real Corely/provider key is provisioned.
const key = createPrivateKey({ key: Buffer.from(`302e020100300506032b657004220420${'01'.repeat(32)}`, 'hex'), format: 'der', type: 'pkcs8' });
const publicKey = createPublicKey(key), jwk = publicKey.export({ format: 'jwk' });
const hash = value => createHash('sha256').update(value).digest('base64url');
const thumbprint = hash(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: jwk.x }));
const TOKEN = `vm_models_access_${'t'.repeat(43)}`;
const fixtureRecord = { kind: 'CORELY_DEV_VM_MODEL_IDENTITY', version: 1, vm: 'new-api-dev-20261022',
  hostIdHash: HOST, keyThumbprint: thumbprint, privateKeyPem: key.export({ format: 'pem', type: 'pkcs8' }).toString() };
const negativeHeaders = { 'content-type': 'application/json', 'cache-control': 'no-store', 'www-authenticate': 'DPoP error="invalid_token"' };
const protocol = event => event.status === 'CLOUD_AUTHORITY_PROBE_READY' ? 'CONNECT' :
  event.status === 'CORELY_AUTHORITY_CONNECTED' ? 'BEFORE' : event.status === 'CORELY_AUTHORITY_STATUS_VERIFIED' ?
    (event.check === 'BEFORE' ? 'AFTER_RESTART' : 'REVOKE') :
    event.status === 'CORELY_REMOTE_REVOCATION_CONFIRMED' ? 'NEGATIVE_AFTER_RESTART' : undefined;

async function fixture(mode = 'success') {
  const stateDir = await realpath(await mkdtemp(join(tmpdir(), 'corely-authority-probe-fixture-')));
  await chmod(stateDir, 0o700);
  await writeFile(join(stateDir, 'corely-vm-model-identity.json'), JSON.stringify(fixtureRecord), { mode: 0o600 });
  const initialBytes = await readFile(join(stateDir, 'corely-vm-model-identity.json'));
  let wall = 1_800_000_000_000, monotonic = 10_000, expiresAt, revoked = false, closed = 0, identityClosed = 0;
  let requests = 0, negativeRequests = 0, cancelled = false;
  const seen = new Set(), proofs = [], abort = new AbortController();
  const now = () => wall, monotonicNow = () => monotonic;
  const advance = ms => { wall += ms; monotonic += ms; };
  const status = () => ({ status: 'CORELY_VM_MODEL_JOB_AUTHORITY_VALID', scope: SCOPE, resource: RESOURCE,
    tenantId: 'moztech', brandId: 'moztech-test', vmHostIdHash: HOST, keyThumbprint: thumbprint, expiresAt,
    syntheticOnly: true, modelTransportEnabled: mode === 'model-on', apiFallbackEnabled: false,
    sendingCapability: false, learningCapability: false });
  const metadata = Object.freeze({ status: 'CORELY_DEV_VM_MODEL_IDENTITY_READY', vm: 'new-api-dev-20261022',
    hostIdHash: HOST, keyThumbprint: thumbprint, syntheticOnly: true, apiFallbackEnabled: false });
  const transport = {
    async fetchImpl(url, init) {
      requests++;
      assert.equal(init.redirect, 'error'); assert.equal(init.cache, 'no-store'); assert.equal(init.credentials, 'omit');
      assert.equal(url.startsWith(`${ISSUER}/`), true);
      const headers = new Headers(init.headers), parts = headers.get('dpop').split('.');
      assert.equal(parts.length, 3);
      const head = JSON.parse(Buffer.from(parts[0], 'base64url')), proof = JSON.parse(Buffer.from(parts[1], 'base64url'));
      assert.deepEqual(head, { typ: 'dpop+jwt', alg: 'EdDSA', jwk: { kty: 'OKP', crv: 'Ed25519', x: jwk.x } });
      assert.equal(verify(null, Buffer.from(`${parts[0]}.${parts[1]}`), publicKey, Buffer.from(parts[2], 'base64url')), true);
      assert.equal(proof.htu, url); assert.equal(proof.htm, init.method); assert.equal(proof.iat, Math.floor(wall / 1000));
      assert.equal(seen.has(proof.jti), false); seen.add(proof.jti); proofs.push(proof);
      if (url.endsWith('/status') || url.endsWith('/revoke')) {
        assert.equal(headers.get('authorization'), `DPoP ${TOKEN}`); assert.equal(proof.ath, hash(TOKEN));
      } else assert.equal(Object.hasOwn(proof, 'ath'), false);
      if (url === `${ISSUER}/device_authorization`) return Response.json({ device_code: `vm_models_device_${'d'.repeat(43)}`,
        user_code: 'ABCD-0123', verification_uri: CONSENT, verification_uri_complete: `${CONSENT}?requestId=vm_models_${'r'.repeat(43)}`,
        expires_in: 300, interval: 5 });
      if (url === `${ISSUER}/token`) {
        expiresAt = wall + 3_600_000;
        return Response.json({ access_token: TOKEN, token_type: 'DPoP', scope: SCOPE, expires_in: 3600 });
      }
      if (url === `${ISSUER}/revoke`) {
        revoked = true;
        if (mode === 'unknown-revoke') return new Response('PRIVATE_REVOKE_MARKER', { status: 200 });
        return new Response(null, { status: 200, headers: { 'content-length': '0' } });
      }
      assert.equal(url, `${ISSUER}/status`); assert.equal(init.method, 'GET');
      if (!revoked) {
        if (mode === 'invalid-before') return Response.json({ ...status(), extra: 'PRIVATE_STATUS_MARKER' });
        return Response.json(status());
      }
      negativeRequests++;
      assert.equal(negativeRequests, 1); assert.equal(init.body, undefined);
      if (mode === 'network-uncertain') { queueMicrotask(() => abort.abort()); return new Promise(() => {}); }
      if (mode === 'unfinished-eof') {
        const body = new ReadableStream({ start(c) { c.enqueue(Buffer.from('{"error":"invalid_token"}')); queueMicrotask(() => abort.abort()); },
          cancel() { cancelled = true; } });
        return new Response(body, { status: 401, headers: negativeHeaders });
      }
      if (mode === 'duplicate') return new Response('{"error":"invalid_token","error":"invalid_token"}', { status: 401, headers: negativeHeaders });
      if (mode === 'escaped') return new Response('{"err\\u006fr":"invalid_token"}', { status: 401, headers: negativeHeaders });
      if (mode === 'extra') return Response.json({ error: 'invalid_token', detail: 'PRIVATE_BODY_MARKER' }, { status: 401, headers: negativeHeaders });
      if (mode === 'invalid-dpop') return Response.json({ error: 'invalid_dpop_proof' }, { status: 401, headers: negativeHeaders });
      if (mode === 'expired-error') return Response.json({ error: 'expired_token' }, { status: 401, headers: negativeHeaders });
      if (mode === 'wrong-challenge') return Response.json({ error: 'invalid_token' }, { status: 401, headers: { ...negativeHeaders, 'www-authenticate': 'Bearer' } });
      if (mode === 'cacheable') return Response.json({ error: 'invalid_token' }, { status: 401, headers: { ...negativeHeaders, 'cache-control': 'private' } });
      if (mode === 'length-mismatch') return Response.json({ error: 'invalid_token' }, { status: 401, headers: { ...negativeHeaders, 'content-length': '1' } });
      if (mode === 'oversized') return new Response(' '.repeat(4096) + '{"error":"invalid_token"}', { status: 401, headers: negativeHeaders });
      if (mode === 'redirected') { const response = Response.json({ error: 'invalid_token' }, { status: 401, headers: negativeHeaders });
        Object.defineProperty(response, 'redirected', { value: true }); return response; }
      if (mode === 'wrong-url') { const response = Response.json({ error: 'invalid_token' }, { status: 401, headers: negativeHeaders });
        Object.defineProperty(response, 'url', { value: 'https://example.invalid/status' }); return response; }
      if (mode === 'http-200' || mode === 'http-403') return Response.json({ error: 'invalid_token' }, { status: mode === 'http-200' ? 200 : 403, headers: negativeHeaders });
      return Response.json({ error: 'invalid_token' }, { status: 401, headers: negativeHeaders });
    },
    close() { closed++; },
  };
  return { stateDir, transport, signal: abort.signal, now, monotonicNow, sleep: async ms => advance(ms),
    identityFactory: async () => ({ receipt: () => metadata,
      connect: options => connectCorelyVmModelJobs({ ...options, privateKey: key, expectedKeyThumbprint: thumbprint }),
      close: async () => { identityClosed++; } }),
    async event(event) {
      if (event.status === 'CORELY_AUTHORITY_STATUS_VERIFIED' && event.check === 'BEFORE') advance(1000);
      if (event.status === 'CORELY_REMOTE_REVOCATION_CONFIRMED') {
        advance(1000);
        if (mode === 'window-expired') advance(300_000);
        if (mode === 'grant-expired') advance(3_600_000);
        if (mode === 'clock-rollback') wall -= 10_000;
        if (mode === 'weak-key-mode') await chmod(join(stateDir, 'corely-vm-model-identity.json'), 0o644);
        if (mode === 'changed-key-record') await writeFile(join(stateDir, 'corely-vm-model-identity.json'), JSON.stringify({ ...fixtureRecord, privateKeyPem: 'PRIVATE_INVALID_KEY' }));
        if (mode === 'key-symlink') {
          await rename(join(stateDir, 'corely-vm-model-identity.json'), join(stateDir, 'saved-key.json'));
          await symlink(join(stateDir, 'saved-key.json'), join(stateDir, 'corely-vm-model-identity.json'));
        }
      }
    },
    stats: () => ({ requests, negativeRequests, closed, identityClosed, cancelled, proofs }),
    async cleanup() { await rm(stateDir, { force: true, recursive: true }); },
    async unchanged() { assert.deepEqual(await readdir(stateDir), ['corely-vm-model-identity.json']);
      assert.deepEqual(await readFile(join(stateDir, 'corely-vm-model-identity.json')), initialBytes); },
  };
}

async function runControlled(mode, { stopAt, eofAt, maximumRuntimeMs } = {}) {
  const f = await fixture(mode), input = new PassThrough(), events = [], writes = [];
  const output = new Writable({ write(chunk, _encoding, done) {
    writes.push(chunk.toString()); const event = JSON.parse(chunk); events.push(event); done();
    setImmediate(() => { void (async () => {
      if (input.destroyed) return;
      await f.event(event);
      if (event.status === stopAt) { input.write('STOP\n'); return; }
      if (event.status === eofAt) { input.end(); return; }
      const value = protocol(event); if (value) input.write(`${value}\n`);
    })().catch(error => input.destroy(error)); });
  } });
  try {
    const receipt = await runCorelyVmAuthorityProbe({ ...f, input, output, ...(maximumRuntimeMs ? { maximumRuntimeMs } : {}) });
    return { receipt, events, encoded: writes.join(''), stats: f.stats(), inputDestroyed: input.destroyed, unchanged: () => f.unchanged() };
  } finally { await f.cleanup(); }
}

const childMode = process.argv[2]?.startsWith('fixture-') ? process.argv[2].slice(8) : undefined;
if (childMode) {
  const f = await fixture(childMode);
  try {
    const receipt = await runCorelyVmAuthorityProbe({ ...f, maximumRuntimeMs: 3000 });
    assert.equal(f.stats().closed, 1); assert.equal(f.stats().identityClosed, 1);
    await f.unchanged();
    process.exitCode = receipt.status === 'CLOUD_AUTHORITY_PROBE_COMPLETE' ? 0 : 1;
  } finally { await f.cleanup(); }
} else {
  test('normal sealed-client grant survives controlled restart; a fresh single proof proves revoked token denial', async () => {
    const result = await runControlled('success');
    assert.equal(result.receipt.status, 'CLOUD_AUTHORITY_PROBE_COMPLETE');
    assert.deepEqual({ before: result.receipt.beforeVerified, after: result.receipt.afterVerified, revoked: result.receipt.remoteRevocation,
      negative: result.receipt.serverPostRestartDenialVerified, expiry: result.receipt.originalGrantExpiryPreserved },
    { before: true, after: true, revoked: 'CONFIRMED', negative: true, expiry: true });
    assert.equal(result.stats.requests, 6); assert.equal(result.stats.negativeRequests, 1);
    assert.equal(result.stats.closed, 1); assert.equal(result.stats.identityClosed, 1); assert.equal(result.inputDestroyed, true);
    assert.equal(result.stats.proofs.length, 6); assert.equal(new Set(result.stats.proofs.map(proof => proof.jti)).size, 6);
    assert.equal(result.receipt.cloudRevisionVerifiedByThisDriver, false);
    assert.equal(result.receipt.livePersonalInferenceVerified, false); assert.equal(result.receipt.modelCalls, 0);
    assert.equal(result.receipt.providerRequestsMade, 0); assert.equal(result.receipt.apiFallbackUsed, false);
    assert.doesNotMatch(result.encoded, /vm_models_access_|PRIVATE|privateKeyPem|DPoP|"ath"|"jti"|device_code|access_token/);
  });

  test('only complete unambiguous 401 invalid_token with no-store and DPoP challenge passes', async t => {
    for (const mode of ['duplicate', 'escaped', 'extra', 'invalid-dpop', 'expired-error', 'wrong-challenge', 'cacheable',
      'length-mismatch', 'oversized', 'redirected', 'wrong-url', 'http-200', 'http-403', 'unfinished-eof', 'network-uncertain']) {
      await t.test(mode, async () => {
        const result = await runControlled(mode);
        assert.equal(result.receipt.status, 'CLOUD_AUTHORITY_PROBE_HELD');
        assert.equal(result.receipt.serverPostRestartDenialVerified, false);
        assert.equal(result.receipt.remoteRevocation, 'CONFIRMED'); assert.equal(result.stats.negativeRequests, 1);
        assert.equal(result.stats.closed, 1); assert.equal(result.stats.identityClosed, 1);
        if (mode === 'unfinished-eof') assert.equal(result.stats.cancelled, true);
        assert.doesNotMatch(result.encoded, /vm_models_access_|PRIVATE|privateKeyPem|DPoP|"ath"|"jti"|device_code|access_token/);
      });
    }
  });

  test('expiry, rollback, changed private record and link/mode failures never send a negative request', async t => {
    for (const mode of ['window-expired', 'grant-expired', 'clock-rollback', 'weak-key-mode', 'changed-key-record', 'key-symlink']) {
      await t.test(mode, async () => {
        const result = await runControlled(mode);
        assert.equal(result.receipt.status, 'CLOUD_AUTHORITY_PROBE_HELD');
        assert.equal(result.stats.negativeRequests, 0); assert.equal(result.stats.closed, 1);
        assert.equal(result.receipt.remoteRevocation, 'CONFIRMED');
        assert.doesNotMatch(result.encoded, /vm_models_access_|PRIVATE|privateKeyPem|DPoP/);
      });
    }
  });

  test('invalid BEFORE metadata and enabled model gate never admit a diagnostic token', async t => {
    for (const mode of ['invalid-before', 'model-on']) await t.test(mode, async () => {
      const result = await runControlled(mode);
      assert.equal(result.receipt.status, 'CLOUD_AUTHORITY_PROBE_HELD');
      assert.equal(result.receipt.beforeVerified, false); assert.equal(result.stats.negativeRequests, 0);
      assert.equal(result.receipt.remoteRevocation, 'CONFIRMED'); assert.equal(result.stats.closed, 1);
    });
  });

  test('unknown strict revocation is not retried or confused with server denial', async () => {
    const result = await runControlled('unknown-revoke');
    assert.equal(result.receipt.status, 'CLOUD_AUTHORITY_PROBE_HELD');
    assert.equal(result.receipt.remoteRevocation, 'UNKNOWN'); assert.equal(result.stats.negativeRequests, 0);
    assert.equal(result.stats.requests, 5); assert.equal(result.stats.closed, 1);
    assert.doesNotMatch(result.encoded, /PRIVATE_REVOKE_MARKER|vm_models_access_/);
  });

  test('STOP and EOF before revocation close input and make one bounded server cleanup attempt', async t => {
    for (const choice of ['stopAt', 'eofAt']) await t.test(choice, async () => {
      const result = await runControlled('success', { [choice]: 'CORELY_AUTHORITY_CONNECTED' });
      assert.equal(result.receipt.status, 'CLOUD_AUTHORITY_PROBE_HELD');
      assert.equal(result.receipt.remoteRevocation, 'CONFIRMED'); assert.equal(result.stats.requests, 3);
      assert.equal(result.inputDestroyed, true); assert.equal(result.stats.closed, 1); assert.equal(result.stats.negativeRequests, 0);
    });
  });

  test('dedicated child closes real stdin and naturally exits, including unknown revocation and unfinished EOF', async t => {
    for (const mode of ['success', 'unknown-revoke', 'unfinished-eof']) await t.test(mode, async () => {
      const child = spawn(process.execPath, [fileURLToPath(import.meta.url), `fixture-${mode}`], {
        env: { PATH: process.env.PATH, HOME: tmpdir() }, stdio: ['pipe', 'pipe', 'pipe'] });
      let stdout = '', stderr = '', pending = '', final;
      const timer = setTimeout(() => child.kill('SIGKILL'), 5000);
      child.stderr.setEncoding('utf8'); child.stderr.on('data', chunk => { stderr += chunk; });
      child.stdout.setEncoding('utf8'); child.stdout.on('data', chunk => {
        stdout += chunk; pending += chunk;
        while (pending.includes('\n')) {
          const at = pending.indexOf('\n'), event = JSON.parse(pending.slice(0, at)); pending = pending.slice(at + 1);
          if (event.status === 'CLOUD_AUTHORITY_PROBE_COMPLETE' || event.status === 'CLOUD_AUTHORITY_PROBE_HELD') final = event;
          const value = protocol(event); if (value) setImmediate(() => { if (!child.stdin.destroyed) child.stdin.write(`${value}\n`); });
        }
      });
      const result = await new Promise((accept, reject) => { child.once('error', reject); child.once('close', (code, signal) => accept({ code, signal })); });
      clearTimeout(timer); child.stdin.destroy();
      assert.equal(result.signal, null); assert.equal(result.code, mode === 'success' ? 0 : 1);
      assert.equal(stderr, ''); assert.equal(final.localCleanupConfirmed, true);
      assert.equal(final.remoteRevocation, mode === 'unknown-revoke' ? 'UNKNOWN' : 'CONFIRMED');
      assert.equal(final.serverPostRestartDenialVerified, mode === 'success');
      assert.doesNotMatch(stdout, /vm_models_access_|PRIVATE|privateKeyPem|DPoP|"ath"|"jti"/);
    });
  });
}
