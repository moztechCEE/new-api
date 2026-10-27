import assert from 'node:assert/strict';
import { createPrivateKey } from 'node:crypto';
import { mkdirSync, renameSync } from 'node:fs';
import { chmod, link, lstat, mkdtemp, readFile, readdir, realpath, rename, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { after, before, test } from 'node:test';
import { openCorelyVmModelIdentity, openCorelyVmModelWorkerLifecycle, runCorelyVmModelWorker,
  parseVmModelWorkerCommand, VmModelWorkerError } from './corely-vm-model-worker.mjs';
import { CORELY_VM_MODEL_JOB_SCOPE as SCOPE, CORELY_VM_MODEL_JOB_RESOURCE as RESOURCE,
  CORELY_VM_HOST_ID_HASH as HOST, CORELY_VM_VERIFICATION_URI as VERIFICATION } from './corely-vm-model-job-client.mjs';
import { createSiwcModelTransports } from './siwc-local-model-port.mjs';
import { digest, MODEL } from './siwc-local-runtime.mjs';

const realFetch = globalThis.fetch;
before(() => { globalThis.fetch = () => { throw new Error('EXTERNAL_NETWORK_DISABLED'); }; });
after(() => { globalThis.fetch = realFetch; });
const code = expected => error => error instanceof VmModelWorkerError && error.code === expected && error.message === expected && !error.cause;
const canonical = value => value && typeof value === 'object' ? Array.isArray(value) ? value.map(canonical)
  : Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
// Public deterministic test-only material. No actual VM key is generated.
const fixtureKey = () => createPrivateKey({ key: Buffer.from(`302e020100300506032b657004220420${'01'.repeat(32)}`, 'hex'), format: 'der', type: 'pkcs8' });
const KEY_FILE = 'corely-vm-model-identity.json', PROMPT_FILE = 'corely-vm-model-consent.json', LOCK_FILE = 'corely-vm-model-worker.lock';

async function storage(t) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'corely-vm-worker-fixture-')));
  await chmod(root, 0o700); t.after(() => rm(root, { recursive: true, force: true }));
  const host = { kind: 'NEW_API_SIWC_DEV_HOST', version: 1, runtime: 'vm', vm: 'new-api-dev-20261022',
    hostId: 'urn:uuid:11111111-1111-4111-8111-111111111111' };
  await writeFile(join(root, 'host.json'), JSON.stringify(host), { mode: 0o600 });
  return { root, host, hostBytes: await readFile(join(root, 'host.json')) };
}
async function identity(t) {
  const f = await storage(t);
  const held = await openCorelyVmModelIdentity(f.root, { initialize: true, keyFactory: fixtureKey });
  t.after(() => held.close()); return { ...f, held, thumbprint: held.receipt().keyThumbprint };
}
const approval = thumbprint => ({ verificationUri: VERIFICATION,
  verificationUriComplete: `${VERIFICATION}?requestId=vm_models_${'r'.repeat(43)}`, userCode: 'ABCD-0123', expiresIn: 300,
  interval: 5, scope: SCOPE, vmHostIdHash: HOST, keyThumbprint: thumbprint });

test('explicit init-key uses one protected app-owned key, preserves host identity, and exposes no key getter', async t => {
  const f = await storage(t); let generated = 0;
  await assert.rejects(openCorelyVmModelIdentity(f.root, { keyFactory: () => { generated++; return fixtureKey(); } }), code('WORKER_IDENTITY_NOT_INITIALIZED'));
  assert.equal(generated, 0); assert.deepEqual(await readdir(f.root), ['host.json']);
  const first = await openCorelyVmModelIdentity(f.root, { initialize: true, keyFactory: () => { generated++; return fixtureKey(); } });
  const before = await readFile(join(f.root, KEY_FILE)), stat = await lstat(join(f.root, KEY_FILE));
  assert.equal(stat.mode & 0o777, 0o600); assert.equal(stat.nlink, 1);
  assert.deepEqual(Object.keys(first).sort(), ['close', 'connect', 'receipt']);
  assert.doesNotMatch(JSON.stringify(first.receipt()), /PRIVATE KEY|privateKeyPem|access_token|refresh_token|hostId"/);
  await first.close(); await first.close();
  const second = await openCorelyVmModelIdentity(f.root, { initialize: true, keyFactory: () => { generated++; throw new Error('NO_ROTATION'); } });
  assert.equal(generated, 1); assert.deepEqual(await readFile(join(f.root, KEY_FILE)), before);
  assert.deepEqual(await readFile(join(f.root, 'host.json')), f.hostBytes);
  await assert.rejects(second.connect({ onAuthorize: async () => {} }), code('WORKER_HOST_MISMATCH'));
  await second.close();
});

test('weak permissions, links, malformed records, and a changed host fail before authority connection', async t => {
  for (const kind of ['permissions', 'symlink', 'hardlink', 'host changed', 'duplicate', 'invalid key', 'oversized', 'directory symlink']) {
    await t.test(kind, async t => {
      const f = await identity(t); await f.held.close(); const path = join(f.root, KEY_FILE);
      if (kind === 'permissions') await chmod(path, 0o644);
      if (kind === 'symlink') { await rename(path, `${path}.original`); await symlink(`${path}.original`, path); }
      if (kind === 'hardlink') await link(path, `${path}.other`);
      if (kind === 'host changed') await writeFile(join(f.root, 'host.json'), JSON.stringify({ ...f.host, hostId: 'urn:uuid:22222222-2222-4222-8222-222222222222' }));
      if (kind === 'duplicate') await writeFile(path, (await readFile(path, 'utf8')).replace('"version":1', '"version":1,"version":1'));
      if (kind === 'invalid key') { const record = JSON.parse(await readFile(path)); record.privateKeyPem = 'PRIVATE_TEST_MARKER'; await writeFile(path, JSON.stringify(record)); }
      if (kind === 'oversized') await writeFile(path, 'x'.repeat(16_385));
      let selected = f.root;
      if (kind === 'directory symlink') { selected = `${f.root}-link`; await symlink(f.root, selected); t.after(() => rm(selected, { force: true })); }
      await assert.rejects(openCorelyVmModelIdentity(selected), error => error instanceof VmModelWorkerError &&
        ['WORKER_STORAGE_INVALID', 'WORKER_STORAGE_NOT_PRIVATE', 'WORKER_IDENTITY_INVALID'].includes(error.code) && !JSON.stringify(error).includes('PRIVATE_TEST_MARKER'));
    });
  }
});

test('lifecycle lock is exclusive and consent reference is protected, token-free and removed after use', async t => {
  const f = await identity(t), lifecycle = await openCorelyVmModelWorkerLifecycle(f.root, f.thumbprint);
  await assert.rejects(openCorelyVmModelWorkerLifecycle(f.root, f.thumbprint), code('WORKER_ALREADY_RUNNING'));
  const receipt = await lifecycle.presentConsent(approval(f.thumbprint));
  assert.doesNotMatch(JSON.stringify(receipt), /ABCD|requestId|vm_models_|access|refresh|PRIVATE/);
  const path = join(f.root, PROMPT_FILE), record = JSON.parse(await readFile(path));
  assert.equal((await lstat(path)).mode & 0o777, 0o600);
  assert.deepEqual(Object.keys(record).sort(), ['kind', 'version', 'verificationUriComplete', 'userCode', 'expiresIn', 'keyThumbprint', 'syntheticOnly', 'apiFallbackEnabled'].sort());
  await assert.rejects(lifecycle.presentConsent(approval(f.thumbprint)), code('WORKER_AUTHORITY_HELD'));
  await lifecycle.clearConsent(); await assert.rejects(readFile(path), { code: 'ENOENT' });
  await lifecycle.close(); await assert.rejects(readFile(join(f.root, LOCK_FILE)), { code: 'ENOENT' });
  const reopened = await openCorelyVmModelWorkerLifecycle(f.root, f.thumbprint); await reopened.close();
});

test('directory inode replacement during explicit bootstrap is rejected without writing a key into the replacement', async t => {
  const f = await storage(t), moved = `${f.root}-moved`;
  t.after(() => rm(moved, { recursive: true, force: true }));
  await assert.rejects(openCorelyVmModelIdentity(f.root, { initialize: true, keyFactory: () => {
    renameSync(f.root, moved); mkdirSync(f.root, { mode: 0o700 }); return fixtureKey();
  } }), code('WORKER_STORAGE_NOT_PRIVATE'));
  assert.deepEqual(await readdir(f.root), []); assert.deepEqual(await readdir(moved), ['host.json']);
  assert.deepEqual(await readFile(join(moved, 'host.json')), f.hostBytes);
});

test('replaced consent inode is never deleted and malformed authorization cannot be persisted', async t => {
  const f = await identity(t), lifecycle = await openCorelyVmModelWorkerLifecycle(f.root, f.thumbprint);
  await assert.rejects(lifecycle.presentConsent({ ...approval(f.thumbprint), device_code: 'PRIVATE_DEVICE_MARKER' }), code('WORKER_AUTHORITY_HELD'));
  await assert.rejects(lifecycle.presentConsent({ ...approval(f.thumbprint), verificationUriComplete: 1 }), code('WORKER_AUTHORITY_HELD'));
  await assert.rejects(readFile(join(f.root, PROMPT_FILE)), { code: 'ENOENT' });
  await lifecycle.presentConsent(approval(f.thumbprint));
  const path = join(f.root, PROMPT_FILE); await rename(path, `${path}.old`);
  await writeFile(path, 'REPLACEMENT_MUST_SURVIVE', { mode: 0o600 });
  await assert.rejects(lifecycle.close(), code('WORKER_CLEANUP_UNCONFIRMED'));
  assert.equal(await readFile(path, 'utf8'), 'REPLACEMENT_MUST_SURVIVE');
  await assert.rejects(readFile(join(f.root, LOCK_FILE)), { code: 'ENOENT' });
});

function request(purpose, index) {
  const content = { version: 1, callId: `synthetic-call-${index}`, workload: purpose === 'support_decision' ? 'DECISION_LLM' : 'REPLY_LLM',
    purpose, model: MODEL, scope: { tenantId: 'moztech', brandId: 'moztech-test', synthetic: true, jobId: 'server-synthetic-job' },
    system: 'SYNTHETIC_PRIVATE_PROMPT', user: 'SYNTHETIC_PRIVATE_QUESTION', schemaSha256: null };
  return { ...content, inputSha256: digest(JSON.stringify(canonical(content))) };
}
function workerFixture({ purposes = ['support_decision', 'reply_generation', 'semantic_reply_review'], quota = false,
  statusChange, generateChange, completeChange, maintainChange } = {}) {
  const controller = new AbortController(), events = [], claims = [], generated = [], completions = [], sleeps = [];
  let index = 0, closed = 0, statusReads = 0, infoQuota = false;
  const state = { status: 'SYNTHETIC_VM_MODEL_TRANSPORT_V2', contractVersion: 2, producerConnected: true, authMode: 'siwc_plan',
    enrolled: true, syntheticOnly: true, tenantId: 'moztech', brandId: 'moztech-test', scope: SCOPE,
    apiFallbackEnabled: false, sendingCapability: false, learningCapability: false };
  const sessions = { async generate(alias, input, signal) {
    generated.push({ alias, purpose: input.purpose, callId: input.callId });
    assert.ok(signal instanceof AbortSignal); assert.equal(signal.aborted, false);
    if (generateChange) return generateChange(alias, input, signal);
    const bound = { accountAlias: alias, authMode: 'siwc_plan', accountVerified: true, model: MODEL, callId: input.callId,
      inputSha256: input.inputSha256, schemaSha256: input.schemaSha256 };
    if (quota && alias === 'info') return { ...bound, status: 'quota_exhausted', code: 'QUOTA_EXHAUSTED', authenticated: true };
    return { ...bound, status: 'success', completionStatus: 'completed', text: 'SYNTHETIC_PRIVATE_REPLY',
      usage: { inputTokens: 21, outputTokens: 8, cachedInputTokens: 0 } };
  } };
  const client = {
    receipt: () => ({ scope: SCOPE, resource: RESOURCE, syntheticOnly: true, apiFallbackEnabled: false, sendingCapability: false, learningCapability: false }),
    enrollModels: async () => ({}),
    modelStatus: async () => { statusReads++; return statusChange ? statusChange({ ...state }, statusReads) : { ...state }; },
    claimModel: async alias => {
      claims.push(alias);
      if (index >= purposes.length) return null;
      const wanted = quota && infoQuota ? 'eason' : 'info';
      if (alias !== wanted) return null;
      return { leaseId: `63388770-cd07-4b5b-a53b-f73ee875a54${index}`, accountAlias: alias, expiresAt: Date.now() + 50000,
        request: request(purposes[index], index) };
    },
    completeModel: async (leaseId, result) => {
      completions.push({ leaseId, result });
      if (completeChange) return completeChange(result);
      if (result.status === 'quota_exhausted') infoQuota = true;
      index++;
      return { accepted: true, replayed: false, callId: result.callId, resultSha256: digest(JSON.stringify(result)) };
    },
    close: () => { closed++; },
  };
  const options = { client, ports: createSiwcModelTransports(sessions), signal: controller.signal, onReceipt: async receipt => { events.push(receipt); },
    sleep: async ms => { sleeps.push(ms); }, pollIntervalMs: 1000, maxJobs: purposes.length || 1, maxIdlePolls: 2,
    producerWaitMs: 2000, maintainSessions: maintainChange ?? (async () => {}) };
  return { options, controller, events, claims, generated, completions, sleeps, closed: () => closed };
}

test('resident loop serially completes decision, generation and independent review through real bound model helpers', async () => {
  const f = workerFixture(), result = await runCorelyVmModelWorker(f.options);
  assert.equal(result.reason, 'JOB_LIMIT'); assert.equal(result.completed, 3); assert.equal(f.closed(), 1);
  assert.deepEqual(f.generated.map(call => call.purpose), ['support_decision', 'reply_generation', 'semantic_reply_review']);
  assert.equal(new Set(f.generated.map(call => call.callId)).size, 3);
  assert.ok(f.generated.every(call => call.alias === 'info')); assert.deepEqual(f.claims, ['info', 'info', 'info']);
  assert.equal(f.completions.length, 3); assert.equal(f.events.length, 4);
  assert.doesNotMatch(JSON.stringify(f.events), /SYNTHETIC_PRIVATE|access_token|refresh_token|PRIVATE KEY/);
  assert.ok(f.events.every(event => event.apiFallbackUsed === false && event.sendingPerformed === false && event.learningPerformed === false));
});

test('default queue polling adds only one bounded second per empty stage without repeating completed model work', async () => {
  const f = workerFixture(); delete f.options.pollIntervalMs;
  const claim = f.options.client.claimModel, complete = f.options.client.completeModel;
  let empty = true;
  f.options.client.claimModel = async (...args) => {
    if (empty) { if (args[0] === 'eason') empty = false; return null; }
    return claim(...args);
  };
  f.options.client.completeModel = async (...args) => { const receipt = await complete(...args); empty = true; return receipt; };
  assert.equal((await runCorelyVmModelWorker(f.options)).completed, 3);
  assert.deepEqual(f.sleeps, [1000, 1000, 1000]);
  assert.deepEqual(f.generated.map(call => call.purpose), ['support_decision', 'reply_generation', 'semantic_reply_review']);
  assert.equal(new Set(f.generated.map(call => call.callId)).size, 3);
  assert.equal(f.completions.length, 3); assert.equal(f.closed(), 1);
});

test('polling and nominal 24-hour idle-count limits remain bounded independently of grant authority', async t => {
  for (const [name, change] of [['poll too fast', { pollIntervalMs: 999 }], ['poll too slow', { pollIntervalMs: 30001 }],
    ['idle unbounded', { maxIdlePolls: 0 }], ['idle beyond 24-hour count', { maxIdlePolls: 86401 }]]) await t.test(name, async () => {
    const f = workerFixture({ purposes: [] });
    await assert.rejects(runCorelyVmModelWorker({ ...f.options, ...change }), code('WORKER_OPTIONS_INVALID'));
    assert.equal(f.generated.length, 0); assert.equal(f.claims.length, 0); assert.equal(f.sleeps.length, 0);
  });
  await t.test('24-hour count is admitted but cancellation still stops the first wait', async () => {
    const f = workerFixture({ purposes: [] });
    f.options.sleep = async ms => { f.sleeps.push(ms); f.controller.abort(); };
    await assert.rejects(runCorelyVmModelWorker({ ...f.options, maxIdlePolls: 86400 }), code('WORKER_ABORTED'));
    assert.deepEqual(f.sleeps, [1000]); assert.equal(f.generated.length, 0); assert.equal(f.closed(), 1);
  });
});

test('only a server-enqueued Eason job after bound Info quota is consumed; ordinary failures never rotate', async t => {
  const f = workerFixture({ purposes: ['reply_generation', 'reply_generation'], quota: true });
  assert.equal((await runCorelyVmModelWorker(f.options)).completed, 2);
  assert.deepEqual(f.generated.map(call => call.alias), ['info', 'eason']);
  assert.deepEqual(f.completions.map(call => call.result.status), ['quota_exhausted', 'success']);
  await t.test('uncertain provider', async () => {
    const held = workerFixture({ generateChange: async () => { throw new Error('PRIVATE_PROVIDER_DETAIL'); } });
    await assert.rejects(runCorelyVmModelWorker(held.options), code('WORKER_EXECUTION_HELD'));
    assert.deepEqual(held.generated.map(call => call.alias), ['info']); assert.deepEqual(held.claims, ['info']);
    assert.equal(held.completions.length, 0); assert.equal(held.closed(), 1);
  });
});

test('legacy, missing producer, lost authority and maintenance failure hold before any model call', async t => {
  for (const kind of ['legacy', 'producer missing', 'revoked', 'expired', 'maintenance']) await t.test(kind, async () => {
    const f = workerFixture({ statusChange: status => {
      if (kind === 'legacy') { status.status = 'SYNTHETIC_VM_MODEL_TRANSPORT'; delete status.contractVersion; status.producerConnected = false; }
      if (kind === 'producer missing') status.producerConnected = false;
      if (['revoked', 'expired'].includes(kind)) throw new Error(`PRIVATE_${kind}`);
      return status;
    }, maintainChange: kind === 'maintenance' ? async () => { throw new Error('PRIVATE_SESSION_DETAIL'); } : undefined });
    await assert.rejects(runCorelyVmModelWorker(f.options), code(kind === 'legacy' ? 'WORKER_AUTHORITY_HELD'
      : kind === 'producer missing' ? 'WORKER_PRODUCER_NOT_READY' : 'WORKER_EXECUTION_HELD'));
    assert.equal(f.generated.length, 0); assert.equal(f.claims.length, 0); assert.equal(f.closed(), 1);
    if (kind === 'producer missing') assert.deepEqual(f.sleeps, [1000, 1000]);
  });
});

test('producer readiness may be awaited but is never invented or activated by the consumer', async () => {
  const f = workerFixture({ purposes: ['reply_generation'], statusChange: (status, reads) => ({ ...status, producerConnected: reads > 1 }) });
  assert.equal((await runCorelyVmModelWorker(f.options)).completed, 1); assert.deepEqual(f.sleeps, [1000]);
  assert.equal(f.events[0].status, 'CORELY_VM_MODEL_WORKER_READY'); assert.equal(f.generated.length, 1);
});

test('loss of ready producer before a claim cannot be bypassed by an earlier readiness receipt', async () => {
  const f = workerFixture({ statusChange: (status, reads) => ({ ...status, producerConnected: reads === 1 }) });
  await assert.rejects(runCorelyVmModelWorker(f.options), code('WORKER_AUTHORITY_HELD'));
  assert.equal(f.claims.length, 0); assert.equal(f.generated.length, 0); assert.equal(f.closed(), 1);
});

test('uncertain or revoked completion is one-shot and never regenerated', async () => {
  const f = workerFixture({ completeChange: () => { throw new Error('PRIVATE_RECEIPT_LOST_OR_REVOKED'); } });
  await assert.rejects(runCorelyVmModelWorker(f.options), code('WORKER_EXECUTION_HELD'));
  assert.equal(f.generated.length, 1); assert.equal(f.completions.length, 1); assert.equal(f.closed(), 1);
  assert.equal(f.events.length, 1);
});

test('abort interrupts an uncooperative inference without completing or polling another lease', async () => {
  let entered; const started = new Promise(resolve => { entered = resolve; });
  const f = workerFixture({ generateChange: async () => { entered(); return new Promise(() => {}); } });
  const running = runCorelyVmModelWorker(f.options); await started; f.controller.abort();
  await assert.rejects(running, code('WORKER_ABORTED'));
  assert.equal(f.generated.length, 1); assert.equal(f.completions.length, 0); assert.equal(f.closed(), 1); assert.deepEqual(f.claims, ['info']);
});

test('idle bounds stop without spending model allowance, and CLI accepts no credential/model/endpoint overrides', async () => {
  const f = workerFixture({ purposes: [] });
  assert.equal((await runCorelyVmModelWorker(f.options)).reason, 'IDLE_LIMIT');
  assert.equal(f.generated.length, 0); assert.equal(f.closed(), 1); assert.deepEqual(f.sleeps, [1000]);
  assert.deepEqual(parseVmModelWorkerCommand(['run', '--state-dir', '/state']), { command: 'run', stateDir: '/state' });
  for (const args of [['run', '--api-key', 'PRIVATE_ARG'], ['init-key', '--state-dir', '/state', '--model', MODEL], ['run', '--state-dir', '../state']]) {
    assert.throws(() => parseVmModelWorkerCommand(args), code('WORKER_OPTIONS_INVALID'));
  }
  const child = spawnSync(process.execPath, ['bin/corely-vm-model-worker.mjs', 'run', '--api-key', 'PRIVATE_ARG'],
    { cwd: process.cwd(), env: { PATH: '/usr/bin:/bin', HOME: tmpdir() }, encoding: 'utf8', timeout: 5000 });
  assert.equal(child.status, 1); assert.doesNotMatch(child.stdout + child.stderr, /PRIVATE_ARG|PRIVATE KEY|access_token|refresh_token|Error:/);
  assert.equal(JSON.parse(child.stdout).code, 'WORKER_OPTIONS_INVALID');
});
