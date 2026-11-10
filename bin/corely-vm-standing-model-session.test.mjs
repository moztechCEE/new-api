import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { openCorelyVmStandingModelSession as open } from './corely-vm-standing-model-session.mjs';
import { CORELY_VM_STANDING_MODEL_SCOPE } from './corely-vm-standing-model-client.mjs';
import { CORELY_VM_MODEL_JOB_SCOPE } from './corely-vm-model-job-client.mjs';

const START = 1_800_000_000_000, GW = '58c3839d-11bd-4b6c-907a-c647fca28104', JOB = '22b698d7-f576-4d65-96a5-f3e1a4fc8727';
const hash = v => createHash('sha256').update(v).digest('hex');
const code = expected => error => error.code === expected && error.message === expected;
const held = code('STANDING_MODEL_SESSION_HELD'), closed = code('STANDING_MODEL_SESSION_CLOSED');
const canonical = v => typeof v === 'object' && v !== null ? Object.fromEntries(Object.keys(v).sort().map(k => [k, canonical(v[k])])) : v;
const flags = { syntheticOnly: true, apiFallbackEnabled: false, noPaidCredits: true };
const parent = { parentId: `vm_models_standing_model_parent_${'a'.repeat(42)}A`, parentGeneration: 2, standingExpiresAt: START + 300_000 };

function fixture(options = {}) {
  const calls = [], state = { time: START, generation: parent.parentGeneration, child: null, alias: 'info', leased: false, gateway: false };
  const clock = () => state.time;
  const request = canonical({ version: 1, callId: 'synthetic-session-call', model: 'gpt-6.1-sol', workload: 'REPLY_LLM', purpose: 'semantic_reply_review',
    scope: { tenantId: 'moztech', brandId: 'moztech-test', synthetic: true, jobId: 'synthetic-job' },
    system: 'Synthetic system', user: 'Synthetic prompt', schemaSha256: null });
  request.inputSha256 = hash(JSON.stringify(request));
  const controller = new AbortController(), credentials = Object.freeze({ placeholder: 'test-only' });
  const authority = {
    async status() {
      calls.push('status'); return { status: 'CORELY_VM_STANDING_MODEL_AUTHORITY_ACTIVE', scope: CORELY_VM_STANDING_MODEL_SCOPE, ...flags, ...parent,
        generation: state.generation, childExpiresAt: state.child, ...options.status };
    },
    async renew() {
      calls.push('renew'); assert.equal(state.gateway || state.leased, false);
      if (options.renewLost) throw Error('fixture');
      const predecessorDenialVerified = state.child !== null; state.child = clock() + 120_000;
      return { status: 'CORELY_VM_STANDING_MODEL_RENEWAL_VERIFIED', ...flags, ...parent, generation: ++state.generation,
        childExpiresAt: state.child, predecessorDenialVerified };
    },
    async modelStatus() {
      calls.push('modelStatus'); assert.equal(state.gateway, true);
      return { status: 'SYNTHETIC_VM_MODEL_TRANSPORT_V2', contractVersion: 2, authorityProfile: 'standing-model', tenantId: 'moztech',
        brandId: 'moztech-test', scope: CORELY_VM_MODEL_JOB_SCOPE, authMode: 'siwc_plan', enrolled: true, producerConnected: true,
        ...flags, sendingCapability: false, learningCapability: false, expiresAt: parent.standingExpiresAt, ...options.modelStatus };
    },
    async claimModel(account) {
      calls.push(`claim:${account}`); assert.equal(state.gateway, true); assert.equal(state.leased, false);
      if (options.claimLost) throw Error('fixture');
      if (account !== state.alias) return null;
      state.leased = true;
      return { leaseId: JOB, accountAlias: options.wrongAccount ?? account, expiresAt: clock() + 45_000, request };
    },
    async completeModel(leaseId, result) {
      calls.push('complete'); assert.equal(state.gateway && state.leased, true); assert.equal(leaseId, JOB);
      state.leased = false;
      if (options.completionLost) throw Error('fixture');
      return { accepted: true, replayed: false, callId: request.callId, resultSha256: hash(JSON.stringify(result)), ...options.complete };
    },
    async failModel(leaseId) {
      calls.push('fail'); assert.equal(state.gateway && state.leased, true); assert.equal(leaseId, JOB);
      state.leased = false;
      return { held: true, reason: 'EXECUTION_UNAVAILABLE' };
    },
    close() { calls.push('authority:close'); },
  };
  const gateway = {
    receipt() { return { status: 'GATEWAY_ROTATION_READY', generation: 4, expiresAt: START + 290_000, parentExpiresAt: parent.standingExpiresAt,
      ...flags, ...options.gateway }; },
    async withLease(operation) {
      calls.push('gateway:acquire'); assert.equal(state.leased, false); state.gateway = true;
      try {
        const settled = await operation({ credentials, signal: controller.signal, generation: 4, leaseId: GW });
        assert.deepEqual(settled, { status: 'CORELY_DEV_GATEWAY_LEASE_SETTLED', generation: 4, leaseId: GW });
        return { status: settled.status, generation: settled.generation };
      } finally { state.gateway = false; calls.push('gateway:exit'); }
    },
    close() { calls.push('gateway:close'); },
  };
  const session = open({ enabled: true, authority, gateway, expectedParent: parent, signal: controller.signal, now: clock,
    async generate({ request: exactRequest, credentials: active, signal, ...binding }) {
      calls.push(`generate:${binding.accountAlias}`);
      assert.deepEqual(exactRequest, request); assert.equal(active, credentials); assert.equal(state.gateway && state.leased, true);
      assert.equal(binding.gatewayGeneration, 4); assert.equal(binding.leaseId, JOB); assert.equal(signal.aborted, false);
      if (options.wait) await options.wait;
      if (options.abort) controller.abort();
      if (options.generationLost) throw Error('fixture');
      if (options.definitiveStop) return { ...binding, status: 'GENERATION_DEFINITIVELY_STOPPED' };
      return { ...binding, status: 'GENERATION_SETTLED', result: { accountAlias: binding.accountAlias, authMode: 'siwc_plan',
        accountVerified: true, model: request.model, callId: request.callId, inputSha256: request.inputSha256,
        schemaSha256: null, status: 'success', completionStatus: 'completed', text: 'Synthetic result',
        usage: { inputTokens: 3, outputTokens: 1, cachedInputTokens: 0 } } };
    } });
  return { calls, state, session, controller };
}

test('default off; foreign parent, paid/expired gateway and lost renewal never claim or generate', async () => {
  assert.throws(() => open({ get authority() { assert.fail('disabled touched port'); } }), code('STANDING_MODEL_SESSION_DISABLED'));
  for (const [options, expected] of [
    [{ status: { parentGeneration: parent.parentGeneration + 1 } }, ['status']],
    [{ gateway: { noPaidCredits: false } }, []], [{ gateway: { expiresAt: START + 1 } }, []],
    [{ renewLost: true }, ['status', 'renew']],
    [{ modelStatus: { apiFallbackEnabled: true } }, ['status', 'renew', 'gateway:acquire', 'modelStatus', 'gateway:exit']],
  ]) {
    const f = fixture(options);
    await assert.rejects(f.session.runOnce(), held);
    await assert.rejects(f.session.runOnce(), closed);
    assert.deepEqual(f.calls, [...expected, 'authority:close', 'gateway:close']);
  }
});

test('gateway acquired before claims; exact Corely account; renewal only idle', async () => {
  const f = fixture(), info = await f.session.runOnce();
  assert.deepEqual(f.calls.splice(0), ['status', 'renew', 'gateway:acquire', 'modelStatus', 'claim:info', 'generate:info', 'complete', 'gateway:exit']);
  assert.equal(info.status, 'STANDING_MODEL_LEASE_COMPLETED'); assert.equal(info.accountAlias, 'info');
  assert.equal(info.model, 'gpt-6.1-sol'); assert.equal(info.purpose, 'semantic_reply_review');
  assert.equal(info.apiFallbackEnabled || info.paidCreditsEnabled || info.sendingPerformed || info.learningPerformed, false);
  f.state.time += 30_000; f.state.alias = 'eason';
  const eason = await f.session.runOnce();
  assert.deepEqual(f.calls.splice(0), ['status', 'renew', 'gateway:acquire', 'modelStatus', 'claim:info', 'claim:eason', 'generate:eason', 'complete', 'gateway:exit']);
  assert.equal(eason.accountAlias, 'eason');
  f.state.alias = null;
  assert.equal((await f.session.runOnce()).status, 'NO_SYNTHETIC_MODEL_JOB');
  assert.deepEqual(f.calls, ['status', 'gateway:acquire', 'modelStatus', 'claim:info', 'claim:eason', 'gateway:exit']);
  f.session.close();
});

test('unknown claim/generation/complete, mismatched account and cancellation cannot fail or retry a job', async () => {
  for (const [options, suffix] of [
    [{ claimLost: true }, []], [{ wrongAccount: 'eason' }, []], [{ generationLost: true }, ['generate:info']],
    [{ abort: true }, ['generate:info']], [{ completionLost: true }, ['generate:info', 'complete']],
    [{ complete: { replayed: true } }, ['generate:info', 'complete']],
  ]) {
    const f = fixture(options);
    await assert.rejects(f.session.runOnce(), held);
    await assert.rejects(f.session.runOnce(), closed);
    assert.deepEqual(f.calls.filter(v => !v.endsWith('close') && v !== 'gateway:exit'),
      ['status', 'renew', 'gateway:acquire', 'modelStatus', 'claim:info', ...suffix]);
    assert.equal(f.calls.filter(v => v === 'fail').length, 0);
  }
});

test('concurrent work cannot renew or claim; settled stop causes only one exact terminal failure', async () => {
  let release;
  const f = fixture({ wait: new Promise(resolve => { release = resolve; }), definitiveStop: true });
  const pending = f.session.runOnce();
  await assert.rejects(f.session.runOnce(), code('STANDING_MODEL_SESSION_BUSY'));
  release();
  assert.equal((await pending).status, 'STANDING_MODEL_LEASE_TERMINAL_CONFIRMED');
  await assert.rejects(f.session.runOnce(), closed);
  assert.deepEqual(f.calls, ['status', 'renew', 'gateway:acquire', 'modelStatus', 'claim:info', 'generate:info', 'fail',
    'gateway:exit', 'authority:close', 'gateway:close']);
});
