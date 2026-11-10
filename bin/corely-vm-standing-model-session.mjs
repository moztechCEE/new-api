// Unwired scheduler boundary. The operator must separately attest the model
// standing parent and gateway installation, and give this session exclusive
// ownership of both clients. No consent, enrollment, secret issue or I/O here.
import { createHash } from 'node:crypto';
import { snapshotModelRequest, snapshotModelResult } from './corely-model-contract.mjs';
import { CORELY_VM_MODEL_JOB_SCOPE } from './corely-vm-model-job-client.mjs';
import { CORELY_VM_STANDING_MODEL_SCOPE } from './corely-vm-standing-model-client.mjs';

const LEASE_MS = 60_000, RENEW_HEADROOM_MS = 100_000, DAY_MS = 86_400_000;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const digest = value => createHash('sha256').update(value).digest('hex');
const fail = code => { throw Object.assign(new Error(code), { code }); };
const held = () => fail('STANDING_MODEL_SESSION_HELD');
const exact = (value, keys) => value && typeof value === 'object' && [Object.prototype, null].includes(Object.getPrototypeOf(value)) &&
  Reflect.ownKeys(value).length === keys.length && keys.every(key => Object.hasOwn(Object.getOwnPropertyDescriptor(value, key) ?? {}, 'value'));
const noPaid = value => value?.syntheticOnly === true && value.apiFallbackEnabled === false && value.noPaidCredits === true;

function bounded(signal, operation) {
  return new Promise((resolve, reject) => {
    const abort = () => reject(new Error('STANDING_MODEL_SESSION_HELD'));
    if (signal.aborted) { abort(); return; }
    signal.addEventListener('abort', abort, { once: true });
    Promise.resolve().then(() => { signal.throwIfAborted(); return operation(); })
      .then(resolve, reject).finally(() => signal.removeEventListener('abort', abort));
  });
}

export function openCorelyVmStandingModelSession(options = {}) {
  if (options.enabled !== true) fail('STANDING_MODEL_SESSION_DISABLED');
  const { authority, gateway, generate, expectedParent, signal, now = Date.now } = options;
  if (!['status', 'renew', 'modelStatus', 'claimModel', 'completeModel', 'failModel', 'close'].every(key => typeof authority?.[key] === 'function') ||
      !['receipt', 'withLease', 'close'].every(key => typeof gateway?.[key] === 'function') ||
      typeof generate !== 'function' || typeof now !== 'function' || !(signal instanceof AbortSignal) || signal.aborted ||
      !exact(expectedParent, ['parentId', 'parentGeneration', 'standingExpiresAt']) ||
      typeof expectedParent.parentId !== 'string' || !/^vm_models_standing_model_parent_[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/u.test(expectedParent.parentId) ||
      !Number.isSafeInteger(expectedParent.parentGeneration) || expectedParent.parentGeneration < 1 ||
      !Number.isSafeInteger(expectedParent.standingExpiresAt)) fail('STANDING_MODEL_SESSION_OPTIONS_INVALID');
  const parent = Object.freeze({ ...expectedParent }), controller = new AbortController();
  let busy = false, closed = false, child, lastClock = -1;
  const close = () => {
    if (closed) return;
    closed = true; child = undefined; controller.abort(); signal.removeEventListener('abort', close);
    for (const port of [authority, gateway]) { try { port.close(); } catch { /* Remain closed. */ } }
  };
  signal.addEventListener('abort', close, { once: true });
  const time = () => {
    const wall = now();
    if (closed || !Number.isSafeInteger(wall) || wall < 0 || wall < lastClock || wall >= parent.standingExpiresAt) held();
    lastClock = wall; return wall;
  };
  const sameParent = value => noPaid(value) && Object.keys(parent).every(key => value[key] === parent[key]) &&
    Number.isSafeInteger(value.generation) && value.generation >= parent.parentGeneration;
  const readyGateway = value => noPaid(value) && value.status === 'GATEWAY_ROTATION_READY' &&
    Number.isSafeInteger(value.generation) && value.generation > 0 &&
    Number.isSafeInteger(value.expiresAt) && Number.isSafeInteger(value.parentExpiresAt) &&
    value.expiresAt > time() + LEASE_MS && value.expiresAt <= value.parentExpiresAt && value.parentExpiresAt <= parent.standingExpiresAt;
  const step = (ms, action) => {
    const permit = AbortSignal.any([controller.signal, AbortSignal.timeout(ms)]);
    return bounded(permit, () => action(permit));
  };
  return Object.freeze({
    close,
    async runOnce() {
      if (closed) fail('STANDING_MODEL_SESSION_CLOSED');
      if (busy) fail('STANDING_MODEL_SESSION_BUSY');
      busy = true;
      try {
        if (!readyGateway(gateway.receipt())) held();
        const before = await step(35_000, () => authority.status());
        if (!sameParent(before) || before.status !== 'CORELY_VM_STANDING_MODEL_AUTHORITY_ACTIVE' ||
            before.scope !== CORELY_VM_STANDING_MODEL_SCOPE ||
            child && (before.generation !== child.generation || before.childExpiresAt !== child.childExpiresAt)) held();
        if (!child || child.childExpiresAt - time() <= RENEW_HEADROOM_MS) {
          const next = await step(70_000, () => authority.renew());
          const at = time();
          if (!sameParent(next) || next.status !== 'CORELY_VM_STANDING_MODEL_RENEWAL_VERIFIED' ||
              next.generation !== before.generation + 1 || next.predecessorDenialVerified !== Boolean(child) ||
              !Number.isSafeInteger(next.childExpiresAt) || next.childExpiresAt <= at + RENEW_HEADROOM_MS ||
              next.childExpiresAt > Math.min(at + DAY_MS, parent.standingExpiresAt)) held();
          child = Object.freeze({ generation: next.generation, childExpiresAt: next.childExpiresAt });
        }
        const currentGateway = gateway.receipt();
        if (!readyGateway(currentGateway)) held();
        let entered = false, outcome;
        const gatewayReceipt = await step(70_000, active => gateway.withLease(async permit => {
          if (entered || !exact(permit, ['generation', 'leaseId', 'credentials', 'signal']) ||
              permit.generation !== currentGateway.generation || typeof permit.leaseId !== 'string' || !UUID.test(permit.leaseId) ||
              !(permit.signal instanceof AbortSignal)) held();
          entered = true;
          const guard = AbortSignal.any([active, permit.signal]);
          const status = await bounded(guard, () => authority.modelStatus(guard));
          if (status?.status !== 'SYNTHETIC_VM_MODEL_TRANSPORT_V2' || status.contractVersion !== 2 || status.authorityProfile !== 'standing-model' ||
              status.tenantId !== 'moztech' || status.brandId !== 'moztech-test' || status.scope !== CORELY_VM_MODEL_JOB_SCOPE ||
              status.authMode !== 'siwc_plan' || status.enrolled !== true || status.producerConnected !== true || status.syntheticOnly !== true ||
              status.apiFallbackEnabled !== false || status.sendingCapability !== false || status.learningCapability !== false ||
              status.expiresAt !== parent.standingExpiresAt) held();
          let lease, accountAlias;
          for (const account of ['info', 'eason']) {
            if (child.childExpiresAt - time() <= 92_000) held();
            lease = await bounded(guard, () => authority.claimModel(account, guard));
            if (lease !== null) { accountAlias = account; break; } // Polling is not an account-failure decision.
          }
          const settle = () => {
            guard.throwIfAborted(); time();
            return { status: 'CORELY_DEV_GATEWAY_LEASE_SETTLED', generation: permit.generation, leaseId: permit.leaseId };
          };
          if (lease === null) {
            outcome = { status: 'NO_SYNTHETIC_MODEL_JOB', modelRequestsMade: 0 }; return settle();
          }
          const at = time();
          if (!exact(lease, ['leaseId', 'accountAlias', 'expiresAt', 'request']) || lease.accountAlias !== accountAlias ||
              typeof lease.leaseId !== 'string' || !UUID.test(lease.leaseId) || !Number.isSafeInteger(lease.expiresAt) ||
              lease.expiresAt <= at || lease.expiresAt > Math.min(at + LEASE_MS, child.childExpiresAt, currentGateway.expiresAt)) held();
          const request = snapshotModelRequest(lease.request);
          if (!['DECISION_LLM', 'REPLY_LLM'].includes(request.workload) || request.purpose === 'image_analysis') held();
          const owned = AbortSignal.any([guard, AbortSignal.timeout(Math.max(1, lease.expiresAt - time()))]);
          const binding = Object.freeze({ accountAlias, callId: request.callId, leaseId: lease.leaseId, gatewayGeneration: permit.generation });
          const result = await bounded(owned, () => generate(Object.freeze({ ...binding, request, credentials: permit.credentials, signal: owned })));
          owned.throwIfAborted();
          const boundKeys = Object.keys(binding), definitiveStop = exact(result, ['status', ...boundKeys]);
          if (!definitiveStop && !exact(result, ['status', 'result', ...boundKeys]) ||
              lease.expiresAt <= time() || !boundKeys.every(key => result[key] === binding[key])) held();
          if (definitiveStop && result.status === 'GENERATION_DEFINITIVELY_STOPPED') {
            // Only the trusted generator can attest cleanup/no later model
            // output. Abort, rejection or uncertain completion is NOT proof.
            const stopped = await bounded(owned, () => authority.failModel(lease.leaseId, owned));
            if (!exact(stopped, ['held', 'reason']) || stopped.held !== true || stopped.reason !== 'EXECUTION_UNAVAILABLE') held();
            outcome = { status: 'STANDING_MODEL_LEASE_TERMINAL_CONFIRMED', accountAlias }; return settle();
          }
          if (definitiveStop || result.status !== 'GENERATION_SETTLED') held();
          const receipt = snapshotModelResult(result.result, request, accountAlias, 'siwc_plan'), resultSha256 = digest(JSON.stringify(receipt));
          const accepted = await bounded(owned, () => authority.completeModel(lease.leaseId, receipt, owned));
          if (!exact(accepted, ['accepted', 'replayed', 'callId', 'resultSha256']) || accepted.accepted !== true || accepted.replayed !== false ||
              accepted.callId !== request.callId || accepted.resultSha256 !== resultSha256 || lease.expiresAt <= time()) held();
          owned.throwIfAborted();
          outcome = { status: 'STANDING_MODEL_LEASE_COMPLETED', accountAlias, model: request.model,
            purpose: request.purpose, outcome: receipt.status, callIdSha256: digest(request.callId) };
          return settle();
        }));
        time();
        if (!outcome || !exact(gatewayReceipt, ['status', 'generation']) || gatewayReceipt.status !== 'CORELY_DEV_GATEWAY_LEASE_SETTLED' ||
            gatewayReceipt.generation !== currentGateway.generation) held();
        if (outcome.status === 'STANDING_MODEL_LEASE_TERMINAL_CONFIRMED') close();
        return Object.freeze({ ...outcome, apiFallbackEnabled: false, paidCreditsEnabled: false, sendingPerformed: false, learningPerformed: false });
      } catch { close(); held(); }
      finally { busy = false; }
    },
  });
}
