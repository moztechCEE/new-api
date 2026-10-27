// Private pull worker: only a separately authorized Corely synthetic lease
// can reach an app-owned SIWC port. No job creation or customer operations.
import { ProbeError, MODEL, digest } from './siwc-local-runtime.mjs';
import { snapshotModelRequest, snapshotModelResult } from './corely-model-contract.mjs';

export async function executeOneCorelyModelJob(client, ports, signal) {
  if (!(signal instanceof AbortSignal) || !client || !['modelStatus', 'claimModel', 'completeModel'].every(key => typeof client[key] === 'function') ||
      !ports || Object.keys(ports).some(key => !['info', 'eason'].includes(key))) throw new ProbeError('MODEL_WORKER_INVALID');
  signal.throwIfAborted();
  const status = await client.modelStatus(signal);
  if (status.authMode !== 'siwc_plan' || status.enrolled !== true || status.syntheticOnly !== true || status.tenantId !== 'moztech' ||
      status.brandId !== 'moztech-test' || status.apiFallbackEnabled !== false || status.sendingCapability !== false ||
      status.learningCapability !== false) throw new ProbeError('MODEL_WORKER_NOT_ADMITTED');
  let lease = await client.claimModel('info', signal);
  // The Corely router, not this worker, creates an Eason job only after it
  // receives a bound authenticated Info-quota receipt. Polling an empty queue
  // is not account fallback and cannot itself generate a paid request.
  if (lease === null) lease = await client.claimModel('eason', signal);
  if (lease === null) return Object.freeze({ status: 'NO_SYNTHETIC_MODEL_JOB', modelRequestsMade: 0, apiFallbackUsed: false });
  signal.throwIfAborted();
  if (!lease || !['info', 'eason'].includes(lease.accountAlias) || !Number.isSafeInteger(lease.expiresAt) || lease.expiresAt <= Date.now() ||
      lease.expiresAt > Date.now() + 60_000) throw new ProbeError('MODEL_WORKER_LEASE_INVALID');
  const request = snapshotModelRequest(lease.request), port = ports[lease.accountAlias];
  if (port?.authMode !== 'siwc_plan' || port.capabilities?.text !== true || typeof port.generate !== 'function' ||
      ((request.responseFormat === 'json' || request.responseSchema) && port.capabilities.structuredJson !== true)) throw new ProbeError('MODEL_WORKER_NOT_ADMITTED');
  const active = AbortSignal.any([signal, AbortSignal.timeout(Math.max(1, lease.expiresAt - Date.now()))]);
  const result = snapshotModelResult(await port.generate(request, active), request, lease.accountAlias, 'siwc_plan');
  active.throwIfAborted();
  const receipt = await client.completeModel(lease.leaseId, result, active);
  active.throwIfAborted();
  const expected = digest(JSON.stringify(result));
  if (receipt?.accepted !== true || receipt.callId !== request.callId || receipt.resultSha256 !== expected) throw new ProbeError('MODEL_WORKER_COMPLETION_UNCONFIRMED');
  // Logs may use this receipt; neither the prompt nor the generated text is in it.
  return Object.freeze({ status: 'CORELY_SYNTHETIC_MODEL_JOB_COMPLETED', accountAlias: lease.accountAlias, authMode: 'siwc_plan', model: MODEL,
    workload: request.workload, purpose: request.purpose, callIdHash: digest(request.callId), inputSha256: request.inputSha256,
    schemaSha256: request.schemaSha256, resultSha256: expected, outcome: result.status,
    apiFallbackUsed: false, sendingPerformed: false, learningPerformed: false });
}
