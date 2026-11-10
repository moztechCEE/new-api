// Distinct DEV standing-model protocol. No process/env lookup, credential
// import, provider/gateway call, persistence, or automatic worker admission.
import { KeyObject, createHash, createPublicKey, randomUUID, sign } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { CORELY_VM_HOST_ID_HASH, CORELY_VM_MODEL_JOB_ISSUER, CORELY_VM_MODEL_JOB_RESOURCE, CORELY_VM_MODEL_JOB_SCOPE,
  CORELY_VM_VERIFICATION_URI } from './corely-vm-model-job-client.mjs';
import { snapshotModelRequest, snapshotModelResult } from './corely-model-contract.mjs';

export const CORELY_VM_STANDING_MODEL_SCOPE = 'corely:dev-vm-standing-model-jobs';
export const CORELY_VM_STANDING_MODEL_ISSUER = `${CORELY_VM_MODEL_JOB_ISSUER}/standing-model`;
const MAX_CHILD_MS = 86_400_000, MAX_PARENT_MS = 30 * MAX_CHILD_MS, MAX_MODEL_BODY = 1024 * 1024;
const REQUEST_ID = /^vm_standing_model_[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/u;
const PARENT_ID = /^vm_models_standing_model_parent_[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/u;
const CHILD_TOKEN = /^vm_models_standing_model_access_[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/u;
const BASE64URL32 = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/u;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const DENIED = Symbol('standing-model-child-denied');
const sha = (value, encoding = 'base64url') => createHash('sha256').update(value).digest(encoding);
const exact = (value, fields) => value !== null && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).length === fields.length && fields.every(field => Object.hasOwn(value, field));
const codes = new Set(['STANDING_MODEL_DISABLED', 'STANDING_MODEL_OPTIONS_INVALID', 'STANDING_MODEL_KEY_INVALID',
  'STANDING_MODEL_CLOSED', 'STANDING_MODEL_BUSY', 'STANDING_MODEL_HELD', 'STANDING_MODEL_RECOVERY_REQUIRED',
  'STANDING_MODEL_EXECUTION_TERMINAL', 'STANDING_MODEL_DISPATCH_DISABLED', 'STANDING_MODEL_LEASE_NOT_CURRENT']);
export class StandingModelClientError extends Error {
  constructor(code) { super(codes.has(code) ? code : 'STANDING_MODEL_HELD'); this.name = 'StandingModelClientError'; this.code = this.message; }
}
const failure = code => new StandingModelClientError(code);
const hold = () => { throw failure('STANDING_MODEL_HELD'); };

// JSON.parse discards duplicate members. Check every decoded member name
// (including escaped aliases) before using a remote receipt or lease.
function unambiguousJson(text) {
  const value = JSON.parse(text), levels = [];
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '{') levels.push(new Set());
    else if (c === '[') levels.push(null);
    else if (c === '}' || c === ']') levels.pop();
    else if (c === '"') {
      const start = i;
      for (i++; text[i] !== '"'; i++) if (text[i] === '\\') i++;
      let after = i + 1; while (/\s/u.test(text[after] ?? '')) after++;
      if (text[after] === ':') {
        const level = levels.at(-1), key = JSON.parse(text.slice(start, i + 1));
        if (!level || level.has(key)) hold();
        level.add(key);
      }
    }
  }
  return value;
}

function untilAbort(work, signal) {
  const operation = Promise.resolve(work);
  if (signal.aborted) { void operation.catch(() => {}); return Promise.reject(signal.reason); }
  return new Promise((resolve, reject) => {
    const abort = () => { signal.removeEventListener('abort', abort); reject(signal.reason); };
    signal.addEventListener('abort', abort, { once: true });
    operation.then(value => { signal.removeEventListener('abort', abort); resolve(value); },
      error => { signal.removeEventListener('abort', abort); reject(error); });
  });
}

async function fixedJson(endpoint, { method, body, jwt, token, fetchImpl, signal, timeoutMs, limit, childStatus }) {
  const serialized = body === undefined ? undefined : JSON.stringify(body);
  if (serialized !== undefined && Buffer.byteLength(serialized) > limit) hold();
  const deadline = new AbortController(), active = AbortSignal.any([signal, deadline.signal]);
  const timer = setTimeout(() => deadline.abort(failure('STANDING_MODEL_HELD')), timeoutMs);
  let reader, response;
  try {
    response = await untilAbort(Promise.resolve().then(() => {
      active.throwIfAborted();
      return fetchImpl(endpoint, { method, redirect: 'error', credentials: 'omit', cache: 'no-store', signal: active,
        headers: { Accept: 'application/json', 'Accept-Encoding': 'identity', DPoP: jwt,
          ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...(token ? { Authorization: `DPoP ${token}` } : {}) },
        ...(serialized === undefined ? {} : { body: serialized }) });
    }), active);
    const headers = response?.headers;
    if (!headers || response.redirected || response.url && response.url !== endpoint || headers.get('cache-control') !== 'no-store' ||
        headers.has('content-encoding') || !/^application\/json(?:\s*;\s*charset=utf-8)?$/iu.test(headers.get('content-type') ?? '') ||
        !response.body?.getReader) hold();
    const length = headers.get('content-length');
    if (length !== null && (!/^(?:0|[1-9][0-9]*)$/u.test(length) || Number(length) > limit)) hold();
    reader = response.body.getReader(); const chunks = []; let bytes = 0, ended = false;
    for (let reads = 0; reads < (limit === MAX_MODEL_BODY ? 2048 : 64); reads++) {
      const part = await untilAbort(reader.read(), active);
      if (part.done) { ended = true; break; }
      if (!(part.value instanceof Uint8Array) || (bytes += part.value.byteLength) > limit) hold();
      chunks.push(part.value);
    }
    if (!ended || length !== null && Number(length) !== bytes) hold();
    const text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)), value = unambiguousJson(text);
    if (response.status === 409 && exact(value, ['error']) && value.error === 'execution_terminal') throw failure('STANDING_MODEL_EXECUTION_TERMINAL');
    if (childStatus && response.status === 401 && headers.get('www-authenticate') === 'DPoP error="invalid_token"' &&
        /^\s*\{\s*"error"\s*:\s*"invalid_token"\s*\}\s*$/u.test(text)) return DENIED;
    if (response.status !== 200 || !value || typeof value !== 'object' || Array.isArray(value)) hold();
    return value;
  } finally {
    clearTimeout(timer);
    if (reader) { try { void Promise.resolve(reader.cancel()).catch(() => {}); reader.releaseLock(); } catch { /* Nothing retained. */ } }
    else if (response?.body && !response.body.locked) { try { void Promise.resolve(response.body.cancel()).catch(() => {}); } catch { /* Nothing retained. */ } }
  }
}

export function openCorelyVmStandingModelAuthority(options = {}) {
  if (!options || typeof options !== 'object' || Array.isArray(options) || Object.keys(options).some(key =>
    !['enabled', 'enableModelDispatch', 'privateKey', 'expectedKeyThumbprint', 'fetchImpl', 'signal', 'now', 'monotonicNow', 'requestTimeoutMs'].includes(key))) {
    throw failure('STANDING_MODEL_OPTIONS_INVALID');
  }
  if (options.enabled !== true) throw failure('STANDING_MODEL_DISABLED');
  const { enableModelDispatch = false, privateKey, expectedKeyThumbprint, fetchImpl = globalThis.fetch, signal, now = Date.now,
    monotonicNow = () => performance.now(), requestTimeoutMs = 15_000 } = options;
  if (typeof enableModelDispatch !== 'boolean' || typeof fetchImpl !== 'function' || typeof now !== 'function' || typeof monotonicNow !== 'function' ||
      signal !== undefined && !(signal instanceof AbortSignal) || !Number.isSafeInteger(requestTimeoutMs) || requestTimeoutMs < 10 || requestTimeoutMs > 30_000) {
    throw failure('STANDING_MODEL_OPTIONS_INVALID');
  }
  if (signal?.aborted) throw failure('STANDING_MODEL_CLOSED');
  let key = privateKey, jwk, thumbprint;
  try {
    if (!(key instanceof KeyObject) || key.type !== 'private' || key.asymmetricKeyType !== 'ed25519') throw new Error();
    const publicKey = createPublicKey(key).export({ format: 'jwk' });
    if (publicKey.kty !== 'OKP' || publicKey.crv !== 'Ed25519' || !BASE64URL32.test(publicKey.x ?? '')) throw new Error();
    jwk = { kty: 'OKP', crv: 'Ed25519', x: publicKey.x };
    thumbprint = sha(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x }));
    if (thumbprint !== expectedKeyThumbprint) throw new Error();
  } catch { throw failure('STANDING_MODEL_KEY_INVALID'); }

  const controller = new AbortController(), leases = new Map();
  let child = null, parent = null, lastGeneration = null, busy = false, closed = false, enrolled = false, lastWall = -1, lastMono = -1;
  function close() {
    closed = true; key = undefined; child = null; parent = null; lastGeneration = null; enrolled = false; leases.clear();
    controller.abort(failure('STANDING_MODEL_CLOSED')); signal?.removeEventListener('abort', close);
  }
  signal?.addEventListener('abort', close, { once: true });
  const clock = () => {
    const wall = now(), mono = monotonicNow();
    if (!Number.isSafeInteger(wall) || wall < 0 || wall < lastWall || wall > Number.MAX_SAFE_INTEGER - MAX_PARENT_MS - requestTimeoutMs ||
        !Number.isFinite(mono) || mono < 0 || mono < lastMono || mono > Number.MAX_SAFE_INTEGER - MAX_PARENT_MS) hold();
    lastWall = wall; lastMono = mono; return { wall, mono };
  };
  const request = async (family, name, { body, token, generation, operationSignal, limit = 4096 } = {}) => {
    if (closed || !key) throw failure('STANDING_MODEL_CLOSED');
    if (operationSignal !== undefined && !(operationSignal instanceof AbortSignal)) throw failure('STANDING_MODEL_OPTIONS_INVALID');
    const active = operationSignal ? AbortSignal.any([controller.signal, operationSignal]) : controller.signal;
    active.throwIfAborted();
    const endpoint = `${family === 'authority' ? CORELY_VM_STANDING_MODEL_ISSUER : CORELY_VM_MODEL_JOB_RESOURCE}/${name}`;
    const method = body === undefined ? 'GET' : 'POST';
    const claims = { htu: endpoint, htm: method, iat: Math.floor(clock().wall / 1000), jti: randomUUID(), scope: CORELY_VM_STANDING_MODEL_SCOPE,
      ...(generation === undefined ? {} : { generation }), ...(token ? { ath: sha(token) } : {}) };
    const unsigned = [{ typ: 'dpop+jwt', alg: 'EdDSA', jwk }, claims].map(value => Buffer.from(JSON.stringify(value)).toString('base64url')).join('.');
    const jwt = `${unsigned}.${sign(null, Buffer.from(unsigned), key).toString('base64url')}`;
    const value = await fixedJson(endpoint, { method, body, token, jwt, fetchImpl, signal: active, timeoutMs: requestTimeoutMs, limit,
      childStatus: family === 'authority' && name === 'child-status' });
    active.throwIfAborted();
    return value;
  };
  const future = (value, wall, bound) => Number.isSafeInteger(value) && value > wall && value <= wall + bound;
  const live = (candidate, t = clock()) => Boolean(candidate && !closed && t.wall < candidate.wallDeadline && t.mono < candidate.monoDeadline);
  const sameParent = (a, b) => a.parentId === b.parentId && a.parentGeneration === b.parentGeneration &&
    a.standingExpiresAt === b.standingExpiresAt && a.maxChildSeconds === b.maxChildSeconds;
  const readStatus = async () => {
    const value = await request('authority', 'status'), { wall } = clock();
    if (!exact(value, ['status', 'generation', 'parentId', 'parentGeneration', 'standingExpiresAt', 'childExpiresAt', 'maxChildSeconds',
      'keyThumbprint', 'vmHostIdHash', 'scope', 'syntheticOnly', 'apiFallbackEnabled', 'noPaidCredits']) ||
      value.status !== 'CORELY_VM_STANDING_MODEL_AUTHORITY_ACTIVE' || typeof value.parentId !== 'string' || !PARENT_ID.test(value.parentId) ||
      !Number.isSafeInteger(value.parentGeneration) || value.parentGeneration < 1 || !Number.isSafeInteger(value.generation) ||
      value.generation < value.parentGeneration || value.generation >= Number.MAX_SAFE_INTEGER || !future(value.standingExpiresAt, wall, MAX_PARENT_MS) ||
      !Number.isSafeInteger(value.maxChildSeconds) || value.maxChildSeconds < 120 || value.maxChildSeconds > MAX_CHILD_MS / 1000 ||
      value.keyThumbprint !== thumbprint || value.vmHostIdHash !== CORELY_VM_HOST_ID_HASH || value.scope !== CORELY_VM_STANDING_MODEL_SCOPE ||
      value.syntheticOnly !== true || value.apiFallbackEnabled !== false || value.noPaidCredits !== true ||
      value.childExpiresAt !== null && (!future(value.childExpiresAt, wall, value.maxChildSeconds * 1000) || value.childExpiresAt > value.standingExpiresAt) ||
      parent && !sameParent(value, parent)) hold();
    return Object.freeze(value);
  };
  const status = async () => {
    const value = await readStatus();
    if (lastGeneration !== null && value.generation !== lastGeneration || child && (!live(child) || value.childExpiresAt !== child.childExpiresAt)) hold();
    parent = value; lastGeneration = value.generation; return value;
  };
  const readChild = async (token, expiresAt) => {
    const value = await request('authority', 'child-status', { token });
    if (value === DENIED) return value;
    if (!exact(value, ['status', 'expiresAt', 'syntheticOnly', 'apiFallbackEnabled']) || value.status !== 'CORELY_VM_STANDING_MODEL_CHILD_VALID' ||
        value.expiresAt !== expiresAt || value.expiresAt <= clock().wall || value.syntheticOnly !== true || value.apiFallbackEnabled !== false) hold();
    return Object.freeze(value);
  };
  const exclusive = action => async (...args) => {
    if (closed) throw failure('STANDING_MODEL_CLOSED');
    if (busy) throw failure('STANDING_MODEL_BUSY');
    busy = true; let renewalDispatched = false;
    try { return await action(() => { renewalDispatched = true; }, ...args); }
    catch (error) {
      if (error instanceof StandingModelClientError && ['STANDING_MODEL_BUSY', 'STANDING_MODEL_DISPATCH_DISABLED',
        'STANDING_MODEL_OPTIONS_INVALID', 'STANDING_MODEL_LEASE_NOT_CURRENT'].includes(error.code)) throw error;
      close();
      if (error instanceof StandingModelClientError && error.code === 'STANDING_MODEL_EXECUTION_TERMINAL') throw error;
      throw failure(renewalDispatched ? 'STANDING_MODEL_RECOVERY_REQUIRED' : 'STANDING_MODEL_HELD');
    } finally { busy = false; }
  };
  const modelRequest = async (name, body, operationSignal, limit) => {
    if (!live(child)) hold();
    const value = await request('model', name, { token: child.token, body, operationSignal, limit });
    if (!live(child)) hold();
    return value;
  };
  const baseModel = value => value.authMode === 'siwc_plan' && value.syntheticOnly === true && value.apiFallbackEnabled === false &&
    value.sendingCapability === false && value.learningCapability === false && value.vmHostIdHash === CORELY_VM_HOST_ID_HASH &&
    value.keyThumbprint === thumbprint && value.expiresAt === parent?.standingExpiresAt;
  const requireDispatch = () => { if (!enableModelDispatch) throw failure('STANDING_MODEL_DISPATCH_DISABLED'); };
  const readModelStatus = async operationSignal => {
    const value = await modelRequest('status', undefined, operationSignal);
    const fields = ['status', 'scope', 'tenantId', 'brandId', 'authMode', 'syntheticOnly', 'enrolled', 'producerConnected', 'apiFallbackEnabled',
      'sendingCapability', 'learningCapability', 'vmHostIdHash', 'keyThumbprint', 'expiresAt', 'authorityProfile'];
    const v2 = value.status === 'SYNTHETIC_VM_MODEL_TRANSPORT_V2';
    if (!exact(value, v2 ? [...fields, 'contractVersion'] : fields) || (v2 ? value.contractVersion !== 2 :
      value.status !== 'SYNTHETIC_VM_MODEL_TRANSPORT' || value.producerConnected !== false) || !baseModel(value) ||
      value.authorityProfile !== 'standing-model' || value.scope !== CORELY_VM_MODEL_JOB_SCOPE || value.tenantId !== 'moztech' ||
      value.brandId !== 'moztech-test' || typeof value.enrolled !== 'boolean' || typeof value.producerConnected !== 'boolean' ||
      value.producerConnected && !value.enrolled) hold();
    return Object.freeze(value);
  };
  return Object.freeze({
    prepare: exclusive(async () => {
      if (child || parent) hold();
      const value = await request('authority', 'prepare', { body: {} }), { wall } = clock();
      if (!exact(value, ['status', 'requestId', 'verification_uri_complete', 'requestExpiresAt', 'standingExpiresAt']) ||
          value.status !== 'CORELY_VM_STANDING_MODEL_CONSENT_REQUIRED' || typeof value.requestId !== 'string' || !REQUEST_ID.test(value.requestId) ||
          value.verification_uri_complete !== `${CORELY_VM_VERIFICATION_URI}?requestId=${value.requestId}` ||
          !future(value.requestExpiresAt, wall, 300_000) || !future(value.standingExpiresAt, wall, MAX_PARENT_MS) ||
          value.requestExpiresAt >= value.standingExpiresAt) hold();
      return Object.freeze(value);
    }),
    status: exclusive(status),
    renew: exclusive(async markDispatched => {
      if (leases.size) throw failure('STANDING_MODEL_BUSY');
      const before = await status(), started = clock(), predecessor = child;
      if (predecessor && !live(predecessor, started)) hold();
      markDispatched();
      const result = await request('authority', 'renew', { body: { generation: before.generation }, generation: before.generation });
      if (!exact(result, ['access_token', 'token_type', 'expires_in', 'scope']) || typeof result.access_token !== 'string' || !CHILD_TOKEN.test(result.access_token) ||
          result.access_token === predecessor?.token || result.token_type !== 'DPoP' || result.scope !== CORELY_VM_STANDING_MODEL_SCOPE ||
          !Number.isSafeInteger(result.expires_in) || result.expires_in < 1 || result.expires_in > before.maxChildSeconds) hold();
      const after = await readStatus();
      if (!sameParent(before, after) || after.generation !== before.generation + 1 || after.childExpiresAt === null ||
          await readChild(result.access_token, after.childExpiresAt) === DENIED) hold();
      if (predecessor && (!live(predecessor) || await readChild(predecessor.token, predecessor.childExpiresAt) !== DENIED || !live(predecessor))) hold();
      const lifetime = result.expires_in * 1000;
      const candidate = { token: result.access_token, childExpiresAt: after.childExpiresAt, wallDeadline: Math.min(started.wall + lifetime, after.childExpiresAt),
        monoDeadline: started.mono + lifetime };
      if (!live(candidate)) hold();
      parent = after; lastGeneration = after.generation; child = candidate;
      if (enrolled && !(await readModelStatus()).enrolled) hold();
      return Object.freeze({ status: 'CORELY_VM_STANDING_MODEL_RENEWAL_VERIFIED', parentId: after.parentId, parentGeneration: after.parentGeneration,
        generation: after.generation, standingExpiresAt: after.standingExpiresAt, childExpiresAt: after.childExpiresAt,
        predecessorDenialVerified: Boolean(predecessor), syntheticOnly: true, apiFallbackEnabled: false, noPaidCredits: true });
    }),
    childStatus: exclusive(async () => {
      if (!live(child)) hold();
      const value = await readChild(child.token, child.childExpiresAt);
      if (!live(child)) hold();
      if (value === DENIED) { close(); return Object.freeze({ status: 'CORELY_VM_STANDING_MODEL_CHILD_DENIED', errorClass: 'invalid_token' }); }
      return value;
    }),
    modelStatus: exclusive(async (_mark, operationSignal) => readModelStatus(operationSignal)),
    enrollModels: exclusive(async (_mark, operationSignal) => {
      requireDispatch();
      await readModelStatus(operationSignal);
      const value = await modelRequest('enroll', {}, operationSignal);
      if (!exact(value, ['enrolled', 'authMode', 'syntheticOnly', 'apiFallbackEnabled', 'sendingCapability', 'learningCapability',
        'vmHostIdHash', 'keyThumbprint', 'expiresAt']) || !baseModel(value) || value.enrolled !== true) hold();
      if (!(await readModelStatus(operationSignal)).enrolled) hold();
      enrolled = true; return Object.freeze(value);
    }),
    claimModel: exclusive(async (_mark, accountAlias, operationSignal) => {
      requireDispatch();
      if (!enrolled || !['info', 'eason'].includes(accountAlias)) throw failure('STANDING_MODEL_OPTIONS_INVALID');
      if (leases.size) throw failure('STANDING_MODEL_BUSY');
      const value = await modelRequest('claim', { accountAlias }, operationSignal, MAX_MODEL_BODY);
      if (!exact(value, ['authMode', 'lease']) || value.authMode !== 'siwc_plan') hold();
      if (value.lease === null) return null;
      const lease = value.lease;
      if (!exact(lease, ['leaseId', 'accountAlias', 'expiresAt', 'request']) || typeof lease.leaseId !== 'string' || !UUID.test(lease.leaseId) || lease.accountAlias !== accountAlias ||
          !future(lease.expiresAt, clock().wall, 60_000) || lease.expiresAt > child.wallDeadline) hold();
      const request = snapshotModelRequest(lease.request);
      if (!['DECISION_LLM', 'REPLY_LLM'].includes(request.workload) || request.purpose === 'image_analysis') hold();
      const owned = Object.freeze({ leaseId: lease.leaseId, accountAlias, expiresAt: lease.expiresAt, request });
      leases.set(lease.leaseId, owned); return owned;
    }),
    completeModel: exclusive(async (_mark, leaseId, input, operationSignal) => {
      requireDispatch();
      const lease = leases.get(leaseId);
      if (!lease || lease.expiresAt <= clock().wall) throw failure('STANDING_MODEL_LEASE_NOT_CURRENT');
      const result = snapshotModelResult(input, lease.request, lease.accountAlias, 'siwc_plan');
      const expected = sha(JSON.stringify(result), 'hex');
      leases.delete(leaseId); // One attempt, even when receipt is lost.
      const value = await modelRequest('complete', { leaseId, result }, operationSignal, MAX_MODEL_BODY);
      if (lease.expiresAt <= clock().wall || !exact(value, ['accepted', 'replayed', 'callId', 'resultSha256']) || value.accepted !== true ||
          typeof value.replayed !== 'boolean' || value.callId !== lease.request.callId || value.resultSha256 !== expected) hold();
      return Object.freeze(value);
    }),
    failModel: exclusive(async (_mark, leaseId, operationSignal) => {
      requireDispatch();
      const lease = leases.get(leaseId);
      if (!lease || lease.expiresAt <= clock().wall) throw failure('STANDING_MODEL_LEASE_NOT_CURRENT');
      leases.delete(leaseId);
      try {
        const value = await modelRequest('fail', { leaseId }, operationSignal);
        if (lease.expiresAt <= clock().wall || !exact(value, ['held', 'reason']) || value.held !== true || value.reason !== 'EXECUTION_UNAVAILABLE') hold();
        return Object.freeze(value);
      } finally { close(); }
    }),
    close,
  });
}
