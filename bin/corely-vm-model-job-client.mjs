// Dedicated DEV VM synthetic-job authority. This is not an OpenAI credential
// importer, provider client, public producer, or normal customer-service route.
import { KeyObject, createHash, createPublicKey, randomUUID, sign } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { snapshotModelRequest, snapshotModelResult } from './corely-model-contract.mjs';

export const CORELY_VM_MODEL_JOB_RESOURCE = 'https://moztech-api-dev-candidates-sp5g377smq-de.a.run.app/work-candidates/vm-model-jobs';
export const CORELY_VM_MODEL_JOB_ISSUER = `${CORELY_VM_MODEL_JOB_RESOURCE}/oauth`;
export const CORELY_VM_MODEL_JOB_SCOPE = 'corely:dev-vm-model-jobs';
export const CORELY_VM_MODEL_JOB_CLIENT_ID = 'corely-vm-model-jobs-dev';
export const CORELY_VM_HOST_ID_HASH = '89d0316d433fbf80da04c4b8ad5a2cc12daa28d8720886916ba2f6b9558519e0';
export const CORELY_VM_VERIFICATION_URI = 'https://agent-dev.corely.cc/ops/work-candidates/vm-model-jobs/connect';
const MAX_GRANT_MS = 86_400_000;
const MAX_POLL_WAKEUPS = 32;
const CODES = new Set(['INVALID_OPTIONS', 'INVALID_KEY', 'ABORTED', 'AUTHORIZATION_FAILED', 'AUTHORIZATION_TIMEOUT',
  'AUTHORIZATION_DENIED', 'DEVICE_RESPONSE_INVALID', 'TOKEN_RESPONSE_INVALID', 'TOKEN_EXCHANGE_UNCERTAIN',
  'GRANT_EXPIRED', 'GRANT_CLOSED', 'RESOURCE_REQUEST_UNCERTAIN', 'RESOURCE_RESPONSE_INVALID', 'MODEL_JOB_NOT_CURRENT']);
export class VmModelJobClientError extends Error {
  constructor(code) { super(CODES.has(code) ? code : 'INVALID_OPTIONS'); this.name = 'VmModelJobClientError'; this.code = this.message; }
}
const failure = code => new VmModelJobClientError(code);
const sha256 = value => createHash('sha256').update(value).digest('base64url');

function untilAborted(work, signal) {
  if (signal.aborted) return Promise.reject(signal.reason);
  return new Promise((resolve, reject) => {
    const abort = () => { signal.removeEventListener('abort', abort); reject(signal.reason); };
    signal.addEventListener('abort', abort, { once: true });
    Promise.resolve(work).then(value => { signal.removeEventListener('abort', abort); resolve(value); },
      error => { signal.removeEventListener('abort', abort); reject(error); });
  });
}

function waitInterval(ms, signal) {
  return new Promise((resolve, reject) => {
    const abort = () => { clearTimeout(timer); reject(failure('ABORTED')); };
    const timer = setTimeout(() => { signal.removeEventListener('abort', abort); resolve(); }, ms);
    if (signal.aborted) abort(); else signal.addEventListener('abort', abort, { once: true });
  });
}

/** Only called with this module's fixed TLS endpoints. No redirects, cookies,
 * retries, logging, unbounded bodies, or raw provider errors escape here. */
async function requestJson(endpoint, { fetchImpl, method = 'POST', body, proof, token, signal, requestTimeoutMs, limit = 16_384, kind, flatResponse = false }) {
  const controller = new AbortController(), abort = () => controller.abort(failure('ABORTED'));
  const uncertain = kind === 'token' ? 'TOKEN_EXCHANGE_UNCERTAIN' : kind === 'resource' ? 'RESOURCE_REQUEST_UNCERTAIN' : 'AUTHORIZATION_FAILED';
  const invalid = kind === 'token' ? 'TOKEN_RESPONSE_INVALID' : kind === 'resource' ? 'RESOURCE_RESPONSE_INVALID' : 'DEVICE_RESPONSE_INVALID';
  const serialized = body === undefined ? undefined : JSON.stringify(body);
  if (serialized !== undefined && Buffer.byteLength(serialized) > limit) throw failure(invalid);
  signal?.addEventListener('abort', abort, { once: true }); if (signal?.aborted) abort();
  const timer = setTimeout(() => controller.abort(failure(uncertain)), requestTimeoutMs);
  let reader, response;
  try {
    response = await untilAborted(Promise.resolve().then(() => {
      controller.signal.throwIfAborted();
      return fetchImpl(endpoint, { method, redirect: 'error', credentials: 'omit', cache: 'no-store',
        headers: { Accept: 'application/json', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
          ...(proof ? { DPoP: proof } : {}), ...(token ? { Authorization: `DPoP ${token}` } : {}) },
        ...(serialized === undefined ? {} : { body: serialized }), signal: controller.signal });
    }), controller.signal);
    if (!response || response.redirected || (response.url && response.url !== endpoint) ||
        !/^application\/json(?:\s*;|$)/i.test(response.headers?.get('content-type') ?? '') || !response.body?.getReader) throw failure(invalid);
    reader = response.body.getReader(); const chunks = []; let size = 0;
    for (;;) {
      const part = await untilAborted(reader.read(), controller.signal); if (part.done) break;
      if (!(part.value instanceof Uint8Array) || (size += part.value.byteLength) > limit) throw failure(invalid);
      chunks.push(part.value);
    }
    let text, value;
    try { text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)); value = JSON.parse(text); }
    catch { throw failure(invalid); }
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw failure(invalid);
    // Both OAuth responses are flat, fixed-field JSON. Reject escaped or
    // duplicate member names instead of accepting ambiguous credentials.
    if (kind !== 'resource' || flatResponse) {
      const names = [...text.matchAll(/"([a-z_]+)"\s*:/g)].map(match => match[1]);
      if (text.includes('\\') || names.length !== Object.keys(value).length || new Set(names).size !== names.length) throw failure(invalid);
    }
    if (kind === 'token' && response.status === 400 && Object.keys(value).length === 1 &&
        ['authorization_pending', 'slow_down', 'access_denied', 'expired_token'].includes(value.error)) return { oauthError: value.error };
    if (response.status !== 200) throw failure(invalid);
    return value;
  } catch (error) {
    if (error instanceof VmModelJobClientError) throw error;
    if (controller.signal.aborted && controller.signal.reason instanceof VmModelJobClientError) throw controller.signal.reason;
    throw failure(uncertain);
  } finally {
    clearTimeout(timer); signal?.removeEventListener('abort', abort);
    if (reader) { try { Promise.resolve(reader.cancel()).catch(() => {}); reader.releaseLock(); } catch { /* No late result is accepted. */ } }
    else if (response?.body && !response.body.locked) void response.body.cancel().catch(() => {});
  }
}

/** The caller supplies a pre-verified, protected-store Ed25519 KeyObject.
 * This helper neither generates nor persists keys/tokens. It never reads env,
 * native logins, OpenAI credentials, customers, or arbitrary URLs/operations. */
export async function connectCorelyVmModelJobs(options = {}) {
  if (!options || typeof options !== 'object' || Array.isArray(options) || Object.keys(options).some(key =>
    !['privateKey', 'expectedKeyThumbprint', 'onAuthorize', 'fetchImpl', 'signal', 'now', 'monotonicNow', 'sleep', 'requestTimeoutMs'].includes(key))) throw failure('INVALID_OPTIONS');
  const { privateKey, expectedKeyThumbprint, onAuthorize, fetchImpl = globalThis.fetch, signal, now = Date.now,
    monotonicNow = () => performance.now(), sleep = waitInterval, requestTimeoutMs = 15_000 } = options;
  if (typeof onAuthorize !== 'function' || typeof fetchImpl !== 'function' || typeof now !== 'function' || typeof monotonicNow !== 'function' || typeof sleep !== 'function' ||
      !Number.isSafeInteger(requestTimeoutMs) || requestTimeoutMs < 10 || requestTimeoutMs > 30_000 ||
      (signal !== undefined && !(signal instanceof AbortSignal))) throw failure('INVALID_OPTIONS');
  if (signal?.aborted) throw failure('ABORTED');
  let jwk, keyThumbprint;
  try {
    if (!(privateKey instanceof KeyObject) || privateKey.type !== 'private' || privateKey.asymmetricKeyType !== 'ed25519') throw failure('INVALID_KEY');
    const exported = createPublicKey(privateKey).export({ format: 'jwk' });
    if (exported.kty !== 'OKP' || exported.crv !== 'Ed25519' || !/^[A-Za-z0-9_-]{43}$/.test(exported.x)) throw failure('INVALID_KEY');
    jwk = Object.freeze({ kty: 'OKP', crv: 'Ed25519', x: exported.x });
    keyThumbprint = sha256(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: exported.x }));
    if (keyThumbprint !== expectedKeyThumbprint) throw failure('INVALID_KEY');
  } catch { throw failure('INVALID_KEY'); }
  let lastClock = -1;
  const readClock = () => {
    let value; try { value = now(); } catch { throw failure('INVALID_OPTIONS'); }
    if (!Number.isSafeInteger(value) || value < 0 || value < lastClock) throw failure('INVALID_OPTIONS');
    lastClock = value; return value;
  };
  let lastMonotonic = -1;
  const readMonotonic = () => {
    let value; try { value = monotonicNow(); } catch { throw failure('INVALID_OPTIONS'); }
    if (!Number.isFinite(value) || value < 0 || value > Number.MAX_SAFE_INTEGER - MAX_GRANT_MS || value < lastMonotonic) throw failure('INVALID_OPTIONS');
    lastMonotonic = value; return value;
  };
  const proof = (endpoint, method, accessToken) => {
    const header = Buffer.from(JSON.stringify({ typ: 'dpop+jwt', alg: 'EdDSA', jwk })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ htu: endpoint, htm: method, iat: Math.floor(readClock() / 1000), jti: randomUUID(),
      ...(accessToken ? { ath: sha256(accessToken) } : {}) })).toString('base64url');
    const message = `${header}.${payload}`;
    try { return `${message}.${sign(null, Buffer.from(message), privateKey).toString('base64url')}`; }
    catch { throw failure('INVALID_KEY'); }
  };
  const authorizationStarted = readClock(), authorizationMonotonic = readMonotonic();
  const transaction = new AbortController(), abort = () => transaction.abort(failure('ABORTED'));
  signal?.addEventListener('abort', abort, { once: true });
  const timer = setTimeout(() => transaction.abort(failure('AUTHORIZATION_TIMEOUT')), 300_000);
  let token = '', expiresAt = 0, tokenStarted = 0, grantLifetime = 0;
  try {
    const deviceEndpoint = `${CORELY_VM_MODEL_JOB_ISSUER}/device_authorization`;
    const device = await requestJson(deviceEndpoint, { fetchImpl, requestTimeoutMs,
      signal: transaction.signal, kind: 'device', proof: proof(deviceEndpoint, 'POST'),
      body: { client_id: CORELY_VM_MODEL_JOB_CLIENT_ID, scope: CORELY_VM_MODEL_JOB_SCOPE,
        resource: CORELY_VM_MODEL_JOB_RESOURCE, vm_host_id_hash: CORELY_VM_HOST_ID_HASH, jwk } });
    if (Object.keys(device).length !== 6 || !/^vm_models_device_[A-Za-z0-9_-]{43}$/.test(device.device_code ?? '') ||
        !/^[A-F0-9]{4}-[A-F0-9]{4}$/.test(device.user_code ?? '') || device.verification_uri !== CORELY_VM_VERIFICATION_URI ||
        typeof device.verification_uri_complete !== 'string' || !device.verification_uri_complete.startsWith(`${CORELY_VM_VERIFICATION_URI}?requestId=vm_models_`) ||
        !/^vm_models_[A-Za-z0-9_-]{43}$/.test(device.verification_uri_complete.slice(`${CORELY_VM_VERIFICATION_URI}?requestId=`.length)) ||
        device.expires_in !== 300 || device.interval !== 5) throw failure('DEVICE_RESPONSE_INVALID');
    await untilAborted(Promise.resolve().then(() => onAuthorize(Object.freeze({ verificationUri: CORELY_VM_VERIFICATION_URI,
      verificationUriComplete: device.verification_uri_complete, userCode: device.user_code, expiresIn: 300, interval: 5,
      scope: CORELY_VM_MODEL_JOB_SCOPE, vmHostIdHash: CORELY_VM_HOST_ID_HASH, keyThumbprint }))), transaction.signal);
    let interval = 5000;
    for (;;) {
      let wall = readClock(), monotonic = readMonotonic();
      const wallDeadline = wall + interval, monotonicDeadline = monotonic + interval;
      let wakeups = 0;
      // Timers may wake early. Keep both deadlines fixed for this poll and
      // supplement only the remaining wait; never shorten the server interval
      // or restart the five-minute authorization lifetime.
      for (;;) {
        const authorizationRemaining = Math.min(authorizationStarted + 300_000 - wall,
          authorizationMonotonic + 300_000 - monotonic);
        if (authorizationRemaining <= 0) throw failure('AUTHORIZATION_TIMEOUT');
        const remaining = Math.max(wallDeadline - wall, monotonicDeadline - monotonic);
        if (remaining <= 0) break;
        if (++wakeups > MAX_POLL_WAKEUPS) throw failure('INVALID_OPTIONS');
        await untilAborted(sleep(Math.ceil(Math.min(remaining, authorizationRemaining)), transaction.signal), transaction.signal);
        const previousWall = wall, previousMonotonic = monotonic;
        wall = readClock(); monotonic = readMonotonic();
        if (wall === previousWall && monotonic === previousMonotonic) throw failure('INVALID_OPTIONS');
      }
      const endpoint = `${CORELY_VM_MODEL_JOB_ISSUER}/token`, started = readClock(), startedMonotonic = readMonotonic();
      const value = await requestJson(endpoint, { fetchImpl, requestTimeoutMs, signal: transaction.signal, kind: 'token', proof: proof(endpoint, 'POST'),
        body: { grant_type: 'urn:ietf:params:oauth:grant-type:device_code', client_id: CORELY_VM_MODEL_JOB_CLIENT_ID,
          resource: CORELY_VM_MODEL_JOB_RESOURCE, device_code: device.device_code } });
      if (value.oauthError === 'authorization_pending') continue;
      if (value.oauthError === 'slow_down') { interval += 5000; continue; }
      if (value.oauthError === 'access_denied') throw failure('AUTHORIZATION_DENIED');
      if (value.oauthError === 'expired_token') throw failure('AUTHORIZATION_TIMEOUT');
      if (Object.keys(value).length !== 4 || !/^vm_models_access_[A-Za-z0-9_-]{43}$/.test(value.access_token ?? '') ||
          value.token_type !== 'DPoP' || value.scope !== CORELY_VM_MODEL_JOB_SCOPE || !Number.isSafeInteger(value.expires_in) ||
          value.expires_in < 1 || value.expires_in * 1000 > MAX_GRANT_MS) throw failure('TOKEN_RESPONSE_INVALID');
      grantLifetime = value.expires_in * 1000; expiresAt = started + grantLifetime; tokenStarted = startedMonotonic;
      token = value.access_token;
      if (readClock() >= expiresAt || readMonotonic() - tokenStarted >= grantLifetime) throw failure('GRANT_EXPIRED');
      break;
    }
  } catch (error) {
    token = '';
    if (error instanceof VmModelJobClientError) throw error;
    if (transaction.signal.aborted && transaction.signal.reason instanceof VmModelJobClientError) throw transaction.signal.reason;
    throw failure('AUTHORIZATION_FAILED');
  } finally { clearTimeout(timer); signal?.removeEventListener('abort', abort); }
  let closed = false, held = false, stopping = false;
  const leases = new Map();
  const close = () => { closed = true; token = ''; leases.clear(); signal?.removeEventListener('abort', close); };
  signal?.addEventListener('abort', close, { once: true });
  const live = (terminal = false) => {
    if (signal?.aborted) { close(); throw failure('ABORTED'); }
    if (closed || !token) throw failure('GRANT_CLOSED');
    if (stopping && !terminal) throw failure('GRANT_CLOSED');
    if (held) throw failure('RESOURCE_REQUEST_UNCERTAIN');
    if (readClock() >= expiresAt || readMonotonic() - tokenStarted >= grantLifetime) { close(); throw failure('GRANT_EXPIRED'); }
  };
  const resource = async (operation, body, operationSignal, { limit = 1024 * 1024, flatResponse = false, timeoutMs = requestTimeoutMs, terminal = false } = {}) => {
    live(terminal);
    if (operationSignal !== undefined && !(operationSignal instanceof AbortSignal)) throw failure('INVALID_OPTIONS');
    const active = signal && operationSignal ? AbortSignal.any([signal, operationSignal]) : signal ?? operationSignal;
    const endpoint = `${CORELY_VM_MODEL_JOB_RESOURCE}/${operation}`, method = operation === 'status' ? 'GET' : 'POST';
    try {
      const value = await requestJson(endpoint, { fetchImpl, requestTimeoutMs: timeoutMs, signal: active, kind: 'resource', method, body,
        token, proof: proof(endpoint, method, token), limit, flatResponse });
      live(terminal); return value;
    } catch (error) { held = true; throw error; }
  };
  const bindingValid = value => value.vmHostIdHash === CORELY_VM_HOST_ID_HASH && value.keyThumbprint === keyThumbprint;
  live();
  return Object.freeze({
    receipt() { live(); return Object.freeze({ status: 'CORELY_VM_MODEL_JOB_GRANT_CONNECTED', scope: CORELY_VM_MODEL_JOB_SCOPE,
      resource: CORELY_VM_MODEL_JOB_RESOURCE, vmHostIdHash: CORELY_VM_HOST_ID_HASH, keyThumbprint, expiresAt,
      syntheticOnly: true, apiFallbackEnabled: false, sendingCapability: false, learningCapability: false }); },
    async modelStatus(operationSignal) {
      const value = await resource('status', undefined, operationSignal);
      // V1 explicitly has no producer. The hosted synthetic producer is a
      // paired V2 contract, not permission to accept a bare boolean flip or
      // extra fields from an unknown service/version.
      const legacy = Object.keys(value).length === 14 && value.status === 'SYNTHETIC_VM_MODEL_TRANSPORT' && value.producerConnected === false;
      const hosted = Object.keys(value).length === 15 && value.status === 'SYNTHETIC_VM_MODEL_TRANSPORT_V2' &&
        value.contractVersion === 2 && typeof value.producerConnected === 'boolean';
      if ((!legacy && !hosted) || value.scope !== CORELY_VM_MODEL_JOB_SCOPE ||
          value.tenantId !== 'moztech' || value.brandId !== 'moztech-test' || value.authMode !== 'siwc_plan' || value.syntheticOnly !== true ||
          typeof value.enrolled !== 'boolean' || value.apiFallbackEnabled !== false ||
          value.sendingCapability !== false || value.learningCapability !== false || !bindingValid(value) || !Number.isSafeInteger(value.expiresAt) ||
          value.expiresAt <= readClock() || value.expiresAt > expiresAt + requestTimeoutMs) throw failure('RESOURCE_RESPONSE_INVALID');
      return Object.freeze({ ...value });
    },
    async enrollModels(operationSignal) {
      const value = await resource('enroll', {}, operationSignal);
      if (Object.keys(value).length !== 9 || value.enrolled !== true || value.authMode !== 'siwc_plan' || value.syntheticOnly !== true ||
          value.apiFallbackEnabled !== false || value.sendingCapability !== false || value.learningCapability !== false || !bindingValid(value) ||
          !Number.isSafeInteger(value.expiresAt) || value.expiresAt <= readClock() || value.expiresAt > expiresAt + requestTimeoutMs) throw failure('RESOURCE_RESPONSE_INVALID');
      return Object.freeze({ ...value });
    },
    async claimModel(accountAlias, operationSignal) {
      live(); if (!['info', 'eason'].includes(accountAlias)) throw failure('INVALID_OPTIONS');
      for (const [id, lease] of leases) if (lease.expiresAt <= readClock()) leases.delete(id);
      if (leases.size >= 32) throw failure('MODEL_JOB_NOT_CURRENT');
      const value = await resource('claim', { accountAlias }, operationSignal);
      if (Object.keys(value).length !== 2 || value.authMode !== 'siwc_plan') throw failure('RESOURCE_RESPONSE_INVALID');
      if (value.lease === null) return null;
      const lease = value.lease;
      if (!lease || typeof lease !== 'object' || Array.isArray(lease) || Object.keys(lease).length !== 4 ||
          !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(lease.leaseId ?? '') || lease.accountAlias !== accountAlias ||
          !Number.isSafeInteger(lease.expiresAt) || lease.expiresAt <= readClock() || lease.expiresAt > Math.min(expiresAt + requestTimeoutMs, readClock() + 60_000) ||
          leases.has(lease.leaseId)) throw failure('RESOURCE_RESPONSE_INVALID');
      let request; try { request = snapshotModelRequest(lease.request); } catch { throw failure('RESOURCE_RESPONSE_INVALID'); }
      const owned = Object.freeze({ leaseId: lease.leaseId, accountAlias, expiresAt: lease.expiresAt, request });
      leases.set(owned.leaseId, owned); return owned;
    },
    async completeModel(leaseId, input, operationSignal) {
      live(); const lease = leases.get(leaseId);
      if (!lease || lease.expiresAt <= readClock()) throw failure('MODEL_JOB_NOT_CURRENT');
      let result; try { result = snapshotModelResult(input, lease.request, lease.accountAlias, 'siwc_plan'); }
      catch { throw failure('RESOURCE_RESPONSE_INVALID'); }
      const expected = createHash('sha256').update(JSON.stringify(result)).digest('hex');
      // A completion is a one-shot submission. Lost/malformed receipts never
      // permit a second submission or an implicit model re-execution.
      leases.delete(leaseId);
      const value = await resource('complete', { leaseId, result }, operationSignal);
      if (lease.expiresAt <= readClock() || Object.keys(value).length !== 4 || value.accepted !== true || typeof value.replayed !== 'boolean' ||
          value.callId !== lease.request.callId || value.resultSha256 !== expected) throw failure('RESOURCE_RESPONSE_INVALID');
      return Object.freeze({ ...value });
    },
    async failModel(leaseId, operationSignal) {
      live(); const lease = leases.get(leaseId);
      if (!lease || lease.expiresAt <= readClock()) throw failure('MODEL_JOB_NOT_CURRENT');
      // Only an owned, still-leased call can stop this grant. A failed or lost
      // completion has already consumed its local lease and cannot be retried
      // here. No prompt, result, provider error or credential enters this body.
      leases.delete(leaseId);
      stopping = true;
      try {
        const value = await resource('fail', { leaseId }, operationSignal,
          { limit: 4096, flatResponse: true, timeoutMs: Math.min(requestTimeoutMs, 5000), terminal: true });
        if (lease.expiresAt <= readClock() || Object.keys(value).length !== 2 || value.held !== true ||
            value.reason !== 'EXECUTION_UNAVAILABLE') throw failure('RESOURCE_RESPONSE_INVALID');
        return Object.freeze({ held: true, reason: 'EXECUTION_UNAVAILABLE' });
      } finally { close(); }
    },
    close() { close(); return Object.freeze({ status: 'CORELY_VM_MODEL_JOB_GRANT_CLOSED', remoteRevocation: 'NOT_PERFORMED' }); },
  });
}
