// Owner-operated local synthetic experiment, using native New API type 57.
// This is not SIWC, a hosted deployment, a billing proof, or a credential importer.
import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { types } from 'node:util';
import { corelyPlanPayload } from './siwc-local-model-port.mjs';
import { consumePlanTextStream, MODEL, ProbeError } from './siwc-local-runtime.mjs';
import { ModelContractError, snapshotModelRequest, snapshotModelResult } from './corely-model-contract.mjs';

const OWNER_TTL_MS = 120_000, CALL_TTL_MS = 60_000, MAX_CALLS = 100;
const ERROR_CODES = new Set(['INVALID_CONFIGURATION', 'INVALID_REQUEST', 'ATTESTATION_FAILED', 'ATTESTATION_CHANGED',
  'GATEWAY_CLOSED', 'GATEWAY_EXPIRED', 'GATEWAY_ABORTED', 'GATEWAY_TIMEOUT', 'GATEWAY_REPLAY_OR_CAPACITY',
  'GATEWAY_UNAVAILABLE', 'GATEWAY_RESPONSE_INVALID', 'GATEWAY_HTTP_FAILURE', 'INVALID_OUTPUT', 'INVALID_STRUCTURED_OUTPUT']);
const ERRORS = new WeakMap();
export class CodexLocalGatewayError extends Error {
  constructor(code) {
    const safe = ERROR_CODES.has(code) ? code : 'GATEWAY_UNAVAILABLE';
    super(safe); this.name = 'CodexLocalGatewayError'; this.code = safe; ERRORS.set(this, safe);
  }
}
const reject = code => { throw new CodexLocalGatewayError(code); };

function ownData(input, allowed, code) {
  try {
    if (!input || typeof input !== 'object' || types.isProxy(input) || Array.isArray(input) ||
        ![Object.prototype, null].includes(Object.getPrototypeOf(input))) reject(code);
    const result = Object.create(null);
    for (const key of Reflect.ownKeys(input)) {
      if (typeof key !== 'string' || !allowed.includes(key)) reject(code);
      const descriptor = Object.getOwnPropertyDescriptor(input, key);
      if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) reject(code);
      result[key] = descriptor.value;
    }
    return result;
  } catch { reject(code); }
}

function localEndpoint(value) {
  try {
    if (typeof value !== 'string' || !/^http:\/\/127\.0\.0\.1:[1-9][0-9]{3,4}\/v1\/responses$/.test(value)) reject('INVALID_CONFIGURATION');
    const url = new URL(value);
    if (+url.port < 1024 || +url.port > 65535 || url.href !== value) reject('INVALID_CONFIGURATION');
    return value;
  } catch { reject('INVALID_CONFIGURATION'); }
}

function whileActive(work, signal) {
  if (signal.aborted) return Promise.reject(new CodexLocalGatewayError('GATEWAY_ABORTED'));
  return new Promise((resolve, fail) => {
    const abort = () => { signal.removeEventListener('abort', abort); fail(new CodexLocalGatewayError('GATEWAY_ABORTED')); };
    signal.addEventListener('abort', abort, { once: true });
    Promise.resolve(work).then(value => { signal.removeEventListener('abort', abort); resolve(value); },
      error => { signal.removeEventListener('abort', abort); fail(error); });
  });
}

function discardResponse(response) {
  try {
    if (!types.isProxy(response) && response instanceof Response) {
      const body = response.body;
      if (body && !body.locked) void body.cancel().catch(() => {});
    }
  } catch { /* Cleanup must never expose a foreign response value. */ }
}

function attestationSnapshot(input, binding, clock) {
  const proof = ownData(input, ['version', 'accountAlias', 'model', 'authMode', 'accountVerified', 'nativeChannelType',
    'localOnly', 'apiFallbackEnabled', 'freshLoginVerified', 'configurationRevision', 'expiresAt'], 'ATTESTATION_FAILED');
  if (proof.version !== 1 || proof.accountAlias !== binding.accountAlias || proof.model !== MODEL ||
      proof.authMode !== 'managed_chatgpt' || proof.accountVerified !== true || proof.nativeChannelType !== 57 ||
      proof.localOnly !== true || proof.apiFallbackEnabled !== false || proof.freshLoginVerified !== true ||
      typeof proof.configurationRevision !== 'string' || !/^[a-f0-9]{64}$/.test(proof.configurationRevision) ||
      !Number.isSafeInteger(proof.expiresAt) || proof.expiresAt <= clock) reject('ATTESTATION_FAILED');
  return Object.freeze(proof);
}

const SOURCE_VERSION = 'new-api.local-codex-attest.v1', SOURCE_RPC_TTL_MS = 5000;
const HEX64 = /^[a-f0-9]{64}$/;
const SOURCE_RESPONSE_KEYS = ['version', 'channel_id', 'model', 'group', 'nonce', 'phase', 'call_id_hash',
  'input_sha256', 'schema_sha256', 'route_revision', 'issued_at', 'expires_at', 'proof'];

function framedParts(digest, values) {
  for (const value of values) {
    const bytes = Buffer.from(value, 'utf8'), size = Buffer.alloc(4);
    size.writeUInt32BE(bytes.length); digest.update(size); digest.update(bytes); bytes.fill(0);
  }
  return digest;
}

/** Only a fresh, dedicated local login bootstrap may supply these four values.
 * This derives an in-memory comparison key; it neither logs in nor refreshes,
 * reads, transports or stores the underlying credential anywhere.
 */
export function deriveCodexLocalAttestationKey(freshTokens) {
  const tokens = ownData(freshTokens, ['access_token', 'id_token', 'refresh_token', 'account_id'], 'INVALID_CONFIGURATION');
  const values = ['access_token', 'id_token', 'refresh_token', 'account_id'].map(field => tokens[field]);
  if (values.some(value => typeof value !== 'string' || value.length === 0 || Buffer.byteLength(value, 'utf8') > 65_536)) reject('INVALID_CONFIGURATION');
  const digest = createHash('sha256').update('new-api.codex-credential.v1\0', 'utf8');
  return framedParts(digest, values).digest('hex');
}

function sourceBinding(input) {
  const binding = ownData(input, ['accountAlias', 'model', 'callId', 'inputSha256', 'schemaSha256', 'gatewayUrl'], 'ATTESTATION_FAILED');
  if (Object.keys(binding).length !== 6 || !['info', 'eason'].includes(binding.accountAlias) || binding.model !== MODEL ||
      typeof binding.callId !== 'string' || !/^[A-Za-z0-9_-]{1,160}$/.test(binding.callId) ||
      typeof binding.inputSha256 !== 'string' || !HEX64.test(binding.inputSha256) ||
      (binding.schemaSha256 !== null && (typeof binding.schemaSha256 !== 'string' || !HEX64.test(binding.schemaSha256)))) reject('ATTESTATION_FAILED');
  try { localEndpoint(binding.gatewayUrl); } catch { reject('ATTESTATION_FAILED'); }
  return Object.freeze(binding);
}

/** The trusted private bootstrap must separately fence the actual Go image,
 * fresh account login, and complete channel/token/group/retry configuration
 * before AND after every callback. This helper proves only the selected current
 * channel's credential and configuration against that fresh-login key. This is
 * a snapshot/possession check, not proof that inference used the route or debited
 * any quota, and not an authorization grant or bearer token.
 * No prompt, raw credential, MFA operation, HTTP listener or model call exists
 * here. The existing raw-key endpoint retains its normal MFA protection.
 */
export function createCodexLocalSourceAttestor(options) {
  const config = ownData(options, ['accounts', 'requestAttestation', 'signal', 'now'], 'INVALID_CONFIGURATION');
  const requestAttestation = config.requestAttestation, now = config.now ?? Date.now, parentSignal = config.signal;
  if (typeof requestAttestation !== 'function' || types.isProxy(requestAttestation) || typeof now !== 'function' || types.isProxy(now) ||
      types.isProxy(parentSignal) || !(parentSignal instanceof AbortSignal)) reject('INVALID_CONFIGURATION');
  const accounts = ownData(config.accounts, ['info', 'eason'], 'INVALID_CONFIGURATION'), credentials = new Map();
  for (const alias of ['info', 'eason']) {
    const account = ownData(accounts[alias], ['channelId', 'group', 'credentialProofKey64hex', 'freshLoginVerified'], 'INVALID_CONFIGURATION');
    if (!Number.isSafeInteger(account.channelId) || account.channelId <= 0 || typeof account.group !== 'string' || account.group === '' ||
        /[\u0000-\u001f\u007f,]/u.test(account.group) || account.group.trim() !== account.group || Buffer.byteLength(account.group, 'utf8') > 64 ||
        account.freshLoginVerified !== true || typeof account.credentialProofKey64hex !== 'string' || !HEX64.test(account.credentialProofKey64hex)) reject('INVALID_CONFIGURATION');
    credentials.set(alias, { channelId: account.channelId, group: account.group, key: Buffer.from(account.credentialProofKey64hex, 'hex') });
  }
  if (credentials.get('info').channelId === credentials.get('eason').channelId ||
      timingSafeEqual(credentials.get('info').key, credentials.get('eason').key)) reject('INVALID_CONFIGURATION');
  let lastClock;
  const clock = () => {
    let value;
    try { value = now(); } catch { reject('ATTESTATION_FAILED'); }
    if (!Number.isSafeInteger(value) || value < 0 || value > Number.MAX_SAFE_INTEGER - OWNER_TTL_MS ||
        (lastClock !== undefined && value < lastClock)) reject('GATEWAY_EXPIRED');
    lastClock = value; return value;
  };
  const expiresAt = clock() + OWNER_TTL_MS, lifetime = new AbortController(), revisions = new Map(), seen = new Set();
  let closed = false, handles = new WeakMap();
  const close = () => {
    if (closed) return;
    closed = true;
    for (const account of credentials.values()) account.key.fill(0);
    credentials.clear(); revisions.clear(); seen.clear(); handles = new WeakMap(); clearTimeout(timer);
    parentSignal.removeEventListener('abort', close); lifetime.abort();
  };
  const timer = setTimeout(close, OWNER_TTL_MS); timer.unref();
  parentSignal.addEventListener('abort', close, { once: true });
  if (parentSignal.aborted) close();
  const checkActive = active => {
    if (closed) reject('GATEWAY_CLOSED');
    if (clock() >= expiresAt) { close(); reject('GATEWAY_EXPIRED'); }
    if (active.aborted) reject('GATEWAY_ABORTED');
  };
  const attest = async input => {
    let active, deadline, state, pendingPhase;
    try {
      const context = ownData(input, ['phase', 'handle', 'binding', 'outcome', 'signal'], 'ATTESTATION_FAILED');
      if (Object.keys(ownData(context.handle, [], 'ATTESTATION_FAILED')).length !== 0) reject('ATTESTATION_FAILED');
      state = handles.get(context.handle);
      const binding = sourceBinding(context.binding);
      if (Object.keys(context).length !== 5 || types.isProxy(context.signal) || !(context.signal instanceof AbortSignal) ||
          !['before', 'after'].includes(context.phase) || (context.phase === 'before' ? context.outcome !== 'pending' :
            !['success', 'http_failure'].includes(context.outcome))) reject('ATTESTATION_FAILED');
      deadline = AbortSignal.timeout(SOURCE_RPC_TTL_MS);
      active = AbortSignal.any([context.signal, lifetime.signal, deadline]); checkActive(active);
      if (context.phase === 'before') {
        const call = `${binding.accountAlias}:${binding.callId}`;
        if (state || seen.has(call) || seen.size >= MAX_CALLS) reject('ATTESTATION_FAILED');
        seen.add(call); state = { binding, signal: context.signal, phase: 'before-pending' }; handles.set(context.handle, state);
      } else {
        if (!state || state.phase !== 'before-complete' || state.signal !== context.signal || state.expiresAt <= clock() ||
            Object.keys(binding).some(key => binding[key] !== state.binding[key])) reject('ATTESTATION_FAILED');
        state.phase = 'after-pending';
      }
      pendingPhase = state.phase;
      const account = credentials.get(binding.accountAlias);
      let nonce;
      do { nonce = randomBytes(32).toString('hex'); } while (nonce === state.nonce);
      state.nonce = nonce;
      const payload = Object.freeze({ nonce, phase: context.phase, call_id_hash: createHash('sha256').update(binding.callId, 'utf8').digest('hex'),
        input_sha256: binding.inputSha256, schema_sha256: binding.schemaSha256, model: binding.model, group: account.group });
      const rpc = Object.freeze({ accountAlias: binding.accountAlias, channelId: account.channelId, payload, signal: active });
      let raw;
      try {
        raw = await whileActive(Promise.resolve().then(() => { checkActive(active); return requestAttestation(rpc); }), active);
      } catch {
        checkActive(active); reject('ATTESTATION_FAILED');
      }
      checkActive(active);
      const proof = ownData(raw, SOURCE_RESPONSE_KEYS, 'ATTESTATION_FAILED'), currentTime = clock();
      if (Object.keys(proof).length !== SOURCE_RESPONSE_KEYS.length || proof.version !== SOURCE_VERSION || proof.channel_id !== account.channelId ||
          proof.model !== binding.model || proof.group !== account.group || proof.nonce !== payload.nonce || proof.phase !== context.phase ||
          proof.call_id_hash !== payload.call_id_hash || proof.input_sha256 !== binding.inputSha256 || proof.schema_sha256 !== binding.schemaSha256 ||
          typeof proof.route_revision !== 'string' || !HEX64.test(proof.route_revision) || typeof proof.proof !== 'string' || !HEX64.test(proof.proof) ||
          !Number.isSafeInteger(proof.issued_at) || !Number.isSafeInteger(proof.expires_at) || proof.issued_at < 0 ||
          Math.abs(proof.issued_at - currentTime) > 5000 || proof.expires_at <= currentTime || proof.expires_at <= proof.issued_at ||
          proof.expires_at - proof.issued_at > OWNER_TTL_MS) reject('ATTESTATION_FAILED');
      const mac = framedParts(createHmac('sha256', account.key), [proof.version, proof.nonce, proof.phase, proof.call_id_hash,
        proof.input_sha256, proof.schema_sha256 ?? '-', proof.model, proof.group, `${proof.channel_id}`, proof.route_revision,
        `${proof.issued_at}`, `${proof.expires_at}`]).digest();
      if (!timingSafeEqual(mac, Buffer.from(proof.proof, 'hex'))) reject('ATTESTATION_FAILED');
      if (revisions.has(binding.accountAlias) && revisions.get(binding.accountAlias) !== proof.route_revision) reject('ATTESTATION_CHANGED');
      revisions.set(binding.accountAlias, proof.route_revision);
      checkActive(active);
      if (state.phase !== pendingPhase) reject('ATTESTATION_FAILED');
      const boundExpiry = Math.min(proof.expires_at, expiresAt, state.expiresAt ?? expiresAt);
      if (boundExpiry <= clock()) reject('ATTESTATION_FAILED');
      state.expiresAt = boundExpiry; state.phase = context.phase === 'before' ? 'before-complete' : 'after-complete';
      return Object.freeze({ version: 1, accountAlias: binding.accountAlias, model: MODEL, authMode: 'managed_chatgpt', accountVerified: true,
        nativeChannelType: 57, localOnly: true, apiFallbackEnabled: false, freshLoginVerified: true,
        configurationRevision: proof.route_revision, expiresAt: boundExpiry });
    } catch (error) {
      if (state) state.phase = 'failed';
      if (closed) reject('GATEWAY_CLOSED');
      if (deadline?.aborted) reject('ATTESTATION_FAILED');
      if (active?.aborted) reject('GATEWAY_ABORTED');
      if (ERRORS.has(error)) throw new CodexLocalGatewayError(ERRORS.get(error));
      reject('ATTESTATION_FAILED');
    }
  };
  return Object.freeze({ attest, close });
}

/** The trusted LOCAL bootstrap supplies the fresh-login/account/model evidence
 * and rechecks isolated Go channel/token configuration before AND after a call.
 * It must verify the selected token has exactly its fresh type57 account, no
 * alternative upstream, override, retry, or paid API route. The empty handle is
 * per-call identity, not a reusable grant. No prompt or credential enters it.
 * These assertions are not established by localhost, a model name, or SSE alone.
 * There is deliberately no HTTP listener, account switching, or API fallback.
 */
export function createCodexLocalGatewayModelTransports(options) {
  const config = ownData(options, ['gatewayUrl', 'accounts', 'attest', 'signal', 'fetchImpl', 'now'], 'INVALID_CONFIGURATION');
  const endpoint = localEndpoint(config.gatewayUrl), attest = config.attest;
  const fetchImpl = config.fetchImpl ?? globalThis.fetch, now = config.now ?? Date.now;
  if (typeof attest !== 'function' || typeof fetchImpl !== 'function' || typeof now !== 'function' ||
      types.isProxy(config.signal) || !(config.signal instanceof AbortSignal)) reject('INVALID_CONFIGURATION');
  const accounts = ownData(config.accounts, ['info', 'eason'], 'INVALID_CONFIGURATION'), tokens = new Map();
  for (const alias of ['info', 'eason']) {
    const account = ownData(accounts[alias], ['gatewayToken'], 'INVALID_CONFIGURATION');
    if (typeof account.gatewayToken !== 'string' || !/^[A-Za-z0-9._~-]{32,512}$/.test(account.gatewayToken)) reject('INVALID_CONFIGURATION');
    tokens.set(alias, account.gatewayToken);
  }
  if (tokens.get('info') === tokens.get('eason')) reject('INVALID_CONFIGURATION');
  let lastClock;
  const clock = () => {
    let value;
    try { value = now(); } catch { reject('GATEWAY_UNAVAILABLE'); }
    if (!Number.isSafeInteger(value) || value < 0 || value > Number.MAX_SAFE_INTEGER - OWNER_TTL_MS ||
        (lastClock !== undefined && value < lastClock)) reject('GATEWAY_EXPIRED');
    lastClock = value; return value;
  };
  const expiresAt = clock() + OWNER_TTL_MS, lifetime = new AbortController(), seen = new Set(), busy = new Set();
  let closed = false;
  const close = () => {
    if (closed) return;
    closed = true; tokens.clear(); seen.clear(); clearTimeout(timer);
    config.signal.removeEventListener('abort', close); lifetime.abort();
  };
  const timer = setTimeout(close, OWNER_TTL_MS); timer.unref();
  config.signal.addEventListener('abort', close, { once: true });
  if (config.signal.aborted) close();
  const activeCheck = active => {
    if (closed) reject('GATEWAY_CLOSED');
    if (clock() >= expiresAt) { close(); reject('GATEWAY_EXPIRED'); }
    if (active.aborted) reject('GATEWAY_ABORTED');
  };
  const generate = async (alias, input, signal) => {
    let request;
    try { request = snapshotModelRequest(input); } catch { reject('INVALID_REQUEST'); }
    if (types.isProxy(signal) || !(signal instanceof AbortSignal)) reject('INVALID_REQUEST');
    const ownerActive = AbortSignal.any([signal, lifetime.signal]);
    activeCheck(ownerActive);
    const key = `${alias}:${request.callId}`;
    if (seen.has(key) || seen.size >= MAX_CALLS || busy.has(alias)) reject('GATEWAY_REPLAY_OR_CAPACITY');
    seen.add(key); busy.add(alias);
    const binding = Object.freeze({ accountAlias: alias, model: MODEL, callId: request.callId,
      inputSha256: request.inputSha256, schemaSha256: request.schemaSha256, gatewayUrl: endpoint });
    const handle = Object.freeze({});
    const fresh = async (phase, outcome) => {
      activeCheck(ownerActive);
      const sourceDeadline = AbortSignal.timeout(SOURCE_RPC_TTL_MS), sourceActive = AbortSignal.any([ownerActive, sourceDeadline]);
      let value;
      try { value = await whileActive(Promise.resolve().then(() => { activeCheck(sourceActive);
        // Stable owner/caller identity is shared across phases; each source RPC
        // has its own bounded wait and the trusted source helper also aborts its
        // callback independently. No completed model deadline owns this check.
        return attest(Object.freeze({ phase, handle, binding, outcome, signal: ownerActive })); }), sourceActive); }
      catch { activeCheck(ownerActive); reject('ATTESTATION_FAILED'); }
      activeCheck(ownerActive);
      if (sourceDeadline.aborted) reject('ATTESTATION_FAILED');
      return attestationSnapshot(value, binding, clock());
    };
    let response, responseBody, modelDeadline, modelActive, modelFinished = false;
    try {
      const before = await fresh('before', 'pending');
      const { payload } = corelyPlanPayload(request, alias);
      // The 60s budget starts at dispatch, not while source verification waits,
      // and ends only after the full model stream has completed.
      modelDeadline = AbortSignal.timeout(CALL_TTL_MS);
      modelActive = AbortSignal.any([ownerActive, modelDeadline]);
      const fetching = Promise.resolve().then(() => {
        activeCheck(modelActive);
        if (before.expiresAt <= clock()) reject('ATTESTATION_FAILED');
        return fetchImpl(endpoint, { method: 'POST', redirect: 'error', credentials: 'omit', cache: 'no-store',
          headers: { Authorization: `Bearer ${tokens.get(alias)}`, 'Content-Type': 'application/json', Accept: 'text/event-stream',
            'X-Client-Request-Id': randomUUID() }, body: JSON.stringify(payload), signal: modelActive });
      });
      // A fetch implementation may ignore cancellation and resolve only after
      // its owner has gone away. Observe and discard that late body as well.
      void fetching.then(value => { if (modelActive.aborted) discardResponse(value); }, () => {});
      response = await whileActive(fetching, modelActive);
      activeCheck(modelActive);
      if (!response || types.isProxy(response) || !(response instanceof Response) || response.redirected ||
          (response.url && response.url !== endpoint)) reject('GATEWAY_RESPONSE_INVALID');
      responseBody = response.body;
      if (!response.ok) {
        modelFinished = true;
        const after = await fresh('after', 'http_failure');
        if (after.configurationRevision !== before.configurationRevision) reject('ATTESTATION_CHANGED');
        if (before.expiresAt <= clock()) reject('ATTESTATION_FAILED');
        // Native errors cannot attest account funding or quota. In particular,
        // generic 429 never triggers Eason or paid API fallback from this port.
        reject('GATEWAY_HTTP_FAILURE');
      }
      const media = response.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase();
      if (media !== 'text/event-stream') reject('GATEWAY_RESPONSE_INVALID');
      const receipt = await whileActive(consumePlanTextStream(responseBody, modelActive), modelActive);
      activeCheck(modelActive);
      modelFinished = true;
      const result = snapshotModelResult({ accountAlias: alias, authMode: 'managed_chatgpt', accountVerified: true, model: MODEL,
        callId: request.callId, inputSha256: request.inputSha256, schemaSha256: request.schemaSha256,
        status: 'success', completionStatus: 'completed', text: receipt.text,
        usage: { inputTokens: receipt.usage.inputTokens, outputTokens: receipt.usage.outputTokens,
          cachedInputTokens: receipt.cachedInputTokens } }, request, alias, 'managed_chatgpt');
      const after = await fresh('after', 'success');
      if (after.configurationRevision !== before.configurationRevision) reject('ATTESTATION_CHANGED');
      if (before.expiresAt <= clock()) reject('ATTESTATION_FAILED');
      activeCheck(ownerActive); return result;
    } catch (error) {
      if (ownerActive.aborted) reject(closed ? 'GATEWAY_CLOSED' : 'GATEWAY_ABORTED');
      if (!modelFinished && modelDeadline?.aborted) reject('GATEWAY_TIMEOUT');
      if (ERRORS.has(error)) throw new CodexLocalGatewayError(ERRORS.get(error));
      // Only fixed shared-validator classes can cross this boundary. Never
      // retain an upstream exception/body, diagnostic, cause, or access token.
      let contractCode;
      try {
        if (!types.isProxy(error) && error instanceof ModelContractError) {
          const descriptor = Object.getOwnPropertyDescriptor(error, 'code');
          if (descriptor && Object.hasOwn(descriptor, 'value') &&
              ['INVALID_OUTPUT', 'INVALID_STRUCTURED_OUTPUT'].includes(descriptor.value)) contractCode = descriptor.value;
        }
      } catch { /* A foreign typed error cannot supply executable diagnostics. */ }
      if (contractCode) reject(contractCode);
      if (!types.isProxy(error) && error instanceof ProbeError) reject('GATEWAY_RESPONSE_INVALID');
      reject('GATEWAY_UNAVAILABLE');
    } finally {
      busy.delete(alias);
      discardResponse(response);
    }
  };
  const port = alias => Object.freeze({ authMode: 'managed_chatgpt',
    capabilities: Object.freeze({ text: true, structuredJson: true, images: false }),
    generate: (request, signal) => generate(alias, request, signal) });
  return Object.freeze({ ports: Object.freeze({ info: port('info'), eason: port('eason') }), close });
}
