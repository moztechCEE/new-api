// Owner-operated local synthetic experiment, using native New API type 57.
// This is not SIWC, a hosted deployment, a billing proof, or a credential importer.
import { randomUUID } from 'node:crypto';
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
    const deadline = AbortSignal.timeout(CALL_TTL_MS), active = AbortSignal.any([signal, lifetime.signal, deadline]);
    activeCheck(active);
    const key = `${alias}:${request.callId}`;
    if (seen.has(key) || seen.size >= MAX_CALLS || busy.has(alias)) reject('GATEWAY_REPLAY_OR_CAPACITY');
    seen.add(key); busy.add(alias);
    const binding = Object.freeze({ accountAlias: alias, model: MODEL, callId: request.callId,
      inputSha256: request.inputSha256, schemaSha256: request.schemaSha256, gatewayUrl: endpoint });
    const handle = Object.freeze({});
    const fresh = async (phase, outcome) => {
      activeCheck(active);
      let value;
      try { value = await whileActive(Promise.resolve().then(() => { activeCheck(active);
        return attest(Object.freeze({ phase, handle, binding, outcome, signal: active })); }), active); }
      catch { activeCheck(active); reject('ATTESTATION_FAILED'); }
      activeCheck(active); return attestationSnapshot(value, binding, clock());
    };
    let response, responseBody;
    try {
      const before = await fresh('before', 'pending');
      const { payload } = corelyPlanPayload(request, alias);
      const fetching = Promise.resolve().then(() => {
        activeCheck(active);
        if (before.expiresAt <= clock()) reject('ATTESTATION_FAILED');
        return fetchImpl(endpoint, { method: 'POST', redirect: 'error', credentials: 'omit', cache: 'no-store',
          headers: { Authorization: `Bearer ${tokens.get(alias)}`, 'Content-Type': 'application/json', Accept: 'text/event-stream',
            'X-Client-Request-Id': randomUUID() }, body: JSON.stringify(payload), signal: active });
      });
      // A fetch implementation may ignore cancellation and resolve only after
      // its owner has gone away. Observe and discard that late body as well.
      void fetching.then(value => { if (active.aborted) discardResponse(value); }, () => {});
      response = await whileActive(fetching, active);
      activeCheck(active);
      if (!response || types.isProxy(response) || !(response instanceof Response) || response.redirected ||
          (response.url && response.url !== endpoint)) reject('GATEWAY_RESPONSE_INVALID');
      responseBody = response.body;
      if (!response.ok) {
        const after = await fresh('after', 'http_failure');
        if (after.configurationRevision !== before.configurationRevision) reject('ATTESTATION_CHANGED');
        if (before.expiresAt <= clock()) reject('ATTESTATION_FAILED');
        // Native errors cannot attest account funding or quota. In particular,
        // generic 429 never triggers Eason or paid API fallback from this port.
        reject('GATEWAY_HTTP_FAILURE');
      }
      const media = response.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase();
      if (media !== 'text/event-stream') reject('GATEWAY_RESPONSE_INVALID');
      const receipt = await whileActive(consumePlanTextStream(responseBody, active), active);
      activeCheck(active);
      const result = snapshotModelResult({ accountAlias: alias, authMode: 'managed_chatgpt', accountVerified: true, model: MODEL,
        callId: request.callId, inputSha256: request.inputSha256, schemaSha256: request.schemaSha256,
        status: 'success', completionStatus: 'completed', text: receipt.text,
        usage: { inputTokens: receipt.usage.inputTokens, outputTokens: receipt.usage.outputTokens,
          cachedInputTokens: receipt.cachedInputTokens } }, request, alias, 'managed_chatgpt');
      const after = await fresh('after', 'success');
      if (after.configurationRevision !== before.configurationRevision) reject('ATTESTATION_CHANGED');
      if (before.expiresAt <= clock()) reject('ATTESTATION_FAILED');
      activeCheck(active); return result;
    } catch (error) {
      if (deadline.aborted) reject('GATEWAY_TIMEOUT');
      if (active.aborted) reject(closed ? 'GATEWAY_CLOSED' : 'GATEWAY_ABORTED');
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
