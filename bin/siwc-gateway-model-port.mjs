// Private synthetic DEV transport. New API is on the inference path, but never
// receives app-owned OAuth credentials. It receives only a separate gateway key.
// Release prerequisite: the exact dedicated token/model/path must match a
// strict-affinity, single-attempt rule and a single SIWC-only channel/group.
// No cross-group retry, paid channel, parameter/status mapping, or broad header
// passthrough is permitted. This module cannot attest an administrator's config.
// OWASP ASVS 5.0 controls considered: 4.1.1-4, 4.2.1-5, 10.1.1, 10.3.1-2,
// 12.2.1-2 and 12.3.1-4. TLS/private listener configuration is the bootstrap's
// responsibility; these focused controls are not a full ASVS compliance claim.
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { isIP } from 'node:net';
import { MODEL, ProbeError, consumePlanTextStream, digest } from './siwc-local-runtime.mjs';
import { corelyPlanPayload } from './siwc-local-model-port.mjs';
import { snapshotModelRequest, snapshotModelResult } from './corely-model-contract.mjs';

const DEV_GATEWAY = 'https://newapi-dev.corely.cc/v1/responses';
const NONCE_KEY = 'corely_siwc_nonce';
const MAX_BODY = 8 * 1024 * 1024 + 4096;
const MAX_PENDING = 32;
const MAX_CALLS = 1000;
const CALL_TTL = 60_000;
const BODY_TTL = 10_000;
const DIAGNOSTIC_REASONS = new Set(['GATEWAY_REQUEST_REJECTED', 'GATEWAY_BODY_INVALID', 'GATEWAY_NONCE_INVALID',
  'GATEWAY_NONCE_UNBOUND', 'GATEWAY_NONCE_REPLAY', 'GATEWAY_INVOCATION_EXPIRED', 'GATEWAY_PAYLOAD_MISMATCH',
  'GATEWAY_CALL_ABORTED', 'GATEWAY_RESPONSE_INVALID', 'GATEWAY_RECEIPT_MISMATCH', 'GATEWAY_RECEIPT_INVALID',
  'EXACT_MODEL_NOT_AVAILABLE', 'UPSTREAM_REQUEST_FAILED', 'INVALID_UPSTREAM_CONTENT_TYPE', 'UPSTREAM_RESPONSE_TOO_LARGE',
  'INVALID_UPSTREAM_RESPONSE', 'SESSION_NOT_ELIGIBLE', 'SESSION_REAUTH_REQUIRED', 'SESSION_OPERATION_ABORTED',
  'SESSION_BUSY_OR_LOCKED', 'SESSION_CLOCK_INVALID', 'SESSION_RECORD_INVALID', 'SESSION_RECORD_TOO_LARGE',
  'SESSION_STORAGE_INVALID', 'SESSION_STORAGE_UNAVAILABLE', 'SESSION_STORAGE_NOT_PRIVATE', 'SESSION_STORAGE_WRITE_FAILED',
  'SESSION_LOCK_CLEANUP_UNCONFIRMED', 'REFRESH_OUTCOME_UNCERTAIN', 'REFRESH_CLIENT_INVALID', 'REFRESH_IDENTITY_INVALID',
  'REFRESH_SCOPE_INVALID', 'REFRESH_PERSISTENCE_FAILED', 'REFRESH_REMOTE_REVOCATION_UNCONFIRMED',
  'MODEL_CALL_REPLAY_OR_CAPACITY', 'MODEL_PORT_INVALID', 'MODEL_PORT_UNAVAILABLE', 'MODEL_PORT_TIMEOUT',
  'INFERENCE_RESPONSE_INVALID', 'INVALID_STREAM_CONTENT_TYPE', 'INFERENCE_NOT_COMPLETED', 'MISSING_COMPLETED_EVENT',
  'INVALID_STREAM_EVENT', 'NON_TEXT_OUTPUT_REJECTED', 'OUTPUT_TOO_LARGE', 'STREAM_TOO_LARGE', 'STREAM_INTERRUPTED',
  'INVALID_COMPLETION', 'COMPLETED_OUTPUT_MISMATCH', 'INVALID_USAGE_RECEIPT', 'INVALID_OUTPUT', 'INVALID_STRUCTURED_OUTPUT',
  'INVALID_REQUEST', 'SCOPE_NOT_ADMITTED', 'UNSUPPORTED_CAPABILITY', 'INPUT_MISMATCH', 'INVALID_RECEIPT']);
const credential = value => typeof value === 'string' && /^[A-Za-z0-9._~-]{32,512}$/.test(value);
const reject = code => { throw new ProbeError(code); };
const secretHash = value => createHash('sha256').update(value).digest();

// Audit only fixed enums and bounded protocol status. Never inspect messages,
// causes, provider bodies/headers, identity, input/output values or credentials.
// Own data descriptors also prevent a foreign error getter being evaluated.
function failureDiagnostic(error) {
  try {
    const code = Object.getOwnPropertyDescriptor(error, 'code')?.value;
    if (DIAGNOSTIC_REASONS.has(code)) return { reason: code };
    if (typeof code === 'string') {
      const match = /^(INFERENCE|UPSTREAM)_HTTP_([1-5][0-9]{2})$/.exec(code);
      if (match) return { reason: match[1] === 'INFERENCE' ? 'INFERENCE_HTTP_ERROR' : 'UPSTREAM_HTTP_ERROR', httpStatus: Number(match[2]) };
    }
  } catch { /* Untrusted error objects never become diagnostic content. */ }
  return { reason: 'UNKNOWN_ERROR' };
}

function gatewayEndpoint(value) {
  let url;
  try { url = new URL(value); } catch { reject('GATEWAY_OPTIONS_INVALID'); }
  if (typeof value !== 'string' || url.href !== value || url.username || url.password || url.search || url.hash ||
      url.pathname !== '/v1/responses' || (value !== DEV_GATEWAY && !(url.protocol === 'http:' &&
        url.hostname === '127.0.0.1' && /^\d+$/.test(url.port) && Number(url.port) >= 1024))) reject('GATEWAY_OPTIONS_INVALID');
  return url.href;
}

function privatePeer(address) {
  if (typeof address !== 'string') return false;
  if (address.startsWith('::ffff:')) address = address.slice(7);
  if (address === '::1') return true;
  if (isIP(address) === 6) return /^(?:fc|fd)[0-9a-f]{2}:/i.test(address);
  if (isIP(address) !== 4) return false;
  const [a, b] = address.split('.').map(Number);
  return a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

function serviceRequest(req, expectedSecret) {
  if (!privatePeer(req.socket?.remoteAddress) || req.method !== 'POST' || req.url !== '/v1/responses') return false;
  const headers = req.headers ?? {};
  if (Object.keys(headers).some(key => /^(?:origin|cookie|referer|forwarded|x-forwarded-.+|sec-.+)$/i.test(key)) ||
      /mozilla\//i.test(headers['user-agent'] ?? '') ||
      typeof headers.authorization !== 'string' ||
      !/^application\/json(?:;\s*charset=utf-8)?$/i.test(headers['content-type'] ?? '') ||
      (headers['transfer-encoding'] !== undefined && headers['content-length'] !== undefined)) return false;
  if (Array.isArray(req.rawHeaders)) {
    const counts = new Map();
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      const key = String(req.rawHeaders[i]).toLowerCase();
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    if (['authorization', 'content-type', 'content-length', 'transfer-encoding', 'host'].some(key => (counts.get(key) ?? 0) > 1)) return false;
  }
  return timingSafeEqual(secretHash(headers.authorization), secretHash(`Bearer ${expectedSecret}`));
}

async function whileActive(work, signal) {
  signal.throwIfAborted();
  return new Promise((resolve, fail) => {
    const abort = () => { signal.removeEventListener('abort', abort); fail(new ProbeError('GATEWAY_CALL_ABORTED')); };
    signal.addEventListener('abort', abort, { once: true });
    Promise.resolve(work).then(value => { signal.removeEventListener('abort', abort); resolve(value); },
      error => { signal.removeEventListener('abort', abort); fail(error); });
  });
}

async function readServiceBody(req, signal) {
  const declared = req.headers?.['content-length'];
  if (declared !== undefined && (typeof declared !== 'string' || !/^(?:0|[1-9]\d{0,7})$/.test(declared) ||
      Number(declared) > MAX_BODY)) reject('GATEWAY_BODY_INVALID');
  const chunks = [];
  let length = 0;
  const iterator = req[Symbol.asyncIterator]();
  try {
    for (;;) {
      const part = await whileActive(iterator.next(), signal);
      if (part.done) break;
      const chunk = Buffer.from(part.value);
      length += chunk.length;
      if (length > MAX_BODY) reject('GATEWAY_BODY_INVALID');
      chunks.push(chunk);
    }
    if (declared !== undefined && Number(declared) !== length) reject('GATEWAY_BODY_INVALID');
    return new TextDecoder('utf8', { fatal: true }).decode(Buffer.concat(chunks));
  } catch {
    if (typeof iterator.return === 'function') void Promise.resolve(iterator.return()).catch(() => {});
    reject(signal.aborted ? 'GATEWAY_CALL_ABORTED' : 'GATEWAY_BODY_INVALID');
  }
}

function respond(res, status, code) {
  if (res.destroyed || res.writableEnded) return;
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  res.end(JSON.stringify({ error: { type: 'corely_siwc_error', code, message: 'Corely SIWC request held' } }));
}

function completedFrame(result, nonce) {
  const total = result.usage.inputTokens + result.usage.outputTokens;
  if (!Number.isSafeInteger(total)) reject('GATEWAY_RECEIPT_INVALID');
  // This is a bridge envelope around an already terminal-verified SIWC result,
  // not a claim that this component generated model tokens itself.
  return `event: response.completed\ndata: ${JSON.stringify({ type: 'response.completed', response: {
    id: `resp_corely_${nonce}`, object: 'response', status: 'completed', model: MODEL,
    output: [{ id: `msg_corely_${nonce}`, type: 'message', role: 'assistant', status: 'completed',
      content: [{ type: 'output_text', text: result.text, annotations: [] }] }],
    usage: { input_tokens: result.usage.inputTokens, output_tokens: result.usage.outputTokens, total_tokens: total,
      input_tokens_details: { cached_tokens: result.usage.cachedInputTokens } },
  } })}\n\n`;
}

/** The returned HTTP(S) handler must be mounted on an isolated private listener,
 * never the public dashboard. Only sessions.generate owns SIWC credentials and
 * account leases. The two secrets here have separate service audiences.
 * No files, credentials, prompts, outputs or real input values are logged. */
export function createSiwcGatewayModelTransports({ sessions, gatewayUrl, gatewayToken, bridgeSecret, signal,
  fetchImpl = globalThis.fetch, onDiagnostic = () => {} } = {}) {
  const endpoint = gatewayEndpoint(gatewayUrl);
  if (!sessions || typeof sessions.generate !== 'function' || !(signal instanceof AbortSignal) || typeof fetchImpl !== 'function' ||
      typeof onDiagnostic !== 'function' || !credential(gatewayToken) || !credential(bridgeSecret) || gatewayToken === bridgeSecret) reject('GATEWAY_OPTIONS_INVALID');
  let gatewayKey = gatewayToken, serviceSecret = bridgeSecret, closed = false;
  const lifetime = new AbortController(), pending = new Map(), usedCalls = new Set();
  const diagnose = (stage, error, httpStatus, consumed) => {
    const failure = failureDiagnostic(error);
    const status = failure.httpStatus ?? httpStatus;
    const event = Object.freeze({ stage, reason: failure.reason,
      httpStatus: Number.isInteger(status) && status >= 100 && status <= 599 ? status : null, consumed });
    // Observers cannot affect admission, replay ownership, or failure handling;
    // neither a throw nor a rejected/slow promise is awaited or retried.
    try { void Promise.resolve(onDiagnostic(event)).catch(() => {}); } catch { /* Metadata-only observer failure is isolated. */ }
  };
  const close = () => {
    if (closed) return;
    closed = true;
    lifetime.abort();
    for (const record of pending.values()) { clearTimeout(record.timer); record.controller.abort(); record.result = undefined; }
    pending.clear(); usedCalls.clear(); gatewayKey = ''; serviceSecret = '';
    signal.removeEventListener('abort', close);
  };
  signal.addEventListener('abort', close, { once: true });
  if (signal.aborted) close();

  const generate = async (alias, input, callerSignal) => {
    if (!(callerSignal instanceof AbortSignal)) reject('GATEWAY_OPTIONS_INVALID');
    if (closed || callerSignal.aborted) reject('GATEWAY_CALL_ABORTED');
    const request = snapshotModelRequest(input), key = digest(`${alias}:${request.callId}`);
    if (usedCalls.has(key) || usedCalls.size >= MAX_CALLS || pending.size >= MAX_PENDING) reject('GATEWAY_REPLAY_OR_CAPACITY');
    usedCalls.add(key);
    const nonce = randomBytes(32).toString('base64url');
    const { payload } = corelyPlanPayload(request, alias);
    if (Object.hasOwn(payload, 'metadata')) reject('GATEWAY_PAYLOAD_INVALID');
    // Gateway-only metadata is stripped by selecting the stored original
    // contract below; it is never part of sessions.generate/public Responses.
    const wire = JSON.stringify({ ...payload, metadata: { [NONCE_KEY]: nonce } });
    if (Buffer.byteLength(wire) > MAX_BODY) reject('GATEWAY_BODY_INVALID');
    const controller = new AbortController(), active = AbortSignal.any([callerSignal, lifetime.signal, controller.signal]);
    const record = { alias, request, wire, controller, state: 'pending', consumed: false, result: undefined,
      expiresAt: Date.now() + CALL_TTL, timer: undefined };
    record.timer = setTimeout(() => { record.state = 'held'; record.result = undefined; controller.abort(); }, CALL_TTL);
    record.timer.unref?.();
    pending.set(nonce, record);
    let response, stage = 'GATEWAY_FETCH';
    try {
      response = await whileActive(Promise.resolve().then(() => {
        active.throwIfAborted();
        return fetchImpl(endpoint, { method: 'POST', redirect: 'error', credentials: 'omit', cache: 'no-store', signal: active,
          headers: { Authorization: `Bearer ${gatewayKey}`, 'Content-Type': 'application/json', Accept: 'text/event-stream' }, body: wire });
      }), active);
      stage = 'GATEWAY_RESPONSE';
      active.throwIfAborted();
      if (!response || response.redirected || (response.url && response.url !== endpoint)) reject('GATEWAY_RESPONSE_INVALID');
      if (response.status === 429 && record.state === 'quota' && record.result?.status === 'quota_exhausted') return record.result;
      if (response.status !== 200 || !/^text\/event-stream(?:;\s*charset=utf-8)?$/i.test(response.headers?.get('content-type') ?? '')) reject('GATEWAY_RESPONSE_INVALID');
      stage = 'GATEWAY_RESULT';
      const receipt = await whileActive(consumePlanTextStream(response.body, active), active);
      active.throwIfAborted();
      const original = record.result;
      if (record.state !== 'success' || !original || original.status !== 'success' || receipt.model !== MODEL ||
          receipt.responseIdHash !== digest(`resp_corely_${nonce}`) || receipt.text !== original.text ||
          receipt.usage.inputTokens !== original.usage.inputTokens || receipt.usage.outputTokens !== original.usage.outputTokens ||
          receipt.cachedInputTokens !== original.usage.cachedInputTokens) reject('GATEWAY_RECEIPT_MISMATCH');
      return original;
    } catch (error) {
      diagnose(stage, active.aborted ? new ProbeError('GATEWAY_CALL_ABORTED') : error, response?.status, record.consumed);
      if (active.aborted) reject('GATEWAY_CALL_ABORTED');
      if (error instanceof ProbeError) throw error;
      reject('GATEWAY_CALL_HELD');
    } finally {
      clearTimeout(record.timer);
      record.state = 'held'; record.result = undefined;
      controller.abort(); pending.delete(nonce);
      if (response?.body && !response.body.locked) void response.body.cancel().catch(() => {});
    }
  };

  const handleRequest = async (req, res) => {
    if (closed || !serviceRequest(req, serviceSecret)) {
      diagnose('BRIDGE_ADMISSION', new ProbeError('GATEWAY_REQUEST_REJECTED'), 403, false);
      respond(res, 403, 'bridge_request_rejected'); return;
    }
    const disconnected = new AbortController(), bodyDeadline = AbortSignal.timeout(BODY_TTL);
    const disconnect = () => { if (!res.writableEnded) disconnected.abort(); };
    req.once('aborted', disconnect); res.once('close', disconnect);
    let record, consumed = false, stage = 'BRIDGE_BODY';
    try {
      const body = await readServiceBody(req, AbortSignal.any([lifetime.signal, disconnected.signal, bodyDeadline]));
      let value;
      try { value = JSON.parse(body); } catch { reject('GATEWAY_BODY_INVALID'); }
      stage = 'BRIDGE_INVOCATION';
      const nonce = value?.metadata?.[NONCE_KEY];
      if (typeof nonce !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(nonce)) reject('GATEWAY_NONCE_INVALID');
      record = pending.get(nonce);
      if (!record) reject('GATEWAY_NONCE_UNBOUND');
      if (record.state !== 'pending') reject('GATEWAY_NONCE_REPLAY');
      if (record.expiresAt <= Date.now() || record.controller.signal.aborted) reject('GATEWAY_INVOCATION_EXPIRED');
      if (body !== record.wire) reject('GATEWAY_PAYLOAD_MISMATCH');
      // Consume synchronously before any session work or await. Replays never
      // execute a second inference, including after a timeout/uncertain result.
      record.state = 'running'; record.consumed = consumed = true;
      const active = AbortSignal.any([lifetime.signal, disconnected.signal, record.controller.signal]);
      stage = 'BRIDGE_SESSION';
      const generated = await whileActive(Promise.resolve().then(() => {
        active.throwIfAborted();
        return sessions.generate(record.alias, record.request, active);
      }), active);
      stage = 'BRIDGE_RESULT';
      const result = snapshotModelResult(generated, record.request, record.alias, 'siwc_plan');
      active.throwIfAborted();
      if (closed || record.state !== 'running' || record.expiresAt <= Date.now() || pending.get(nonce) !== record) reject('GATEWAY_CALL_ABORTED');
      if (result.status === 'quota_exhausted') {
        record.result = result; record.state = 'quota';
        respond(res, 429, 'subscription_sharing_usage_limit_exceeded');
        return;
      }
      stage = 'BRIDGE_RESPONSE';
      const frame = completedFrame(result, nonce);
      record.result = result; record.state = 'success';
      res.writeHead(200, { 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
      res.end(frame);
    } catch (error) {
      diagnose(stage, error, 409, consumed);
      if (consumed && record?.state === 'running') { record.state = 'held'; record.result = undefined; record.controller.abort(); }
      respond(res, 409, 'bridge_request_held');
    } finally {
      req.removeListener('aborted', disconnect); res.removeListener('close', disconnect);
    }
  };
  const port = alias => Object.freeze({ authMode: 'siwc_plan',
    capabilities: Object.freeze({ text: true, structuredJson: true, images: false }),
    generate: (request, callerSignal) => generate(alias, request, callerSignal) });
  return Object.freeze({ ports: Object.freeze({ info: port('info'), eason: port('eason') }), handleRequest, close });
}
