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
const credential = value => typeof value === 'string' && /^[A-Za-z0-9._~-]{32,512}$/.test(value);
const reject = code => { throw new ProbeError(code); };
const secretHash = value => createHash('sha256').update(value).digest();

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
  fetchImpl = globalThis.fetch } = {}) {
  const endpoint = gatewayEndpoint(gatewayUrl);
  if (!sessions || typeof sessions.generate !== 'function' || !(signal instanceof AbortSignal) || typeof fetchImpl !== 'function' ||
      !credential(gatewayToken) || !credential(bridgeSecret) || gatewayToken === bridgeSecret) reject('GATEWAY_OPTIONS_INVALID');
  let gatewayKey = gatewayToken, serviceSecret = bridgeSecret, closed = false;
  const lifetime = new AbortController(), pending = new Map(), usedCalls = new Set();
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
    const record = { alias, request, wire, controller, state: 'pending', result: undefined,
      expiresAt: Date.now() + CALL_TTL, timer: undefined };
    record.timer = setTimeout(() => { record.state = 'held'; record.result = undefined; controller.abort(); }, CALL_TTL);
    record.timer.unref?.();
    pending.set(nonce, record);
    let response;
    try {
      response = await whileActive(Promise.resolve().then(() => {
        active.throwIfAborted();
        return fetchImpl(endpoint, { method: 'POST', redirect: 'error', credentials: 'omit', cache: 'no-store', signal: active,
          headers: { Authorization: `Bearer ${gatewayKey}`, 'Content-Type': 'application/json', Accept: 'text/event-stream' }, body: wire });
      }), active);
      active.throwIfAborted();
      if (!response || response.redirected || (response.url && response.url !== endpoint)) reject('GATEWAY_RESPONSE_INVALID');
      if (response.status === 429 && record.state === 'quota' && record.result?.status === 'quota_exhausted') return record.result;
      if (response.status !== 200 || !/^text\/event-stream(?:;\s*charset=utf-8)?$/i.test(response.headers?.get('content-type') ?? '')) reject('GATEWAY_RESPONSE_INVALID');
      const receipt = await whileActive(consumePlanTextStream(response.body, active), active);
      active.throwIfAborted();
      const original = record.result;
      if (record.state !== 'success' || !original || original.status !== 'success' || receipt.model !== MODEL ||
          receipt.responseIdHash !== digest(`resp_corely_${nonce}`) || receipt.text !== original.text ||
          receipt.usage.inputTokens !== original.usage.inputTokens || receipt.usage.outputTokens !== original.usage.outputTokens ||
          receipt.cachedInputTokens !== original.usage.cachedInputTokens) reject('GATEWAY_RECEIPT_MISMATCH');
      return original;
    } catch (error) {
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
    if (closed || !serviceRequest(req, serviceSecret)) { respond(res, 403, 'bridge_request_rejected'); return; }
    const disconnected = new AbortController(), bodyDeadline = AbortSignal.timeout(BODY_TTL);
    const disconnect = () => { if (!res.writableEnded) disconnected.abort(); };
    req.once('aborted', disconnect); res.once('close', disconnect);
    let record, consumed = false;
    try {
      const body = await readServiceBody(req, AbortSignal.any([lifetime.signal, disconnected.signal, bodyDeadline]));
      let value;
      try { value = JSON.parse(body); } catch { reject('GATEWAY_BODY_INVALID'); }
      const nonce = value?.metadata?.[NONCE_KEY];
      if (typeof nonce !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(nonce)) reject('GATEWAY_INVOCATION_INVALID');
      record = pending.get(nonce);
      if (!record || record.state !== 'pending' || record.expiresAt <= Date.now() || record.controller.signal.aborted || body !== record.wire) reject('GATEWAY_INVOCATION_INVALID');
      // Consume synchronously before any session work or await. Replays never
      // execute a second inference, including after a timeout/uncertain result.
      record.state = 'running'; consumed = true;
      const active = AbortSignal.any([lifetime.signal, disconnected.signal, record.controller.signal]);
      const result = snapshotModelResult(await whileActive(Promise.resolve().then(() => {
        active.throwIfAborted();
        return sessions.generate(record.alias, record.request, active);
      }), active), record.request, record.alias, 'siwc_plan');
      active.throwIfAborted();
      if (closed || record.state !== 'running' || record.expiresAt <= Date.now() || pending.get(nonce) !== record) reject('GATEWAY_CALL_ABORTED');
      if (result.status === 'quota_exhausted') {
        record.result = result; record.state = 'quota';
        respond(res, 429, 'subscription_sharing_usage_limit_exceeded');
        return;
      }
      const frame = completedFrame(result, nonce);
      record.result = result; record.state = 'success';
      res.writeHead(200, { 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
      res.end(frame);
    } catch {
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
