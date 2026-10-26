import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import { performance } from 'node:perf_hooks';

export const CORELY_MODEL_JOB_RESOURCE = 'https://moztech-api-dev-candidates-sp5g377smq-de.a.run.app/work-candidates/model-jobs';
export const CORELY_MODEL_JOB_ISSUER = `${CORELY_MODEL_JOB_RESOURCE}/oauth`;
export const CORELY_MODEL_JOB_SCOPE = 'corely:dev-model-jobs';
export const CORELY_MODEL_JOB_CLIENT_ID = 'corely-local-model-jobs-dev';
export const CORELY_MODEL_JOB_REDIRECT = 'http://127.0.0.1:47632/corely/model-jobs/callback';
const CALLBACK_PATH = '/corely/model-jobs/callback';
const TOKEN_PATTERN = /^models_access_[A-Za-z0-9_-]{43}$/;
const MAX_BODY = 16_384;
const CODES = new Set(['INVALID_OPTIONS', 'INVALID_CALLBACK', 'AUTHORIZATION_DENIED', 'AUTHORIZATION_TIMEOUT',
  'AUTHORIZATION_FAILED', 'ABORTED', 'LOOPBACK_UNAVAILABLE', 'LOOPBACK_CLEANUP_UNCONFIRMED',
  'TOKEN_RESPONSE_INVALID', 'TOKEN_EXCHANGE_UNCERTAIN', 'REVOKE_UNCONFIRMED', 'GRANT_EXPIRED', 'GRANT_CLOSED']);

export class ModelJobClientError extends Error {
  constructor(code) { super(CODES.has(code) ? code : 'INVALID_OPTIONS'); this.name = 'ModelJobClientError'; this.code = this.message; }
}
const failure = code => new ModelJobClientError(code);

/** Validates only the one transaction's exact loopback response, never an
 * arbitrary authorization server, redirect URI or bearer token supplied by UI. */
export function validateModelJobCallback(rawUrl, expectedState) {
  if (typeof rawUrl !== 'string' || rawUrl.length > 4096 || /[\u0000-\u0020\u007f]/.test(rawUrl) || /%(?![\da-f]{2})/i.test(rawUrl) ||
      typeof expectedState !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(expectedState)) throw failure('INVALID_CALLBACK');
  let url;
  try { url = new URL(rawUrl); } catch { throw failure('INVALID_CALLBACK'); }
  if (url.origin + url.pathname !== CORELY_MODEL_JOB_REDIRECT || url.hash || url.username || url.password ||
      rawUrl.split('?')[0] !== CORELY_MODEL_JOB_REDIRECT) throw failure('INVALID_CALLBACK');
  const keys = [...url.searchParams.keys()];
  if (keys.length !== 3 || keys.some(key => !['state', 'iss', 'code', 'error'].includes(key)) || new Set(keys).size !== keys.length ||
      url.searchParams.get('iss') !== CORELY_MODEL_JOB_ISSUER) throw failure('INVALID_CALLBACK');
  const actual = Buffer.from(url.searchParams.get('state') ?? ''), expected = Buffer.from(expectedState);
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) throw failure('INVALID_CALLBACK');
  if (url.searchParams.has('error')) {
    if (url.searchParams.get('error') !== 'access_denied' || url.searchParams.has('code')) throw failure('INVALID_CALLBACK');
    throw failure('AUTHORIZATION_DENIED');
  }
  const code = url.searchParams.get('code');
  if (!/^models_code_[A-Za-z0-9_-]{43}$/.test(code ?? '')) throw failure('INVALID_CALLBACK');
  return code;
}

function untilAborted(work, signal) {
  if (signal.aborted) return Promise.reject(signal.reason);
  return new Promise((resolve, reject) => {
    const abort = () => { signal.removeEventListener('abort', abort); reject(signal.reason); };
    signal.addEventListener('abort', abort, { once: true });
    Promise.resolve(work).then(value => { signal.removeEventListener('abort', abort); resolve(value); },
      error => { signal.removeEventListener('abort', abort); reject(error); });
  });
}

/** Only the two fixed TLS credential endpoints are reachable. Even a fetch
 * implementation that ignores AbortSignal cannot hang the caller indefinitely. */
async function credentialRequest(operation, form, { fetchImpl, requestTimeoutMs, signal, captureToken }) {
  const endpoint = `${CORELY_MODEL_JOB_ISSUER}/${operation}`;
  const controller = new AbortController();
  const interrupted = () => controller.abort(signal.reason);
  if (signal?.aborted) interrupted(); else signal?.addEventListener('abort', interrupted, { once: true });
  const timer = setTimeout(() => controller.abort(failure(operation === 'token' ? 'TOKEN_EXCHANGE_UNCERTAIN' : 'REVOKE_UNCONFIRMED')), requestTimeoutMs);
  let reader;
  try {
    if (controller.signal.aborted) throw controller.signal.reason;
    const response = await untilAborted(Promise.resolve().then(() => {
      if (controller.signal.aborted) throw controller.signal.reason;
      return fetchImpl(endpoint, { method: 'POST', redirect: 'error',
      credentials: 'omit', cache: 'no-store', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: form.toString(), signal: controller.signal });
    }), controller.signal);
    if (!response || response.redirected === true || (response.url && response.url !== endpoint) ||
        typeof response.status !== 'number' || !response.headers) throw failure('TOKEN_RESPONSE_INVALID');
    if (operation === 'revoke' && response.status === 200 && response.body === null) return undefined;
    if (!response.body?.getReader) throw failure('TOKEN_RESPONSE_INVALID');
    reader = response.body.getReader();
    const chunks = []; let size = 0;
    for (;;) {
      const part = await untilAborted(reader.read(), controller.signal);
      if (part.done) break;
      if (!(part.value instanceof Uint8Array)) throw failure('TOKEN_RESPONSE_INVALID');
      const remaining = MAX_BODY - size;
      chunks.push(part.value.subarray(0, Math.max(0, remaining))); size += part.value.byteLength;
      if (captureToken) {
        // Retain only usable short-lived tokens for cleanup, including when a
        // trusted endpoint returned malformed JSON or duplicate/escaped keys.
        const text = Buffer.concat(chunks).toString('utf8');
        for (const match of text.matchAll(/"(?:[^"\\\u0000-\u001f]|\\(?:["\\/bfnrt]|u[\da-fA-F]{4}))*"/g)) {
          try { const value = JSON.parse(match[0]); if (TOKEN_PATTERN.test(value)) captureToken(value); } catch { /* No raw response is retained. */ }
        }
      }
      if (size > MAX_BODY) throw failure('TOKEN_RESPONSE_INVALID');
    }
    if (response.status !== 200) throw failure('TOKEN_RESPONSE_INVALID');
    const bytes = Buffer.concat(chunks);
    if (operation === 'revoke') {
      if (bytes.length !== 0) throw failure('REVOKE_UNCONFIRMED');
      return undefined;
    }
    if (!/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type') ?? '')) throw failure('TOKEN_RESPONSE_INVALID');
    let text, value;
    try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); value = JSON.parse(text); } catch { throw failure('TOKEN_RESPONSE_INVALID'); }
    const keys = value && typeof value === 'object' && !Array.isArray(value) ? Object.keys(value) : [];
    // This fixed server emits a flat four-field object. Escaped or duplicate
    // field names are rejected rather than ambiguously interpreted.
    const wireKeys = [...text.matchAll(/"(access_token|token_type|expires_in|scope)"\s*:/g)].map(match => match[1]);
    if (text.includes('\\') || keys.length !== 4 || wireKeys.length !== 4 || new Set(wireKeys).size !== 4 ||
        keys.some(key => !['access_token', 'token_type', 'expires_in', 'scope'].includes(key)) ||
        typeof value.access_token !== 'string' || !TOKEN_PATTERN.test(value.access_token) || value.token_type !== 'Bearer' ||
        value.expires_in !== 900 || value.scope !== CORELY_MODEL_JOB_SCOPE) throw failure('TOKEN_RESPONSE_INVALID');
    captureToken(value.access_token);
    return value.access_token;
  } catch (error) {
    if (error instanceof ModelJobClientError) throw error;
    if (controller.signal.aborted && controller.signal.reason instanceof ModelJobClientError) throw controller.signal.reason;
    throw failure(operation === 'token' ? 'TOKEN_EXCHANGE_UNCERTAIN' : 'REVOKE_UNCONFIRMED');
  } finally {
    clearTimeout(timer); signal?.removeEventListener('abort', interrupted);
    if (reader) { try { Promise.resolve(reader.cancel()).catch(() => {}); reader.releaseLock(); } catch { /* Cancellation is best effort; no success is inferred. */ } }
  }
}

/** Auth-only milestone: normal owner-operated OAuth, in-memory grant, no
 * resource read, model job, provider, sending, learning or API fallback. */
export async function connectCorelyModelJobs(options = {}) {
  const keys = options && typeof options === 'object' && !Array.isArray(options) ? Object.keys(options) : [];
  if (!options || keys.some(key => !['onAuthorize', 'fetchImpl', 'signal', 'timeoutMs', 'requestTimeoutMs', 'now'].includes(key))) throw failure('INVALID_OPTIONS');
  const { onAuthorize, fetchImpl = globalThis.fetch, signal, timeoutMs = 300_000, requestTimeoutMs = 15_000, now = Date.now } = options;
  if (typeof onAuthorize !== 'function' || typeof fetchImpl !== 'function' || typeof now !== 'function' ||
      !Number.isSafeInteger(timeoutMs) || timeoutMs < 10 || timeoutMs > 300_000 || !Number.isSafeInteger(requestTimeoutMs) ||
      requestTimeoutMs < 10 || requestTimeoutMs > 30_000 || (signal !== undefined && !(signal instanceof AbortSignal))) throw failure('INVALID_OPTIONS');
  if (signal?.aborted) throw failure('ABORTED');
  let lastClock = -1;
  const readClock = () => {
    let value;
    try { value = now(); } catch { throw failure('INVALID_OPTIONS'); }
    if (!Number.isSafeInteger(value) || value < 0 || value < lastClock) throw failure('INVALID_OPTIONS');
    lastClock = value; return value;
  };
  readClock();
  const transaction = new AbortController(), abort = () => transaction.abort(failure('ABORTED'));
  signal?.addEventListener('abort', abort, { once: true });
  const timer = setTimeout(() => transaction.abort(failure('AUTHORIZATION_TIMEOUT')), timeoutMs);
  const state = randomBytes(32).toString('base64url'), verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const tokens = new Set(); let tokenOverflow = false;
  const captureToken = value => {
    if (tokens.has(value)) return;
    if (tokens.size >= 32) { tokenOverflow = true; return; }
    tokens.add(value);
  };
  let closePromise, callbackUsed = false, attempts = 0, token = '', expiresAt = 0, tokenStarted = 0, exchangeStarted = false;
  let resolveCallback, rejectCallback;
  const callback = new Promise((resolve, reject) => { resolveCallback = resolve; rejectCallback = reject; });
  callback.catch(() => {});
  const server = createServer({ maxHeaderSize: 4096 }, (req, res) => {
    res.setHeader('Cache-Control', 'no-store'); res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Connection', 'close');
    const hosts = req.rawHeaders.filter((_value, index) => index % 2 === 0 && req.rawHeaders[index].toLowerCase() === 'host');
    if (callbackUsed) { res.writeHead(410).end('Authorization response already used.'); return; }
    try {
      if (req.method !== 'GET' || hosts.length !== 1 || req.headers.host !== '127.0.0.1:47632' ||
          req.socket.remoteAddress !== '127.0.0.1' || typeof req.url !== 'string' || !req.url.startsWith(`${CALLBACK_PATH}?`) ||
          req.headers['transfer-encoding'] || (req.headers['content-length'] && req.headers['content-length'] !== '0')) throw failure('INVALID_CALLBACK');
      const code = validateModelJobCallback(`http://127.0.0.1:47632${req.url}`, state);
      callbackUsed = true; res.once('finish', () => resolveCallback(code));
      res.writeHead(200).end('Corely authorization received. Return to the local assistant.');
    } catch (error) {
      attempts++;
      if (error instanceof ModelJobClientError && error.code === 'AUTHORIZATION_DENIED') {
        callbackUsed = true; res.once('finish', () => rejectCallback(error));
        res.writeHead(403).end('Authorization was declined.'); return;
      }
      res.writeHead(400).end('Invalid authorization response.');
      if (attempts >= 8) { callbackUsed = true; rejectCallback(failure('INVALID_CALLBACK')); }
    }
  });
  server.headersTimeout = 5000; server.requestTimeout = 5000; server.timeout = 5000; server.maxRequestsPerSocket = 1; server.maxConnections = 16;
  server.on('clientError', (_error, socket) => socket.destroy());
  server.on('error', () => rejectCallback(failure('LOOPBACK_UNAVAILABLE')));
  const closeListener = (immediate = false) => {
    if (closePromise) return closePromise;
    closePromise = new Promise((resolve, reject) => {
      const closeTimer = setTimeout(() => { reject(failure('LOOPBACK_CLEANUP_UNCONFIRMED')); server.closeAllConnections(); }, 1000);
      server.close(error => { clearTimeout(closeTimer); error && error.code !== 'ERR_SERVER_NOT_RUNNING' ? reject(failure('LOOPBACK_CLEANUP_UNCONFIRMED')) : resolve(); });
      if (immediate) server.closeAllConnections(); else server.closeIdleConnections();
    });
    return closePromise;
  };
  const revokeTokens = async () => {
    const results = await Promise.allSettled([...tokens].map(async value => {
      await credentialRequest('revoke', new URLSearchParams({ token: value, token_type_hint: 'access_token', client_id: CORELY_MODEL_JOB_CLIENT_ID }),
        { fetchImpl, requestTimeoutMs }); tokens.delete(value);
    }));
    if (results.some(result => result.status === 'rejected') || tokens.size || tokenOverflow) throw failure('REVOKE_UNCONFIRMED');
  };
  try {
    await untilAborted(new Promise((resolve, reject) => {
      server.once('error', () => reject(failure('LOOPBACK_UNAVAILABLE')));
      server.listen({ port: 47632, host: '127.0.0.1', signal: transaction.signal }, resolve);
    }), transaction.signal);
    const url = new URL(`${CORELY_MODEL_JOB_ISSUER}/authorize`);
    for (const [key, value] of Object.entries({ response_type: 'code', client_id: CORELY_MODEL_JOB_CLIENT_ID,
      redirect_uri: CORELY_MODEL_JOB_REDIRECT, scope: CORELY_MODEL_JOB_SCOPE, resource: CORELY_MODEL_JOB_RESOURCE,
      state, code_challenge: challenge, code_challenge_method: 'S256' })) url.searchParams.set(key, value);
    await untilAborted(Promise.resolve().then(() => {
      if (transaction.signal.aborted) throw transaction.signal.reason;
      return onAuthorize(url.href);
    }), transaction.signal);
    const code = await untilAborted(callback, transaction.signal);
    await closeListener();
    expiresAt = readClock() + 900_000; tokenStarted = performance.now();
    if (!Number.isSafeInteger(expiresAt)) throw failure('INVALID_OPTIONS');
    exchangeStarted = true;
    token = await credentialRequest('token', new URLSearchParams({ grant_type: 'authorization_code', client_id: CORELY_MODEL_JOB_CLIENT_ID,
      redirect_uri: CORELY_MODEL_JOB_REDIRECT, resource: CORELY_MODEL_JOB_RESOURCE, code, code_verifier: verifier }),
    { fetchImpl, requestTimeoutMs, signal: transaction.signal, captureToken });
    if (transaction.signal.aborted) throw transaction.signal.reason;
    if (readClock() >= expiresAt || performance.now() - tokenStarted >= 900_000) throw failure('GRANT_EXPIRED');
  } catch (error) {
    let cleanupFailed = false;
    try { await revokeTokens(); } catch { cleanupFailed = true; }
    try { await closeListener(true); } catch { if (!cleanupFailed) throw failure('LOOPBACK_CLEANUP_UNCONFIRMED'); }
    if (cleanupFailed) throw failure('REVOKE_UNCONFIRMED');
    if (exchangeStarted && !tokens.size && error instanceof ModelJobClientError &&
        ['ABORTED', 'AUTHORIZATION_TIMEOUT'].includes(error.code)) throw failure('TOKEN_EXCHANGE_UNCERTAIN');
    if (error instanceof ModelJobClientError) throw error;
    throw failure('AUTHORIZATION_FAILED');
  } finally {
    clearTimeout(timer); signal?.removeEventListener('abort', abort);
  }
  let closed = false, revokePromise, revocationFailed = false;
  const session = Object.freeze({
    receipt() {
      if (revocationFailed) throw failure('REVOKE_UNCONFIRMED');
      if (closed || !token) throw failure('GRANT_CLOSED');
      if (signal?.aborted) throw failure('ABORTED');
      if (readClock() >= expiresAt || performance.now() - tokenStarted >= 900_000) throw failure('GRANT_EXPIRED');
      return Object.freeze({ status: 'CORELY_MODEL_JOB_GRANT_CONNECTED', scope: CORELY_MODEL_JOB_SCOPE, resource: CORELY_MODEL_JOB_RESOURCE,
        tenantId: 'moztech', brandId: 'moztech-test', syntheticOnly: true, currentServerAuthority: 'NOT_CHECKED',
        jobOperations: 'NOT_IMPLEMENTED', customerDataAccessed: false, modelExecuted: false, apiFallbackUsed: false,
        sendingPerformed: false, learningPerformed: false });
    },
    async revoke() {
      closed = true;
      if (!revokePromise) revokePromise = revokeTokens().then(() => { token = ''; revocationFailed = false; signal?.removeEventListener('abort', lifetimeAbort); },
        () => { revokePromise = undefined; revocationFailed = true; throw failure('REVOKE_UNCONFIRMED'); });
      await revokePromise;
      return Object.freeze({ status: 'CORELY_MODEL_JOB_GRANT_REVOKED', revocationConfirmed: true });
    },
  });
  const lifetimeAbort = () => { session.revoke().catch(() => {}); };
  signal?.addEventListener('abort', lifetimeAbort, { once: true });
  if (signal?.aborted) { await session.revoke(); throw failure('ABORTED'); }
  return session;
}
