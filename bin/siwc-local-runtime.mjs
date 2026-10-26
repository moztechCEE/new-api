// Local personal-project SIWC probe. Not a hosted-service credential importer.
import { createHash, createPublicKey, randomBytes, randomUUID, timingSafeEqual, verify } from 'node:crypto';

export const ISSUER = 'https://auth.openai.com';
export const RESOURCE = 'https://api.openai.com/v1';
export const MODEL = 'gpt-6.1-sol';
export const PROBE_INPUT = 'Reply with exactly: Corely local plan probe OK.';
export const PROBE_OUTPUT = 'Corely local plan probe OK.';
export const SCOPES = 'openid profile email offline_access resource.invoke chatgpt.tokens.use.direct';
const PLAN_ERROR_CODES = new Set(['subscription_sharing_user_not_eligible', 'subscription_sharing_usage_limit_exceeded',
  'subscription_sharing_usage_unavailable', 'subscription_sharing_unsupported_capability', 'subscription_sharing_route_not_supported',
  'subscription_sharing_invalid_user', 'chatpass_v2_scope_not_authorized', 'chatpass_v2_invalid_authorization_context',
  'subscription_sharing_user_unavailable']);

export class ProbeError extends Error {
  constructor(code, diagnostic) {
    super(code); this.code = code;
    if (!diagnostic || typeof diagnostic !== 'object') return;
    const safe = {};
    if (Number.isInteger(diagnostic.httpStatus) && diagnostic.httpStatus >= 100 && diagnostic.httpStatus <= 599) safe.httpStatus = diagnostic.httpStatus;
    if (['SSE', 'JSON', 'HTML', 'TEXT', 'BINARY', 'OTHER', 'MISSING'].includes(diagnostic.contentTypeClass)) safe.contentTypeClass = diagnostic.contentTypeClass;
    if (['NOT_PARSED', 'EMPTY', 'SSE_SHAPED', 'HTML_SHAPED', 'OTHER_TEXT', 'OVER_LIMIT', 'ARRAY', 'SCALAR', 'ERROR_OBJECT', 'DETAIL_OBJECT', 'RESPONSE_OBJECT', 'OTHER_OBJECT', 'UNREADABLE'].includes(diagnostic.bodyShape)) safe.bodyShape = diagnostic.bodyShape;
    if (diagnostic.catalogModelVerified === true) safe.catalogModelVerified = true;
    if (PLAN_ERROR_CODES.has(diagnostic.errorCode)) safe.errorCode = diagnostic.errorCode;
    if (['completed', 'in_progress', 'failed', 'incomplete', 'queued'].includes(diagnostic.responseStatus)) safe.responseStatus = diagnostic.responseStatus;
    if (typeof diagnostic.requestIdHash === 'string' && /^[0-9a-f]{64}$/.test(diagnostic.requestIdHash)) safe.requestIdHash = diagnostic.requestIdHash;
    if (typeof diagnostic.clientRequestId === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(diagnostic.clientRequestId)) safe.clientRequestId = diagnostic.clientRequestId;
    if (Number.isInteger(diagnostic.responseHeaderCount) && diagnostic.responseHeaderCount >= 0 && diagnostic.responseHeaderCount <= 256) safe.responseHeaderCount = diagnostic.responseHeaderCount;
    if (['basic', 'cors', 'default', 'error', 'opaque', 'opaqueredirect'].includes(diagnostic.fetchResponseType)) safe.fetchResponseType = diagnostic.fetchResponseType;
    this.diagnostic = Object.freeze(safe);
  }
}
const fail = code => { throw new ProbeError(code); };
export const digest = value => createHash('sha256').update(value).digest('hex');

export function createAttempt(hostId, redirectUri, now = Date.now(), registration = {}) {
  if (!/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(hostId)) fail('INVALID_HOST_ID');
  let callback;
  try { callback = new URL(redirectUri); } catch { fail('INVALID_CALLBACK'); }
  if (callback.protocol !== 'http:' || callback.hostname !== '127.0.0.1' ||
      callback.pathname !== '/auth/callback' || !callback.port || callback.search || callback.hash ||
      callback.username || callback.password) fail('INVALID_CALLBACK');
  const state = randomBytes(32).toString('base64url');
  const nonce = randomBytes(32).toString('base64url');
  const verifier = randomBytes(48).toString('base64url');
  const url = new URL('/api/accounts/authorize', ISSUER);
  const clientId = registration.clientId;
  if (clientId !== undefined && (!/^[A-Za-z0-9_-]{1,256}$/.test(clientId) || clientId === 'dynamic_agent_client')) fail('INVALID_REGISTRATION');
  for (const [key, value] of Object.entries({
    client_id: clientId ?? 'dynamic_agent_client',
    ext_agent_host_id: hostId, response_type: 'code', redirect_uri: redirectUri,
    scope: SCOPES, resource: RESOURCE, state, nonce, code_challenge_method: 'S256',
    code_challenge: createHash('sha256').update(verifier).digest('base64url'),
  })) url.searchParams.set(key, value);
  if (!clientId) url.searchParams.set('agent_name_hint', 'New API Local Personal Plan Pilot');
  return { state, nonce, verifier, redirectUri, clientId, expiresAt: now + 600_000, used: false, url: url.href };
}

export function consumeCallback(rawUrl, attempt, now = Date.now()) {
  if (attempt.used) fail('CALLBACK_ALREADY_CONSUMED');
  if (now >= attempt.expiresAt) fail('CALLBACK_EXPIRED');
  if (rawUrl.length > 32_768) fail('INVALID_CALLBACK');
  let url;
  try { url = new URL(rawUrl, attempt.redirectUri); } catch { fail('INVALID_CALLBACK'); }
  const expected = new URL(attempt.redirectUri);
  if (url.origin !== expected.origin || url.pathname !== expected.pathname || url.hash) fail('INVALID_CALLBACK');
  for (const key of new Set(url.searchParams.keys())) {
    if (url.searchParams.getAll(key).length !== 1) fail('DUPLICATE_CALLBACK_PARAMETER');
  }
  const state = url.searchParams.get('state') ?? '';
  const a = Buffer.from(state), b = Buffer.from(attempt.state);
  if (a.length !== b.length || !timingSafeEqual(a, b)) fail('INVALID_STATE');
  const iss = url.searchParams.get('iss');
  if (iss !== null && iss !== ISSUER) fail('INVALID_ISSUER');
  attempt.used = true;
  if (url.searchParams.has('error')) fail('AUTHORIZATION_NOT_GRANTED');
  const returnedClientId = url.searchParams.get('client_id');
  if (attempt.clientId && returnedClientId !== null && returnedClientId !== attempt.clientId) fail('REGISTRATION_MISMATCH');
  const clientId = returnedClientId ?? attempt.clientId ?? '';
  const code = url.searchParams.get('code') ?? '';
  if (!/^[A-Za-z0-9_-]{1,256}$/.test(clientId) || clientId === 'dynamic_agent_client' ||
      code.length < 1 || code.length > 8192 || /[\r\n]/.test(code)) fail('REGISTRATION_INCOMPLETE');
  return { clientId, form: new URLSearchParams({ grant_type: 'authorization_code', client_id: clientId,
    code, code_verifier: attempt.verifier, redirect_uri: attempt.redirectUri, resource: RESOURCE }) };
}

export function validateSession(token, jwks, clientId, nonce, expectedEmail, now = Date.now(), expectedSubjectHash) {
  if (!token || typeof token !== 'object' || typeof token.id_token !== 'string' ||
      token.id_token.length > 32768 || typeof token.access_token !== 'string' ||
      !token.access_token || token.access_token.length > 65536 ||
      token.token_type?.toLowerCase() !== 'bearer' || !Number.isInteger(token.expires_in) ||
      token.expires_in < 1 || token.expires_in > 86400 || typeof token.scope !== 'string' ||
      (token.refresh_token !== undefined && (typeof token.refresh_token !== 'string' || !token.refresh_token || token.refresh_token.length > 65536))) fail('INVALID_TOKEN_RESPONSE');
  const parts = token.id_token.split('.');
  if (parts.length !== 3 || parts.some(p => !/^[A-Za-z0-9_-]+$/.test(p))) fail('INVALID_ID_TOKEN');
  let header, claims;
  try {
    header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  } catch { fail('INVALID_ID_TOKEN'); }
  if (!header || typeof header !== 'object' || Array.isArray(header) || header.alg !== 'RS256' || typeof header.kid !== 'string' ||
      header.jku || header.x5u || header.crit || header.b64 === false) fail('INVALID_ID_TOKEN_HEADER');
  const keys = Array.isArray(jwks?.keys) ? jwks.keys.filter(k => k?.kid === header.kid &&
    k.kty === 'RSA' && (!k.alg || k.alg === 'RS256') && (!k.use || k.use === 'sig')) : [];
  if (keys.length !== 1) fail('UNKNOWN_SIGNING_KEY');
  let valid = false;
  try {
    const key = createPublicKey({ key: { kty: 'RSA', n: keys[0].n, e: keys[0].e }, format: 'jwk' });
    valid = verify('RSA-SHA256', Buffer.from(parts.slice(0, 2).join('.')), key, Buffer.from(parts[2], 'base64url'));
  } catch { fail('INVALID_ID_TOKEN_SIGNATURE'); }
  if (!valid) fail('INVALID_ID_TOKEN_SIGNATURE');
  const seconds = Math.floor(now / 1000);
  if (!claims || typeof claims !== 'object' || Array.isArray(claims) || claims.iss !== ISSUER || typeof claims.sub !== 'string' || !claims.sub ||
      !Number.isInteger(claims.exp) || claims.exp <= seconds || !Number.isInteger(claims.iat) ||
      claims.iat > seconds + 60 || claims.iat >= claims.exp || claims.nonce !== nonce ||
      (claims.nbf !== undefined && (!Number.isInteger(claims.nbf) || claims.nbf > seconds + 60))) fail('INVALID_ID_TOKEN_CLAIMS');
  const audiences = typeof claims.aud === 'string' ? [claims.aud] : claims.aud;
  if (!Array.isArray(audiences) || !audiences.includes(clientId) ||
      (audiences.length > 1 && claims.azp !== clientId) ||
      (claims.azp !== undefined && claims.azp !== clientId)) fail('INVALID_AUDIENCE');
  if (typeof claims.email !== 'string' || claims.email.toLowerCase() !== expectedEmail.toLowerCase() ||
      claims.email_verified !== true) fail('ACCOUNT_NOT_EXPECTED');
  if (expectedSubjectHash && digest(claims.sub) !== expectedSubjectHash) fail('ACCOUNT_NOT_EXPECTED');
  const scopes = new Set(token.scope.split(/\s+/));
  if (!scopes.has('chatgpt.tokens.use.direct') || !scopes.has('resource.invoke')) fail('PLAN_USAGE_NOT_GRANTED');
  return { accessToken: token.access_token, refreshToken: token.refresh_token,
    expiresAt: now + token.expires_in * 1000, clientId, subjectHash: digest(claims.sub),
    planScopeGranted: true, accountMatchesExpected: true };
}

export async function publicJson(url, init = {}, fetchImpl = fetch, signal) {
  const target = new URL(url);
  const allowed = new Set([
    `${ISSUER}/.well-known/openid-configuration`, `${ISSUER}/.well-known/jwks.json`,
    `${ISSUER}/api/accounts/oauth/token`, `${ISSUER}/api/accounts/oauth/revoke`, `${RESOURCE}/models`,
  ]);
  if (!allowed.has(target.href)) fail('ENDPOINT_NOT_ALLOWED');
  let response;
  try { response = await fetchImpl(target.href, { ...init, redirect: 'error', signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(20_000)]) : AbortSignal.timeout(20_000) }); }
  catch { fail('UPSTREAM_REQUEST_FAILED'); }
  if (response.status < 200 || response.status >= 300) fail(`UPSTREAM_HTTP_${response.status}`);
  if (target.pathname.endsWith('/revoke')) {
    if (response.status !== 200) fail('REVOCATION_NOT_CONFIRMED');
    try {
      if (response.body) for await (const chunk of response.body) {
        if (chunk.length) fail('REVOCATION_NOT_CONFIRMED');
      }
    } catch (error) {
      if (error instanceof ProbeError) throw error;
      fail('REVOCATION_NOT_CONFIRMED');
    }
    return {};
  }
  if (!response.headers.get('content-type')?.includes('application/json')) fail('INVALID_UPSTREAM_CONTENT_TYPE');
  const bytes = [];
  let length = 0;
  try {
    for await (const chunk of response.body) {
      length += chunk.length;
      if (length > 1_048_576) fail('UPSTREAM_RESPONSE_TOO_LARGE');
      bytes.push(Buffer.from(chunk));
    }
    return JSON.parse(Buffer.concat(bytes).toString('utf8'));
  } catch (error) {
    if (error instanceof ProbeError) throw error;
    fail('INVALID_UPSTREAM_RESPONSE');
  }
}

export function selectExactModel(catalog) {
  if (!Array.isArray(catalog?.models) || !catalog.models.some(m => m?.slug === MODEL && m.visibility === 'list')) {
    fail('EXACT_MODEL_NOT_AVAILABLE');
  }
  return MODEL;
}

export function syntheticRequest() {
  return { model: MODEL, input: [{ role: 'user', content: PROBE_INPUT }], store: false, stream: true };
}

// Fixed enums and hashes only: never retain raw headers, bodies, messages or credentials.
export async function inferenceFailureDiagnostic(response, timeoutMs = 3000) {
  const media = response.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase() ?? '';
  const mediaClasses = new Map([['text/event-stream', 'SSE'], ['application/json', 'JSON'],
    ['text/html', 'HTML'], ['text/plain', 'TEXT'], ['application/octet-stream', 'BINARY']]);
  const diagnostic = { httpStatus: response.status, contentTypeClass: media ? mediaClasses.get(media) ?? 'OTHER' : 'MISSING',
    catalogModelVerified: true, bodyShape: 'NOT_PARSED' };
  const requestId = response.headers.get('x-request-id');
  if (requestId && requestId.length <= 1024) diagnostic.requestIdHash = digest(requestId);
  const bytes = [];
  let length = 0, reader, timer;
  try {
    const deadline = new Promise((_, reject) => { timer = setTimeout(() => reject(new ProbeError('DIAGNOSTIC_TIMEOUT')), Math.max(1, Math.min(timeoutMs, 3000))); });
    reader = response.body?.getReader();
    while (reader) {
      const part = await Promise.race([reader.read(), deadline]);
      if (part.done) break;
      length += part.value.length;
      if (length > 16384) { diagnostic.bodyShape = 'OVER_LIMIT'; return diagnostic; }
      bytes.push(Buffer.from(part.value));
    }
    const text = new TextDecoder('utf8', { fatal: true }).decode(Buffer.concat(bytes));
    if (!text.trim()) { diagnostic.bodyShape = 'EMPTY'; return diagnostic; }
    // Inspect only bounded shape when MIME is absent/wrong; never treat this as a completed inference.
    if (media !== 'application/json' && !/^[\s]*[\[{]/.test(text)) {
      diagnostic.bodyShape = /^(?:event:|data:|:)/m.test(text) ? 'SSE_SHAPED' :
        /^\s*(?:<!doctype\s+html\b|<html\b|<[a-z][^>]*>)/i.test(text) ? 'HTML_SHAPED' : 'OTHER_TEXT';
      return diagnostic;
    }
    const body = JSON.parse(text);
    diagnostic.bodyShape = Array.isArray(body) ? 'ARRAY' : body === null || typeof body !== 'object' ? 'SCALAR' :
      body.error && typeof body.error === 'object' && !Array.isArray(body.error) ? 'ERROR_OBJECT' :
      Object.hasOwn(body, 'detail') ? 'DETAIL_OBJECT' : body.object === 'response' ? 'RESPONSE_OBJECT' : 'OTHER_OBJECT';
    if (PLAN_ERROR_CODES.has(body?.error?.code)) diagnostic.errorCode = body.error.code;
    if (body?.object === 'response' && ['completed', 'in_progress', 'failed', 'incomplete', 'queued'].includes(body.status)) {
      diagnostic.responseStatus = body.status;
    }
  } catch { diagnostic.bodyShape = 'UNREADABLE'; }
  finally { clearTimeout(timer); void reader?.cancel().catch(() => {}); }
  return diagnostic;
}

export async function consumeProbeStream(body) {
  const decoder = new TextDecoder('utf8', { fatal: true });
  let buffer = '', total = 0, text = '', completed;
  function consume(frame) {
    const data = frame.split(/\r?\n/).filter(line => line.startsWith('data:')).map(line => line.slice(5).trimStart()).join('\n');
    if (!data || data === '[DONE]') return;
    let event;
    try { event = JSON.parse(data); } catch { fail('INVALID_STREAM_EVENT'); }
    if (!event || typeof event !== 'object' || Array.isArray(event) || typeof event.type !== 'string') fail('INVALID_STREAM_EVENT');
    if (['error', 'response.failed', 'response.incomplete'].includes(event.type)) fail('INFERENCE_NOT_COMPLETED');
    if (event.type === 'response.output_text.delta') {
      if (completed || typeof event.delta !== 'string') fail('INVALID_STREAM_EVENT');
      text += event.delta;
      if (text.length > 65536) fail('OUTPUT_TOO_LARGE');
    }
    if (event.type === 'response.completed') {
      if (completed || event.response?.status !== 'completed' || event.response?.model !== MODEL ||
          typeof event.response?.id !== 'string' || !event.response.id) fail('INVALID_COMPLETION');
      completed = event.response;
    }
  }
  try {
    for await (const chunk of body) {
      total += chunk.length;
      if (total > 1_048_576) fail('STREAM_TOO_LARGE');
      buffer += decoder.decode(chunk, { stream: true });
      let split;
      while ((split = /\r?\n\r?\n/.exec(buffer))) {
        consume(buffer.slice(0, split.index));
        buffer = buffer.slice(split.index + split[0].length);
      }
    }
    buffer += decoder.decode();
    if (buffer.trim()) consume(buffer);
  } catch (error) {
    if (error instanceof ProbeError) throw error;
    fail('STREAM_INTERRUPTED');
  }
  if (!completed) fail('MISSING_COMPLETED_EVENT');
  if (!Array.isArray(completed.output)) fail('INVALID_COMPLETION');
  const finalText = completed.output.filter(i => i?.type === 'message')
    .flatMap(i => i.content ?? []).filter(c => c.type === 'output_text').map(c => c.text).join('');
  if (!finalText || finalText.trim() !== PROBE_OUTPUT || (text && text !== finalText)) fail('SYNTHETIC_OUTPUT_MISMATCH');
  return { completed: true, model: MODEL, responseIdHash: digest(completed.id), outputHash: digest(finalText) };
}

export async function runSyntheticProbe(session, fetchImpl = fetch, signal) {
  if (!session?.planScopeGranted || !session.accountMatchesExpected || session.expiresAt <= Date.now()) fail('SESSION_NOT_ELIGIBLE');
  const headers = { Authorization: `Bearer ${session.accessToken}` };
  const catalog = await publicJson(`${RESOURCE}/models`, { headers }, fetchImpl, signal);
  selectExactModel(catalog);
  const clientRequestId = randomUUID();
  let response;
  try {
    response = await fetchImpl(`${RESOURCE}/responses`, { method: 'POST', headers: { ...headers, 'Content-Type': 'application/json', Accept: 'text/event-stream', 'X-Client-Request-Id': clientRequestId },
      body: JSON.stringify(syntheticRequest()), redirect: 'error', signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(120_000)]) : AbortSignal.timeout(120_000) });
  } catch { fail('INFERENCE_REQUEST_FAILED'); }
  const failureDiagnostic = async () => ({ ...await inferenceFailureDiagnostic(response), clientRequestId,
    responseHeaderCount: Math.min([...response.headers.keys()].length, 256), fetchResponseType: response.type });
  if (!response.ok) throw new ProbeError(`INFERENCE_HTTP_${response.status}`, await failureDiagnostic());
  const media = response.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase();
  if (media !== 'text/event-stream') throw new ProbeError('INVALID_STREAM_CONTENT_TYPE', await failureDiagnostic());
  return consumeProbeStream(response.body);
}
