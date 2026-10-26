#!/usr/bin/env node
// Owner-operated, one synthetic case. The transport, not the model, owns OAuth
// and Corely calls. No public inference listener or account/API fallback pool.
import { createServer } from 'node:http';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { resolve, isAbsolute } from 'node:path';
import { pathToFileURL } from 'node:url';
import { runHarnessCandidate, HarnessError } from './codex-harness-pilot.mjs';
import { parseCandidateOutput, validateSyntheticPacket } from './codex-harness-candidate-contract.mjs';

export const CORELY_RESOURCE = 'https://moztech-api-dev-candidates-sp5g377smq-de.a.run.app/work-candidates/mcp';
export const CORELY_ISSUER = 'https://moztech-api-dev-candidates-sp5g377smq-de.a.run.app/work-candidates/local/oauth';
export const CORELY_SCOPE = 'corely:dev-work-candidates';
export const CORELY_CLIENT_ID = 'corely-local-codex-dev';
export const CORELY_REDIRECT = 'http://127.0.0.1:47631/corely/callback';
const TOOLS = new Set(['corely_work_candidate_status', 'corely_work_candidate_create_case', 'corely_work_candidate_read_case',
  'corely_work_candidate_get', 'corely_work_candidate_submit']);
const CODES = new Set(['INVALID_OPTIONS', 'CONNECTION_FAILED', 'AUTH_REQUIRED', 'AUTH_DENIED', 'AUTH_TIMEOUT',
  'INVALID_CALLBACK', 'HTTP_FAILED', 'NETWORK_UNCERTAIN', 'INVALID_RESPONSE', 'UNSAFE_CAPABILITIES', 'SOURCE_INVALID',
  'SOURCE_EXPIRED', 'CANDIDATE_FAILED', 'CANDIDATE_MISMATCH', 'REVOKE_UNCONFIRMED', 'API_PHASES_NOT_MIGRATED']);
export class CorelyLocalError extends Error {
  constructor(code) { super(CODES.has(code) ? code : 'INVALID_RESPONSE'); this.code = this.message; }
}
const fail = code => { throw new CorelyLocalError(code); };

export function validateCorelyStatus(status) {
  if (status?.mode !== 'SYNTHETIC_WORK_CANDIDATE_PILOT' || status.tenantId !== 'moztech' || status.brandId !== 'moztech-test' ||
      status.syntheticOnly !== true || status.realCustomerData !== false || status.noApiFallback !== true ||
      status.workCapabilities?.canApprove !== false || status.workCapabilities?.canSend !== false || status.workCapabilities?.canLearn !== false ||
      status.qualityReviewUsesApi !== true || status.decisionUsesApi !== true || status.normalOpsHumanReviewRequired !== true ||
      status.normalOpsEditSaveSendLearningRetained !== true) fail('UNSAFE_CAPABILITIES');
}

export function validateCorelyCallback(rawUrl, expectedState) {
  let url;
  try { url = new URL(rawUrl, CORELY_REDIRECT); } catch { fail('INVALID_CALLBACK'); }
  if (url.origin + url.pathname !== CORELY_REDIRECT || url.hash || url.username || url.password ||
      [...url.searchParams.keys()].some(key => !['state', 'iss', 'code', 'error'].includes(key)) ||
      [...new Set(url.searchParams.keys())].some(key => url.searchParams.getAll(key).length !== 1) ||
      url.searchParams.get('iss') !== CORELY_ISSUER) fail('INVALID_CALLBACK');
  const state = url.searchParams.get('state');
  if (typeof state !== 'string' || typeof expectedState !== 'string' || Buffer.byteLength(state) !== Buffer.byteLength(expectedState) ||
      !timingSafeEqual(Buffer.from(state), Buffer.from(expectedState))) fail('INVALID_CALLBACK');
  if (url.searchParams.has('error')) {
    if (url.searchParams.get('error') !== 'access_denied' || url.searchParams.has('code')) fail('INVALID_CALLBACK');
    fail('AUTH_DENIED');
  }
  const code = url.searchParams.get('code');
  if (!/^[A-Za-z0-9_-]{43}$/.test(code ?? '')) fail('INVALID_CALLBACK');
  return code;
}

async function jsonRequest(url, { token, body, form = false, fetchImpl = fetch, timeoutMs = 15000 } = {}) {
  if (![CORELY_RESOURCE, `${CORELY_ISSUER}/token`, `${CORELY_ISSUER}/revoke`].includes(url)) fail('INVALID_OPTIONS');
  const controller = new AbortController(); let reader;
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(url, { method: 'POST', redirect: 'error', credentials: 'omit', cache: 'no-store',
      headers: { Accept: 'application/json', 'Content-Type': form ? 'application/x-www-form-urlencoded' : 'application/json',
        ...(token ? { Authorization: `Bearer ${token}`, 'MCP-Protocol-Version': '2025-11-25' } : {}) },
      body: form ? new URLSearchParams(body).toString() : JSON.stringify(body), signal: controller.signal });
    if (response.redirected || (response.url && response.url !== url) || response.status !== 200) fail('HTTP_FAILED');
    if (url.endsWith('/revoke')) return { revoked: true };
    if (!/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type') ?? '') || !response.body) fail('INVALID_RESPONSE');
    const declared = response.headers.get('content-length');
    if (declared && (!/^\d+$/.test(declared) || Number(declared) > 240_000)) fail('INVALID_RESPONSE');
    reader = response.body.getReader(); const chunks = []; let size = 0;
    for (;;) {
      const chunk = await reader.read(); if (chunk.done) break;
      size += chunk.value.byteLength; if (size > 240_000) fail('INVALID_RESPONSE'); chunks.push(chunk.value);
    }
    try { return JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(Buffer.concat(chunks))); }
    catch { fail('INVALID_RESPONSE'); }
  } catch (error) { throw error instanceof CorelyLocalError ? error : new CorelyLocalError('NETWORK_UNCERTAIN'); }
  finally { clearTimeout(timer); controller.abort(); if (reader) void reader.cancel().catch(() => {}); }
}

export async function connectCorelyLocal({ onAuthorize = async () => fail('AUTH_REQUIRED'), fetchImpl = fetch } = {}) {
  const state = randomBytes(32).toString('base64url'), verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  let settle, rejectCallback, handled = false, invalidAttempts = 0, timer;
  const callback = new Promise((resolveCallback, reject) => { settle = resolveCallback; rejectCallback = reject; });
  callback.catch(() => {});
  const server = createServer((request, response) => {
    response.setHeader('Cache-Control', 'no-store'); response.setHeader('Content-Type', 'text/plain; charset=utf-8');
    response.setHeader('Referrer-Policy', 'no-referrer'); response.setHeader('X-Content-Type-Options', 'nosniff');
    try {
      if (handled || request.method !== 'GET' || request.headers.host !== '127.0.0.1:47631' ||
          !request.url || request.url.length > 4096) fail('INVALID_CALLBACK');
      const code = validateCorelyCallback(request.url, state);
      handled = true; response.end('Corely DEV connection received. You may close this tab.'); settle(code);
    } catch (error) {
      response.statusCode = 400; response.end('This Corely DEV connection request could not be verified.');
      if (error instanceof CorelyLocalError && error.code === 'AUTH_DENIED') { handled = true; rejectCallback(error); }
      else if (++invalidAttempts >= 8) rejectCallback(new CorelyLocalError('INVALID_CALLBACK'));
    }
  });
  let token;
  try {
    await new Promise((ready, reject) => { server.once('error', () => reject(new CorelyLocalError('CONNECTION_FAILED'))); server.listen(47631, '127.0.0.1', ready); });
    const url = new URL(`${CORELY_ISSUER}/authorize`);
    for (const [key, value] of Object.entries({ client_id: CORELY_CLIENT_ID, redirect_uri: CORELY_REDIRECT,
      response_type: 'code', scope: CORELY_SCOPE, resource: CORELY_RESOURCE, state, code_challenge: challenge, code_challenge_method: 'S256' })) {
      url.searchParams.set(key, value);
    }
    timer = setTimeout(() => rejectCallback(new CorelyLocalError('AUTH_TIMEOUT')), 5 * 60_000);
    await onAuthorize(url.href);
    const code = await callback;
    const result = await jsonRequest(`${CORELY_ISSUER}/token`, { fetchImpl, form: true, body: { grant_type: 'authorization_code',
      client_id: CORELY_CLIENT_ID, redirect_uri: CORELY_REDIRECT, resource: CORELY_RESOURCE, code, code_verifier: verifier } });
    // Save any usable issued token only in this closure so malformed responses
    // can still be revoked, never logged or handed to the model.
    if (typeof result.access_token === 'string' && /^[A-Za-z0-9_-]{43}$/.test(result.access_token)) token = result.access_token;
    if (!token || result.token_type !== 'Bearer' || result.scope !== CORELY_SCOPE || result.expires_in !== 1800) fail('INVALID_RESPONSE');
    let sequence = 0, revoked = false;
    return {
      async call(name, args = {}) {
        if (revoked || !TOOLS.has(name)) fail('INVALID_OPTIONS');
        const id = ++sequence;
        const response = await jsonRequest(CORELY_RESOURCE, { token, fetchImpl, timeoutMs: 120000,
          body: { jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } } });
        if (response.jsonrpc !== '2.0' || response.id !== id || response.error || response.result?.isError === true ||
            !response.result?.structuredContent) fail('INVALID_RESPONSE');
        return response.result.structuredContent;
      },
      async revoke() {
        if (revoked) return;
        await jsonRequest(`${CORELY_ISSUER}/revoke`, { fetchImpl, form: true, body: { token, client_id: CORELY_CLIENT_ID } });
        revoked = true; token = undefined;
      },
    };
  } catch (error) {
    if (token) {
      try { await jsonRequest(`${CORELY_ISSUER}/revoke`, { fetchImpl, form: true, body: { token, client_id: CORELY_CLIENT_ID } }); }
      catch { fail('REVOKE_UNCONFIRMED'); }
    }
    throw error;
  } finally {
    clearTimeout(timer);
    if (server.listening) await new Promise(done => { server.close(done); server.closeAllConnections(); });
  }
}

// Transport is dependency-injected for offline regression; the CLI supplies only
// the fixed normal-OAuth transport above. No caller-provided customer IDs/text.
export async function exerciseCorelyCandidate({ session, generate, allowApiPreparationAndReview = false }) {
  let result, failure;
  try {
    validateCorelyStatus(await session.call('corely_work_candidate_status'));
    // The whole-chain personal-plan-first goal is not met by composition alone.
    // Do not spend API credits on preparation/review just because login passed.
    if (allowApiPreparationAndReview !== true) fail('API_PHASES_NOT_MIGRATED');
    const created = structuredClone(await session.call('corely_work_candidate_create_case'));
    if (created?.tenantId !== 'moztech' || created.brandId !== 'moztech-test' || typeof created.caseId !== 'string' ||
        !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(created.caseId)) fail('SOURCE_INVALID');
    const packet = structuredClone(await session.call('corely_work_candidate_read_case', { caseId: created.caseId }));
    let checked;
    try { checked = validateSyntheticPacket(packet); } catch { fail('SOURCE_INVALID'); }
    if (packet.caseId !== created.caseId || packet.sourceMessageId !== created.sourceMessageId ||
        packet.data.conversationId !== created.conversationId) fail('SOURCE_INVALID');
    const before = await session.call('corely_work_candidate_get', { caseId: created.caseId });
    if (before?.synthetic !== true || before.candidate !== null) fail('CANDIDATE_MISMATCH');
    const generated = await generate(checked.packet);
    if (generated?.status !== 'SYNTHETIC_CANDIDATE_GENERATED' || generated.authMode !== 'chatgpt' ||
        generated.expectedAccountMatch !== true || generated.model !== 'gpt-6.1-sol' || generated.generationCompleted !== true ||
        generated.outputValidated !== true || generated.apiFallbackUsed !== false || !generated.candidate) fail('CANDIDATE_FAILED');
    if (checked.expiresAt <= Date.now()) fail('SOURCE_EXPIRED');
    let candidate;
    try { candidate = parseCandidateOutput(JSON.stringify(generated.candidate), checked); } catch { fail('CANDIDATE_FAILED'); }
    const payload = Object.freeze({ caseId: created.caseId, readReceipt: packet.readReceipt, snapshotHash: packet.snapshotHash,
      ...candidate, idempotencyKey: `codex_${randomBytes(24).toString('hex')}` });
    let receipt;
    try { receipt = await session.call('corely_work_candidate_submit', payload); }
    catch (error) {
      // One uncertain transport retry reuses IDENTICAL payload and key. HTTP,
      // quality, role or source failures never cause another generation.
      if (!(error instanceof CorelyLocalError) || error.code !== 'NETWORK_UNCERTAIN') throw error;
      receipt = await session.call('corely_work_candidate_submit', payload);
    }
    if (receipt?.status !== 'PENDING' || receipt.sourceMessageId !== packet.sourceMessageId ||
        receipt.qualityReviewUsesApi !== true || typeof receipt.reviewId !== 'string' ||
        receipt.textSha256 !== createHash('sha256').update(candidate.text).digest('hex') ||
        receipt.workCanApprove !== false || receipt.workCanSend !== false || receipt.workCanLearn !== false) fail('CANDIDATE_MISMATCH');
    const saved = await session.call('corely_work_candidate_get', { caseId: created.caseId });
    if (saved?.synthetic !== true || saved.candidate?.reviewId !== receipt.reviewId || saved.candidate.status !== 'PENDING' ||
        saved.candidate.sourceMessageId !== packet.sourceMessageId || saved.candidate.text !== candidate.text ||
        saved.candidate.workCanApprove !== false || saved.candidate.workCanSend !== false || saved.candidate.workCanLearn !== false) fail('CANDIDATE_MISMATCH');
    result = { status: 'CORELY_LOCAL_CANDIDATE_SAVED', syntheticOnly: true, generationAuthMode: 'chatgpt', model: generated.model,
      candidateReadbackMatched: true, candidateStatus: 'PENDING', decisionUsesApi: true, qualityReviewUsesApi: true,
      apiGenerationFallbackUsed: false, exactPlanDebitAttested: false, sendingPerformed: false, learningPerformed: false,
      customerServiceE2E: 'NOT_RUN' };
  } catch (error) { failure = error; }
  try { await session.revoke(); } catch { fail('REVOKE_UNCONFIRMED'); }
  if (failure) throw failure;
  return { ...result, corelyGrantRevoked: true };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    if (process.argv.length !== 4 || process.argv[2] !== '--executable' || !isAbsolute(process.argv[3])) fail('INVALID_OPTIONS');
    const session = await connectCorelyLocal({ onAuthorize: async authUrl => {
      process.stdout.write(`${JSON.stringify({ status: 'NORMAL_CORELY_DEV_CONSENT_REQUIRED', authUrl })}\n`);
    } });
    const receipt = await exerciseCorelyCandidate({ session, generate: packet => runHarnessCandidate({
      executable: process.argv[3], packet, account: 'info', login: true,
      onLogin: async authUrl => process.stdout.write(`${JSON.stringify({ status: 'NORMAL_CODEX_INFO_LOGIN_REQUIRED', authUrl })}\n`),
    }) });
    process.stdout.write(`${JSON.stringify(receipt)}\n`);
  } catch (error) {
    process.stdout.write(`${JSON.stringify({ status: 'CORELY_LOCAL_CANDIDATE_FAILED',
      code: error instanceof CorelyLocalError || error instanceof HarnessError ? error.code : 'INVALID_RESPONSE',
      apiGenerationFallbackUsed: false })}\n`);
    process.exitCode = 1;
  }
}
