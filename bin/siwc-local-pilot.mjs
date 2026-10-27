#!/usr/bin/env node
// One local personal-project probe, not a Corely hosted gateway or token importer.
import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, rename, unlink } from 'node:fs/promises';
import { dirname, resolve, isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createAttempt, consumeCallback, validateSession, publicJson, runSyntheticProbe, ISSUER, ProbeError } from './siwc-local-runtime.mjs';
import { createTransientSiwcModelPort } from './siwc-local-model-port.mjs';

const project = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const hostPath = resolve(project, '.local-tests/siwc-personal-pilot/host.json');
const safe = value => process.stdout.write(`${JSON.stringify(value)}\n`);

// Only non-secret host/client/verified-subject mappings are retained. Never tokens.
export async function loadRegistration(path = hostPath) {
  const parent = dirname(path);
  for (const [dir, privateOnly] of [[dirname(parent), false], [parent, true]]) {
    try { await mkdir(dir, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw new ProbeError('HOST_STORAGE_UNAVAILABLE'); }
    const stat = await lstat(dir);
    if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & (privateOnly ? 0o077 : 0o022)) ||
        (process.getuid && stat.uid !== process.getuid())) throw new ProbeError('HOST_STORAGE_NOT_PRIVATE');
  }
  try {
    const handle = await open(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    const value = { hostId: `urn:uuid:${randomUUID()}` };
    try { await handle.writeFile(JSON.stringify(value)); } finally { await handle.close(); }
    return value;
  } catch (error) { if (error.code !== 'EEXIST') throw new ProbeError('HOST_STORAGE_UNAVAILABLE'); }
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stat = await handle.stat();
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > 4096 || (stat.mode & 0o077) ||
        (process.getuid && stat.uid !== process.getuid())) throw new ProbeError('HOST_STORAGE_NOT_PRIVATE');
    const value = JSON.parse(await handle.readFile('utf8'));
    if (!value || Array.isArray(value) || Object.keys(value).some(k => !['hostId', 'clientId', 'subjectHash'].includes(k)) ||
        !/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value.hostId) ||
        (value.clientId !== undefined && (!/^[A-Za-z0-9_-]{1,256}$/.test(value.clientId) || value.clientId === 'dynamic_agent_client')) ||
        (value.subjectHash !== undefined && (!value.clientId || !/^[0-9a-f]{64}$/.test(value.subjectHash)))) throw new ProbeError('HOST_STORAGE_INVALID');
    return value;
  } catch (error) { throw error instanceof ProbeError ? error : new ProbeError('HOST_STORAGE_INVALID'); }
  finally { await handle?.close(); }
}

export async function saveRegistration(value, path = hostPath) {
  const temporary = `${path}.${randomUUID()}.tmp`;
  let handle;
  try {
    handle = await open(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    // Explicit fields prevent accidental future token persistence.
    await handle.writeFile(JSON.stringify({ hostId: value.hostId, clientId: value.clientId, subjectHash: value.subjectHash }));
    await handle.sync();
    await handle.close(); handle = undefined;
    await rename(temporary, path);
  } catch { throw new ProbeError('HOST_STORAGE_UNAVAILABLE'); }
  finally { await handle?.close(); await unlink(temporary).catch(() => {}); }
}

export async function startLocalPilot(options = {}) {
  if (!options || typeof options !== 'object' || Array.isArray(options) ||
      Object.keys(options).some(key => !['registrationPath', 'fetchImpl', 'runSyntheticModelJobs'].includes(key)) ||
      (options.registrationPath !== undefined && (typeof options.registrationPath !== 'string' || !isAbsolute(options.registrationPath))) ||
      (options.runSyntheticModelJobs !== undefined && typeof options.runSyntheticModelJobs !== 'function') ||
      (options.fetchImpl !== undefined && typeof options.fetchImpl !== 'function')) throw new ProbeError('INVALID_LOCAL_PILOT_OPTIONS');
  const registrationPath = options.registrationPath ?? hostPath, fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const profile = await loadRegistration(registrationPath);
  const lockPath = `${registrationPath}.lock`;
  let lock;
  try { lock = await open(lockPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600); }
  catch { throw new ProbeError('LOCAL_PILOT_ALREADY_ACTIVE_OR_LOCKED'); }
  const abort = new AbortController();
  let attempt, origin, session, cleanupToken, cleanupClientId, deadline;
  let phase = 'WAITING_FOR_OWNER_CONSENT', inFlight = false, stopped = false;
  let complete;
  const completion = new Promise(resolve => { complete = resolve; });
  const server = createServer((request, response) => {
    void handleRequest(request, response).catch(() => {
      if (!response.headersSent) response.writeHead(400, { 'Content-Type': 'text/plain' });
      response.end('LOCAL_REQUEST_FAILED');
    });
  });
  async function stop() {
    if (stopped) return;
    stopped = true;
    clearTimeout(deadline);
    process.removeListener('SIGINT', interrupt);
    process.removeListener('SIGTERM', interrupt);
    abort.abort();
    let revoked = false;
    const revocationAttempted = Boolean(cleanupToken && cleanupClientId);
    if (cleanupToken && cleanupClientId) {
      for (let retry = 0; retry < 2 && !revoked; retry++) {
        try {
          await publicJson(`${ISSUER}/api/accounts/oauth/revoke`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({ token: cleanupToken, token_type_hint: 'refresh_token', client_id: cleanupClientId }) }, fetchImpl);
          revoked = true;
        } catch { if (retry === 0) await new Promise(done => setTimeout(done, 500)); }
      }
    }
    session = undefined; cleanupToken = undefined;
    if (revocationAttempted && !revoked) process.exitCode = 1;
    safe({ status: 'SESSION_REFERENCES_DISCARDED', remoteRevocationAttempted: revocationAttempted,
      remoteRevocationConfirmed: revoked, credentialsPersisted: false,
      disconnectInChatGptSettingsIfUnconfirmed: revocationAttempted && !revoked });
    server.close();
    server.closeAllConnections();
    await lock.close();
    await unlink(lockPath).catch(() => {});
    complete(Object.freeze({ phase, remoteRevocationAttempted: revocationAttempted, remoteRevocationConfirmed: revoked, credentialsPersisted: false }));
  }
  function interrupt() { phase = 'INTERRUPTED'; process.exitCode = 130; void stop(); }
  async function handleRequest(request, response) {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Referrer-Policy', 'no-referrer');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
    const finish = (status, text) => { response.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8' }); response.end(text); };
    if (stopped || !origin || !['127.0.0.1', '::ffff:127.0.0.1'].includes(request.socket.remoteAddress) ||
        request.headers.host !== new URL(origin).host || (request.headers.origin && request.headers.origin !== origin)) return finish(403, 'Request not permitted.');
    if (request.method !== 'GET') return finish(405, 'Method not permitted.');
    if (!request.url || request.url.length > 32768 || !request.url.startsWith('/') || request.url.startsWith('//')) return finish(400, 'INVALID_CALLBACK');
    const url = new URL(request.url, origin);
    if (url.pathname === '/' && !url.search) {
      if (phase !== 'WAITING_FOR_OWNER_CONSENT') return finish(409, 'This one-shot attempt has already started.');
      response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return response.end(`<!doctype html><meta charset="utf-8"><title>New API 本機個人方案驗證</title><h1>New API 本機個人方案驗證</h1><p>僅登入 info@moztech.cc，驗證 GPT-6.1 Sol 與${options.runSyntheticModelJobs ? 'Corely DEV 本機合成模型鏈路' : '固定合成題'}。這不是雲端客服接通。</p><p>不讀真實顧客、不送出、不寫學習、不使用 API key；憑證只留本次程序記憶體，測後嘗試撤銷。</p><p>本機只保留不含憑證的工具註冊對應，以免重複建立註冊。</p><p><a href="${attempt.url.replaceAll('&', '&amp;')}">Continue with ChatGPT</a></p>`);
    }
    if (url.pathname === '/status' && !url.search) return finish(200, JSON.stringify({ phase, noApiKeyFallback: true, noCloud: true }));
    if (url.pathname !== '/auth/callback') return finish(404, 'Not found.');
    if (inFlight) return finish(409, 'This attempt has already been consumed.');
    let registration;
    try { registration = consumeCallback(request.url, attempt); }
    catch (error) {
      finish(400, error instanceof ProbeError ? error.code : 'INVALID_CALLBACK');
      if (attempt.used) { phase = 'AUTHORIZATION_NOT_COMPLETED'; process.exitCode = 1; void stop(); }
      return;
    }
    inFlight = true;
    phase = 'VALIDATING_AUTHORIZATION';
    response.writeHead(303, { Location: '/status' }); response.end();
    try {
      // Keep the issued ID even if exchange fails, as required for retrying the same registration.
      profile.clientId = registration.clientId;
      await saveRegistration(profile, registrationPath);
      const discovery = await publicJson(`${ISSUER}/.well-known/openid-configuration`, {}, fetchImpl, abort.signal);
      if (discovery.issuer !== ISSUER || discovery.jwks_uri !== `${ISSUER}/.well-known/jwks.json` ||
          discovery.authorization_endpoint !== `${ISSUER}/api/accounts/authorize` ||
          discovery.token_endpoint !== `${ISSUER}/api/accounts/oauth/token` ||
          discovery.revocation_endpoint !== `${ISSUER}/api/accounts/oauth/revoke`) throw new ProbeError('DISCOVERY_NOT_EXPECTED');
      const token = await publicJson(discovery.token_endpoint, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: registration.form }, fetchImpl, abort.signal);
      // Retain a bounded cleanup handle before validation, including rejected account grants.
      if (typeof token.refresh_token === 'string' && token.refresh_token.length > 0 && token.refresh_token.length <= 65536) {
        cleanupToken = token.refresh_token; cleanupClientId = registration.clientId;
      }
      const jwks = await publicJson(discovery.jwks_uri, {}, fetchImpl, abort.signal);
      session = validateSession(token, jwks, registration.clientId, attempt.nonce, 'info@moztech.cc', Date.now(), profile.subjectHash);
      if (!cleanupToken) throw new ProbeError('RENEWABLE_SESSION_NOT_AVAILABLE');
      if (abort.signal.aborted) throw new ProbeError('ATTEMPT_EXPIRED');
      profile.subjectHash = session.subjectHash;
      await saveRegistration(profile, registrationPath);
      if (options.runSyntheticModelJobs) {
        phase = 'RUNNING_CORELY_SYNTHETIC_MODEL_JOBS';
        const port = createTransientSiwcModelPort({ ...session, alias: 'info' }, fetchImpl, abort.signal);
        const result = await options.runSyntheticModelJobs(port);
        if (abort.signal.aborted) throw new ProbeError('ATTEMPT_EXPIRED');
        if (!result || typeof result !== 'object' || Array.isArray(result) || result.passed !== true || result.apiKeyUsed !== false ||
            !Number.isSafeInteger(result.modelCalls) || result.modelCalls < 1 || result.modelCalls > 50 ||
            Object.keys(result).some(key => !['passed', 'apiKeyUsed', 'modelCalls'].includes(key))) throw new ProbeError('CORELY_LOCAL_MODEL_TEST_NOT_VERIFIED');
        phase = 'LOCAL_CORELY_MODEL_JOBS_COMPLETED';
        safe({ status: phase, model: 'gpt-6.1-sol', modelCalls: result.modelCalls, planScopeGranted: true, accountMatchesInfo: true,
          authorizationPath: 'SIWC_PLAN_GRANT', planAuthorizedInferenceVerified: true, hostedCorelyTested: false,
          exactDebitAmountVerified: false, apiKeyFallbackUsed: false, credentialsPersisted: false, completedAt: new Date().toISOString() });
        return;
      }
      phase = 'RUNNING_ONE_SYNTHETIC_PROBE';
      const result = await runSyntheticProbe(session, fetchImpl, abort.signal);
      phase = 'LOCAL_DIRECT_PROBE_COMPLETED';
      safe({ status: phase, ...result, planScopeGranted: true, accountMatchesInfo: true,
        authorizationPath: 'SIWC_PLAN_GRANT', planAuthorizedInferenceVerified: true, planDebitVerified: false,
        newApiRelayTested: false, hostedCorelyTested: false,
        exactDebitAmountVerified: false, apiKeyFallbackUsed: false, credentialsPersisted: false,
        completedAt: new Date().toISOString() });
    } catch (error) {
      phase = 'PROBE_FAILED';
      process.exitCode = 1;
      safe({ status: phase, code: error instanceof ProbeError ? error.code : 'INTERNAL_ERROR',
        diagnostic: error instanceof ProbeError ? error.diagnostic : undefined,
        ...(session ? { accountMatchesInfo: session.accountMatchesExpected === true, planScopeGranted: session.planScopeGranted === true } : {}),
        apiKeyFallbackUsed: false });
    } finally { await stop(); }
  }
  server.requestTimeout = 10000;
  server.headersTimeout = 10000;
  server.maxHeadersCount = 30;
  try { await new Promise((accept, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', accept); }); }
  catch { await lock.close(); await unlink(lockPath).catch(() => {}); throw new ProbeError('LOCAL_LISTENER_UNAVAILABLE'); }
  origin = `http://127.0.0.1:${server.address().port}`;
  attempt = createAttempt(profile.hostId, `${origin}/auth/callback`, Date.now(), profile);
  deadline = setTimeout(() => { phase = 'ATTEMPT_EXPIRED'; process.exitCode = 1; void stop(); }, 600000);
  process.once('SIGINT', interrupt);
  process.once('SIGTERM', interrupt);
  safe({ status: phase, localUrl: origin, app: 'New API Local Personal Plan Pilot', expectedAccount: 'info@moztech.cc',
    noCloud: true, noCustomerData: true, credentialsPersisted: false, registrationMappingRetained: true, noApiKeyFallback: true });
  return Object.freeze({ localUrl: origin, completion, close: stop });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3 || process.argv[2] !== '--authorize-info-local-only') {
    safe({ status: 'NOT_STARTED', scope: 'LOCAL_PERSONAL_PROJECT_SYNTHETIC_ONLY',
      command: 'node bin/siwc-local-pilot.mjs --authorize-info-local-only',
      createsNewAuthorization: true, noCloud: true, noApiKeyFallback: true,
      credentialsPersisted: false, noCustomerData: true });
  } else {
    startLocalPilot().catch(error => { safe({ status: 'NOT_STARTED', code: error instanceof ProbeError ? error.code : 'LOCAL_SETUP_FAILED' }); process.exitCode = 1; });
  }
}
