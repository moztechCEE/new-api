#!/usr/bin/env node
// Explicit operator commands for app-owned, owner-operated DEV synthetic SIWC.
// No arbitrary prompts, customer data, credential export to stdout or API key.
import { createServer } from 'node:http';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { createAttempt, consumeCallback, publicJson, ISSUER, ProbeError } from './siwc-local-runtime.mjs';
import { openSessionStore, retainIssuedRegistration, persistValidatedAuthorization, writeEnrollment,
  importEnrollment, forgetTransferredEnrollment, createPersistentPlanSessions, SESSION_ACCOUNTS, revokeRenewableSession } from './siwc-local-sessions.mjs';

const APP_NAME = 'New API DEV Personal Plan';
const safe = value => process.stdout.write(`${JSON.stringify(value)}\n`);
const fail = code => { throw new ProbeError(code); };
const errorCode = error => error instanceof ProbeError ? error.code : 'SESSION_COMMAND_FAILED';
const cleanEnvironment = ['OPENAI_API_KEY', 'OPENAI_BASE_URL', 'OPENAI_ACCESS_TOKEN', 'CODEX_HOME', 'CODEX_INTERNAL_ORIGINATOR_OVERRIDE',
  'NODE_OPTIONS', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy', 'NODE_EXTRA_CA_CERTS', 'NODE_TLS_REJECT_UNAUTHORIZED'];
const unsafeDiagnostics = ['NODE_DEBUG', 'NODE_DEBUG_NATIVE', 'NODE_V8_COVERAGE', 'SSLKEYLOGFILE',
  'SSL_CERT_FILE', 'SSL_CERT_DIR', 'OPENSSL_CONF', 'NODE_USE_ENV_PROXY', 'NODE_USE_SYSTEM_CA'];

export function assertIsolatedSessionEnvironment(env = process.env) {
  if ([...cleanEnvironment, ...unsafeDiagnostics].some(key => key in env) || Object.keys(env).some(key => /^CORELY_.*API.*KEY$/i.test(key))) fail('SESSION_ENVIRONMENT_NOT_ISOLATED');
}

/** Starts normal OAuth on the browser's computer. Only this app's new session
 * is persisted; the old one-shot local pilot retains its memory-only contract. */
export async function startPersistentEnrollment({ store, alias, targetHostId, fetchImpl = globalThis.fetch, signal }) {
  if (store.host.runtime !== 'enrollment' || !Object.hasOwn(SESSION_ACCOUNTS, alias) ||
    !/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(targetHostId ?? '') ||
    targetHostId === store.host.hostId) fail('ENROLLMENT_NOT_ADMITTED');
  const saved = await store.read(alias);
  if (saved && ['active', 'refresh_pending'].includes(saved.state)) fail('EXISTING_SESSION_MUST_DISCONNECT');
  const controller = new AbortController();
  let attempt, origin, inFlight = false, phase = 'WAITING_FOR_OWNER_CONSENT', persisted = false;
  let cleanupToken, cleanupClientId, deadline, completed = false;
  let accept, reject;
  const completion = new Promise((resolve, fail) => { accept = resolve; reject = fail; });
  completion.catch(() => {});
  const server = createServer({ maxHeaderSize: 8192 }, (request, response) => {
    void handle(request, response).catch(() => { if (!response.headersSent) response.writeHead(400); response.end('Request failed.'); });
  });
  function close() { server.close(); server.closeAllConnections(); }
  async function finish(error, result) {
    if (completed) return;
    completed = true; clearTimeout(deadline); signal?.removeEventListener('abort', abort);
    let revoked;
    if (!persisted && cleanupToken && cleanupClientId) {
      revoked = await revokeRenewableSession({ refreshToken: cleanupToken, clientId: cleanupClientId }, fetchImpl);
    }
    cleanupToken = undefined; attempt = undefined;
    if (error) {
      phase = 'ENROLLMENT_HELD';
      reject(new ProbeError(revoked === false ? 'ENROLLMENT_REMOTE_REVOCATION_UNCONFIRMED' : errorCode(error)));
    } else { phase = 'ENROLLMENT_SAVED_FOR_TRANSFER'; accept(result); }
    // The redirect target remains briefly readable; no tokens or auth URL are
    // exposed by it. Closing this listener never revokes a persisted session.
    const closeTimer = setTimeout(close, 15000); closeTimer.unref();
  }
  function abort() {
    controller.abort();
    if (!inFlight) { void finish(new ProbeError('ENROLLMENT_ABORTED')); close(); }
  }
  async function handle(request, response) {
    response.setHeader('Cache-Control', 'no-store'); response.setHeader('Referrer-Policy', 'no-referrer');
    response.setHeader('X-Content-Type-Options', 'nosniff'); response.setHeader('Content-Type', 'text/plain; charset=utf-8');
    response.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
    const end = (status, text) => { response.writeHead(status); response.end(text); };
    const hosts = request.rawHeaders.filter((_value, index) => index % 2 === 0 && request.rawHeaders[index].toLowerCase() === 'host');
    if (!origin || !['127.0.0.1', '::ffff:127.0.0.1'].includes(request.socket.remoteAddress) ||
      hosts.length !== 1 || request.headers.host !== new URL(origin).host ||
      (request.headers.origin && request.headers.origin !== origin) || request.headers['transfer-encoding'] ||
      (request.headers['content-length'] && request.headers['content-length'] !== '0')) return end(403, 'Request not permitted.');
    if (request.method !== 'GET') return end(405, 'Method not permitted.');
    if (!request.url || request.url.length > 32768 || !request.url.startsWith('/') || request.url.startsWith('//')) return end(400, 'Invalid request.');
    if (request.url === '/status') return end(200, JSON.stringify({ phase, expectedAccount: SESSION_ACCOUNTS[alias],
      credentialsPersisted: persisted, syntheticOnly: true, apiFallbackEnabled: false }));
    if (request.url === '/') {
      if (completed || inFlight || controller.signal.aborted) return end(409, 'This authorization has already started.');
      response.writeHead(302, { Location: attempt.url }); return response.end();
    }
    if (!request.url.startsWith('/auth/callback?')) return end(404, 'Not found.');
    if (completed || inFlight || controller.signal.aborted) return end(409, 'Authorization already consumed.');
    let registration;
    try { registration = consumeCallback(request.url, attempt); }
    catch (error) { end(400, errorCode(error)); if (attempt.used) await finish(error); return; }
    inFlight = true; phase = 'VALIDATING_AUTHORIZATION';
    response.writeHead(303, { Location: '/status' }); response.end();
    try {
      await retainIssuedRegistration(store, alias, registration.clientId);
      const discovery = await publicJson(`${ISSUER}/.well-known/openid-configuration`, {}, fetchImpl, controller.signal);
      if (discovery.issuer !== ISSUER || discovery.jwks_uri !== `${ISSUER}/.well-known/jwks.json` ||
        discovery.authorization_endpoint !== `${ISSUER}/api/accounts/authorize` ||
        discovery.token_endpoint !== `${ISSUER}/api/accounts/oauth/token` ||
        discovery.revocation_endpoint !== `${ISSUER}/api/accounts/oauth/revoke`) fail('DISCOVERY_NOT_EXPECTED');
      const token = await publicJson(discovery.token_endpoint, { method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: registration.form }, fetchImpl, controller.signal);
      if (typeof token.refresh_token === 'string' && token.refresh_token.length > 0 && token.refresh_token.length <= 65536) {
        cleanupToken = token.refresh_token; cleanupClientId = registration.clientId;
      }
      const jwks = await publicJson(discovery.jwks_uri, {}, fetchImpl, controller.signal);
      if (controller.signal.aborted) fail('ENROLLMENT_ABORTED');
      const receipt = await persistValidatedAuthorization(store, alias, { token, jwks, clientId: registration.clientId, nonce: attempt.nonce });
      persisted = true;
      const transfer = await writeEnrollment(store, alias, targetHostId);
      await finish(undefined, { status: 'ENROLLMENT_SAVED_FOR_TRANSFER', ...receipt, ...transfer,
        app: APP_NAME, modelExecuted: false, sendingPerformed: false, learningPerformed: false });
    } catch (error) { await finish(error); }
  }
  server.headersTimeout = 5000; server.requestTimeout = 5000; server.timeout = 5000;
  server.maxRequestsPerSocket = 1; server.maxConnections = 16;
  server.on('clientError', (_error, socket) => socket.destroy());
  try { await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); }); }
  catch { close(); fail('ENROLLMENT_LISTENER_UNAVAILABLE'); }
  origin = `http://127.0.0.1:${server.address().port}`;
  attempt = createAttempt(store.host.hostId, `${origin}/auth/callback`, Date.now(), { clientId: saved?.clientId, agentName: APP_NAME });
  deadline = setTimeout(() => { controller.abort(); if (!inFlight) { void finish(new ProbeError('ENROLLMENT_EXPIRED')); close(); } }, 600000);
  signal?.addEventListener('abort', abort, { once: true });
  if (signal?.aborted) abort();
  return Object.freeze({ localUrl: origin, expectedAccount: SESSION_ACCOUNTS[alias], app: APP_NAME, completion,
    close: async () => { controller.abort(); if (!inFlight && !completed) await finish(new ProbeError('ENROLLMENT_ABORTED')); close(); } });
}

export function parseSessionCommand(argv) {
  const commands = ['init-vm', 'authorize', 'prepare-transfer', 'import', 'forget-transferred', 'status', 'probe', 'maintain', 'disconnect'];
  if (!commands.includes(argv[0]) || argv.length % 2 !== 1) fail('SESSION_COMMAND_INVALID');
  const options = {};
  for (let index = 1; index < argv.length; index += 2) {
    const key = argv[index], value = argv[index + 1];
    if (!['--state-dir', '--account', '--target-host-id', '--imported-sha256'].includes(key) || Object.hasOwn(options, key) ||
      typeof value !== 'string' || !value || value.startsWith('--')) fail('SESSION_COMMAND_INVALID');
    options[key] = value;
  }
  const allowed = {
    'init-vm': ['--state-dir'], authorize: ['--state-dir', '--account', '--target-host-id'],
    'prepare-transfer': ['--state-dir', '--account', '--target-host-id'], import: ['--state-dir', '--account'],
    'forget-transferred': ['--state-dir', '--account', '--imported-sha256'], status: ['--state-dir'],
    probe: ['--state-dir'], maintain: ['--state-dir'], disconnect: ['--state-dir', '--account'],
  }[argv[0]];
  if (Object.keys(options).length !== allowed.length || allowed.some(key => !options[key]) ||
    (options['--account'] && !Object.hasOwn(SESSION_ACCOUNTS, options['--account']))) fail('SESSION_COMMAND_INVALID');
  return { command: argv[0], options };
}

async function readImportStdin() {
  const chunks = []; let size = 0;
  for await (const chunk of process.stdin) { size += chunk.length; if (size > 262144) fail('ENROLLMENT_NOT_ADMITTED'); chunks.push(Buffer.from(chunk)); }
  try { return JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(Buffer.concat(chunks))); } catch { fail('ENROLLMENT_NOT_ADMITTED'); }
}

export async function runSessionCommand(argv) {
  const { command, options } = parseSessionCommand(argv);
  assertIsolatedSessionEnvironment();
  const enrollment = ['authorize', 'prepare-transfer', 'forget-transferred'].includes(command);
  const store = await openSessionStore(options['--state-dir'], { runtime: enrollment ? 'enrollment' : 'vm' });
  if (command === 'init-vm') return safe({ status: 'DEV_VM_HOST_READY', ...store.host, credentialsCreated: false });
  if (command === 'prepare-transfer') return safe(await writeEnrollment(store, options['--account'], options['--target-host-id']));
  if (command === 'forget-transferred') return safe(await forgetTransferredEnrollment(store, options['--account'], options['--imported-sha256']));
  if (command === 'import') {
    const bundle = await readImportStdin();
    const jwks = await publicJson(`${ISSUER}/.well-known/jwks.json`);
    return safe({ status: 'DEV_SESSION_IMPORTED', ...await importEnrollment(store, options['--account'], bundle, jwks) });
  }
  if (command === 'authorize') {
    const controller = new AbortController(), stop = () => controller.abort();
    process.once('SIGINT', stop); process.once('SIGTERM', stop);
    let enrollment;
    try {
      enrollment = await startPersistentEnrollment({ store, alias: options['--account'], targetHostId: options['--target-host-id'], signal: controller.signal });
      safe({ status: 'WAITING_FOR_OWNER_CONSENT', localUrl: enrollment.localUrl, expectedAccount: enrollment.expectedAccount,
        app: enrollment.app, syntheticOnly: true, credentialsWillPersist: true, apiFallbackEnabled: false });
      safe(await enrollment.completion);
    } finally { process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); await enrollment?.close(); }
    return;
  }
  const sessions = createPersistentPlanSessions(store);
  if (command === 'status') return safe(await sessions.status());
  if (command === 'probe') return safe({ status: 'DEV_FIXED_PROBE_COMPLETED', ...await sessions.probeInAccountOrder() });
  if (command === 'disconnect') {
    const receipt = await sessions.disconnect(options['--account']); safe(receipt);
    if (receipt.remoteRevocationAttempted && !receipt.remoteRevocationConfirmed) process.exitCode = 1;
    return;
  }
  const controller = new AbortController(), stop = () => controller.abort();
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
  try {
    let previous = '';
    while (!controller.signal.aborted) {
      const receipt = await sessions.maintain(controller.signal), serialized = JSON.stringify(receipt);
      if (serialized !== previous) { safe(receipt); previous = serialized; }
      try { await delay(30000, undefined, { signal: controller.signal }); } catch { /* Normal daemon shutdown. */ }
    }
  } catch (error) { if (!controller.signal.aborted) throw error; }
  finally { process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runSessionCommand(process.argv.slice(2)).catch(error => { safe({ status: 'DEV_SESSION_COMMAND_HELD', code: errorCode(error), apiFallbackUsed: false }); process.exitCode = 1; });
}
