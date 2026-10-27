// App-owned SIWC sessions for the owner-operated New API DEV synthetic pilot.
// No native Codex/Luna cache, API key, general-purpose proxy or customer input.
import { randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, realpath, rename, unlink } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { ISSUER, RESOURCE, SCOPES, ProbeError, digest, publicJson, validateSession, runSyntheticProbe } from './siwc-local-runtime.mjs';

export const VM_NAME = 'new-api-dev-20261022';
export const SESSION_ACCOUNTS = Object.freeze({ info: 'info@moztech.cc', eason: 'moztecheason@gmail.com' });
const HOST_KIND = 'NEW_API_SIWC_DEV_HOST';
const SESSION_KIND = 'NEW_API_SIWC_DEV_SESSION';
const MAX_RECORD = 262144;
const HOST_ID = /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const CLIENT_ID = /^(?!dynamic_agent_client$)[A-Za-z0-9_-]{1,256}$/;
const HASH = /^[0-9a-f]{64}$/;
const STATES = new Set(['disconnected', 'active', 'refresh_pending', 'reauth_required']);
const INVALID_REFRESH = new Set(['invalid_grant', 'invalid_refresh_token', 'token_expired', 'refresh_token_expired',
  'refresh_token_invalidated', 'refresh_token_reused']);
const fail = code => { throw new ProbeError(code); };
const object = value => Boolean(value && typeof value === 'object' && !Array.isArray(value));
const timestamp = value => Number.isSafeInteger(value) && value >= 0 && value <= Number.MAX_SAFE_INTEGER - 86400000;
const secret = (value, limit = 65536) => typeof value === 'string' && value.length > 0 && value.length <= limit && !/[\u0000-\u0020\u007f]/.test(value);
const sameKeys = (value, keys) => object(value) && Object.keys(value).every(key => keys.includes(key));
const tokenKeys = ['accessToken', 'refreshToken', 'idToken', 'nonce', 'expiresAt', 'scopes'];

function account(alias) {
  if (!Object.hasOwn(SESSION_ACCOUNTS, alias)) fail('ACCOUNT_NOT_ADMITTED');
  return SESSION_ACCOUNTS[alias];
}
function validateRecord(value, alias, hostId) {
  account(alias);
  if (!sameKeys(value, ['kind', 'version', 'alias', 'email', 'issuer', 'hostId', 'authorizationHostId', 'state',
    'clientId', 'subjectHash', 'createdAt', 'updatedAt', 'revision', ...tokenKeys]) ||
    value.kind !== SESSION_KIND || value.version !== 1 || value.alias !== alias || value.email !== account(alias) ||
    value.issuer !== ISSUER || value.hostId !== hostId || !HOST_ID.test(value.authorizationHostId ?? '') ||
    !STATES.has(value.state) || !CLIENT_ID.test(value.clientId ?? '') ||
    !timestamp(value.createdAt) || !timestamp(value.updatedAt) || value.createdAt > value.updatedAt ||
    !Number.isSafeInteger(value.revision) || value.revision < 1 ||
    (value.subjectHash !== undefined && !HASH.test(value.subjectHash))) fail('SESSION_RECORD_INVALID');
  if (['active', 'refresh_pending'].includes(value.state)) {
    if (!HASH.test(value.subjectHash ?? '') || !secret(value.accessToken) || !secret(value.refreshToken) ||
      !secret(value.idToken, 32768) || !secret(value.nonce, 256) || !timestamp(value.expiresAt) ||
      value.expiresAt <= value.updatedAt || value.expiresAt > value.updatedAt + 86400000 ||
      !Array.isArray(value.scopes) || value.scopes.length > 16 || new Set(value.scopes).size !== value.scopes.length ||
      value.scopes.some(scope => typeof scope !== 'string' || !/^[a-z_.:]{1,128}$/.test(scope)) ||
      !['resource.invoke', 'chatgpt.tokens.use.direct'].every(scope => value.scopes.includes(scope))) fail('SESSION_RECORD_INVALID');
  } else if (tokenKeys.some(key => Object.hasOwn(value, key))) fail('SESSION_RECORD_INVALID');
  return value;
}

async function privateRead(path, { optional = false } = {}) {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stat = await handle.stat();
    if (!stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o777) !== 0o600 || stat.size > MAX_RECORD ||
      (process.getuid && stat.uid !== process.getuid())) fail('SESSION_STORAGE_NOT_PRIVATE');
    return JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(await handle.readFile()));
  } catch (error) {
    if (optional && error.code === 'ENOENT') return undefined;
    throw error instanceof ProbeError ? error : new ProbeError('SESSION_STORAGE_INVALID');
  } finally { await handle?.close(); }
}

async function privateWrite(root, filename, value, { exclusive = false } = {}) {
  const path = join(root, filename), temporary = join(root, `.${filename}.${randomUUID()}.tmp`);
  let handle;
  try {
    const bytes = JSON.stringify(value);
    if (Buffer.byteLength(bytes) > MAX_RECORD) fail('SESSION_RECORD_TOO_LARGE');
    if (!exclusive) await privateRead(path, { optional: true });
    handle = await open(exclusive ? path : temporary,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    await handle.writeFile(bytes); await handle.sync(); await handle.close(); handle = undefined;
    if (!exclusive) await rename(temporary, path);
    const dir = await open(root, constants.O_RDONLY);
    try { await dir.sync(); } finally { await dir.close(); }
  } catch (error) {
    if (exclusive && error.code === 'EEXIST') throw error;
    throw error instanceof ProbeError ? error : new ProbeError('SESSION_STORAGE_WRITE_FAILED');
  } finally { await handle?.close(); if (!exclusive) await unlink(temporary).catch(() => {}); }
}

/** The selected application path is canonicalized; no credential-store discovery
 * or native runtime home is consulted. Existing weak permissions are rejected,
 * never silently repaired. The VM's host ID is separate from imported sessions. */
export async function openSessionStore(path, { runtime = 'vm' } = {}) {
  if (typeof path !== 'string' || !isAbsolute(path) || !['vm', 'enrollment'].includes(runtime)) fail('SESSION_STORAGE_PATH_INVALID');
  const selected = resolve(path);
  let root;
  try {
    const parent = await realpath(dirname(selected));
    root = join(parent, basename(selected));
    if (root === parent || root === '/') fail('SESSION_STORAGE_PATH_INVALID');
    const parentStat = await lstat(parent);
    if (!parentStat.isDirectory() || ((parentStat.mode & 0o022) && !(parentStat.mode & 0o1000))) fail('SESSION_STORAGE_NOT_PRIVATE');
    let stat;
    try { stat = await lstat(root); }
    catch (error) {
      if (error.code !== 'ENOENT') throw error;
      try { await mkdir(root, { mode: 0o700 }); } catch (creation) { if (creation.code !== 'EEXIST') throw creation; }
      stat = await lstat(root);
    }
    if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o700 ||
      (process.getuid && stat.uid !== process.getuid())) fail('SESSION_STORAGE_NOT_PRIVATE');
  } catch (error) { throw error instanceof ProbeError ? error : new ProbeError('SESSION_STORAGE_UNAVAILABLE'); }
  let host = await privateRead(join(root, 'host.json'), { optional: true });
  if (!host) {
    const candidate = { kind: HOST_KIND, version: 1, runtime, vm: VM_NAME, hostId: `urn:uuid:${randomUUID()}` };
    try { await privateWrite(root, 'host.json', candidate, { exclusive: true }); host = candidate; }
    catch (error) { if (error.code !== 'EEXIST') throw error; host = await privateRead(join(root, 'host.json')); }
  }
  if (!sameKeys(host, ['kind', 'version', 'runtime', 'vm', 'hostId']) || Object.keys(host).length !== 5 ||
    host.kind !== HOST_KIND || host.version !== 1 || host.runtime !== runtime || host.vm !== VM_NAME || !HOST_ID.test(host.hostId ?? '')) fail('HOST_RECORD_INVALID');
  const queues = new Map();
  async function locked(alias, action) {
    account(alias);
    const previous = queues.get(alias) ?? Promise.resolve();
    let release;
    const current = new Promise(resolve => { release = resolve; });
    const tail = previous.then(() => current); queues.set(alias, tail);
    await previous;
    let lock;
    const lockPath = join(root, `${alias}.lock`);
    try {
      try { lock = await open(lockPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600); }
      catch { fail('SESSION_BUSY_OR_LOCKED'); }
      return await action();
    } finally {
      let cleanupFailed = false;
      if (lock) {
        try { await lock.close(); } catch { cleanupFailed = true; }
        try { await unlink(lockPath); } catch { cleanupFailed = true; }
      }
      release(); if (queues.get(alias) === tail) queues.delete(alias);
      if (cleanupFailed) fail('SESSION_LOCK_CLEANUP_UNCONFIRMED');
    }
  }
  const read = async alias => {
    account(alias);
    const record = await privateRead(join(root, `${alias}.json`), { optional: true });
    return record ? validateRecord(record, alias, host.hostId) : undefined;
  };
  const write = async (alias, record) => privateWrite(root, `${alias}.json`, validateRecord(record, alias, host.hostId));
  return Object.freeze({ host: Object.freeze({ ...host }), root, locked, read, write });
}

export async function retainIssuedRegistration(store, alias, clientId, now = Date.now()) {
  account(alias);
  if (!CLIENT_ID.test(clientId ?? '') || !timestamp(now)) fail('INVALID_REGISTRATION');
  return store.locked(alias, async () => {
    const old = await store.read(alias);
    if (old && (old.clientId !== clientId || now < old.updatedAt)) fail('REGISTRATION_MISMATCH');
    if (!old) await store.write(alias, { kind: SESSION_KIND, version: 1, alias, email: account(alias), issuer: ISSUER,
      hostId: store.host.hostId, authorizationHostId: store.host.hostId, state: 'disconnected', clientId,
      createdAt: now, updatedAt: now, revision: 1 });
    return Object.freeze({ clientId, ...(old?.subjectHash ? { subjectHash: old.subjectHash } : {}) });
  });
}

/** Called only by this app's normal OAuth callback, never by an inference API. */
export async function persistValidatedAuthorization(store, alias, { token, jwks, clientId, nonce }, now = Date.now()) {
  account(alias);
  return store.locked(alias, async () => {
    const old = await store.read(alias);
    if (!timestamp(now) || (old && (old.clientId !== clientId || now < old.updatedAt))) fail('REGISTRATION_MISMATCH');
    const session = validateSession(token, jwks, clientId, nonce, account(alias), now, old?.subjectHash);
    const scopes = token.scope.split(/\s+/).filter(Boolean);
    if (!session.refreshToken || !scopes.includes('offline_access')) fail('RENEWABLE_SESSION_NOT_AVAILABLE');
    if (scopes.some(scope => !SCOPES.split(' ').includes(scope))) fail('PLAN_SCOPE_NOT_ADMITTED');
    const record = { kind: SESSION_KIND, version: 1, alias, email: account(alias), issuer: ISSUER,
      hostId: store.host.hostId, authorizationHostId: store.host.hostId, state: 'active', clientId,
      subjectHash: session.subjectHash, accessToken: session.accessToken, refreshToken: session.refreshToken,
      idToken: token.id_token, nonce, expiresAt: session.expiresAt, scopes,
      createdAt: old?.createdAt ?? now, updatedAt: now, revision: (old?.revision ?? 0) + 1 };
    await store.write(alias, record);
    return sessionMetadata(record);
  });
}

function withoutTokens(record, state, now) {
  const clean = { ...record, state, updatedAt: now, revision: record.revision + 1 };
  for (const key of tokenKeys) delete clean[key];
  return clean;
}
function sessionMetadata(record) {
  return Object.freeze({ alias: record.alias, expectedAccount: record.email, state: record.state,
    identityVerified: Boolean(record.subjectHash), registrationRetained: true,
    ...(record.expiresAt ? { expiresAt: record.expiresAt } : {}), revision: record.revision,
    authorizationSource: 'APP_OWNED_SIWC', apiFallbackEnabled: false, syntheticOnly: true });
}

/** An import accepts only this application's protected enrollment record.
 * The destination retains its previously initialized VM host ID. It cannot
 * replace another account/client identity or import native credential formats. */
export async function importEnrollment(store, alias, bundle, jwks, now = Date.now()) {
  if (store.host.runtime !== 'vm') fail('IMPORT_DESTINATION_NOT_VM');
  account(alias);
  if (!sameKeys(bundle, ['kind', 'version', 'targetVm', 'targetHostId', 'record']) || Object.keys(bundle).length !== 5 ||
    bundle.kind !== 'NEW_API_SIWC_ENROLLMENT' || bundle.version !== 1 || bundle.targetVm !== VM_NAME ||
    bundle.targetHostId !== store.host.hostId || !object(bundle.record)) fail('ENROLLMENT_NOT_ADMITTED');
  const source = validateRecord(bundle.record, alias, bundle.record.hostId);
  if (source.state !== 'active' || source.hostId === store.host.hostId || source.authorizationHostId !== source.hostId ||
    !timestamp(now) || now < source.updatedAt || source.expiresAt <= now) fail('ENROLLMENT_NOT_ADMITTED');
  const secondsRemaining = Math.floor((source.expiresAt - now) / 1000);
  validateSession({ id_token: source.idToken, access_token: source.accessToken, refresh_token: source.refreshToken,
    token_type: 'Bearer', expires_in: secondsRemaining, scope: source.scopes.join(' ') }, jwks,
  source.clientId, source.nonce, account(alias), now, source.subjectHash);
  return store.locked(alias, async () => {
    const old = await store.read(alias);
    if (old && (old.clientId !== source.clientId || (old.subjectHash && old.subjectHash !== source.subjectHash))) fail('REGISTRATION_MISMATCH');
    if (old && ['active', 'refresh_pending'].includes(old.state)) fail('EXISTING_SESSION_MUST_DISCONNECT');
    if (old && (now < old.updatedAt || (old.subjectHash && source.updatedAt <= old.updatedAt))) fail('ENROLLMENT_REPLAY_REJECTED');
    const record = { ...source, hostId: store.host.hostId, createdAt: old?.createdAt ?? source.createdAt,
      updatedAt: now, revision: (old?.revision ?? 0) + 1 };
    await store.write(alias, record);
    return Object.freeze({ ...sessionMetadata(record), importedEnrollmentSha256: digest(JSON.stringify(bundle)),
      targetHostIdHash: digest(store.host.hostId) });
  });
}

export async function writeEnrollment(store, alias, targetHostId) {
  if (store.host.runtime !== 'enrollment' || !HOST_ID.test(targetHostId ?? '') || targetHostId === store.host.hostId) fail('ENROLLMENT_NOT_ADMITTED');
  return store.locked(alias, async () => {
    const record = await store.read(alias);
    if (!record || record.state !== 'active') fail('SESSION_REAUTH_REQUIRED');
    const filename = `${alias}.transfer.json`;
    await privateWrite(store.root, filename, { kind: 'NEW_API_SIWC_ENROLLMENT', version: 1, targetVm: VM_NAME, targetHostId, record });
    return Object.freeze({ file: join(store.root, filename), alias, targetVm: VM_NAME, credentialsIncluded: true,
      instruction: 'TRANSFER_THIS_APP_RECORD_OVER_SSH_STDIN_THEN_ERASE_LOCAL_COPY', apiFallbackEnabled: false });
  });
}

export async function forgetTransferredEnrollment(store, alias, importedEnrollmentSha256) {
  if (store.host.runtime !== 'enrollment' || !HASH.test(importedEnrollmentSha256 ?? '')) fail('ENROLLMENT_NOT_ADMITTED');
  account(alias);
  return store.locked(alias, async () => {
    const path = join(store.root, `${alias}.transfer.json`);
    const bundle = await privateRead(path);
    const record = await store.read(alias);
    if (digest(JSON.stringify(bundle)) !== importedEnrollmentSha256 || !record || bundle.record?.clientId !== record.clientId ||
      bundle.record?.subjectHash !== record.subjectHash) fail('ENROLLMENT_NOT_ADMITTED');
    await store.write(alias, withoutTokens(record, 'disconnected', Math.max(Date.now(), record.updatedAt)));
    try { await unlink(path); } catch { fail('ENROLLMENT_LOCAL_CLEANUP_UNCONFIRMED'); }
    return Object.freeze({ alias, localCredentialsRemoved: true, registrationRetained: true, remoteSessionRevoked: false });
  });
}

async function refreshTokenRequest(record, fetchImpl, signal) {
  let response;
  try {
    response = await fetchImpl(`${ISSUER}/api/accounts/oauth/token`, { method: 'POST', redirect: 'error', credentials: 'omit', cache: 'no-store',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: new URLSearchParams({ grant_type: 'refresh_token', client_id: record.clientId,
        refresh_token: record.refreshToken, resource: RESOURCE }),
      signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(20000)]) : AbortSignal.timeout(20000) });
    if (response.redirected || (response.url && response.url !== `${ISSUER}/api/accounts/oauth/token`) ||
      !/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type') ?? '')) fail('REFRESH_OUTCOME_UNCERTAIN');
    const chunks = []; let size = 0;
    for await (const chunk of response.body ?? []) {
      size += chunk.length; if (size > MAX_RECORD) fail('REFRESH_OUTCOME_UNCERTAIN'); chunks.push(Buffer.from(chunk));
    }
    const value = JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(Buffer.concat(chunks)));
    if (!response.ok) {
      const code = typeof value?.error === 'string' ? value.error : value?.error?.code;
      if (INVALID_REFRESH.has(code) && response.status >= 400 && response.status < 500) fail('SESSION_REAUTH_REQUIRED');
      if (code === 'invalid_client' && response.status >= 400 && response.status < 500) fail('REFRESH_CLIENT_INVALID');
      fail('REFRESH_OUTCOME_UNCERTAIN');
    }
    return value;
  } catch (error) { throw error instanceof ProbeError ? error : new ProbeError('REFRESH_OUTCOME_UNCERTAIN'); }
}

export async function revokeRenewableSession(record, fetchImpl = globalThis.fetch) {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      await publicJson(`${ISSUER}/api/accounts/oauth/revoke`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: record.refreshToken, token_type_hint: 'refresh_token', client_id: record.clientId }) }, fetchImpl);
      return true;
    } catch (error) {
      if (attempt || !(error instanceof ProbeError) || !(/UPSTREAM_HTTP_5\d{2}$/.test(error.code) || error.code === 'UPSTREAM_REQUEST_FAILED')) return false;
      await delay(500);
    }
  }
  return false;
}

function validatedRefresh(record, token, jwks, now) {
  if (!object(token) || !secret(token.access_token) || token.token_type?.toLowerCase() !== 'bearer' ||
    !Number.isSafeInteger(token.expires_in) || token.expires_in < 1 || token.expires_in > 86400 ||
    (token.refresh_token !== undefined && !secret(token.refresh_token)) ||
    (token.scope !== undefined && typeof token.scope !== 'string')) fail('REFRESH_OUTCOME_UNCERTAIN');
  const scopes = token.scope === undefined ? record.scopes : token.scope.split(/\s+/).filter(Boolean);
  if (new Set(scopes).size !== scopes.length || scopes.some(scope => !record.scopes.includes(scope)) ||
    !['resource.invoke', 'chatgpt.tokens.use.direct'].every(scope => scopes.includes(scope))) fail('REFRESH_SCOPE_INVALID');
  if (token.id_token !== undefined) {
    // OIDC refresh may omit nonce; if present it must bind the original flow.
    let claims;
    try { claims = JSON.parse(Buffer.from(token.id_token.split('.')[1], 'base64url').toString('utf8')); } catch { fail('REFRESH_IDENTITY_INVALID'); }
    try {
      validateSession({ ...token, refresh_token: token.refresh_token ?? record.refreshToken, scope: scopes.join(' ') }, jwks,
        record.clientId, claims.nonce === undefined ? undefined : record.nonce, account(record.alias), now, record.subjectHash);
    } catch { fail('REFRESH_IDENTITY_INVALID'); }
  }
  return { ...record, state: 'active', accessToken: token.access_token, refreshToken: token.refresh_token ?? record.refreshToken,
    idToken: token.id_token ?? record.idToken, scopes, expiresAt: now + token.expires_in * 1000,
    updatedAt: now, revision: record.revision + 1 };
}

/** Caller receives no credential getter. Inference is a fixed synthetic proof
 * until the separate trusted Corely model-job transport is installed. */
export function createPersistentPlanSessions(store, { fetchImpl = globalThis.fetch, now = Date.now } = {}) {
  if (store.host.runtime !== 'vm' || typeof fetchImpl !== 'function' || typeof now !== 'function') fail('SESSION_MANAGER_INVALID');
  const clock = record => {
    const time = now();
    if (!timestamp(time) || (record && time < record.updatedAt)) fail('SESSION_CLOCK_INVALID');
    return time;
  };
  const checkAbort = signal => { if (signal?.aborted) fail('SESSION_OPERATION_ABORTED'); };
  async function withFreshRecord(alias, action, signal) {
    checkAbort(signal);
    return store.locked(alias, async () => {
      checkAbort(signal);
      const record = await store.read(alias);
      if (!record || record.state !== 'active') fail(record?.state === 'refresh_pending' ? 'REFRESH_OUTCOME_UNCERTAIN' : 'SESSION_REAUTH_REQUIRED');
      const start = clock(record);
      if (record.expiresAt > start + 60000) return action(record);
      // A durable pending marker prevents rotating-token reuse after crash,
      // network ambiguity or an atomic replacement failure. Never auto-retry it.
      await store.write(alias, { ...record, state: 'refresh_pending' });
      try {
        const token = await refreshTokenRequest(record, fetchImpl, signal);
        // Save a returned rotating renewal handle for revocation only before
        // JWKS/identity validation. Pending records can never run inference.
        // Otherwise a transient verification/write failure could orphan the
        // new renewable session while retaining only an invalid old token.
        if (object(token) && secret(token.refresh_token) && token.refresh_token !== record.refreshToken) {
          try { await store.write(alias, { ...record, state: 'refresh_pending', refreshToken: token.refresh_token }); }
          catch {
            const revoked = await revokeRenewableSession({ clientId: record.clientId, refreshToken: token.refresh_token }, fetchImpl);
            fail(revoked ? 'REFRESH_PERSISTENCE_FAILED' : 'REFRESH_REMOTE_REVOCATION_UNCONFIRMED');
          }
        }
        const jwks = token.id_token !== undefined ? await publicJson(`${ISSUER}/.well-known/jwks.json`, {}, fetchImpl, signal) : undefined;
        checkAbort(signal);
        const refreshed = validatedRefresh(record, token, jwks, clock(record));
        await store.write(alias, refreshed);
        return action(refreshed);
      } catch (error) {
        if (error instanceof ProbeError && error.code === 'SESSION_REAUTH_REQUIRED') {
          await store.write(alias, withoutTokens(record, 'reauth_required', clock(record)));
        }
        throw error instanceof ProbeError ? error : new ProbeError('REFRESH_OUTCOME_UNCERTAIN');
      }
    });
  }
  async function probe(alias, signal) {
    return withFreshRecord(alias, async record => {
      checkAbort(signal);
      const result = await runSyntheticProbe({ accessToken: record.accessToken, expiresAt: record.expiresAt,
        planScopeGranted: true, accountMatchesExpected: true }, fetchImpl, signal);
      return Object.freeze({ ...result, alias, authorizationSource: 'APP_OWNED_SIWC', runtime: 'DEV_SYNTHETIC_ONLY',
        accountVerified: true, credentialsPersisted: true, apiKeyFallbackUsed: false,
        newApiRelayTested: false, corelyRelayTested: false, exactDebitAmountVerified: false });
    }, signal);
  }
  return Object.freeze({
    async status() {
      const accounts = [];
      for (const alias of ['info', 'eason']) {
        const record = await store.read(alias);
        accounts.push(record ? sessionMetadata(record) : { alias, expectedAccount: account(alias), state: 'not_connected' });
      }
      return Object.freeze({ vm: VM_NAME, runtime: 'DEV_SYNTHETIC_ONLY', hostIdHash: digest(store.host.hostId),
        accounts, accountOrder: ['info', 'eason'], apiFallbackEnabled: false, corelyRelayConnected: false,
        sendingCapability: false, learningCapability: false });
    },
    async maintain(signal) {
      const results = [];
      for (const alias of ['info', 'eason']) {
        checkAbort(signal);
        const record = await store.read(alias);
        if (!record || record.state !== 'active') continue;
        try { results.push(await withFreshRecord(alias, record => sessionMetadata(record), signal)); }
        catch (error) { results.push({ alias, state: 'held', code: error instanceof ProbeError ? error.code : 'SESSION_MANAGER_FAILED' }); }
      }
      return Object.freeze({ status: 'SESSION_MAINTENANCE_COMPLETED', accounts: results, apiFallbackUsed: false });
    },
    probe,
    async probeInAccountOrder(signal) {
      try { return { ...await probe('info', signal), fallbackReason: null }; }
      catch (error) {
        // Only an authenticated provider plan-limit code can choose Eason.
        // A generic 429, timeout, revoked session or unavailable model must hold.
        if (!(error instanceof ProbeError) || error.diagnostic?.errorCode !== 'subscription_sharing_usage_limit_exceeded') throw error;
      }
      return { ...await probe('eason', signal), fallbackReason: 'info_personal_plan_limit_exceeded' };
    },
    async disconnect(alias) {
      return store.locked(alias, async () => {
        const record = await store.read(alias);
        if (!record) return { alias, localSessionCleared: true, remoteRevocationAttempted: false, remoteRevocationConfirmed: false };
        const time = clock(record);
        let revoked = false;
        if (record.refreshToken) {
          revoked = await revokeRenewableSession(record, fetchImpl);
        }
        await store.write(alias, withoutTokens(record, 'disconnected', time));
        return Object.freeze({ alias, localSessionCleared: true, remoteRevocationAttempted: Boolean(record.refreshToken),
          remoteRevocationConfirmed: revoked, disconnectInChatGptSettingsIfUnconfirmed: Boolean(record.refreshToken) && !revoked });
      });
    },
  });
}
