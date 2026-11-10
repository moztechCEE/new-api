// App-owned SIWC sessions for the owner-operated New API DEV synthetic pilot.
// No native Codex/Luna cache, API key, general-purpose proxy or customer input.
import { randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, readFile, readlink, realpath, rename, unlink } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { ISSUER, RESOURCE, SCOPES, MODEL, ProbeError, digest, publicJson, selectExactModel, validateSession, runSyntheticProbe } from './siwc-local-runtime.mjs';
import { runCorelyPlanRequest } from './siwc-local-model-port.mjs';
import { snapshotModelRequest } from './corely-model-contract.mjs';

export const VM_NAME = 'new-api-dev-20261022';
export const SESSION_ACCOUNTS = Object.freeze({ info: 'info@moztech.cc', eason: 'moztecheason@gmail.com' });
const HOST_KIND = 'NEW_API_SIWC_DEV_HOST';
const SESSION_KIND = 'NEW_API_SIWC_DEV_SESSION';
const MAX_RECORD = 262144;
const ACCESS_RENEWAL_WINDOW_MS = 60_000;
const HOST_ID = /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const CLIENT_ID = /^(?!dynamic_agent_client$)[A-Za-z0-9_-]{1,256}$/;
const HASH = /^[0-9a-f]{64}$/;
const STATES = new Set(['disconnected', 'active', 'refresh_pending', 'reauth_required']);
const INVALID_REFRESH = new Set(['invalid_grant', 'invalid_refresh_token', 'token_expired', 'refresh_token_expired',
  'refresh_token_invalidated', 'refresh_token_reused']);
const fail = code => { throw new ProbeError(code); };
const object = value => Boolean(value && typeof value === 'object' && !Array.isArray(value));
const maintenanceOwners = new WeakSet();
// Cancellation is a bound, not a promise that every transport cooperates.
// Observe late rejection even when cancellation wins; never retry rotation.
function awaitSessionOperation(work, signal) {
  const discard = value => { if (value?.body && !value.body.locked) void value.body.cancel().catch(() => {}); };
  if (signal.aborted) { Promise.resolve(work).then(discard, () => {}); return Promise.reject(new ProbeError('SESSION_OPERATION_ABORTED')); }
  return new Promise((accept, reject) => {
    const abort = () => { signal.removeEventListener('abort', abort); reject(new ProbeError('SESSION_OPERATION_ABORTED')); };
    signal.addEventListener('abort', abort, { once: true });
    Promise.resolve(work).then(value => { signal.removeEventListener('abort', abort); if (signal.aborted) { discard(value); reject(new ProbeError('SESSION_OPERATION_ABORTED')); } else accept(value); },
      error => { signal.removeEventListener('abort', abort); reject(error); });
  });
}

/** One owner, two independent account loops. The same per-account store lock
 * serializes background renewal with selected generation; no third process or
 * fallback policy is installed. ASVS 5.0.0 7.3.2/7.4.1/10.1.1: original
 * authority bounds remain intact, pending ambiguity is quarantined, and safe
 * health metadata is distinct from model/quota success. */
export async function runPersistentPlanMaintenance({ sessions, signal, onReceipt = async () => {}, onReady = async () => {},
  sleep = (ms, active) => delay(ms, undefined, { signal: active }), pollIntervalMs = 30000, now = Date.now } = {}) {
  if (!sessions || typeof sessions.maintainAccount !== 'function' || !(signal instanceof AbortSignal) ||
      typeof sessions.openMaintenanceOwner !== 'function' ||
      typeof onReceipt !== 'function' || typeof onReady !== 'function' || typeof sleep !== 'function' || typeof now !== 'function' ||
      !Number.isSafeInteger(pollIntervalMs) || pollIntervalMs < 1000 || pollIntervalMs > 30000) fail('SESSION_MANAGER_INVALID');
  if (signal.aborted) return Object.freeze({ status: 'SESSION_MAINTENANCE_STOPPED', reason: 'OWNER_STOPPED', modelRequestsMade: 0, apiFallbackUsed: false });
  if (maintenanceOwners.has(sessions)) fail('SESSION_BUSY_OR_LOCKED');
  maintenanceOwners.add(sessions);
  const owner = new AbortController(), active = AbortSignal.any([signal, owner.signal]);
  let ownership;
  try {
    ownership = await sessions.openMaintenanceOwner(active);
    if (!ownership || typeof ownership.close !== 'function') fail('SESSION_MAINTENANCE_FAILED');
    await awaitSessionOperation(Promise.resolve().then(onReady), AbortSignal.any([active, AbortSignal.timeout(5000)]));
  } catch (error) {
    owner.abort(); maintenanceOwners.delete(sessions);
    try { await ownership?.close(); } catch { fail('SESSION_LOCK_CLEANUP_UNCONFIRMED'); }
    if (signal.aborted) return Object.freeze({ status: 'SESSION_MAINTENANCE_STOPPED', reason: 'OWNER_STOPPED', modelRequestsMade: 0, apiFallbackUsed: false });
    throw error instanceof ProbeError ? error : new ProbeError('SESSION_MAINTENANCE_FAILED');
  }
  const tasks = ['info', 'eason'].map(async alias => {
    let previous;
    while (!active.aborted) {
      let value;
      try { value = await sessions.maintainAccount(alias, active); }
      catch (error) { if (active.aborted) return; value = { alias, state: 'held', code: 'SESSION_MAINTENANCE_FAILED' }; }
      if (active.aborted) return;
      const checkedAt = now();
      const usable = value?.state === 'active' && value.alias === alias && value.expectedAccount === account(alias) &&
        value.identityVerified === true && value.registrationRetained === true && value.authorizationSource === 'APP_OWNED_SIWC' &&
        value.apiFallbackEnabled === false && value.syntheticOnly === true && timestamp(value.expiresAt) && value.expiresAt > checkedAt &&
        Number.isSafeInteger(value.revision) && value.revision > 0;
      const unavailable = value?.alias === alias && value.state === 'held' &&
        ['SESSION_REAUTH_REQUIRED', 'REFRESH_OUTCOME_UNCERTAIN', 'REFRESH_CLIENT_INVALID'].includes(value.code);
      const missing = value?.alias === alias && value.state === 'not_connected';
      const metadata = Object.freeze({ alias, state: usable ? 'active' : missing ? 'not_connected' : 'held',
        healthy: Boolean(usable), apiFallbackUsed: false, ...(usable ? { expiresAt: value.expiresAt, revision: value.revision,
          identityVerified: true, registrationRetained: true, authorizationSource: 'APP_OWNED_SIWC' } :
          missing ? {} : { code: unavailable ? value.code : 'SESSION_MAINTENANCE_FAILED' }) });
      if (!timestamp(checkedAt)) fail('SESSION_CLOCK_INVALID');
      const serialized = JSON.stringify(metadata);
      if (serialized !== previous) {
        try { await awaitSessionOperation(Promise.resolve().then(() => onReceipt(Object.freeze({
            status: 'SESSION_ACCOUNT_MAINTENANCE', ...metadata, checkedAt, healthKind: 'APP_OWNED_SESSION_RECORD', modelRequestsMade: 0 }))),
          AbortSignal.any([active, AbortSignal.timeout(5000)])); }
        catch (error) { if (active.aborted) return; throw error; }
        previous = serialized;
      }
      if (!usable && !unavailable && !missing) fail('SESSION_MAINTENANCE_FAILED');
      try { await awaitSessionOperation(sleep(pollIntervalMs, active), active); }
      catch (error) { if (active.aborted) return; throw error; }
    }
  });
  try {
    await Promise.all(tasks);
    return Object.freeze({ status: 'SESSION_MAINTENANCE_STOPPED', reason: 'OWNER_STOPPED', modelRequestsMade: 0, apiFallbackUsed: false });
  } finally {
    owner.abort();
    // Join both owners before the enclosing worker closes its authority/store.
    await Promise.allSettled(tasks);
    let released = false;
    try { await ownership.close(); released = true; }
    finally { maintenanceOwners.delete(sessions); if (!released) fail('SESSION_LOCK_CLEANUP_UNCONFIRMED'); }
  }
}
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

const LOCK_KIND = 'NEW_API_SIWC_PROCESS_LOCK';
const LOCK_NONCE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MAX_LOCK_PREDECESSORS = 8;
const sameInode = (a, b) => a.dev === b.dev && a.ino === b.ino;
const privateLockFile = stat => stat.isFile() && stat.nlink === 1 && (stat.mode & 0o777) === 0o600 &&
  stat.size <= 4096 && (!process.getuid || stat.uid === process.getuid());

/** Linux start ticks are immutable for one process lifetime. PID alone, age,
 * wall clocks and a different PID namespace can never prove an owner dead. */
function processStart(stat, pid) {
  const end = stat.lastIndexOf(')'), fields = stat.slice(end + 2).trim().split(/\s+/);
  if (!stat.startsWith(`${pid} (`) || end < 0 || !/^[A-Z]$/.test(fields[0] ?? '') || !/^\d{1,24}$/.test(fields[19] ?? '')) return undefined;
  return { state: fields[0], ticks: fields[19] };
}

async function processWitness() {
  const unavailable = { pid: process.pid, bootId: null, pidNamespace: null, startTicks: null };
  if (process.platform !== 'linux') return unavailable;
  try {
    const [boot, pidNamespace, stat] = await Promise.all([readFile('/proc/sys/kernel/random/boot_id', 'utf8'),
      readlink('/proc/self/ns/pid'), readFile('/proc/self/stat', 'utf8')]);
    const bootId = boot.trim(), started = processStart(stat, process.pid);
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(bootId) ||
      !/^pid:\[\d{1,24}\]$/.test(pidNamespace) || !started) return unavailable;
    return { pid: process.pid, bootId, pidNamespace, startTicks: started.ticks };
  } catch { return unavailable; }
}

function validLockRecord(record) {
  const keys = record?.version === 1 ? ['kind', 'version', 'nonce', 'owner'] : ['kind', 'version', 'nonce', 'owner', 'predecessorNonces'];
  if (!sameKeys(record, keys) || Object.keys(record).length !== keys.length ||
    record.kind !== LOCK_KIND || ![1, 2].includes(record.version) || !LOCK_NONCE.test(record.nonce ?? '') ||
    !sameKeys(record.owner, ['pid', 'bootId', 'pidNamespace', 'startTicks']) || Object.keys(record.owner).length !== 4 ||
    !Number.isSafeInteger(record.owner.pid) || record.owner.pid < 1) return false;
  if (record.version === 2 && (!Array.isArray(record.predecessorNonces) || record.predecessorNonces.length > MAX_LOCK_PREDECESSORS ||
    new Set(record.predecessorNonces).size !== record.predecessorNonces.length ||
    record.predecessorNonces.some(nonce => !LOCK_NONCE.test(nonce) || nonce === record.nonce))) return false;
  const { bootId, pidNamespace, startTicks } = record.owner;
  return (bootId === null && pidNamespace === null && startTicks === null) ||
    (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(bootId ?? '') &&
      /^pid:\[\d{1,24}\]$/.test(pidNamespace ?? '') && /^\d{1,24}$/.test(startTicks ?? ''));
}

async function ownerProvenDead(owner, current) {
  if (process.platform !== 'linux' || !current.bootId || owner.bootId !== current.bootId ||
    owner.pidNamespace !== current.pidNamespace || owner.startTicks === null) return false;
  try {
    const [stat, pidNamespace] = await Promise.all([readFile(`/proc/${owner.pid}/stat`, 'utf8'), readlink(`/proc/${owner.pid}/ns/pid`)]);
    const started = processStart(stat, owner.pid);
    if (pidNamespace !== current.pidNamespace || !started) return false;
    return started.ticks !== owner.startTicks || ['Z', 'X'].includes(started.state);
  } catch (error) {
    if (!['ENOENT', 'ESRCH'].includes(error.code)) return false;
    try { process.kill(owner.pid, 0); return false; }
    catch (error) { return error.code === 'ESRCH'; }
  }
}

/** A recovery sentinel serializes conditional unlink/recreate. Every creator
 * checks it both before and after O_EXCL. Legacy locks, foreign namespaces and
 * an interrupted recovery sentinel remain held; no timeout deletes a live lock.
 * This does not restore a refresh_pending record or extend a Corely grant. */
export async function acquireSessionProcessLock(root, filename) {
  if (typeof root !== 'string' || !isAbsolute(root) || resolve(root) !== root ||
    !['info.lock', 'eason.lock', 'corely-vm-model-worker.lock', 'siwc-session-maintenance.lock'].includes(filename)) fail('SESSION_STORAGE_INVALID');
  let directory, lock, recovery, recoveredOwnerNonce = null, released = false;
  const lockPath = join(root, filename), recoveryPath = `${lockPath}.recovery`;
  try {
    const before = await lstat(root);
    directory = await open(root, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    const admitted = await directory.stat();
    const checkDirectory = async () => {
      const current = await lstat(root), retained = await directory.stat();
      if (!current.isDirectory() || current.isSymbolicLink() || (current.mode & 0o777) !== 0o700 ||
        (process.getuid && current.uid !== process.getuid()) || !sameInode(current, admitted) || !sameInode(retained, admitted)) fail('SESSION_STORAGE_NOT_PRIVATE');
    };
    if (!sameInode(before, admitted)) fail('SESSION_STORAGE_NOT_PRIVATE');
    await checkDirectory();
    const witness = await processWitness();
    const readLock = async path => {
      let handle;
      try {
        await checkDirectory();
        const before = await lstat(path);
        handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
        const stat = await handle.stat();
        if (!privateLockFile(stat) || !sameInode(before, stat)) fail('SESSION_STORAGE_NOT_PRIVATE');
        const bytes = await handle.readFile(), after = await handle.stat(), current = await lstat(path);
        await checkDirectory();
        if (bytes.length > 4096 || bytes.length !== stat.size || !privateLockFile(after) || !privateLockFile(current) ||
          !sameInode(stat, after) || !sameInode(stat, current) || after.size !== stat.size ||
          after.mtimeMs !== stat.mtimeMs || after.ctimeMs !== stat.ctimeMs) fail('SESSION_BUSY_OR_LOCKED');
        const text = new TextDecoder('utf8', { fatal: true }).decode(bytes), record = JSON.parse(text);
        if (JSON.stringify(record) !== text || !validLockRecord(record)) fail('SESSION_BUSY_OR_LOCKED');
        return { stat, record };
      } catch (error) {
        throw error instanceof ProbeError ? error : new ProbeError('SESSION_BUSY_OR_LOCKED');
      } finally { await handle?.close(); }
    };
    const sentinelPresent = async () => {
      await checkDirectory();
      try { await lstat(recoveryPath); return true; }
      catch (error) { if (error.code === 'ENOENT') return false; throw error; }
    };
    const createLock = async (path, predecessorNonces = []) => {
      let handle;
      try {
        await checkDirectory();
        handle = await open(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
        const record = { kind: LOCK_KIND, version: 2, nonce: randomUUID(), owner: witness, predecessorNonces: [...predecessorNonces] };
        await handle.writeFile(JSON.stringify(record)); await handle.sync();
        const stat = await handle.stat(), current = await readLock(path);
        if (!sameInode(stat, current.stat) || current.record.nonce !== record.nonce) fail('SESSION_BUSY_OR_LOCKED');
        await directory.sync();
        return { handle, stat, record, path };
      } catch (error) { await handle?.close(); throw error; }
    };
    const removeOwnLock = async owned => {
      const current = await readLock(owned.path), retained = await owned.handle.stat();
      if (!sameInode(current.stat, owned.stat) || !sameInode(retained, owned.stat) || current.record.nonce !== owned.record.nonce) fail('SESSION_LOCK_CLEANUP_UNCONFIRMED');
      await unlink(owned.path); await directory.sync();
    };
    const cleanup = async () => {
      let failed = false;
      for (const owned of [lock, recovery]) {
        if (!owned) continue;
        try { await removeOwnLock(owned); } catch { failed = true; }
        try { await owned.handle.close(); } catch { failed = true; }
      }
      lock = recovery = undefined;
      try { await directory.close(); } catch { failed = true; }
      if (failed) fail('SESSION_LOCK_CLEANUP_UNCONFIRMED');
    };
    try {
      if (await sentinelPresent()) fail('SESSION_BUSY_OR_LOCKED');
      try { lock = await createLock(lockPath); }
      catch (error) {
        if (error.code !== 'EEXIST') throw error;
        const stale = await readLock(lockPath);
        if (!await ownerProvenDead(stale.record.owner, witness)) fail('SESSION_BUSY_OR_LOCKED');
        recovery = await createLock(recoveryPath);
        const current = await readLock(lockPath), sentinel = await readLock(recoveryPath);
        if (!sameInode(stale.stat, current.stat) || JSON.stringify(stale.record) !== JSON.stringify(current.record) ||
          !sameInode(recovery.stat, sentinel.stat) || recovery.record.nonce !== sentinel.record.nonce ||
          !await ownerProvenDead(current.record.owner, witness)) fail('SESSION_BUSY_OR_LOCKED');
        // Retain bounded, private predecessor evidence before replacing the
        // owner. A second crash must not orphan an older bound consent prompt.
        // This is lock provenance only, never reusable authorization or a grant.
        const predecessors = [...(current.record.predecessorNonces ?? []), current.record.nonce];
        if (predecessors.length > MAX_LOCK_PREDECESSORS) fail('SESSION_BUSY_OR_LOCKED');
        await unlink(lockPath); await directory.sync();
        lock = await createLock(lockPath, predecessors);
        recoveredOwnerNonce = current.record.nonce;
      }
      if (!recovery && await sentinelPresent()) fail('SESSION_BUSY_OR_LOCKED');
      if (recovery) {
        await removeOwnLock(recovery); await recovery.handle.close(); recovery = undefined;
      }
      const release = async () => { if (!released) { released = true; await cleanup(); } };
      // Lifecycle records may bind to this non-secret process lease. Only the
      // proven-dead, exact reclaimed owner is exposed, never a guessed owner.
      Object.defineProperties(release, { ownerNonce: { value: lock.record.nonce, enumerable: true },
        recoveredOwnerNonce: { value: recoveredOwnerNonce, enumerable: true },
        recoveredOwnerNonces: { value: Object.freeze([...lock.record.predecessorNonces]), enumerable: true } });
      return Object.freeze(release);
    } catch (error) {
      await cleanup();
      throw error;
    }
  } catch (error) {
    if (directory && !lock && !recovery) await directory.close().catch(() => {});
    throw error instanceof ProbeError ? error : new ProbeError('SESSION_BUSY_OR_LOCKED');
  }
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
    let unlock;
    try {
      unlock = await acquireSessionProcessLock(root, `${alias}.lock`);
      return await action();
    } finally {
      let cleanupFailed = false;
      try { await unlock?.(); } catch { cleanupFailed = true; }
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

async function oauthSessionJson(endpoint, init, fetchImpl, signal) {
  let response, reader;
  const active = signal ? AbortSignal.any([signal, AbortSignal.timeout(20000)]) : AbortSignal.timeout(20000);
  try {
    if (endpoint !== `${ISSUER}/api/accounts/oauth/token` && endpoint !== `${ISSUER}/.well-known/jwks.json`) fail('REFRESH_OUTCOME_UNCERTAIN');
    response = await awaitSessionOperation(Promise.resolve().then(() => {
      active.throwIfAborted();
      return fetchImpl(endpoint, { ...init, redirect: 'error', credentials: 'omit', cache: 'no-store', signal: active });
    }), active);
    if (response.redirected || (response.url && response.url !== endpoint) ||
      !/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type') ?? '')) fail('REFRESH_OUTCOME_UNCERTAIN');
    if (!response.body?.getReader) fail('REFRESH_OUTCOME_UNCERTAIN');
    reader = response.body.getReader(); const chunks = []; let size = 0;
    for (;;) {
      const part = await awaitSessionOperation(reader.read(), active); if (part.done) break;
      if (!(part.value instanceof Uint8Array) || (size += part.value.byteLength) > MAX_RECORD) fail('REFRESH_OUTCOME_UNCERTAIN');
      chunks.push(Buffer.from(part.value));
    }
    const value = JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(Buffer.concat(chunks)));
    return { status: response.status, value };
  } catch (error) {
    if (active.aborted && !signal?.aborted) fail('REFRESH_OUTCOME_UNCERTAIN');
    throw error instanceof ProbeError ? error : new ProbeError('REFRESH_OUTCOME_UNCERTAIN');
  }
  finally {
    if (reader) { try { Promise.resolve(reader.cancel()).catch(() => {}); reader.releaseLock(); } catch { /* No late refresh is accepted. */ } }
    else if (response?.body && !response.body.locked) void response.body.cancel().catch(() => {});
  }
}

async function refreshTokenRequest(record, fetchImpl, signal) {
  const { status, value } = await oauthSessionJson(`${ISSUER}/api/accounts/oauth/token`, { method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body: new URLSearchParams({ grant_type: 'refresh_token', client_id: record.clientId,
      refresh_token: record.refreshToken, resource: RESOURCE }) }, fetchImpl, signal);
  if (status < 200 || status >= 300) {
    const code = typeof value?.error === 'string' ? value.error : value?.error?.code;
    if (INVALID_REFRESH.has(code) && status >= 400 && status < 500) fail('SESSION_REAUTH_REQUIRED');
    if (code === 'invalid_client' && status >= 400 && status < 500) fail('REFRESH_CLIENT_INVALID');
    fail('REFRESH_OUTCOME_UNCERTAIN');
  }
  return value;
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
  const modelCalls = new Set(), refreshing = new Map();
  const clock = record => {
    const time = now();
    if (!timestamp(time) || (record && time < record.updatedAt)) fail('SESSION_CLOCK_INVALID');
    return time;
  };
  const checkAbort = signal => { if (signal?.aborted) fail('SESSION_OPERATION_ABORTED'); };
  async function withFreshRecord(alias, action, signal, unavailable) {
    checkAbort(signal);
    return store.locked(alias, async () => {
      checkAbort(signal);
      const record = await store.read(alias);
      const start = clock(record);
      if (record?.state === 'reauth_required' && record.subjectHash && unavailable) return unavailable(record);
      if (!record || record.state !== 'active') fail(record?.state === 'refresh_pending' ? 'REFRESH_OUTCOME_UNCERTAIN' : 'SESSION_REAUTH_REQUIRED');
      if (record.expiresAt > start + ACCESS_RENEWAL_WINDOW_MS) return action(record);
      // A durable pending marker prevents rotating-token reuse after crash,
      // network ambiguity or an atomic replacement failure. Never auto-retry it.
      let refreshed;
      refreshing.set(alias, record);
      try {
        await store.write(alias, { ...record, state: 'refresh_pending' });
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
        const identity = token.id_token !== undefined ? await oauthSessionJson(`${ISSUER}/.well-known/jwks.json`,
          { method: 'GET', headers: { Accept: 'application/json' } }, fetchImpl, signal) : undefined;
        if (identity && identity.status !== 200) fail('REFRESH_OUTCOME_UNCERTAIN');
        const jwks = identity?.value;
        checkAbort(signal);
        refreshed = validatedRefresh(record, token, jwks, clock(record));
        await store.write(alias, refreshed);
      } catch (error) {
        if (error instanceof ProbeError && error.code === 'SESSION_REAUTH_REQUIRED') {
          const unavailableRecord = withoutTokens(record, 'reauth_required', clock(record));
          await store.write(alias, unavailableRecord);
          if (unavailable) return unavailable(unavailableRecord);
        }
        throw error instanceof ProbeError ? error : new ProbeError('REFRESH_OUTCOME_UNCERTAIN');
      } finally { refreshing.delete(alias); }
      return action(refreshed);
    });
  }
  async function maintainAccount(alias, signal, { refresh = true } = {}) {
    account(alias); checkAbort(signal);
    const observedOwner = refreshing.get(alias);
    let record = await store.read(alias);
    let owner = refreshing.get(alias);
    // An atomic rename may finish while a read still holds the pending inode.
    // Re-read once after an observed owner exits; never reuse that past owner
    // as a readiness witness for a now-ambiguous pending record.
    if (record?.state === 'refresh_pending' && observedOwner && !owner) { record = await store.read(alias); owner = refreshing.get(alias); }
    const time = clock(record);
    if (!record) return { alias, state: 'not_connected' };
    // This in-process witness exists only while the same manager owns the
    // account lock. It admits waiting for that owner, never use of its old
    // token. After interruption/restart the map is empty: pending stays HOLD.
    const ownedPending = record.state === 'refresh_pending' && owner &&
      ['revision', 'clientId', 'subjectHash', 'hostId', 'expiresAt'].every(key => record[key] === owner[key]);
    if (record.state !== 'active' && !ownedPending) return { alias, state: 'held',
      code: record.state === 'refresh_pending' ? 'REFRESH_OUTCOME_UNCERTAIN' : 'SESSION_REAUTH_REQUIRED' };
    if (!refresh) {
      const metadata = sessionMetadata(record);
      return record.expiresAt <= time + ACCESS_RENEWAL_WINDOW_MS || ownedPending
        ? Object.freeze({ ...metadata, state: 'renewal_due' }) : metadata;
    }
    try { return await withFreshRecord(alias, record => sessionMetadata(record), signal); }
    catch (error) {
      if (signal?.aborted || error instanceof ProbeError && error.code === 'SESSION_OPERATION_ABORTED') throw error;
      return { alias, state: 'held', code: error instanceof ProbeError ? error.code : 'SESSION_MANAGER_FAILED' };
    }
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
    async catalog(alias, signal) {
      account(alias);
      if (!(signal instanceof AbortSignal)) fail('SESSION_MANAGER_INVALID');
      checkAbort(signal);
      // Account selection is explicit. The original lease/renewal authority
      // stays inside withFreshRecord; this endpoint never dispatches inference
      // or interprets catalog availability as quota or a debit receipt.
      return withFreshRecord(alias, async record => {
        const value = await awaitSessionOperation(publicJson(`${RESOURCE}/models`, {
          method: 'GET', credentials: 'omit', cache: 'no-store',
          headers: { Authorization: `Bearer ${record.accessToken}`, Accept: 'application/json' },
        }, fetchImpl, signal), signal);
        checkAbort(signal);
        selectExactModel(value);
        if (record.expiresAt <= clock(record)) fail('SESSION_NOT_ELIGIBLE');
        return Object.freeze({ status: 'DEV_ACCOUNT_MODEL_CATALOG_VERIFIED', alias, model: MODEL,
          authorizationSource: 'APP_OWNED_SIWC', accountVerified: true, planScopeGranted: true,
          catalogModelVerified: true, modelRequestsMade: 0, inferenceVerified: false,
          exactDebitAmountVerified: false, apiKeyFallbackUsed: false });
      }, signal);
    },
    async status() {
      // This is an inspection of persisted authorization, not a refresh,
      // provider readiness check, plan-credit setting, or model receipt.
      const accounts = [];
      for (const alias of ['info', 'eason']) {
        const record = await store.read(alias);
        const observedAt = clock(record);
        const accessExpiryState = !record || record.state === 'disconnected' ? 'not_connected'
          : record.state !== 'active' ? 'held'
          : record.expiresAt <= observedAt ? 'expired'
          : record.expiresAt - observedAt <= ACCESS_RENEWAL_WINDOW_MS ? 'renewal_due' : 'fresh';
        accounts.push(Object.freeze({ ...(record ? sessionMetadata(record)
          : { alias, expectedAccount: account(alias), state: 'not_connected' }), accessExpiryState, observedAt }));
      }
      return Object.freeze({ vm: VM_NAME, runtime: 'DEV_SYNTHETIC_ONLY', hostIdHash: digest(store.host.hostId),
        accounts: Object.freeze(accounts), accountOrder: ['info', 'eason'], apiFallbackEnabled: false, corelyRelayConnected: false,
        inspectionKind: 'PERSISTED_SESSION_ONLY', modelRequestsMade: 0, inferenceVerified: false,
        providerPlanControlsVerified: false, exactDebitAmountVerified: false,
        sendingCapability: false, learningCapability: false });
    },
    async maintain(signal, options) {
      if (options !== undefined && (!sameKeys(options, ['refresh']) || Object.keys(options).length !== 1 ||
        typeof options.refresh !== 'boolean')) fail('SESSION_MANAGER_INVALID');
      const results = [];
      for (const alias of ['info', 'eason']) results.push(await maintainAccount(alias, signal, options));
      return Object.freeze({ status: 'SESSION_MAINTENANCE_COMPLETED', accounts: results, apiFallbackUsed: false });
    },
    maintainAccount(alias, signal) { return maintainAccount(alias, signal); },
    async openMaintenanceOwner(signal) {
      checkAbort(signal);
      const release = await acquireSessionProcessLock(store.root, 'siwc-session-maintenance.lock');
      if (signal?.aborted) { await release(); checkAbort(signal); }
      let closed = false;
      return Object.freeze({ async close() { if (!closed) { closed = true; await release(); } } });
    },
    probe,
    generate(alias, input, signal) {
      account(alias);
      if (!(signal instanceof AbortSignal)) return Promise.reject(new ProbeError('MODEL_PORT_INVALID'));
      checkAbort(signal);
      let request;
      try { request = snapshotModelRequest(input); }
      catch (error) { return Promise.reject(new ProbeError(error.code ?? 'INVALID_REQUEST')); }
      const call = `${alias}:${request.callId}`;
      if (modelCalls.has(call) || modelCalls.size >= 1000) return Promise.reject(new ProbeError('MODEL_CALL_REPLAY_OR_CAPACITY'));
      modelCalls.add(call);
      return withFreshRecord(alias, record => runCorelyPlanRequest({ alias, accessToken: record.accessToken,
        expiresAt: record.expiresAt, planScopeGranted: true, accountMatchesExpected: true }, request, fetchImpl, signal), signal, record => {
        checkAbort(signal);
        // This verifies the retained signed enrollment, not current upstream
        // authentication. No model call has been dispatched for this witness.
        return Object.freeze({ accountAlias: alias, authMode: 'siwc_plan', accountVerified: true, model: request.model,
          callId: request.callId, inputSha256: request.inputSha256, schemaSha256: request.schemaSha256,
          status: 'account_unavailable', code: 'ACCOUNT_UNAVAILABLE', reason: 'REAUTH_REQUIRED', noModelMade: true,
          probeSettled: true, accountEnrollmentRevision: record.revision });
      });
    },
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
