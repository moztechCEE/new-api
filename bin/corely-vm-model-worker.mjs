#!/usr/bin/env node
// Dedicated owner-operated DEV consumer. No listener, producer, API fallback,
// native credential cache, customer operations, or automatic Corely re-consent.
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, realpath, unlink } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { connectCorelyVmModelJobs, CORELY_VM_HOST_ID_HASH, CORELY_VM_MODEL_JOB_SCOPE,
  CORELY_VM_MODEL_JOB_RESOURCE, CORELY_VM_VERIFICATION_URI } from './corely-vm-model-job-client.mjs';
import { executeOneCorelyModelJob } from './siwc-local-corely-worker.mjs';
import { createSiwcModelTransports } from './siwc-local-model-port.mjs';
import { openSessionStore, createPersistentPlanSessions, VM_NAME } from './siwc-local-sessions.mjs';
import { assertIsolatedSessionEnvironment } from './siwc-local-vm.mjs';
import { MODEL, digest } from './siwc-local-runtime.mjs';

const KEY_FILE = 'corely-vm-model-identity.json';
const PROMPT_FILE = 'corely-vm-model-consent.json';
const LOCK_FILE = 'corely-vm-model-worker.lock';
const MAX_RECORD = 16_384;
const CODES = new Set(['WORKER_OPTIONS_INVALID', 'WORKER_STORAGE_INVALID', 'WORKER_STORAGE_NOT_PRIVATE',
  'WORKER_IDENTITY_NOT_INITIALIZED', 'WORKER_IDENTITY_INVALID', 'WORKER_HOST_MISMATCH', 'WORKER_ALREADY_RUNNING',
  'WORKER_CLEANUP_UNCONFIRMED', 'WORKER_AUTHORITY_HELD', 'WORKER_PRODUCER_NOT_READY', 'WORKER_EVENT_UNCONFIRMED',
  'WORKER_SESSION_HELD', 'WORKER_EXECUTION_HELD', 'WORKER_OPERATION_TIMEOUT', 'WORKER_ABORTED', 'WORKER_FAILED']);
export class VmModelWorkerError extends Error {
  constructor(code) { super(CODES.has(code) ? code : 'WORKER_FAILED'); this.name = 'VmModelWorkerError'; this.code = this.message; }
}
const fail = code => { throw new VmModelWorkerError(code); };
const object = value => Boolean(value && typeof value === 'object' && !Array.isArray(value));
const exact = (value, keys) => object(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const sameInode = (left, right) => left.dev === right.dev && left.ino === right.ino;
const owner = stat => !process.getuid || stat.uid === process.getuid();
const privateFile = stat => stat.isFile() && stat.nlink === 1 && (stat.mode & 0o777) === 0o600 && owner(stat) && stat.size <= MAX_RECORD;

async function bounded(work, signal, timeoutMs, code = 'WORKER_OPERATION_TIMEOUT') {
  if (signal.aborted) fail('WORKER_ABORTED');
  const deadline = AbortSignal.timeout(timeoutMs), active = AbortSignal.any([signal, deadline]);
  return new Promise((accept, reject) => {
    const abort = () => { active.removeEventListener('abort', abort); reject(new VmModelWorkerError(signal.aborted ? 'WORKER_ABORTED' : code)); };
    active.addEventListener('abort', abort, { once: true });
    Promise.resolve(work).then(value => { active.removeEventListener('abort', abort); accept(value); },
      error => { active.removeEventListener('abort', abort); reject(error); });
  });
}

/** An existing app-owned VM store is required. No host ID is created or changed.
 * The descriptor remains open and every file operation rechecks its inode. */
async function protectedDirectory(stateDir) {
  let handle;
  try {
    if (typeof stateDir !== 'string' || !isAbsolute(stateDir) || resolve(stateDir) !== stateDir) fail('WORKER_STORAGE_INVALID');
    const parent = await realpath(dirname(stateDir)), root = join(parent, basename(stateDir));
    if (root !== stateDir || root === parent) fail('WORKER_STORAGE_INVALID');
    const parentStat = await lstat(parent);
    if (!parentStat.isDirectory() || ((parentStat.mode & 0o022) && !(parentStat.mode & 0o1000))) fail('WORKER_STORAGE_NOT_PRIVATE');
    const before = await lstat(root);
    handle = await open(root, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    const admitted = await handle.stat();
    if (!admitted.isDirectory() || !owner(admitted) || (admitted.mode & 0o777) !== 0o700 || !sameInode(before, admitted)) fail('WORKER_STORAGE_NOT_PRIVATE');
    const check = async () => {
      const current = await lstat(root), retained = await handle.stat();
      if (!current.isDirectory() || current.isSymbolicLink() || !owner(current) || (current.mode & 0o777) !== 0o700 ||
          !sameInode(current, admitted) || !sameInode(retained, admitted)) fail('WORKER_STORAGE_NOT_PRIVATE');
    };
    const read = async (filename, optional = false) => {
      let file;
      try {
        await check(); const path = join(root, filename), before = await lstat(path);
        file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
        const stat = await file.stat();
        if (!privateFile(stat) || !sameInode(before, stat)) fail('WORKER_STORAGE_NOT_PRIVATE');
        const buffer = Buffer.alloc(MAX_RECORD + 1); let size = 0;
        while (size < buffer.length) {
          const part = await file.read(buffer, size, buffer.length - size, size);
          if (part.bytesRead === 0) break;
          size += part.bytesRead;
        }
        const bytes = buffer.subarray(0, size), after = await file.stat(), current = await lstat(path);
        await check();
        if (bytes.length > MAX_RECORD || bytes.length !== stat.size || !privateFile(after) || after.size !== stat.size ||
            after.mtimeMs !== stat.mtimeMs || after.ctimeMs !== stat.ctimeMs || !privateFile(current) ||
            !sameInode(stat, after) || !sameInode(stat, current)) fail('WORKER_STORAGE_NOT_PRIVATE');
        const text = new TextDecoder('utf8', { fatal: true }).decode(bytes), value = JSON.parse(text);
        // Our records have one canonical serialization; reject duplicate fields.
        if (JSON.stringify(value) !== text) fail('WORKER_STORAGE_INVALID');
        return value;
      } catch (error) {
        if (optional && error.code === 'ENOENT') return undefined;
        throw error instanceof VmModelWorkerError ? error : new VmModelWorkerError('WORKER_STORAGE_INVALID');
      } finally { await file?.close(); }
    };
    const create = async (filename, value) => {
      let file;
      try {
        await check(); const path = join(root, filename), bytes = JSON.stringify(value);
        if (Buffer.byteLength(bytes) > MAX_RECORD) fail('WORKER_STORAGE_INVALID');
        file = await open(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
        const stat = await file.stat();
        if (!privateFile(stat)) fail('WORKER_STORAGE_NOT_PRIVATE');
        await file.writeFile(bytes); await file.sync(); await check();
        const current = await lstat(path);
        if (!privateFile(current) || !sameInode(stat, current)) fail('WORKER_STORAGE_NOT_PRIVATE');
        await handle.sync();
        // Cleanup may remove only this operation's own inode, never a replacement.
        return async () => {
          await check(); const current = await lstat(path);
          if (!privateFile(current) || !sameInode(stat, current)) fail('WORKER_CLEANUP_UNCONFIRMED');
          await unlink(path); await handle.sync();
        };
      } catch (error) {
        if (error.code === 'EEXIST') fail('WORKER_ALREADY_RUNNING');
        throw error instanceof VmModelWorkerError ? error : new VmModelWorkerError('WORKER_STORAGE_INVALID');
      } finally { await file?.close(); }
    };
    return { read, create, check, async close() {
      try { await handle.close(); } catch { fail('WORKER_CLEANUP_UNCONFIRMED'); }
    } };
  } catch (error) {
    await handle?.close();
    throw error instanceof VmModelWorkerError ? error : new VmModelWorkerError('WORKER_STORAGE_INVALID');
  }
}

/** Generation is reachable only through the explicit init-key command. A fixed
 * keyFactory seam lets offline fixtures avoid provisioning any usable VM key. */
export async function openCorelyVmModelIdentity(stateDir, { initialize = false,
  keyFactory = () => generateKeyPairSync('ed25519').privateKey } = {}) {
  if (typeof initialize !== 'boolean' || typeof keyFactory !== 'function') fail('WORKER_OPTIONS_INVALID');
  const directory = await protectedDirectory(stateDir);
  let key;
  try {
    const host = await directory.read('host.json');
    if (!exact(host, ['kind', 'version', 'runtime', 'vm', 'hostId']) || host.kind !== 'NEW_API_SIWC_DEV_HOST' ||
        host.version !== 1 || host.runtime !== 'vm' || host.vm !== VM_NAME ||
        !/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(host.hostId ?? '')) fail('WORKER_IDENTITY_INVALID');
    const hostIdHash = digest(host.hostId);
    let record = await directory.read(KEY_FILE, true);
    if (!record && initialize) {
      const candidate = keyFactory();
      if (candidate?.type !== 'private' || candidate.asymmetricKeyType !== 'ed25519') fail('WORKER_IDENTITY_INVALID');
      const jwk = createPublicKey(candidate).export({ format: 'jwk' });
      const keyThumbprint = createHash('sha256').update(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: jwk.x })).digest('base64url');
      record = { kind: 'CORELY_DEV_VM_MODEL_IDENTITY', version: 1, vm: VM_NAME, hostIdHash, keyThumbprint,
        privateKeyPem: candidate.export({ format: 'pem', type: 'pkcs8' }).toString() };
      await directory.create(KEY_FILE, record);
    }
    if (!record) fail('WORKER_IDENTITY_NOT_INITIALIZED');
    if (!exact(record, ['kind', 'version', 'vm', 'hostIdHash', 'keyThumbprint', 'privateKeyPem']) ||
        record.kind !== 'CORELY_DEV_VM_MODEL_IDENTITY' || record.version !== 1 || record.vm !== VM_NAME || record.hostIdHash !== hostIdHash ||
        !/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(record.keyThumbprint ?? '') ||
        typeof record.privateKeyPem !== 'string' || record.privateKeyPem.length > 4096) fail('WORKER_IDENTITY_INVALID');
    key = createPrivateKey({ key: record.privateKeyPem, format: 'pem', type: 'pkcs8' });
    const jwk = createPublicKey(key).export({ format: 'jwk' });
    if (key.asymmetricKeyType !== 'ed25519' || key.type !== 'private' || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' ||
        createHash('sha256').update(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: jwk.x })).digest('base64url') !== record.keyThumbprint) fail('WORKER_IDENTITY_INVALID');
    const recordHash = digest(JSON.stringify(record)), hostHash = digest(JSON.stringify(host));
    const metadata = Object.freeze({ status: 'CORELY_DEV_VM_MODEL_IDENTITY_READY', vm: VM_NAME, hostIdHash,
      keyThumbprint: record.keyThumbprint, syntheticOnly: true, apiFallbackEnabled: false });
    record = undefined;
    let closed = false;
    return Object.freeze({
      receipt: () => metadata,
      async connect(options) {
        try {
          if (!key || closed || hostIdHash !== CORELY_VM_HOST_ID_HASH) fail('WORKER_HOST_MISMATCH');
          if (digest(JSON.stringify(await directory.read('host.json'))) !== hostHash ||
              digest(JSON.stringify(await directory.read(KEY_FILE))) !== recordHash) fail('WORKER_IDENTITY_INVALID');
          return await connectCorelyVmModelJobs({ ...options, privateKey: key, expectedKeyThumbprint: metadata.keyThumbprint });
        } catch (error) { throw error instanceof VmModelWorkerError ? error : new VmModelWorkerError('WORKER_AUTHORITY_HELD'); }
      },
      async close() { key = undefined; if (!closed) { closed = true; await directory.close(); } },
    });
  } catch (error) {
    key = undefined; await directory.close();
    throw error instanceof VmModelWorkerError ? error : new VmModelWorkerError('WORKER_IDENTITY_INVALID');
  }
}

/** The owner approval reference is not a model credential. Keep even this
 * short-lived reference out of container logs, and reject stale/replaced files. */
export async function openCorelyVmModelWorkerLifecycle(stateDir, keyThumbprint) {
  if (!/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(keyThumbprint ?? '')) fail('WORKER_OPTIONS_INVALID');
  const directory = await protectedDirectory(stateDir);
  let release, removePrompt, closed = false;
  try { release = await directory.create(LOCK_FILE, { kind: 'CORELY_DEV_VM_MODEL_WORKER_LOCK', version: 1 }); }
  catch (error) { await directory.close(); throw error; }
  const clearConsent = async () => { if (removePrompt) { await removePrompt(); removePrompt = undefined; } };
  return Object.freeze({
    async presentConsent(value) {
      if (closed || removePrompt || !exact(value, ['verificationUri', 'verificationUriComplete', 'userCode', 'expiresIn', 'interval',
        'scope', 'vmHostIdHash', 'keyThumbprint']) || value.verificationUri !== CORELY_VM_VERIFICATION_URI ||
          typeof value.verificationUriComplete !== 'string' ||
          !/^vm_models_[A-Za-z0-9_-]{43}$/.test(value.verificationUriComplete.slice(`${CORELY_VM_VERIFICATION_URI}?requestId=`.length)) ||
          !value.verificationUriComplete.startsWith(`${CORELY_VM_VERIFICATION_URI}?requestId=`) ||
          !/^[A-F0-9]{4}-[A-F0-9]{4}$/.test(value.userCode ?? '') || value.expiresIn !== 300 || value.interval !== 5 ||
          value.scope !== CORELY_VM_MODEL_JOB_SCOPE || value.vmHostIdHash !== CORELY_VM_HOST_ID_HASH || value.keyThumbprint !== keyThumbprint) fail('WORKER_AUTHORITY_HELD');
      removePrompt = await directory.create(PROMPT_FILE, { kind: 'CORELY_DEV_VM_MODEL_CONSENT', version: 1,
        verificationUriComplete: value.verificationUriComplete, userCode: value.userCode, expiresIn: value.expiresIn,
        keyThumbprint: value.keyThumbprint, syntheticOnly: true, apiFallbackEnabled: false });
      return Object.freeze({ status: 'CORELY_VM_MODEL_WORKER_CONSENT_REQUIRED', record: PROMPT_FILE, expiresIn: 300,
        syntheticOnly: true, apiFallbackEnabled: false });
    },
    clearConsent,
    async close() {
      if (closed) return;
      closed = true; let failed = false;
      for (const cleanup of [clearConsent, release]) { try { await cleanup(); } catch { failed = true; } }
      await directory.close(); if (failed) fail('WORKER_CLEANUP_UNCONFIRMED');
    },
  });
}

const readyStatus = status => status?.status === 'SYNTHETIC_VM_MODEL_TRANSPORT_V2' && status.contractVersion === 2 &&
  status.producerConnected === true && status.authMode === 'siwc_plan' && status.enrolled === true && status.syntheticOnly === true &&
  status.tenantId === 'moztech' && status.brandId === 'moztech-test' && status.scope === CORELY_VM_MODEL_JOB_SCOPE &&
  status.apiFallbackEnabled === false && status.sendingCapability === false && status.learningCapability === false;

/** Single-flight consumer. Corely owns producer admission and account fallback;
 * this loop cannot create work, approve a draft, send, learn, or retry ambiguity. */
export async function runCorelyVmModelWorker({ client, ports, signal, onReceipt = async () => {}, sleep = (ms, signal) => delay(ms, undefined, { signal }),
  pollIntervalMs = 1000, maxJobs = 1000, maxIdlePolls = 86400, producerWaitMs = 60000, maintainSessions = async () => {} } = {}) {
  if (!client || !['receipt', 'enrollModels', 'modelStatus', 'claimModel', 'completeModel', 'close'].every(key => typeof client[key] === 'function') ||
      !(signal instanceof AbortSignal) || typeof onReceipt !== 'function' || typeof sleep !== 'function' || typeof maintainSessions !== 'function' ||
      !Number.isSafeInteger(pollIntervalMs) || pollIntervalMs < 1000 || pollIntervalMs > 30000 ||
      !Number.isSafeInteger(maxJobs) || maxJobs < 1 || maxJobs > 1000 || !Number.isSafeInteger(maxIdlePolls) || maxIdlePolls < 1 || maxIdlePolls > 86400 ||
      !Number.isSafeInteger(producerWaitMs) || producerWaitMs < 1000 || producerWaitMs > 60000) fail('WORKER_OPTIONS_INVALID');
  let completed = 0, idle = 0;
  const emit = value => bounded(Promise.resolve().then(() => onReceipt(value)), signal, 5000, 'WORKER_EVENT_UNCONFIRMED');
  const guarded = Object.freeze({
    async modelStatus(active) {
      const status = await client.modelStatus(active);
      if (!readyStatus(status)) fail('WORKER_AUTHORITY_HELD');
      return status;
    },
    claimModel: (...args) => client.claimModel(...args), completeModel: (...args) => client.completeModel(...args),
  });
  try {
    signal.throwIfAborted(); const receipt = client.receipt();
    if (receipt.scope !== CORELY_VM_MODEL_JOB_SCOPE || receipt.resource !== CORELY_VM_MODEL_JOB_RESOURCE ||
        receipt.syntheticOnly !== true || receipt.apiFallbackEnabled !== false || receipt.sendingCapability !== false || receipt.learningCapability !== false) fail('WORKER_AUTHORITY_HELD');
    await bounded(client.enrollModels(signal), signal, 30000);
    let remaining = producerWaitMs;
    const readinessDeadline = AbortSignal.timeout(producerWaitMs), readinessSignal = AbortSignal.any([signal, readinessDeadline]);
    try {
      for (;;) {
        const status = await bounded(client.modelStatus(readinessSignal), readinessSignal, 30000);
        if (readyStatus(status)) break;
        if (status?.status !== 'SYNTHETIC_VM_MODEL_TRANSPORT_V2' || status.contractVersion !== 2 || status.producerConnected !== false) fail('WORKER_AUTHORITY_HELD');
        if (remaining <= 0) fail('WORKER_PRODUCER_NOT_READY');
        const wait = Math.min(remaining, pollIntervalMs); remaining -= wait;
        await bounded(sleep(wait, readinessSignal), readinessSignal, wait + 5000);
      }
    } catch (error) {
      if (readinessDeadline.aborted && !signal.aborted) fail('WORKER_PRODUCER_NOT_READY');
      throw error;
    }
    await emit(Object.freeze({ status: 'CORELY_VM_MODEL_WORKER_READY', contractVersion: 2, syntheticOnly: true,
      model: MODEL, apiFallbackUsed: false, sendingPerformed: false, learningPerformed: false }));
    for (;;) {
      signal.throwIfAborted();
      await bounded(maintainSessions(signal), signal, 60000, 'WORKER_SESSION_HELD');
      const result = await bounded(executeOneCorelyModelJob(guarded, ports, signal), signal, 75000);
      if (result.status === 'NO_SYNTHETIC_MODEL_JOB') {
        if (++idle >= maxIdlePolls) return Object.freeze({ status: 'CORELY_VM_MODEL_WORKER_STOPPED', reason: 'IDLE_LIMIT', completed,
          apiFallbackUsed: false, sendingPerformed: false, learningPerformed: false });
        await bounded(sleep(pollIntervalMs, signal), signal, pollIntervalMs + 5000);
        continue;
      }
      idle = 0; completed++; await emit(result);
      if (completed >= maxJobs) return Object.freeze({ status: 'CORELY_VM_MODEL_WORKER_STOPPED', reason: 'JOB_LIMIT', completed,
        apiFallbackUsed: false, sendingPerformed: false, learningPerformed: false });
    }
  } catch (error) {
    if (signal.aborted) fail('WORKER_ABORTED');
    if (error instanceof VmModelWorkerError) throw error;
    fail('WORKER_EXECUTION_HELD');
  } finally { try { client.close(); } catch { fail('WORKER_CLEANUP_UNCONFIRMED'); } }
}

export function parseVmModelWorkerCommand(argv) {
  if (!Array.isArray(argv) || argv.length !== 3 || !['init-key', 'status', 'run'].includes(argv[0]) || argv[1] !== '--state-dir' ||
      typeof argv[2] !== 'string' || !isAbsolute(argv[2]) || resolve(argv[2]) !== argv[2]) fail('WORKER_OPTIONS_INVALID');
  return Object.freeze({ command: argv[0], stateDir: argv[2] });
}

export async function runVmModelWorkerCommand(argv) {
  const { command, stateDir } = parseVmModelWorkerCommand(argv);
  assertIsolatedSessionEnvironment();
  const safe = value => process.stdout.write(`${JSON.stringify(value)}\n`);
  const identity = await openCorelyVmModelIdentity(stateDir, { initialize: command === 'init-key' });
  let lifecycle;
  const controller = new AbortController(), stop = () => controller.abort();
  try {
    if (command !== 'run') return safe(identity.receipt());
    lifecycle = await openCorelyVmModelWorkerLifecycle(stateDir, identity.receipt().keyThumbprint);
    process.once('SIGINT', stop); process.once('SIGTERM', stop);
    const store = await openSessionStore(stateDir), sessions = createPersistentPlanSessions(store);
    const client = await identity.connect({ signal: controller.signal, onAuthorize: async value => {
      safe(await lifecycle.presentConsent(value));
    } });
    await lifecycle.clearConsent();
    safe(await runCorelyVmModelWorker({ client, ports: createSiwcModelTransports(sessions), signal: controller.signal,
      onReceipt: safe, maintainSessions: async active => {
        const maintenance = await sessions.maintain(active);
        if (maintenance.accounts.some(account => account.state === 'held')) fail('WORKER_SESSION_HELD');
      } }));
  } finally {
    process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); controller.abort();
    let cleanupFailed = false;
    try { await lifecycle?.close(); } catch { cleanupFailed = true; }
    await identity.close();
    if (cleanupFailed) fail('WORKER_CLEANUP_UNCONFIRMED');
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runVmModelWorkerCommand(process.argv.slice(2)).catch(error => {
    const code = error instanceof VmModelWorkerError ? error.code : 'WORKER_FAILED';
    process.stdout.write(`${JSON.stringify({ status: 'CORELY_VM_MODEL_WORKER_HELD', code, apiFallbackUsed: false })}\n`);
    process.exitCode = 1;
  });
}
