#!/usr/bin/env node
// One-shot owner-operated, no-model DEV diagnostic. The normal sealed client
// still clears its token on revoke. This process alone retains this round's
// admitted token until one fixed post-restart negative request, then drops it.
// ASVS 5.0.0: 7.2.1, 7.3.2, 7.4.1, 10.1.1, 10.3.1/2/5. OAuth2 and Session
// Management Cheat Sheets: sender constraint, backend invalidation, no secrets
// in diagnostics. This is not hosted-provider eligibility or quota evidence.
import { createHash, createPrivateKey, createPublicKey, randomBytes, randomUUID, sign } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, readFile, realpath } from 'node:fs/promises';
import { Agent, request } from 'node:https';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { createInterface } from 'node:readline';
import { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';

const ROOT = dirname(fileURLToPath(import.meta.url));
const ISSUER = 'https://moztech-api-dev-candidates-sp5g377smq-de.a.run.app/work-candidates/vm-model-jobs/oauth';
const STATUS = `${ISSUER}/status`;
const SCOPE = 'corely:dev-vm-model-jobs';
const HOST = '89d0316d433fbf80da04c4b8ad5a2cc12daa28d8720886916ba2f6b9558519e0';
const CONSENT = 'https://agent-dev.corely.cc/ops/work-candidates/vm-model-jobs/connect?requestId=';
const SOURCE_HASHES = Object.freeze({
  'corely-vm-model-worker.mjs': '3db6494534147a84e3efd9d678362a42a1b954be4f23bb64225d93f94e7eff46',
  'corely-vm-model-job-client.mjs': '9d6b7ca65dda29f7def07679f279e10af6a4cf6f9889f12f112a190235705e66',
  'corely-model-contract.mjs': '827c0eb8fa33213969af588a43178fb2d3f329d07e38d2d5802a3ca2610cae48',
  'siwc-local-corely-worker.mjs': '7d6bdeeabdbf9cabf1ccc05f0c906821051b80e5390af6068d3390a7eff5e6f4',
  'siwc-local-model-port.mjs': '3dc7f30ba478e5f5a4cc56a0445385464ecc1df90b48fd63701564b3df08f41f',
  'siwc-gateway-model-port.mjs': '7936ca24626726913bbc7a70bd115018f2d44fb6cfda02b06cb7aaec78beafa8',
  'siwc-local-sessions.mjs': '320e6589e26d71ff6c3ecd72ed4f5bb41b0820e7deb8facb61f313dee3010b7c',
  'siwc-local-vm.mjs': '08eeee8c6c5317fa24f4d34641a461006ba481240206b45b0ac0bf5381620694',
  'siwc-local-runtime.mjs': 'df1bdb948e1d470cd0a3a943304cbe734f6128620dcfef23fcfff502914276b8',
});
const digest = value => createHash('sha256').update(value).digest('hex');
const ath = value => createHash('sha256').update(value).digest('base64url');
const held = () => new Error('AUTHORITY_PROBE_HELD');

function abortable(work, signal) {
  const discard = value => { if (value?.body && !value.body.locked) void value.body.cancel().catch(() => {}); };
  if (signal.aborted) { Promise.resolve(work).then(discard, () => {}); return Promise.reject(held()); }
  return new Promise((accept, reject) => {
    const abort = () => { signal.removeEventListener('abort', abort); reject(held()); };
    signal.addEventListener('abort', abort, { once: true });
    Promise.resolve(work).then(value => { signal.removeEventListener('abort', abort); if (signal.aborted) { discard(value); reject(held()); } else accept(value); },
      () => { signal.removeEventListener('abort', abort); reject(held()); });
  });
}

/** Only the already admitted app-owned Corely identity is readable. No key
 * leaves this module. Every inode/owner/mode check matches the protected store;
 * neither a provider file nor an alternative filename is accepted. */
async function readOwnedProbeIdentity(stateDir, metadata) {
  let directory, file, bytes;
  try {
    if (!isAbsolute(stateDir) || resolve(stateDir) !== stateDir) throw held();
    const parent = await realpath(dirname(stateDir)), root = join(parent, basename(stateDir));
    const parentStat = await lstat(parent), beforeDirectory = await lstat(root);
    if (root !== stateDir || root === parent || !parentStat.isDirectory() ||
        ((parentStat.mode & 0o022) && !(parentStat.mode & 0o1000))) throw held();
    directory = await open(root, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    const admitted = await directory.stat();
    const same = (a, b) => a.dev === b.dev && a.ino === b.ino;
    const privateDirectory = s => s.isDirectory() && (!process.getuid || s.uid === process.getuid()) && (s.mode & 0o777) === 0o700;
    const privateFile = s => s.isFile() && s.nlink === 1 && (!process.getuid || s.uid === process.getuid()) &&
      (s.mode & 0o777) === 0o600 && s.size > 0 && s.size <= 16_384;
    if (!privateDirectory(admitted) || !same(beforeDirectory, admitted)) throw held();
    const path = join(root, 'corely-vm-model-identity.json'), before = await lstat(path);
    file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stat = await file.stat();
    if (!privateFile(stat) || !same(before, stat)) throw held();
    bytes = Buffer.alloc(16_385); let size = 0;
    while (size < bytes.length) {
      const part = await file.read(bytes, size, bytes.length - size, size);
      if (!part.bytesRead) break;
      size += part.bytesRead;
    }
    const after = await file.stat(), current = await lstat(path), currentDirectory = await lstat(root), retained = await directory.stat();
    if (size !== stat.size || size > 16_384 || !privateFile(after) || !privateFile(current) ||
        !same(stat, after) || !same(stat, current) || after.size !== stat.size || current.size !== stat.size ||
        after.mtimeMs !== stat.mtimeMs || after.ctimeMs !== stat.ctimeMs || current.mtimeMs !== stat.mtimeMs || current.ctimeMs !== stat.ctimeMs ||
        !privateDirectory(currentDirectory) || !same(currentDirectory, admitted) || !same(retained, admitted)) throw held();
    const text = new TextDecoder('utf8', { fatal: true }).decode(bytes.subarray(0, size));
    let record = JSON.parse(text);
    const keys = ['kind', 'version', 'vm', 'hostIdHash', 'keyThumbprint', 'privateKeyPem'];
    if (JSON.stringify(record) !== text || !record || Array.isArray(record) || Object.keys(record).length !== keys.length ||
        keys.some(key => !Object.hasOwn(record, key)) || record.kind !== 'CORELY_DEV_VM_MODEL_IDENTITY' || record.version !== 1 ||
        record.vm !== 'new-api-dev-20261022' || record.hostIdHash !== HOST || record.hostIdHash !== metadata.hostIdHash ||
        record.keyThumbprint !== metadata.keyThumbprint || typeof record.privateKeyPem !== 'string' || record.privateKeyPem.length > 4096) throw held();
    const key = createPrivateKey({ key: record.privateKeyPem, format: 'pem', type: 'pkcs8' });
    const jwk = createPublicKey(key).export({ format: 'jwk' });
    if (key.type !== 'private' || key.asymmetricKeyType !== 'ed25519' || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' ||
        ath(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: jwk.x })) !== metadata.keyThumbprint) throw held();
    record = undefined;
    return { key, jwk: { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, snapshot: digest(text) };
  } catch { throw held(); }
  finally { bytes?.fill(0); await file?.close(); await directory?.close(); }
}

/** Fixed candidate endpoints only, normal TLS, no redirect/cookie/retry/proxy.
 * This owned agent and all response streams are destroyed during finalization. */
function ownedCandidateTransport() {
  const agent = new Agent({ keepAlive: false, maxSockets: 1 });
  const sockets = new Set();
  return {
    fetchImpl(url, init) {
      return new Promise((accept, reject) => {
        if (!['device_authorization', 'token', 'status', 'revoke'].some(name => url === `${ISSUER}/${name}`) ||
            !init || init.redirect !== 'error' || init.credentials !== 'omit' || init.cache !== 'no-store') { reject(held()); return; }
        const req = request(url, { agent, method: init.method, headers: Object.fromEntries(new Headers(init.headers)),
          signal: init.signal, minVersion: 'TLSv1.2', maxHeaderSize: 16_384 }, response => {
          try {
            const result = new Response(Readable.toWeb(response), { status: response.statusCode, headers: response.headers });
            Object.defineProperty(result, 'url', { value: url }); accept(result);
          } catch { response.destroy(); reject(held()); }
        });
        req.on('socket', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
        req.on('error', () => reject(held()));
        if (init.body !== undefined) req.write(init.body);
        req.end();
      });
    },
    close() { agent.destroy(); for (const socket of sockets) socket.destroy(); sockets.clear(); },
  };
}

/** Test seams substitute a synthetic sealed identity and fixed-endpoint HTTP,
 * not an exposed token getter/signer. The CLI has no flags or endpoint options.
 * Only public receipts are returned; credentials are closure-local and cleared.
 */
export async function runCorelyVmAuthorityProbe({ stateDir = '/state', input = process.stdin, output = process.stdout,
  identityFactory, transport = ownedCandidateTransport(), now = Date.now, monotonicNow = () => performance.now(), sleep,
  signal, maximumRuntimeMs = 20 * 60_000 } = {}) {
  const runId = randomUUID(), lifetime = new AbortController();
  const calls = { device_authorization: 0, token: 0, status: 0, revoke: 0, negative: 0 };
  let identity, client, lines, timer, work, operation, finishing, stage = 'WAITING_CONNECT', inputBytes = 0;
  let pendingToken = '', retainedToken = '', key, originalKeySnapshot, originalExpiry, originalAuthorityExpiresAt, originalMetadataHash, grantMonotonicDeadline;
  let revocation = 'NOT_PERFORMED', revokedAt, revokedMonotonic, revocationAttempted = false, connected = false;
  let beforeVerified = false, afterVerified = false, denialVerified = false, lastClock = -1, lastMonotonic = -1;
  let complete;
  const completion = new Promise(resolveCompletion => { complete = resolveCompletion; });
  const emit = (status, fields = {}) => new Promise((accept, reject) => {
    output.write(JSON.stringify({ status, runId, ...fields }) + '\n', error => error ? reject(held()) : accept());
  });
  const clock = () => {
    const wall = now(), mono = monotonicNow();
    if (!Number.isSafeInteger(wall) || wall < 0 || wall < lastClock || !Number.isFinite(mono) || mono < 0 || mono < lastMonotonic) throw held();
    lastClock = wall; lastMonotonic = mono; return { wall, mono };
  };
  const candidateFetch = async (url, init) => {
    const name = Object.keys(calls).find(name => name !== 'negative' && url === `${ISSUER}/${name}`);
    if (!name || finishing && name !== 'revoke' || !init || init.redirect !== 'error' || init.credentials !== 'omit' || init.cache !== 'no-store' ||
        init.method !== (name === 'status' ? 'GET' : 'POST') || ++calls[name] > (name === 'token' ? 61 : name === 'status' ? 2 : 1)) throw held();
    if (name === 'status' && stage === 'BEFORE_REQUEST') {
      const value = new Headers(init.headers).get('authorization');
      if (pendingToken || retainedToken || !/^DPoP vm_models_access_[A-Za-z0-9_-]{43}$/.test(value ?? '')) throw held();
      pendingToken = value.slice(5);
    }
    const traceId = randomBytes(16).toString('hex'), startedAt = new Date(clock().wall).toISOString();
    const headers = new Headers(init.headers); headers.set('X-Cloud-Trace-Context', `${traceId}/0;o=1`);
    try {
      const response = await transport.fetchImpl(url, { ...init, headers });
      await emit('CANDIDATE_HTTP_RECEIPT', { operation: name, traceId, startedAt, httpStatus: response.status });
      return response;
    } catch { await emit('CANDIDATE_HTTP_UNCERTAIN', { operation: name, traceId, startedAt }); throw held(); }
  };
  const finish = (reason, requestedSuccess = false) => {
    if (finishing) return finishing;
    finishing = (async () => {
      clearTimeout(timer); operation?.abort();
      if (!client) lifetime.abort();
      lines?.removeAllListeners('line'); lines?.removeAllListeners('close'); input.removeListener('data', boundedInput);
      lines?.close(); input.pause(); input.destroy(); signal?.removeEventListener('abort', stopped);
      try { await work; } catch { /* The operation's outcome is not accepted. */ }
      if (client && !revocationAttempted) {
        revocationAttempted = true;
        try { revocation = (await client.revokeAuthority(AbortSignal.timeout(5000))).remoteRevocation === 'CONFIRMED' ? 'CONFIRMED' : 'UNKNOWN'; }
        catch { revocation = 'UNKNOWN'; }
      } else if (!connected && stage !== 'WAITING_CONNECT') revocation = 'UNKNOWN';
      pendingToken = ''; retainedToken = ''; key = undefined;
      lifetime.abort(); let cleanupConfirmed = false;
      try { client?.close(); await identity?.close(); transport.close(); cleanupConfirmed = true; }
      catch { try { transport.close(); } catch { /* Fixed cleanup failure only. */ } }
      const success = requestedSuccess && beforeVerified && afterVerified && denialVerified && revocation === 'CONFIRMED' && cleanupConfirmed;
      const receipt = Object.freeze({ status: success ? 'CLOUD_AUTHORITY_PROBE_COMPLETE' : 'CLOUD_AUTHORITY_PROBE_HELD', reason,
        beforeVerified, afterVerified, originalGrantExpiryPreserved: beforeVerified && afterVerified, remoteRevocation: revocation,
        serverPostRestartDenialVerified: denialVerified, cloudRevisionVerifiedByThisDriver: false, localCleanupConfirmed: cleanupConfirmed,
        candidateHttpAttempts: Object.values(calls).reduce((sum, value) => sum + value, 0), negativeAttempts: calls.negative,
        modelCalls: 0, providerRequestsMade: 0, apiKeyUsed: false, apiFallbackUsed: false, sending: false, learning: false,
        livePersonalInferenceVerified: false });
      try { await emit(receipt.status, receipt); } catch { /* No raw output error. */ }
      complete(receipt); return receipt;
    })();
    return finishing;
  };
  const stopped = () => { void finish('OPERATOR_STOPPED'); };
  function boundedInput(chunk) {
    inputBytes += typeof chunk === 'string' ? Buffer.byteLength(chunk) : chunk.byteLength;
    if (inputBytes > 1024) void finish('COMMAND_PROTOCOL_HELD');
  }
  const command = async value => {
    operation = new AbortController();
    if (value === 'CONNECT' && stage === 'WAITING_CONNECT') {
      stage = 'AUTHORIZING';
      client = await identity.connect({ fetchImpl: candidateFetch, signal: lifetime.signal, now, monotonicNow, ...(sleep ? { sleep } : {}),
        requestTimeoutMs: 10_000, onAuthorize: descriptor => {
          if (finishing || !descriptor.verificationUriComplete?.startsWith(CONSENT) ||
              !/^vm_models_[A-Za-z0-9_-]{43}$/.test(descriptor.verificationUriComplete.slice(CONSENT.length)) ||
              descriptor.expiresIn !== 300 || descriptor.scope !== SCOPE || descriptor.vmHostIdHash !== HOST ||
              descriptor.keyThumbprint !== identity.receipt().keyThumbprint) throw held();
          return emit('NORMAL_CORELY_CONSENT_REQUIRED', { verificationUriComplete: descriptor.verificationUriComplete,
            expiresIn: 300, scope: SCOPE, modelCalls: 0 });
        } });
      connected = true;
      if (finishing) return;
      stage = 'CONNECTED';
      await emit('CORELY_AUTHORITY_CONNECTED', { nextCommand: 'BEFORE', modelCalls: 0 }); return;
    }
    if (value === 'BEFORE' && stage === 'CONNECTED' || value === 'AFTER_RESTART' && stage === 'BEFORE_VERIFIED') {
      stage = value === 'BEFORE' ? 'BEFORE_REQUEST' : 'AFTER_REQUEST';
      const status = await client.authorityStatus(AbortSignal.any([operation.signal, AbortSignal.timeout(10_000)]));
      if (finishing) return;
      if (status.modelTransportEnabled !== false) throw held();
      const hash = digest(JSON.stringify(status));
      if (value === 'BEFORE') {
        const times = clock();
        originalAuthorityExpiresAt = status.expiresAt;
        originalExpiry = Math.min(status.expiresAt, client.receipt().expiresAt);
        if (!pendingToken || originalExpiry <= times.wall + 30_000) throw held();
        const owned = await readOwnedProbeIdentity(stateDir, identity.receipt());
        originalKeySnapshot = owned.snapshot; owned.key = undefined;
        retainedToken = pendingToken; pendingToken = ''; originalMetadataHash = hash;
        grantMonotonicDeadline = times.mono + originalExpiry - times.wall;
        beforeVerified = true; stage = 'BEFORE_VERIFIED';
      } else {
        if (hash !== originalMetadataHash) throw held();
        afterVerified = true; stage = 'AFTER_VERIFIED';
      }
      await emit('CORELY_AUTHORITY_STATUS_VERIFIED', { check: value, originalAuthorityExpiresAt, deadlineLowerBound: originalExpiry, metadataSha256: hash,
        modelTransportEnabled: false, nextCommand: value === 'BEFORE' ? 'AFTER_RESTART' : 'REVOKE' }); return;
    }
    if (value === 'REVOKE' && stage === 'AFTER_VERIFIED') {
      revocationAttempted = true;
      revocation = (await client.revokeAuthority(AbortSignal.any([operation.signal, AbortSignal.timeout(10_000)]))).remoteRevocation === 'CONFIRMED' ? 'CONFIRMED' : 'UNKNOWN';
      if (revocation !== 'CONFIRMED') throw held();
      const time = clock(); revokedAt = time.wall; revokedMonotonic = time.mono; stage = 'REVOKED';
      await emit('CORELY_REMOTE_REVOCATION_CONFIRMED', { remoteRevocation: revocation, serverPostRestartDenialVerified: false,
        nextCommand: 'NEGATIVE_AFTER_RESTART' }); return;
    }
    if (value === 'NEGATIVE_AFTER_RESTART' && stage === 'REVOKED') {
      // This is the sole operation outside the now-closed sealed client. The
      // operator separately proves the actual replacement revision in logs.
      const time = clock();
      if (!retainedToken || time.wall >= originalExpiry - 30_000 || time.mono >= grantMonotonicDeadline - 30_000 ||
          time.wall - revokedAt >= 300_000 || time.mono - revokedMonotonic >= 300_000 || calls.negative) throw held();
      calls.negative++;
      const owned = await readOwnedProbeIdentity(stateDir, identity.receipt()); key = owned.key; owned.key = undefined;
      if (owned.snapshot !== originalKeySnapshot) throw held();
      const fresh = clock();
      if (fresh.wall >= originalExpiry - 30_000 || fresh.mono >= grantMonotonicDeadline - 30_000 ||
          fresh.wall - revokedAt >= 300_000 || fresh.mono - revokedMonotonic >= 300_000) throw held();
      const header = Buffer.from(JSON.stringify({ typ: 'dpop+jwt', alg: 'EdDSA', jwk: owned.jwk })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({ htu: STATUS, htm: 'GET', iat: Math.floor(fresh.wall / 1000), jti: randomUUID(), ath: ath(retainedToken) })).toString('base64url');
      const message = `${header}.${payload}`;
      let proof = `${message}.${sign(null, Buffer.from(message), key).toString('base64url')}`; key = undefined;
      const traceId = randomBytes(16).toString('hex');
      let response, reader;
      const negativeSignal = AbortSignal.any([operation.signal, AbortSignal.timeout(10_000)]);
      try {
        response = await abortable(transport.fetchImpl(STATUS, { method: 'GET', redirect: 'error', credentials: 'omit', cache: 'no-store',
          headers: { Accept: 'application/json', Authorization: `DPoP ${retainedToken}`, DPoP: proof,
            'X-Cloud-Trace-Context': `${traceId}/0;o=1` }, signal: negativeSignal }), negativeSignal);
        proof = '';
        if (response.status !== 401 || response.redirected || response.url && response.url !== STATUS ||
            !/^application\/json(?:\s*;|$)/i.test(response.headers?.get('content-type') ?? '') ||
            response.headers?.get('cache-control') !== 'no-store' || response.headers?.get('www-authenticate') !== 'DPoP error="invalid_token"' ||
            response.headers?.has('content-encoding') || !response.body?.getReader) throw held();
        reader = response.body.getReader(); const chunks = []; let size = 0, eof = false;
        for (let reads = 0; reads < 32; reads++) {
          const part = await abortable(reader.read(), negativeSignal);
          if (part.done) { eof = true; break; }
          if (!(part.value instanceof Uint8Array) || (size += part.value.byteLength) > 4096) throw held();
          chunks.push(part.value);
        }
        if (!eof) throw held();
        const length = response.headers.get('content-length');
        if (length !== null && (!/^(?:0|[1-9][0-9]*)$/.test(length) || Number(length) !== size)) throw held();
        const text = new TextDecoder('utf8', { fatal: true }).decode(Buffer.concat(chunks));
        if (!/^\s*\{\s*"error"\s*:\s*"invalid_token"\s*\}\s*$/.test(text)) throw held();
        const end = clock();
        if (end.wall >= originalExpiry - 30_000 || end.mono >= grantMonotonicDeadline - 30_000 ||
            end.wall - revokedAt >= 300_000 || end.mono - revokedMonotonic >= 300_000) throw held();
        denialVerified = true; stage = 'DENIAL_VERIFIED';
        await emit('CORELY_POST_RESTART_REVOKED_TOKEN_DENIED', { traceId, httpStatus: 401, errorClass: 'invalid_token',
          completeEofVerified: true, freshProofUsed: true, originalGrantUnexpired: true, cloudRevisionVerifiedByThisDriver: false });
        return 'COMPLETE';
      } finally {
        proof = ''; retainedToken = ''; key = undefined;
        if (reader) { try { Promise.resolve(reader.cancel()).catch(() => {}); reader.releaseLock(); } catch { /* No body is exposed. */ } }
        else if (response?.body && !response.body.locked) void response.body.cancel().catch(() => {});
      }
    }
    throw held();
  };
  try {
    if (typeof maximumRuntimeMs !== 'number' || !Number.isSafeInteger(maximumRuntimeMs) || maximumRuntimeMs < 1 || maximumRuntimeMs > 20 * 60_000) throw held();
    const factory = identityFactory ?? (await import('./corely-vm-model-worker.mjs')).openCorelyVmModelIdentity;
    identity = await factory(stateDir, { initialize: false });
    const metadata = identity.receipt();
    if (metadata.hostIdHash !== HOST || metadata.syntheticOnly !== true || metadata.apiFallbackEnabled !== false) throw held();
    timer = setTimeout(() => { void finish('MAX_RUNTIME_REACHED'); }, maximumRuntimeMs);
    input.on('data', boundedInput);
    lines = createInterface({ input, crlfDelay: Infinity, terminal: false });
    lines.on('line', line => {
      if (finishing) return;
      if (line === 'STOP') { void finish('OPERATOR_STOPPED'); return; }
      if (line.length > 32 || !['CONNECT', 'BEFORE', 'AFTER_RESTART', 'REVOKE', 'NEGATIVE_AFTER_RESTART'].includes(line) || work) {
        void finish('COMMAND_PROTOCOL_HELD'); return;
      }
      work = command(line);
      void work.then(result => { work = undefined; if (result === 'COMPLETE') return finish('REQUESTED_COMPLETE', true); },
        () => { work = undefined; return finish('AUTHORITY_OPERATION_HELD'); });
    });
    lines.on('close', () => { if (!finishing) void finish('INPUT_CLOSED'); });
    signal?.addEventListener('abort', stopped, { once: true });
    if (signal?.aborted) stopped();
    else await emit('CLOUD_AUTHORITY_PROBE_READY', { nextCommand: 'CONNECT', modelCalls: 0, providerRequestsMade: 0 });
  } catch { await finish('DRIVER_START_HELD'); }
  return completion;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const controller = new AbortController();
  const stop = () => controller.abort();
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
  try {
    if (process.argv.length !== 2) throw held();
    for (const [name, expected] of Object.entries(SOURCE_HASHES)) {
      const bytes = await readFile(join(ROOT, name));
      if (bytes.length > 2_000_000 || digest(bytes) !== expected) throw held();
    }
    (await import('./siwc-local-vm.mjs')).assertIsolatedSessionEnvironment();
    const receipt = await runCorelyVmAuthorityProbe({ signal: controller.signal });
    process.exitCode = receipt.status === 'CLOUD_AUTHORITY_PROBE_COMPLETE' ? 0 : 1;
  } catch { process.stdout.write('{"status":"CLOUD_AUTHORITY_PROBE_HELD","reason":"DRIVER_START_HELD"}\n'); process.exitCode = 1; }
  finally { process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); }
}
