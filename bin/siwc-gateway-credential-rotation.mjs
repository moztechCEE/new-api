// Unwired DEV model-route adapter: no secret issuer, provider, listener, file
// reader or HTTP client. A future trusted installer must attest retirement and
// commit; an in-process acknowledgement alone is not remote-route evidence.
import { createHash, createPrivateKey, randomUUID, X509Certificate } from 'node:crypto';
import { createSecureContext } from 'node:tls';

const GATEWAY_URL = 'https://newapi-dev.corely.cc/v1/responses';
const BRIDGE_HOST = 'corely-siwc-bridge';
const DAY_MS = 86_400_000, MAX_AUTHORITY_MS = 30 * DAY_MS, LEASE_MS = 65_000, DRAIN_MS = 70_000, COMMIT_MS = 30_000;
const MAX_GENERATIONS = 4096;
const digest = value => createHash('sha256').update(value).digest('hex');
const fixedFailure = code => Object.assign(new Error(code), { code });
const reject = code => { throw fixedFailure(code); };
const binding = { tenantId: 'moztech', brandId: 'moztech-test', syntheticOnly: true, apiFallbackEnabled: false, noPaidCredits: true };
const bound = value => Object.entries(binding).every(([key, expected]) => value[key] === expected);
const plain = (value, keys, code) => {
  if (!value || typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) reject(code);
  const properties = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(properties).length !== keys.length || keys.some(key => !Object.hasOwn(properties, key) || !Object.hasOwn(properties[key], 'value'))) reject(code);
  return Object.fromEntries(keys.map(key => [key, properties[key].value]));
};

function whileActive(signal, action) {
  return new Promise((resolve, rejectPromise) => {
    const abort = () => rejectPromise(fixedFailure('GATEWAY_ROTATION_HELD'));
    if (signal.aborted) { abort(); return; }
    signal.addEventListener('abort', abort, { once: true });
    Promise.resolve().then(() => {
      signal.throwIfAborted();
      return action();
    }).then(resolve, rejectPromise).finally(() => signal.removeEventListener('abort', abort));
  });
}

function certificate(pem, code) {
  if (typeof pem !== 'string' || pem.length > 16_384) reject(code);
  const cert = new X509Certificate(pem);
  if (cert.toString().trim() !== pem.trim()) reject(code);
  return cert;
}

/** Trusted installer/consumer callbacks own their private inputs and must not
 * retain/log them. This adapter returns only fixed operational metadata. It
 * does not turn arbitrary caller snapshots into an authorization. */
export function openCorelyDevGatewayCredentialRotation(options) {
  if (options?.enabled !== true) reject('GATEWAY_ROTATION_DISABLED');
  const { authority, bridgeCaPem, initial, signal, now = Date.now, monotonicNow = () => performance.now() } = options;
  if (!(signal instanceof AbortSignal) || signal.aborted || typeof now !== 'function' || typeof monotonicNow !== 'function') reject('GATEWAY_ROTATION_OPTIONS_INVALID');
  const controller = new AbortController();
  let active, staged, owner, draining = false, closed = false, lastWall = -1, lastMono = -1;
  const seen = new Set();
  const close = () => {
    if (closed) return;
    closed = true; active = undefined; staged = undefined; seen.clear();
    controller.abort(); signal.removeEventListener('abort', close);
  };
  const clock = () => {
    try {
      const wall = now(), mono = monotonicNow();
      if (!Number.isSafeInteger(wall) || wall < 0 || wall < lastWall || wall > Number.MAX_SAFE_INTEGER - MAX_AUTHORITY_MS ||
          !Number.isFinite(mono) || mono < 0 || mono < lastMono || mono > Number.MAX_SAFE_INTEGER - MAX_AUTHORITY_MS) reject('GATEWAY_ROTATION_HELD');
      lastWall = wall; lastMono = mono; return { wall, mono };
    } catch { close(); reject('GATEWAY_ROTATION_HELD'); }
  };
  const parent = plain(authority, ['kind', 'authorityIdSha256', 'expiresAt', ...Object.keys(binding)], 'GATEWAY_ROTATION_AUTHORITY_INVALID');
  const started = clock();
  if (parent.kind !== 'CORELY_DEV_MODEL_GATEWAY_AUTHORITY_V1' || !bound(parent) ||
      typeof parent.authorityIdSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(parent.authorityIdSha256) ||
      !Number.isSafeInteger(parent.expiresAt) || parent.expiresAt <= started.wall || parent.expiresAt > started.wall + MAX_AUTHORITY_MS) {
    reject('GATEWAY_ROTATION_AUTHORITY_INVALID');
  }
  const parentDeadline = started.mono + (parent.expiresAt - started.wall);
  let ca;
  try {
    ca = certificate(bridgeCaPem, 'GATEWAY_ROTATION_AUTHORITY_INVALID');
    if (!ca.ca) reject('GATEWAY_ROTATION_AUTHORITY_INVALID');
  } catch { reject('GATEWAY_ROTATION_AUTHORITY_INVALID'); }
  const snapshot = (input, time) => {
    try {
      const value = plain(input, ['kind', 'generation', 'authorityIdSha256', 'parentExpiresAt', 'expiresAt',
        'gatewayUrl', 'bridgeHost', 'gatewayToken', 'bridgeSecret', 'tlsCertificatePem', 'tlsPrivateKeyPem', ...Object.keys(binding)],
      'GATEWAY_ROTATION_SNAPSHOT_INVALID');
      if (value.kind !== 'CORELY_DEV_MODEL_GATEWAY_CREDENTIALS_V1' || !bound(value) ||
          value.authorityIdSha256 !== parent.authorityIdSha256 || value.parentExpiresAt !== parent.expiresAt ||
          !Number.isSafeInteger(value.generation) || value.generation < 1 || value.generation >= Number.MAX_SAFE_INTEGER ||
          value.gatewayUrl !== GATEWAY_URL || value.bridgeHost !== BRIDGE_HOST ||
          !Number.isSafeInteger(value.expiresAt) || value.expiresAt <= time.wall ||
          value.expiresAt > Math.min(parent.expiresAt, time.wall + DAY_MS) ||
          typeof value.gatewayToken !== 'string' || !/^[A-Za-z0-9_-]{32,256}$/.test(value.gatewayToken) ||
          typeof value.bridgeSecret !== 'string' || !/^[A-Za-z0-9_-]{43,256}$/.test(value.bridgeSecret) ||
          value.gatewayToken === value.bridgeSecret || typeof value.tlsPrivateKeyPem !== 'string' || value.tlsPrivateKeyPem.length > 16_384) {
        reject('GATEWAY_ROTATION_SNAPSHOT_INVALID');
      }
      const leaf = certificate(value.tlsCertificatePem, 'GATEWAY_ROTATION_SNAPSHOT_INVALID'), key = createPrivateKey(value.tlsPrivateKeyPem);
      const strongKey = key.asymmetricKeyType === 'ed25519' ||
        (key.asymmetricKeyType === 'rsa' && key.asymmetricKeyDetails?.modulusLength >= 3072) ||
        (key.asymmetricKeyType === 'ec' && ['prime256v1', 'secp384r1', 'secp521r1'].includes(key.asymmetricKeyDetails?.namedCurve));
      const covers = cert => Date.parse(cert.validFrom) <= time.wall && Date.parse(cert.validTo) >= value.expiresAt;
      if (!strongKey || leaf.ca || !leaf.checkPrivateKey(key) || leaf.checkHost(BRIDGE_HOST, { subject: 'never', wildcards: false }) !== BRIDGE_HOST ||
          !leaf.checkIssued(ca) || !leaf.verify(ca.publicKey) || !covers(leaf) || !covers(ca)) reject('GATEWAY_ROTATION_SNAPSHOT_INVALID');
      createSecureContext({ key: value.tlsPrivateKeyPem, cert: value.tlsCertificatePem, minVersion: 'TLSv1.2' });
      return Object.freeze({ generation: value.generation, expiresAt: value.expiresAt,
        deadline: Math.min(parentDeadline, time.mono + (value.expiresAt - time.wall)),
        bundleSha256: digest(`CorelyDevModelGatewayCredentials:v1\0${JSON.stringify(value)}`),
        fingerprints: [digest(leaf.publicKey.export({ type: 'spki', format: 'der' })), digest(value.gatewayToken), digest(value.bridgeSecret)],
        material: Object.freeze({ gatewayUrl: value.gatewayUrl, gatewayToken: value.gatewayToken, bridgeSecret: value.bridgeSecret,
          tlsCertificatePem: value.tlsCertificatePem, tlsPrivateKeyPem: value.tlsPrivateKeyPem }) });
    } catch { reject('GATEWAY_ROTATION_SNAPSHOT_INVALID'); }
  };
  active = snapshot(initial, started);
  for (const fingerprint of active.fingerprints) seen.add(fingerprint);
  signal.addEventListener('abort', close, { once: true });
  const check = (version = active) => {
    if (closed || !version || signal.aborted) { close(); reject('GATEWAY_ROTATION_HELD'); }
    const { wall, mono } = clock();
    const remaining = Math.min(parent.expiresAt - wall, parentDeadline - mono, version.expiresAt - wall, version.deadline - mono);
    if (remaining <= 0) { close(); reject('GATEWAY_ROTATION_HELD'); }
    return remaining;
  };
  const receipt = () => {
    check();
    return Object.freeze({ status: draining ? 'GATEWAY_ROTATION_DRAINING' : 'GATEWAY_ROTATION_READY',
      generation: active.generation, expiresAt: active.expiresAt, parentExpiresAt: parent.expiresAt,
      authorityIdSha256: parent.authorityIdSha256,
      syntheticOnly: true, apiFallbackEnabled: false, noPaidCredits: true });
  };
  return Object.freeze({
    receipt, close,
    async withLease(consume) {
      if (typeof consume !== 'function') reject('GATEWAY_ROTATION_OPTIONS_INVALID');
      const remaining = check();
      if (draining || owner) reject('GATEWAY_ROTATION_BUSY');
      const version = active, leaseId = randomUUID();
      let settled;
      owner = new Promise(resolve => { settled = resolve; });
      const permit = AbortSignal.any([controller.signal, AbortSignal.timeout(Math.max(1, Math.ceil(Math.min(LEASE_MS, remaining))))]);
      try {
        const result = plain(await whileActive(permit, () => consume(Object.freeze({
          credentials: version.material, signal: permit, generation: version.generation, leaseId,
        }))), ['status', 'generation', 'leaseId'], 'GATEWAY_ROTATION_HELD');
        check(version);
        if (permit.aborted || result.status !== 'CORELY_DEV_GATEWAY_LEASE_SETTLED' || result.generation !== version.generation ||
            result.leaseId !== leaseId) reject('GATEWAY_ROTATION_HELD');
        return Object.freeze({ status: result.status, generation: result.generation });
      } catch { close(); reject('GATEWAY_ROTATION_HELD'); }
      finally { owner = undefined; settled(); }
    },
    async replace(expectedGeneration, candidate, commit) {
      if (typeof commit !== 'function' || !Number.isSafeInteger(expectedGeneration)) reject('GATEWAY_ROTATION_OPTIONS_INVALID');
      check();
      if (draining) reject('GATEWAY_ROTATION_BUSY');
      const previous = active;
      if (expectedGeneration !== previous.generation) reject('GATEWAY_ROTATION_STALE');
      const next = snapshot(candidate, clock());
      if (next.generation !== previous.generation + 1) reject('GATEWAY_ROTATION_STALE');
      if (seen.size >= MAX_GENERATIONS * 3 || next.fingerprints.some(fingerprint => seen.has(fingerprint))) reject('GATEWAY_ROTATION_SNAPSHOT_INVALID');
      staged = next; draining = true;
      try {
        if (owner) await whileActive(AbortSignal.any([controller.signal, AbortSignal.timeout(DRAIN_MS)]), () => owner);
        const remaining = Math.min(check(previous), check(next));
        if (owner || staged !== next || active !== previous) reject('GATEWAY_ROTATION_HELD');
        const permit = AbortSignal.any([controller.signal, AbortSignal.timeout(Math.max(1, Math.ceil(Math.min(COMMIT_MS, remaining))))]);
        const result = plain(await whileActive(permit, () => commit(Object.freeze({
          previousGeneration: previous.generation, nextGeneration: next.generation, nextExpiresAt: next.expiresAt,
          previousBundleSha256: previous.bundleSha256, nextBundleSha256: next.bundleSha256,
          next: next.material, signal: permit,
        }))), ['status', 'previousGeneration', 'nextGeneration', 'previousBundleSha256', 'nextBundleSha256', 'predecessorRetired'], 'GATEWAY_ROTATION_HELD');
        check(previous); check(next);
        if (permit.aborted || result.status !== 'CORELY_DEV_GATEWAY_CREDENTIALS_COMMITTED' || result.previousGeneration !== previous.generation ||
            result.nextGeneration !== next.generation || result.previousBundleSha256 !== previous.bundleSha256 ||
            result.nextBundleSha256 !== next.bundleSha256 || result.predecessorRetired !== true) reject('GATEWAY_ROTATION_HELD');
        for (const fingerprint of next.fingerprints) seen.add(fingerprint);
        active = next; staged = undefined; draining = false;
        return receipt();
      } catch { close(); reject('GATEWAY_ROTATION_HELD'); }
    },
  });
}
