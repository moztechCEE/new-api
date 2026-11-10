// Standalone DEV issuer adapter. No operator login, provider, bridge changes or
// daemon wiring. A private caller supplies a dedicated owner's scoped PAT and
// an independently verified token-ID-independent routing projection.
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { isIPv4 } from 'node:net';
import { corelyDevGoTokenLoopbackBinding } from './siwc-gateway-go-loopback.mjs';

const BASE = 'https://newapi-dev.corely.cc', MODEL = 'gpt-6.1-sol', DAY = 86_400_000;
// Go issues a random alphanumeric string, not canonical base64url bytes.
const HASH = /^[a-f0-9]{64}$/u, RELAY_TOKEN = /^[A-Za-z0-9]{48}$/u, PAT = /^nap_[A-Za-z0-9]{43}$/u;
const REQUEST_ID = /^[a-zA-Z0-9._-]{1,128}$/u;
const kind = 'CORELY_DEV_GO_TOKEN_JOURNAL_V1', MAX = 4096;
const hash = input => createHash('sha256').update(input).digest('hex');
const deny = code => { throw Object.assign(new Error(code), { code }); };
const hold = () => deny('GO_TOKEN_INSTALL_HELD');
const positive = value => Number.isSafeInteger(value) && value > 0;
const object = value => value && typeof value === 'object' && !Array.isArray(value);
const exact = (value, keys) => object(value) && Reflect.ownKeys(value).length === keys.length &&
  keys.every(key => Object.hasOwn(Object.getOwnPropertyDescriptor(value, key) ?? {}, 'value'));
const same = (a, b) => a.dev === b.dev && a.ino === b.ino;
const secure = (stat, mode) => (stat.mode & 0o777) === mode && (!process.getuid || stat.uid === process.getuid());
const success = value => value?.success === true && value.message === '';

export async function openCorelyDevGoTokenInstaller(options = {}) {
  if (options.enabled !== true) deny('GO_TOKEN_INSTALL_DISABLED');
  const { stateDir, authority, management, fetchImpl, verifyRoute, signal, credentialOnly = false, now = Date.now } = options;
  const loopback = corelyDevGoTokenLoopbackBinding(fetchImpl);
  if (!exact(authority, ['authorityIdSha256', 'expiresAt', 'ownerId', 'group', 'allowedIp', 'channelId']) ||
      !HASH.test(authority.authorityIdSha256) || !positive(authority.expiresAt) || !positive(authority.ownerId) || !positive(authority.channelId) ||
      typeof credentialOnly !== 'boolean' || (credentialOnly ?
        authority.group !== 'corely-dev-siwc' || authority.channelId !== 10 || !loopback ||
          loopback.authorityIdSha256 !== authority.authorityIdSha256 || loopback.ownerId !== authority.ownerId || loopback.allowedIp !== authority.allowedIp :
        typeof authority.group !== 'string' || !/^corely-siwc-[a-z0-9-]{1,32}$/u.test(authority.group) || loopback) || !isIPv4(authority.allowedIp) ||
      !exact(management, ['token', 'expiresAt']) || !PAT.test(management.token) || !positive(management.expiresAt) ||
      management.expiresAt > authority.expiresAt || !isAbsolute(stateDir ?? '') || typeof fetchImpl !== 'function' ||
      typeof verifyRoute !== 'function' || typeof now !== 'function' || !(signal instanceof AbortSignal) || signal.aborted) hold();
  const policy = Object.freeze({ ...authority }), pat = Object.freeze({ ...management });
  const started = now();
  if (!positive(started) || started >= pat.expiresAt || policy.expiresAt - started > (credentialOnly ? 2 * 3_600_000 : 30 * DAY)) hold();
  let wall = started, busy = false, closed = false;
  const active = new AbortController();
  const shutdown = () => { closed = true; active.abort(); signal.removeEventListener('abort', shutdown); };
  signal.addEventListener('abort', shutdown, { once: true });
  const clock = (deadline = pat.expiresAt) => {
    const at = now();
    if (closed || !positive(at) || at < wall || at >= Math.min(deadline, policy.expiresAt, pat.expiresAt)) hold();
    wall = at; return at;
  };
  const label = generation => `corely-siwc-${policy.authorityIdSha256.slice(0, 18)}-${generation}`;
  const journalPath = (generation, phase) => join(stateDir, `${label(generation)}.${phase}.json`);
  const root = await lstat(stateDir).catch(hold);
  if (await realpath(stateDir).catch(hold) !== stateDir || !root.isDirectory() || !secure(root, 0o700)) { shutdown(); hold(); }
  const rootIsCurrent = async () => {
    const stat = await lstat(stateDir);
    if (!stat.isDirectory() || !same(stat, root) || !secure(stat, 0o700)) hold();
  };
  const journal = async (generation, phase, data) => {
    await rootIsCurrent();
    let file, dir;
    try {
      const path = journalPath(generation, phase);
      if (data) {
        // A durable O_EXCL intent is the generation CAS. It is intentionally
        // never removed, even when the network outcome cannot be determined.
        file = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
        await file.writeFile(JSON.stringify(data)); await file.sync();
        dir = await open(stateDir, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
        if (!same(await dir.stat(), root)) hold();
        await dir.sync(); await rootIsCurrent(); return;
      }
      file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
      const first = await file.stat();
      if (!first.isFile() || first.nlink !== 1 || !secure(first, 0o600) || first.size > 2048) hold();
      const bytes = await file.readFile(), last = await file.stat(), current = await lstat(path);
      if (!same(first, current) || first.size !== bytes.length || first.mtimeMs !== last.mtimeMs || last.mtimeMs !== current.mtimeMs) hold();
      await rootIsCurrent(); return JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(bytes));
    } finally { await file?.close(); await dir?.close(); }
  };
  const step = async (operation, permit) => {
    const bound = AbortSignal.any([active.signal, permit, AbortSignal.timeout(8000)]);
    return new Promise((resolve, reject) => {
      const aborted = () => reject(new Error('GO_TOKEN_INSTALL_HELD'));
      if (bound.aborted) { aborted(); return; }
      bound.addEventListener('abort', aborted, { once: true });
      Promise.resolve().then(() => { bound.throwIfAborted(); return operation(bound); })
        .then(resolve, reject).finally(() => bound.removeEventListener('abort', aborted));
    });
  };
  const call = (path, method, permit, { body, token, deadline } = {}) => step(async bound => {
    clock(deadline);
    const headers = { Accept: 'application/json', 'Accept-Language': 'en', 'Accept-Encoding': 'identity',
      'Cache-Control': 'no-cache, no-store', Pragma: 'no-cache',
      Authorization: `Bearer ${token ? `sk-${token}` : pat.token}`, ...(token ? {} : { 'New-Api-User': String(policy.ownerId) }),
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) };
    const response = await fetchImpl(BASE + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body),
      cache: 'no-store', credentials: 'omit', redirect: 'error', signal: bound });
    bound.throwIfAborted();
    const encoding = response.headers.get('content-encoding');
    if (response.redirected || (response.url && response.url !== BASE + path) || encoding && encoding !== 'identity' ||
        !/^application\/json(?:;\s*charset=utf-8)?$/iu.test(response.headers.get('content-type') ?? '') || !response.body) hold();
    const reader = response.body.getReader(), parts = []; let total = 0, ended = false;
    try {
      for (;;) {
        const part = await reader.read();
        bound.throwIfAborted();
        if (part.done) { ended = true; break; }
        if (!(part.value instanceof Uint8Array) || (total += part.value.length) > 32_768) hold();
        parts.push(part.value);
      }
    } finally { if (!ended) void reader.cancel().catch(() => {}); reader.releaseLock(); }
    clock(deadline);
    return { status: response.status, requestId: response.headers.get('x-oneapi-request-id'), age: response.headers.get('age'),
      body: JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(Buffer.concat(parts))) };
  }, permit);
  const routed = (permit, deadline) => step(async bound => {
    const checked = clock(deadline);
    const proof = await verifyRoute(bound);
    bound.throwIfAborted();
    const at = clock(deadline);
    if (!exact(proof, ['authorityIdSha256', 'ownerId', 'group', 'channelId', 'allowedIp', 'model', 'revisionSha256', 'verifiedAt',
      'ordinaryOwner', 'sameOwnerAcrossTokenIds', 'apiFallbackEnabled', 'paidCreditsEnabled', 'bodyPassthrough', 'headerPassthrough', 'retryCount', 'groupRatio',
      ...(credentialOnly ? ['credentialOnly', 'inferenceDisabled'] : [])]) ||
        proof.authorityIdSha256 !== policy.authorityIdSha256 || proof.ownerId !== policy.ownerId || proof.group !== policy.group ||
        proof.channelId !== policy.channelId || proof.allowedIp !== policy.allowedIp || proof.model !== MODEL || !HASH.test(proof.revisionSha256) ||
        !positive(proof.verifiedAt) || proof.verifiedAt < checked - 5000 || proof.verifiedAt > at ||
        proof.ordinaryOwner !== true || proof.sameOwnerAcrossTokenIds !== true || proof.apiFallbackEnabled !== false || proof.paidCreditsEnabled !== false ||
        proof.bodyPassthrough !== !credentialOnly || proof.headerPassthrough !== false || proof.retryCount !== 0 || proof.groupRatio !== 0 ||
        credentialOnly && (proof.credentialOnly !== true || proof.inferenceDisabled !== true)) hold();
    return proof.revisionSha256;
  }, permit);
  const probe = async (token, rejected, permit, deadline, probeIds) => {
    const result = await call('/v1/models', 'GET', permit, { token, deadline });
    if (!REQUEST_ID.test(result.requestId ?? '') || ![null, '0'].includes(result.age) || probeIds.has(result.requestId)) hold();
    probeIds.add(result.requestId);
    if (rejected) {
      const error = result.body?.error;
      if (result.status !== 401 || !exact(result.body, ['error']) || !exact(error, ['type', 'code', 'message']) || error.type !== 'new_api_error' ||
          error.code !== '' || error.message !== `Invalid token (request id: ${result.requestId})`) hold();
    } else if (result.status !== 200 || !exact(result.body, ['success', 'data', 'object']) || result.body.success !== true ||
        result.body.object !== 'list' || !Array.isArray(result.body.data) || result.body.data.length !== 1 || result.body.data[0]?.id !== MODEL) hold();
    return hash(result.requestId);
  };
  const scoped = (value, generation, expiresAt) => object(value) && positive(value.id) && value.user_id === policy.ownerId &&
    typeof value.key === 'string' && /^[A-Za-z0-9]{4}\*{10}[A-Za-z0-9]{4}$/u.test(value.key) && value.name === label(generation) &&
    value.status === 1 && value.expired_time === expiresAt / 1000 && value.model_limits_enabled === true && value.model_limits === MODEL &&
    value.group === policy.group && value.allow_ips === policy.allowedIp && value.cross_group_retry === false && value.auto_groups === null &&
    value.unlimited_quota === false && value.remain_quota === 1 && value.allow_user_quota_query === false;
  const assertOrdinaryOwner = async (permit, deadline) => {
    const self = await call('/api/user/self', 'GET', permit, { deadline });
    if (self.status !== 200 || !success(self.body) || self.body.data?.id !== policy.ownerId || self.body.data.role !== 1 ||
        self.body.data.status !== 1 || self.body.data.group !== policy.group) hold();
  };
  const reveal = async (tokenId, permit, deadline) => {
    const result = await call(`/api/token/${tokenId}/key`, 'POST', permit, { deadline });
    const token = result.body?.data?.key;
    if (result.status !== 200 || !success(result.body) || !exact(result.body.data, ['key']) || !RELAY_TOKEN.test(token ?? '')) hold();
    return token;
  };
  return Object.freeze({
    close: shutdown,
    async rotate({ generation, previousTokenId, previousToken, previousExpiresAt, nextExpiresAt, signal: permit } = {}) {
      if (closed) hold();
      if (busy) deny('GO_TOKEN_INSTALL_BUSY');
      if (!positive(generation) || generation >= MAX || !positive(previousTokenId) || !RELAY_TOKEN.test(previousToken ?? '') ||
          !positive(previousExpiresAt) || !positive(nextExpiresAt) || previousExpiresAt % 1000 || nextExpiresAt % 1000 ||
          !(permit instanceof AbortSignal) || permit.aborted) deny('GO_TOKEN_INSTALL_INVALID');
      busy = true;
      try {
        const start = clock(previousExpiresAt);
        if (previousExpiresAt > policy.expiresAt || nextExpiresAt <= start + 60_000 ||
            nextExpiresAt > Math.min(start + 6 * 3_600_000, pat.expiresAt, policy.expiresAt)) hold();
        const next = generation + 1, previousHash = hash(previousToken), probeIds = new Set();
        const base = { kind, authorityIdSha256: policy.authorityIdSha256, authorityExpiresAt: policy.expiresAt, ownerId: policy.ownerId, group: policy.group,
          ...(credentialOnly ? { credentialOnly: true } : {}) };
        if (generation > 1) {
          const previous = await journal(generation, 'commit');
          if (!exact(previous, [...Object.keys(base), 'generation', 'tokenId', 'tokenSha256', 'expiresAt', 'oldTokenRejected', 'denialRequestIdSha256', 'routeRevisionSha256']) ||
              !Object.keys(base).every(key => previous[key] === base[key]) || previous.generation !== generation ||
              previous.tokenId !== previousTokenId || previous.tokenSha256 !== previousHash || previous.expiresAt !== previousExpiresAt ||
              previous.oldTokenRejected !== true || !HASH.test(previous.denialRequestIdSha256) || !HASH.test(previous.routeRevisionSha256)) hold();
        }
        const revision = await routed(permit, previousExpiresAt);
        await assertOrdinaryOwner(permit, previousExpiresAt);
        const old = await call(`/api/token/${previousTokenId}`, 'GET', permit, { deadline: previousExpiresAt });
        if (old.status !== 200 || !success(old.body) || !scoped(old.body.data, generation, previousExpiresAt) ||
            old.body.data.id !== previousTokenId || old.body.data.key !== `${previousToken.slice(0, 4)}**********${previousToken.slice(-4)}`) hold();
        if (await reveal(previousTokenId, permit, previousExpiresAt) !== previousToken) hold();
        await probe(previousToken, false, permit, previousExpiresAt, probeIds);
        const query = `/api/token/search?keyword=${label(next)}&p=1&page_size=10`;
        const search = async () => {
          const response = await call(query, 'GET', permit, { deadline: previousExpiresAt });
          if (response.status !== 200 || !success(response.body) || !Array.isArray(response.body.data?.items) ||
              response.body.data.total !== response.body.data.items.length) hold();
          return response.body.data.items;
        };
        if ((await search()).length !== 0) hold();
        await journal(next, 'intent', { ...base, generation: next, previousTokenId, previousHash, previousExpiresAt, nextExpiresAt, routeRevisionSha256: revision });
        const result = await call('/api/token/', 'POST', permit, { deadline: previousExpiresAt, body: {
          name: label(next), expired_time: nextExpiresAt / 1000, group: policy.group, allow_ips: policy.allowedIp,
          model_limits_enabled: true, model_limits: MODEL, cross_group_retry: false, allow_user_quota_query: false,
          auto_groups: null, unlimited_quota: false, remain_quota: 1,
        } });
        if (result.status !== 200 || !success(result.body)) hold();
        const rows = await search();
        if (rows.length !== 1 || !scoped(rows[0], next, nextExpiresAt) || rows[0].id === previousTokenId) hold();
        const tokenId = rows[0].id;
        const token = await reveal(tokenId, permit, previousExpiresAt);
        if (token === previousToken || rows[0].key !== `${token.slice(0, 4)}**********${token.slice(-4)}`) hold();
        await probe(token, false, permit, previousExpiresAt, probeIds);
        if (await routed(permit, previousExpiresAt) !== revision) hold();
        await assertOrdinaryOwner(permit, previousExpiresAt);
        const retired = await call(`/api/token/${previousTokenId}`, 'DELETE', permit, { deadline: previousExpiresAt });
        if (retired.status !== 200 || !success(retired.body)) hold();
        const denialRequestIdSha256 = await probe(previousToken, true, permit, previousExpiresAt, probeIds);
        await probe(token, false, permit, previousExpiresAt, probeIds);
        if (await routed(permit, previousExpiresAt) !== revision) hold();
        await journal(next, 'commit', { ...base, generation: next, tokenId, tokenSha256: hash(token), expiresAt: nextExpiresAt,
          oldTokenRejected: true, denialRequestIdSha256, routeRevisionSha256: revision });
        clock(previousExpiresAt); permit.throwIfAborted();
        return Object.freeze({ token, receipt: Object.freeze({ status: 'CORELY_DEV_GO_TOKEN_REPLACEMENT_VERIFIED', generation: next, tokenId,
          expiresAt: nextExpiresAt, predecessorRejected: true, routeRevisionSha256: revision, modelRequestsMade: 0,
          ...(credentialOnly ? { credentialOnly: true } : {}) }) });
      } catch { shutdown(); hold(); } finally { busy = false; }
    },
  });
}
