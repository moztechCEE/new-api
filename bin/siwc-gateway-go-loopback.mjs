// A VM-local credential-control transport, never a model/proxy transport.
import { Agent, request } from 'node:http';
import { isIPv4 } from 'node:net';
import { Readable } from 'node:stream';

const LOGICAL = 'https://newapi-dev.corely.cc', PRIVATE = 'http://127.0.0.1:3000';
const GROUP = 'corely-dev-siwc', MODEL = 'gpt-6.1-sol';
const bindings = new WeakMap();
const agent = new Agent({ keepAlive: false, maxSockets: 1 });
const deny = code => { throw Object.assign(new Error(code), { code }); };
const held = () => deny('GO_TOKEN_LOOPBACK_HELD');
const exact = (value, keys) => value && typeof value === 'object' && [Object.prototype, null].includes(Object.getPrototypeOf(value)) &&
  Reflect.ownKeys(value).length === keys.length && keys.every(key => Object.hasOwn(Object.getOwnPropertyDescriptor(value, key) ?? {}, 'value'));
const integer = value => Number.isSafeInteger(value) && value > 0;

function directRequest(url, options) {
  return new Promise((resolve, reject) => {
    const req = request(url, { method: options.method, headers: options.headers, signal: options.signal, agent }, res => {
      if (res.socket.remoteAddress !== '127.0.0.1' || res.socket.remotePort !== 3000) {
        res.destroy(); reject(new Error('GO_TOKEN_LOOPBACK_HELD')); return;
      }
      const headers = new Headers();
      for (const [name, value] of Object.entries(res.headers)) {
        for (const entry of Array.isArray(value) ? value : [value]) if (entry !== undefined) headers.append(name, entry);
      }
      resolve({ status: res.statusCode, url, headers, body: Readable.toWeb(res) });
    });
    req.once('error', reject);
    req.end(options.body);
  });
}

export function corelyDevGoTokenLoopbackBinding(transport) { return bindings.get(transport); }

export function openCorelyDevGoTokenLoopback(options = {}) {
  if (options.enabled !== true) deny('GO_TOKEN_LOOPBACK_DISABLED');
  // requestImpl is a trusted in-process test seam. There is no CLI/env
  // selection of an HTTP implementation, Host header or alternate target.
  const { authorityIdSha256, ownerId, allowedIp, requestImpl = directRequest } = options;
  if (typeof authorityIdSha256 !== 'string' || !/^[a-f0-9]{64}$/u.test(authorityIdSha256) ||
      !integer(ownerId) || !isIPv4(allowedIp) || typeof requestImpl !== 'function') held();
  const label = `corely-siwc-${authorityIdSha256.slice(0, 18)}-`;
  const search = new RegExp(`^/api/token/search\\?keyword=${label}[1-9][0-9]{0,3}&p=1&page_size=10$`, 'u');
  const id = '[1-9][0-9]{0,15}';
  const metadata = new RegExp(`^/api/token/${id}$`, 'u'), reveal = new RegExp(`^/api/token/${id}/key$`, 'u');
  const transport = async (url, init) => {
    try {
      if (typeof url !== 'string' || !url.startsWith(LOGICAL + '/') ||
          !exact(init, ['method', 'headers', 'body', 'cache', 'credentials', 'redirect', 'signal']) ||
          init.cache !== 'no-store' || init.credentials !== 'omit' || init.redirect !== 'error' ||
          !(init.signal instanceof AbortSignal) || init.signal.aborted) held();
      const path = url.slice(LOGICAL.length), method = init.method, headers = init.headers;
      const probe = path === '/v1/models' && method === 'GET', create = path === '/api/token/' && method === 'POST';
      if (!probe && !create && !(method === 'GET' && (path === '/api/user/self' || metadata.test(path) || search.test(path))) &&
          !(method === 'POST' && reveal.test(path)) && !(method === 'DELETE' && metadata.test(path))) held();
      if (!exact(headers, ['Accept', 'Accept-Language', 'Accept-Encoding', 'Cache-Control', 'Pragma', 'Authorization',
        ...(probe ? [] : ['New-Api-User']), ...(create ? ['Content-Type'] : [])]) ||
          headers.Accept !== 'application/json' || headers['Accept-Language'] !== 'en' || headers['Accept-Encoding'] !== 'identity' ||
          headers['Cache-Control'] !== 'no-cache, no-store' || headers.Pragma !== 'no-cache' ||
          typeof headers.Authorization !== 'string' || !(probe ? /^Bearer sk-[A-Za-z0-9]{48}$/u : /^Bearer nap_[A-Za-z0-9]{43}$/u).test(headers.Authorization) ||
          !probe && headers['New-Api-User'] !== String(ownerId) ||
          (create ? headers['Content-Type'] !== 'application/json' || typeof init.body !== 'string' || Buffer.byteLength(init.body) > 1024 :
            init.body !== undefined)) held();
      if (create) {
        const body = JSON.parse(init.body);
        if (JSON.stringify(body) !== init.body || !exact(body, ['name', 'expired_time', 'group', 'allow_ips', 'model_limits_enabled', 'model_limits', 'cross_group_retry',
          'allow_user_quota_query', 'auto_groups', 'unlimited_quota', 'remain_quota']) ||
            typeof body.name !== 'string' || !new RegExp(`^${label}[1-9][0-9]{0,3}$`, 'u').test(body.name) ||
            !integer(body.expired_time) || body.group !== GROUP || body.allow_ips !== allowedIp ||
            body.model_limits_enabled !== true || body.model_limits !== MODEL || body.cross_group_retry !== false ||
            body.allow_user_quota_query !== false || body.auto_groups !== null || body.unlimited_quota !== false || body.remain_quota !== 1) held();
      }
      const privateUrl = PRIVATE + path;
      const raw = await requestImpl(privateUrl, Object.freeze({ method, headers: Object.freeze({ ...headers }), body: init.body, signal: init.signal }));
      if (init.signal.aborted || raw?.url !== privateUrl || raw.redirected || !Number.isSafeInteger(raw.status) ||
          raw.status < 200 || raw.status > 599 || raw.status >= 300 && raw.status < 400 ||
          !(raw.headers instanceof Headers) || raw.headers.has('location') || !raw.body?.getReader) {
        if (raw?.body && !raw.body.locked) void raw.body.cancel().catch(() => {});
        held();
      }
      return Object.freeze({ url, status: raw.status, headers: raw.headers, body: raw.body, redirected: false });
    } catch { held(); }
  };
  bindings.set(transport, Object.freeze({ authorityIdSha256, ownerId, allowedIp }));
  return Object.freeze(transport);
}
